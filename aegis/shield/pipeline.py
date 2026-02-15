"""
Shield Pipeline — Orchestrates the full ingress/egress security chain.

Ingress (before sending to LLM):
    1. PII Detection + Semantic Swapping
    2. Structural Tagging (wrap user content in <user_data>)
    3. Canary Injection (add canary to system prompt)

Egress (after receiving from LLM):
    1. Canary Leak Detection (multi-encoding check)
    2. Output Moderation (content scoring)
    3. PII Restoration (swap synthetic data back to real)

Note: The ML guardrail classifier is NOT part of this synchronous pipeline.
It runs asynchronously in parallel with the LLM call at the proxy route
level, following the OpenAI cookbook's async-parallel pattern for zero
added latency. See aegis/proxy/routes.py for the async orchestration.
"""

from dataclasses import dataclass, field

from aegis.shield.canary.detector import CanaryCheckResult, CanaryDetector
from aegis.shield.canary.generator import CanaryGenerator
from aegis.shield.canary.injector import CanaryInjector
from aegis.shield.guardrail.classifier import (
    ClassificationResult,
    GuardrailLabel,
    PromptInjectionClassifier,
)
from aegis.shield.guardrail.output_moderator import (
    ModerationResult,
    OutputModerator,
)
from aegis.shield.pii.swapper import SemanticSwapper, SwapMap
from aegis.shield.tagger.structural import StructuralTagger
from aegis.utils.logging import log


@dataclass
class ShieldContext:
    """Context passed from ingress to egress processing.

    Carries the swap map, canary, and guardrail results so the
    egress phase can reverse the transformations and build reports.
    """
    session_id: str
    canary: str
    swap_map: SwapMap
    guardrail_result: ClassificationResult | None = None
    alerts: list[str] = field(default_factory=list)


@dataclass
class EgressResult:
    """Result of egress processing.

    Attributes:
        response_text: The restored response text.
        blocked: Whether the response was blocked.
        moderation: Output moderation result, if run.
        alerts: List of security alerts generated.
    """
    response_text: str
    blocked: bool = False
    moderation: ModerationResult | None = None
    alerts: list[str] = field(default_factory=list)


class ShieldPipeline:
    """Orchestrates Shield ingress and egress processing.

    Ingress chains PII swapping, structural tagging, and canary injection.
    Egress chains canary detection, output moderation, and PII restoration.

    The ML guardrail classifier runs separately at the proxy route level
    in parallel with the LLM call (async pattern). The pipeline accepts
    an optional guardrail_result to carry through to the context for
    reporting purposes.

    Usage:
        shield = ShieldPipeline()
        messages, context = shield.process_ingress(messages, "session-1")
        # ... guardrail + LLM run in parallel ...
        result = shield.process_egress(response_text, context)
    """

    def __init__(
        self,
        swapper: SemanticSwapper | None = None,
        tagger: StructuralTagger | None = None,
        canary_generator: CanaryGenerator | None = None,
        canary_injector: CanaryInjector | None = None,
        canary_detector: CanaryDetector | None = None,
        output_moderator: OutputModerator | None = None,
    ):
        """Initialize the Shield pipeline with its sub-components.

        All components default to their standard implementations if not provided.
        """
        self._swapper = swapper or SemanticSwapper()
        self._tagger = tagger or StructuralTagger()
        self._canary_gen = canary_generator or CanaryGenerator()
        self._canary_injector = canary_injector or CanaryInjector()
        self._canary_detector = canary_detector or CanaryDetector()
        self._output_moderator = output_moderator or OutputModerator()

        log.info("shield.pipeline", "ShieldPipeline initialized")

    def process_ingress(
        self,
        messages: list[dict],
        session_id: str,
        guardrail_result: ClassificationResult | None = None,
    ) -> tuple[list[dict], ShieldContext]:
        """Process outgoing messages before they reach the LLM.

        Pipeline:
            1. Detect and swap PII in all user message content
            2. Wrap user messages in structural isolation tags
            3. Inject a canary token into the system prompt

        Args:
            messages: Chat messages to process.
            session_id: Unique session identifier for swap map tracking.
            guardrail_result: Optional pre-computed guardrail result
                              (for reporting, not blocking — blocking
                              happens at the route level).

        Returns:
            Tuple of (hardened_messages, shield_context).
        """
        log.info("shield.pipeline", f"Ingress processing for session '{session_id}'")

        # 1. PII Swap — process each user message
        processed = [dict(msg) for msg in messages]
        combined_swap_map = SwapMap()

        for i, msg in enumerate(processed):
            if msg.get("role") == "user" and isinstance(msg.get("content"), str):
                sanitized, swap_map = self._swapper.swap(msg["content"])
                processed[i]["content"] = sanitized

                # Merge swap maps
                for real, synthetic in swap_map.real_to_synthetic.items():
                    entity_type = swap_map.entity_types.get(real, "UNKNOWN")
                    combined_swap_map.add(real, synthetic, entity_type)

        # 2. Structural Tagging
        processed = self._tagger.tag(processed)

        # 3. Canary Injection
        canary = self._canary_gen.generate()
        processed = self._canary_injector.inject(processed, canary)

        context = ShieldContext(
            session_id=session_id,
            canary=canary,
            swap_map=combined_swap_map,
            guardrail_result=guardrail_result,
        )

        log.info(
            "shield.pipeline",
            f"Ingress complete: {len(combined_swap_map)} PII swapped, "
            f"canary injected",
        )

        return processed, context

    def process_egress(
        self,
        response_text: str,
        context: ShieldContext,
    ) -> EgressResult:
        """Process incoming response from the LLM.

        Pipeline:
            1. Strip structural isolation tags (clean leaked tags)
            2. Detect system prompt leaks (DATA ISOLATION PROTOCOL)
            3. Check for canary leaks (block if found)
            4. Output moderation (content scoring)
            5. Restore PII (swap synthetic back to real)

        Args:
            response_text: The LLM's response text.
            context: The ShieldContext from the ingress phase.

        Returns:
            EgressResult with the restored text and any alerts.
        """
        log.info(
            "shield.pipeline",
            f"Egress processing for session '{context.session_id}'",
        )
        alerts: list[str] = []

        # 0. Strip structural isolation tags from response
        cleaned_text = self._tagger.untag(response_text)

        # 0b. Detect system prompt leak — DATA ISOLATION PROTOCOL
        isolation_markers = [
            "[DATA ISOLATION PROTOCOL]",
            "[END DATA ISOLATION PROTOCOL]",
        ]
        for marker in isolation_markers:
            if marker in cleaned_text:
                alert_msg = (
                    f"SYSTEM PROMPT LEAK DETECTED: response contains "
                    f"'{marker}'. Response BLOCKED for session "
                    f"'{context.session_id}'."
                )
                log.error("shield.pipeline", alert_msg)
                alerts.append(alert_msg)

                return EgressResult(
                    response_text="[BLOCKED] Security violation detected — "
                                  "system prompt content leaked in response.",
                    blocked=True,
                    alerts=alerts,
                )

        # 1. Canary Check
        canary_result = self._canary_detector.check(cleaned_text, context.canary)

        if canary_result.leaked:
            alert_msg = (
                f"CANARY LEAK DETECTED via {canary_result.detection_method}! "
                f"Response BLOCKED for session '{context.session_id}'."
            )
            log.error("shield.pipeline", alert_msg)
            alerts.append(alert_msg)

            return EgressResult(
                response_text="[BLOCKED] Security violation detected. "
                              "The response has been suppressed.",
                blocked=True,
                alerts=alerts,
            )

        # 2. Output Moderation
        moderation_result = self._output_moderator.moderate(cleaned_text)

        if moderation_result.flagged:
            alert_msg = (
                f"OUTPUT MODERATION FLAGGED: score={moderation_result.score}, "
                f"reasons={moderation_result.reasons}. "
                f"Response BLOCKED for session '{context.session_id}'."
            )
            log.error("shield.pipeline", alert_msg)
            alerts.append(alert_msg)

            return EgressResult(
                response_text="[BLOCKED] Response content flagged by "
                              "output moderation.",
                blocked=True,
                moderation=moderation_result,
                alerts=alerts,
            )

        # 3. PII Restore
        restored_text = self._swapper.restore(cleaned_text, context.swap_map)

        log.info("shield.pipeline", "Egress complete: response cleared")

        return EgressResult(
            response_text=restored_text,
            blocked=False,
            moderation=moderation_result,
            alerts=alerts,
        )


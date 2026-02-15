"""
Proxy Middleware — Chains Shield and Lens processing around LLM calls.

The middleware is the core integration point: it applies security
transformations before the request reaches the LLM (ingress) and
after the response comes back (egress).

The ML guardrail runs at the route level (async parallel with LLM),
not inside the middleware. The middleware handles Shield (PII, canary,
tagger, output moderation) and Lens (unicode, code flattening).
"""

from __future__ import annotations

import uuid

from aegis.lens.pipeline import LensPipeline
from aegis.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Choice,
    Role,
    SecurityReport,
    SecurityVerdict,
)
from aegis.shield.pipeline import ShieldPipeline
from aegis.utils.logging import log


class SecurityMiddleware:
    """Applies Shield + Lens processing to chat completion requests.

    Ingress:
        1. Lens processing (unicode normalization, code flattening)
        2. Shield processing (PII swap, structural tag, canary inject)

    Egress:
        1. Shield egress (canary check → output moderation → PII restore)

    The ML guardrail does NOT run inside the middleware — it runs at
    the route level in parallel with the LLM call. The middleware
    builds responses that include guardrail results passed via context.

    Usage:
        middleware = SecurityMiddleware()
        hardened_messages, ctx = middleware.process_ingress(request)
        # ... guardrail + LLM run in parallel at route level ...
        response = middleware.process_egress(llm_text, ctx, request)
    """

    def __init__(
        self,
        shield: ShieldPipeline | None = None,
        lens: LensPipeline | None = None,
    ):
        """Initialize the security middleware.

        Args:
            shield: Custom ShieldPipeline. Uses default if None.
            lens: Custom LensPipeline. Uses default if None.
        """
        self._shield = shield or ShieldPipeline()
        self._lens = lens or LensPipeline()

        log.info("proxy.middleware", "SecurityMiddleware initialized")

    def process_ingress(
        self,
        request: ChatCompletionRequest,
    ) -> tuple[list[dict], "IngressContext"]:
        """Process an incoming request through the security pipeline.

        Args:
            request: The chat completion request.

        Returns:
            Tuple of (hardened_messages_as_dicts, context).
        """
        session_id = str(uuid.uuid4())

        log.info("proxy.middleware", f"Ingress: session={session_id[:8]}...")

        # Convert to dict messages for processing
        messages = request.to_dict_messages()

        # 1. Lens — sanitize each user message content
        lens_stats: dict[str, int] = {}
        for i, msg in enumerate(messages):
            if msg.get("role") == "user":
                lens_result = self._lens.process(msg["content"])
                messages[i]["content"] = lens_result.sanitized_text
                # Accumulate stats
                for k, v in lens_result.stats.items():
                    lens_stats[k] = lens_stats.get(k, 0) + v

        # 2. Shield — PII swap, structural tag, canary inject
        hardened, shield_ctx = self._shield.process_ingress(messages, session_id)

        context = IngressContext(
            session_id=session_id,
            shield_context=shield_ctx,
            lens_stats=lens_stats,
        )

        log.info("proxy.middleware", "Ingress complete")
        return hardened, context

    def process_egress(
        self,
        llm_response_text: str,
        context: "IngressContext",
        original_request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """Process an LLM response through the security pipeline.

        Args:
            llm_response_text: Raw text from the LLM.
            context: Context from ingress processing.
            original_request: The original request (for metadata).

        Returns:
            A ChatCompletionResponse with security metadata.
        """
        log.info(
            "proxy.middleware",
            f"Egress: session={context.session_id[:8]}...",
        )

        # Shield egress — canary check → output moderation → PII restore
        egress_result = self._shield.process_egress(
            llm_response_text,
            context.shield_context,
        )

        # Build security report with guardrail data
        guardrail = context.shield_context.guardrail_result
        report = SecurityReport(
            pii_entities_swapped=len(context.shield_context.swap_map),
            canary_injected=bool(context.shield_context.canary),
            canary_leaked=egress_result.blocked,
            lens_invisible_chars=context.lens_stats.get(
                "invisible_chars_found", 0,
            ),
            lens_code_constructs=context.lens_stats.get(
                "code_constructs_found", 0,
            ),
            input_guardrail_label=(
                guardrail.label.value if guardrail else "benign"
            ),
            input_guardrail_score=(
                guardrail.score if guardrail else 0.0
            ),
            output_moderation_score=(
                egress_result.moderation.score
                if egress_result.moderation else 1
            ),
            output_moderation_flagged=(
                egress_result.moderation.flagged
                if egress_result.moderation else False
            ),
            alerts=egress_result.alerts,
        )

        if egress_result.blocked:
            report.verdict = SecurityVerdict.BLOCK
            return ChatCompletionResponse.blocked(
                reason="Security violation detected — response suppressed.",
                security=report,
            )

        if report.alerts:
            report.verdict = SecurityVerdict.WARN

        return ChatCompletionResponse.from_text(
            text=egress_result.response_text,
            model=original_request.model,
            response_id=f"aegis-{context.session_id[:8]}",
            security=report,
        )

    def build_blocked_response(
        self,
        context: "IngressContext",
        original_request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """Build a blocked response when the guardrail triggers at ingress.

        Called by the route handler when the async guardrail blocks.

        Args:
            context: Context from ingress (with guardrail result).
            original_request: The original request.

        Returns:
            A ChatCompletionResponse with BLOCK verdict.
        """
        guardrail = context.shield_context.guardrail_result
        report = SecurityReport(
            verdict=SecurityVerdict.BLOCK,
            input_guardrail_label=(
                guardrail.label.value if guardrail else "injection"
            ),
            input_guardrail_score=(
                guardrail.score if guardrail else 1.0
            ),
            alerts=context.shield_context.alerts,
        )
        return ChatCompletionResponse.blocked(
            reason=(
                f"Prompt injection detected "
                f"({guardrail.label.value if guardrail else 'unknown'}) — "
                f"request blocked."
            ),
            security=report,
        )


class IngressContext:
    """Context carried from ingress to egress."""

    def __init__(
        self,
        session_id: str,
        shield_context: object,
        lens_stats: dict[str, int],
    ):
        self.session_id = session_id
        self.shield_context = shield_context
        self.lens_stats = lens_stats

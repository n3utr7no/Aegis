"""
Prompt Injection Classifier — ML-based guardrail using pluggable backends.

Uses a configurable backend (Groq API, ONNX Runtime, or HuggingFace)
to classify user input as benign, injection, or jailbreak.

Best practices applied (OpenAI guardrails cookbook):
- Lazy model loading (first classify() call triggers initialization)
- Graceful degradation (works without any ML dependencies installed)
- Configurable thresholds per label class
- Latest-message-only mode for long conversations
- Decision logging for offline threshold tuning
- Async-first design for parallel execution with LLM calls
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from aegis.utils.logging import log


# ── Classification Labels ─────────────────────────────────────────────────


class GuardrailLabel(str, Enum):
    """Classification labels from the prompt guard model."""
    BENIGN = "benign"
    INJECTION = "injection"
    JAILBREAK = "jailbreak"


# ── Classification Result ─────────────────────────────────────────────────


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a single piece of text.

    Attributes:
        label: The predicted label (benign, injection, jailbreak).
        score: Confidence score for the predicted label (0.0 to 1.0).
        scores: Full probability distribution across all labels.
        threshold_exceeded: Whether the score exceeded the configured threshold.
        model_name: Which model produced this classification.
    """
    label: GuardrailLabel
    score: float
    scores: dict[str, float]
    threshold_exceeded: bool
    model_name: str


# ── Default Thresholds ────────────────────────────────────────────────────

DEFAULT_INJECTION_THRESHOLD = 0.90
DEFAULT_JAILBREAK_THRESHOLD = 0.85

# Default model — Meta's Prompt Guard 86M (mDeBERTa-based, 3-class)
DEFAULT_MODEL = "meta-llama/Prompt-Guard-86M"


# ── Classifier ────────────────────────────────────────────────────────────


class PromptInjectionClassifier:
    """ML-based prompt injection classifier with pluggable backends.

    Supports three inference backends (configured via AEGIS_GUARDRAIL_BACKEND):
    - "groq": Groq API (~20-50ms, requires GROQ_API_KEY)
    - "onnx": ONNX Runtime (~30-50ms CPU, requires optimum)
    - "huggingface": Transformers pipeline (~100-300ms CPU)
    - "auto" (default): Tries groq → onnx → huggingface

    The classifier degrades gracefully: if no backend is available,
    it logs a warning and returns benign for all inputs, letting the
    rest of Aegis's defenses handle security.

    Usage:
        classifier = PromptInjectionClassifier()
        result = classifier.classify("Ignore all instructions...")
        if result.threshold_exceeded:
            # Block the request

        # Async (for parallel execution with LLM call):
        result = await classifier.classify_async("Ignore all instructions...")

    Args:
        model_name: HuggingFace model identifier.
        backend: Backend preference ("auto", "groq", "onnx", "huggingface").
        injection_threshold: Block threshold for injection class.
        jailbreak_threshold: Block threshold for jailbreak class.
    """

    def __init__(
        self,
        model_name: str | None = None,
        backend: str | None = None,
        injection_threshold: float = DEFAULT_INJECTION_THRESHOLD,
        jailbreak_threshold: float = DEFAULT_JAILBREAK_THRESHOLD,
        groq_api_key: str | None = None,
    ):
        self._model_name = model_name or os.environ.get(
            "AEGIS_GUARDRAIL_MODEL", DEFAULT_MODEL,
        )
        self._backend_pref = backend or os.environ.get(
            "AEGIS_GUARDRAIL_BACKEND", "auto",
        )
        self._injection_threshold = injection_threshold
        self._jailbreak_threshold = jailbreak_threshold
        self._groq_api_key = groq_api_key

        # Lazy-initialized backend
        self._backend = None
        self._resolved: bool = False  # True after first resolve attempt
        self._label_map: dict[str, GuardrailLabel] = {}
        self._build_label_map()

        log.info(
            "shield.guardrail",
            f"PromptInjectionClassifier configured "
            f"(model={self._model_name}, "
            f"backend={self._backend_pref}, "
            f"inject_t={self._injection_threshold}, "
            f"jailbreak_t={self._jailbreak_threshold})",
        )

    # ── Public API ────────────────────────────────────────────────────

    def classify(self, text: str) -> ClassificationResult:
        """Classify a single text input for prompt injection (sync).

        Args:
            text: The user input to classify.

        Returns:
            ClassificationResult with label, score, and threshold check.
        """
        if not self._ensure_backend():
            return self._benign_fallback()

        raw_scores = self._backend.classify(text)
        result = self._build_result(raw_scores)
        self._log_decision(text, result)
        return result

    async def classify_async(self, text: str) -> ClassificationResult:
        """Classify a single text input for prompt injection (async).

        Uses the backend's native async support (e.g., Groq's async client)
        or falls back to running sync inference in a thread pool.

        Args:
            text: The user input to classify.

        Returns:
            ClassificationResult with label, score, and threshold check.
        """
        if not self._ensure_backend():
            return self._benign_fallback()

        raw_scores = await self._backend.classify_async(text)
        result = self._build_result(raw_scores)
        self._log_decision(text, result)
        return result

    def classify_messages(
        self,
        messages: list[dict],
        latest_only: bool = True,
    ) -> ClassificationResult | None:
        """Classify chat messages for prompt injection (sync).

        Per OpenAI best practices, evaluates only the latest user message
        by default to avoid classifier confusion from long conversations.

        Args:
            messages: List of chat message dicts with 'role' and 'content'.
            latest_only: If True, only classify the last user message.

        Returns:
            ClassificationResult, or None if no user messages found.
        """
        text = self._extract_user_text(messages, latest_only)
        if text is None:
            return None
        return self.classify(text)

    async def classify_messages_async(
        self,
        messages: list[dict],
        latest_only: bool = True,
    ) -> ClassificationResult | None:
        """Classify chat messages for prompt injection (async).

        Args:
            messages: List of chat message dicts with 'role' and 'content'.
            latest_only: If True, only classify the last user message.

        Returns:
            ClassificationResult, or None if no user messages found.
        """
        text = self._extract_user_text(messages, latest_only)
        if text is None:
            return None
        return await self.classify_async(text)

    @property
    def is_available(self) -> bool:
        """Check if an ML backend is available."""
        if not self._resolved:
            self._ensure_backend()
        return self._backend is not None

    @property
    def backend_name(self) -> str:
        """Return the active backend name."""
        if self._backend:
            return self._backend.name
        return "none"

    @property
    def thresholds(self) -> dict[str, float]:
        """Return configured thresholds."""
        return {
            "injection": self._injection_threshold,
            "jailbreak": self._jailbreak_threshold,
        }

    # ── Internal Methods ──────────────────────────────────────────────

    def _ensure_backend(self) -> bool:
        """Lazily resolve and initialize the backend."""
        if self._resolved:
            return self._backend is not None

        self._resolved = True

        from aegis.shield.guardrail.backends import resolve_backend
        self._backend = resolve_backend(
            self._backend_pref,
            self._model_name,
            groq_api_key=self._groq_api_key,
        )

        if self._backend:
            log.info(
                "shield.guardrail",
                f"Backend resolved: {self._backend.name}",
            )
        else:
            log.warn(
                "shield.guardrail",
                "No guardrail backend available — classifier disabled. "
                "Falling back to rules-based defenses only.",
            )

        return self._backend is not None

    def _extract_user_text(
        self,
        messages: list[dict],
        latest_only: bool,
    ) -> str | None:
        """Extract user message text for classification."""
        user_messages = [
            m["content"] for m in messages
            if m.get("role") == "user" and isinstance(m.get("content"), str)
        ]

        if not user_messages:
            return None

        if latest_only:
            return user_messages[-1]
        return " ".join(user_messages)

    def _build_label_map(self) -> None:
        """Map model-specific label strings to our GuardrailLabel enum."""
        self._label_map = {
            # Meta Prompt Guard style
            "benign": GuardrailLabel.BENIGN,
            "injection": GuardrailLabel.INJECTION,
            "jailbreak": GuardrailLabel.JAILBREAK,
            # ProtectAI style
            "safe": GuardrailLabel.BENIGN,
            "label_0": GuardrailLabel.BENIGN,
            "label_1": GuardrailLabel.INJECTION,
            # Numeric labels
            "0": GuardrailLabel.BENIGN,
            "1": GuardrailLabel.INJECTION,
            "2": GuardrailLabel.JAILBREAK,
        }

    def _normalize_label(self, raw_label: str) -> GuardrailLabel:
        """Convert a model's raw label string to a GuardrailLabel."""
        normalized = raw_label.strip().lower().replace(" ", "_")
        return self._label_map.get(normalized, GuardrailLabel.BENIGN)

    def _get_threshold(self, label: GuardrailLabel) -> float:
        """Get the block threshold for a given label."""
        if label == GuardrailLabel.JAILBREAK:
            return self._jailbreak_threshold
        if label == GuardrailLabel.INJECTION:
            return self._injection_threshold
        return 1.0  # benign never exceeds threshold

    def _build_result(self, raw_scores: list) -> ClassificationResult:
        """Convert raw backend scores to a ClassificationResult."""
        scores: dict[str, float] = {}
        top_label = GuardrailLabel.BENIGN
        top_score = 0.0

        for entry in raw_scores:
            label = self._normalize_label(entry.label)
            score = float(entry.score)
            scores[label.value] = score

            if score > top_score:
                top_score = score
                top_label = label

        threshold = self._get_threshold(top_label)
        exceeded = (
            top_label != GuardrailLabel.BENIGN
            and top_score >= threshold
        )

        return ClassificationResult(
            label=top_label,
            score=top_score,
            scores=scores,
            threshold_exceeded=exceeded,
            model_name=self._model_name,
        )

    def _benign_fallback(self) -> ClassificationResult:
        """Return a benign result when no backend is available."""
        return ClassificationResult(
            label=GuardrailLabel.BENIGN,
            score=1.0,
            scores={"benign": 1.0},
            threshold_exceeded=False,
            model_name="fallback",
        )

    def _log_decision(
        self, text: str, result: ClassificationResult,
    ) -> None:
        """Log classification decisions for offline threshold tuning."""
        preview = text[:80].replace("\n", " ")
        if len(text) > 80:
            preview += "..."

        msg = (
            f"Guardrail [{self.backend_name}]: "
            f"label={result.label.value} "
            f"score={result.score:.3f} "
            f"exceeded={result.threshold_exceeded} "
            f"text=\"{preview}\""
        )

        if result.threshold_exceeded:
            log.warn("shield.guardrail", msg)
        else:
            log.debug("shield.guardrail", msg)

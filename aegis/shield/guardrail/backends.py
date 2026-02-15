"""
Guardrail Backends — Pluggable inference backends for prompt injection classification.

Provides three backends with automatic fallback:
- GroqBackend: Ultra-fast API inference via Groq's LPU hardware (~20-50ms)
- ONNXBackend: Optimized local inference via ONNX Runtime (~30-50ms CPU)
- HuggingFaceBackend: Standard local inference via transformers (~100-300ms CPU)

Each backend takes raw text and returns a list of label/score dicts,
which the classifier normalizes into ClassificationResult objects.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from aegis.utils.logging import log


# ── Backend Result ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RawScore:
    """A single label/score pair from a backend."""
    label: str
    score: float


# ── Abstract Backend ──────────────────────────────────────────────────────


class GuardrailBackend(ABC):
    """Abstract base class for guardrail inference backends.

    Subclasses implement _load() and _infer() to provide model
    predictions via different runtime engines.
    """

    def __init__(self, model_name: str):
        self._model_name = model_name
        self._loaded = False

    @property
    def name(self) -> str:
        """Human-readable backend name."""
        return self.__class__.__name__

    def classify(self, text: str) -> list[RawScore]:
        """Classify text, lazily loading the model on first call.

        Args:
            text: Input text to classify.

        Returns:
            List of RawScore with all class probabilities.
        """
        if not self._loaded:
            self._load()
            self._loaded = True
        return self._infer(text)

    async def classify_async(self, text: str) -> list[RawScore]:
        """Async classification. Overridden by API-based backends.

        Default implementation delegates to sync classify() in a thread.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.classify, text)

    @abstractmethod
    def _load(self) -> None:
        """Load the model. Called once on first classify()."""

    @abstractmethod
    def _infer(self, text: str) -> list[RawScore]:
        """Run inference on the loaded model."""

    @staticmethod
    def is_available() -> bool:
        """Check if this backend's dependencies are installed."""
        return False


# ── Groq Backend ──────────────────────────────────────────────────────────


class GroqBackend(GuardrailBackend):
    """Groq API backend for ultra-fast inference.

    Uses Groq's LPU hardware to run Prompt Guard 2 86M with
    ~20-50ms latency. Requires a GROQ_API_KEY environment variable.

    Groq natively hosts llama-prompt-guard-2-86m for text classification.
    We use their chat completions API with a classification prompt since
    their text-classification endpoint provides the most direct access.
    """

    # Groq's hosted model ID for Prompt Guard
    # NOTE: This is different from the HuggingFace model ID.
    # HuggingFace: "meta-llama/Prompt-Guard-86M"
    # Groq API:   "meta-llama/llama-prompt-guard-2-86m"
    GROQ_MODEL = "meta-llama/llama-prompt-guard-2-86m"

    def __init__(self, model_name: str | None = None, api_key: str | None = None):
        # Always use Groq's own model ID — ignore HuggingFace model names
        super().__init__(self.GROQ_MODEL)
        self._client = None
        self._api_key = api_key or os.environ.get("GROQ_API_KEY", "")

    @staticmethod
    def is_available() -> bool:
        """Check if groq SDK is installed and API key is set."""
        try:
            import groq  # noqa: F401
            return bool(os.environ.get("GROQ_API_KEY"))
        except ImportError:
            return False

    def _load(self) -> None:
        """Initialize the Groq client."""
        import groq
        self._client = groq.Groq(api_key=self._api_key)
        log.info(
            "shield.guardrail.backend",
            f"Groq backend initialized (model={self._model_name})",
        )

    def _infer(self, text: str) -> list[RawScore]:
        """Run classification via Groq API."""
        try:
            response = self._client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": text}],
                temperature=0.0,
                max_tokens=10,
            )

            # Parse the model's response — Prompt Guard returns
            # classification labels like "safe", "injection", "jailbreak"
            raw_label = response.choices[0].message.content.strip().lower()
            return self._parse_label(raw_label)

        except Exception as exc:
            log.error(
                "shield.guardrail.backend",
                f"Groq inference failed: {exc}",
            )
            return [RawScore(label="benign", score=1.0)]

    async def classify_async(self, text: str) -> list[RawScore]:
        """Native async classification via Groq's async client."""
        if not self._loaded:
            self._load()
            self._loaded = True

        try:
            import groq
            async_client = groq.AsyncGroq(api_key=self._api_key)
            response = await async_client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": text}],
                temperature=0.0,
                max_tokens=10,
            )
            raw_label = response.choices[0].message.content.strip().lower()
            return self._parse_label(raw_label)

        except Exception as exc:
            log.error(
                "shield.guardrail.backend",
                f"Groq async inference failed: {exc}",
            )
            return [RawScore(label="benign", score=1.0)]

    def _parse_label(self, raw_label: str) -> list[RawScore]:
        """Parse Prompt Guard's text output into scored labels.

        Prompt Guard 2 86M via Groq returns EITHER:
        - A raw probability float (e.g., "0.9992") representing P(unsafe)
        - A text label like "safe", "injection", "jailbreak"

        We handle both cases.
        """
        # First, try to parse as a numeric score (Prompt Guard 2 behavior)
        try:
            unsafe_score = float(raw_label)
            # The score represents P(unsafe) — higher = more dangerous
            safe_score = 1.0 - unsafe_score

            if unsafe_score >= 0.5:
                # High unsafe probability → classify as jailbreak
                # (Prompt Guard 2 is binary: safe/unsafe, we map unsafe → jailbreak)
                return [
                    RawScore(label="benign", score=safe_score),
                    RawScore(label="injection", score=unsafe_score * 0.4),
                    RawScore(label="jailbreak", score=unsafe_score),
                ]
            else:
                return [
                    RawScore(label="benign", score=safe_score),
                    RawScore(label="injection", score=unsafe_score * 0.4),
                    RawScore(label="jailbreak", score=unsafe_score),
                ]
        except ValueError:
            pass

        # Fallback: parse as a text label (traditional behavior)
        label_map = {
            "safe": "benign",
            "benign": "benign",
            "unsafe": "jailbreak",
            "injection": "injection",
            "jailbreak": "jailbreak",
        }

        detected = "benign"
        for key, mapped in label_map.items():
            if key in raw_label:
                detected = mapped
                break

        if detected == "benign":
            return [
                RawScore(label="benign", score=0.95),
                RawScore(label="injection", score=0.03),
                RawScore(label="jailbreak", score=0.02),
            ]
        elif detected == "injection":
            return [
                RawScore(label="benign", score=0.02),
                RawScore(label="injection", score=0.95),
                RawScore(label="jailbreak", score=0.03),
            ]
        else:
            return [
                RawScore(label="benign", score=0.02),
                RawScore(label="injection", score=0.03),
                RawScore(label="jailbreak", score=0.95),
            ]


# ── ONNX Backend ──────────────────────────────────────────────────────────


class ONNXBackend(GuardrailBackend):
    """ONNX Runtime backend for optimized local inference.

    Uses optimum's ORTModelForSequenceClassification for ~3x faster
    inference compared to raw PyTorch on CPU. The model is automatically
    exported to ONNX format on first load.
    """

    def __init__(self, model_name: str | None = None):
        super().__init__(model_name or "meta-llama/Prompt-Guard-86M")
        self._pipeline = None

    @staticmethod
    def is_available() -> bool:
        """Check if optimum + onnxruntime are installed."""
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification  # noqa
            return True
        except ImportError:
            return False

    def _load(self) -> None:
        """Load the model via optimum's ONNX pipeline."""
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer, pipeline as hf_pipeline

        log.info(
            "shield.guardrail.backend",
            f"Loading ONNX model '{self._model_name}'...",
        )

        tokenizer = AutoTokenizer.from_pretrained(self._model_name)
        model = ORTModelForSequenceClassification.from_pretrained(
            self._model_name,
            export=True,  # auto-export to ONNX if needed
        )

        self._pipeline = hf_pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            top_k=None,
            truncation=True,
            max_length=512,
        )

        log.info("shield.guardrail.backend", "ONNX model loaded")

    def _infer(self, text: str) -> list[RawScore]:
        """Run ONNX inference."""
        raw = self._pipeline(text)
        if isinstance(raw, list) and raw:
            items = raw[0] if isinstance(raw[0], list) else raw
            return [RawScore(label=r["label"], score=r["score"]) for r in items]
        return [RawScore(label="benign", score=1.0)]


# ── HuggingFace Backend ──────────────────────────────────────────────────


class HuggingFaceBackend(GuardrailBackend):
    """Standard HuggingFace transformers backend.

    Uses the transformers text-classification pipeline with PyTorch.
    Simplest to set up but slowest on CPU (~100-300ms per inference).
    """

    def __init__(self, model_name: str | None = None):
        super().__init__(model_name or "meta-llama/Prompt-Guard-86M")
        self._pipeline = None

    @staticmethod
    def is_available() -> bool:
        """Check if transformers + torch are installed."""
        try:
            import transformers  # noqa: F401
            import torch  # noqa: F401
            return True
        except ImportError:
            return False

    def _load(self) -> None:
        """Load the HuggingFace text-classification pipeline."""
        from transformers import pipeline as hf_pipeline

        log.info(
            "shield.guardrail.backend",
            f"Loading HuggingFace model '{self._model_name}'...",
        )

        self._pipeline = hf_pipeline(
            "text-classification",
            model=self._model_name,
            top_k=None,
            truncation=True,
            max_length=512,
        )

        log.info("shield.guardrail.backend", "HuggingFace model loaded")

    def _infer(self, text: str) -> list[RawScore]:
        """Run HuggingFace pipeline inference."""
        raw = self._pipeline(text)
        if isinstance(raw, list) and raw:
            items = raw[0] if isinstance(raw[0], list) else raw
            return [RawScore(label=r["label"], score=r["score"]) for r in items]
        return [RawScore(label="benign", score=1.0)]


# ── Backend Factory ───────────────────────────────────────────────────────


def resolve_backend(
    preference: str = "auto",
    model_name: str | None = None,
    groq_api_key: str | None = None,
) -> GuardrailBackend | None:
    """Resolve a guardrail backend based on preference and availability.

    Args:
        preference: One of "auto", "groq", "onnx", "huggingface".
        model_name: Optional model override.
        groq_api_key: Optional Groq API key (from config).

    Returns:
        An initialized (but not loaded) backend, or None if nothing is available.
    """
    preference = preference.lower().strip()

    if preference == "groq":
        if GroqBackend.is_available():
            return GroqBackend(model_name, api_key=groq_api_key)
        log.warn("shield.guardrail.backend", "Groq requested but unavailable")
        return None

    if preference == "onnx":
        if ONNXBackend.is_available():
            return ONNXBackend(model_name)
        log.warn("shield.guardrail.backend", "ONNX requested but unavailable")
        return None

    if preference == "huggingface":
        if HuggingFaceBackend.is_available():
            return HuggingFaceBackend(model_name)
        log.warn("shield.guardrail.backend", "HuggingFace requested but unavailable")
        return None

    # Auto mode — try groq → onnx → huggingface
    if preference == "auto":
        if GroqBackend.is_available():
            log.info("shield.guardrail.backend", "Auto-selected: Groq")
            return GroqBackend(model_name, api_key=groq_api_key)
        if ONNXBackend.is_available():
            log.info("shield.guardrail.backend", "Auto-selected: ONNX")
            return ONNXBackend(model_name)
        if HuggingFaceBackend.is_available():
            log.info("shield.guardrail.backend", "Auto-selected: HuggingFace")
            return HuggingFaceBackend(model_name)

        log.warn(
            "shield.guardrail.backend",
            "No guardrail backend available. "
            "Install one: pip install aegis[guardrail-groq] or "
            "aegis[guardrail] or aegis[guardrail-onnx]",
        )
        return None

    log.warn(
        "shield.guardrail.backend",
        f"Unknown backend preference '{preference}', falling back to auto",
    )
    return resolve_backend("auto", model_name, groq_api_key=groq_api_key)

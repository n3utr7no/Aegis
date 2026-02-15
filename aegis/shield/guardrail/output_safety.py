"""
Output Safety Classifier — ML-based egress guardrail using LLaMA Guard.

Uses Meta's LLaMA Guard 4 12B (hosted on Groq) to classify LLM responses
for dangerous content categories:
  S1 - Violent Crimes
  S2 - Non-Violent Crimes (fraud, hacking, etc.)
  S3 - Sex-Related Crimes
  S4 - Child Sexual Exploitation
  S5 - Defamation
  S6 - Specialized Advice (medical, legal, financial)
  S7 - Privacy Violations
  S8 - Intellectual Property
  S9 - Indiscriminate Weapons / Dangerous Substances
  S10 - Hate Speech
  S11 - Suicide & Self-Harm
  S12 - Sexual Content
  S13 - Elections

This catches cases where the input guardrail misses (e.g., Grandma exploit)
but the LLM actually generates harmful output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from aegis.utils.logging import log


# Category descriptions for alert messages
_CATEGORY_NAMES: dict[str, str] = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice",
    "S7": "Privacy Violations",
    "S8": "Intellectual Property",
    "S9": "Weapons / Dangerous Substances",
    "S10": "Hate Speech",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
}


@dataclass(frozen=True)
class OutputSafetyResult:
    """Result of ML-based output safety classification.

    Attributes:
        safe: Whether the response is considered safe.
        categories: List of violated category codes (e.g., ["S9"]).
        category_names: Human-readable names of violated categories.
        raw_response: The raw model output for debugging.
    """
    safe: bool
    categories: list[str]
    category_names: list[str]
    raw_response: str


class OutputSafetyClassifier:
    """ML-based output safety guardrail using LLaMA Guard 4 via Groq.

    Classifies LLM responses for dangerous content across 13 safety
    categories. Unlike keyword-based approaches, this uses a dedicated
    safety model trained to understand context and nuance.

    Usage:
        classifier = OutputSafetyClassifier()
        result = await classifier.classify_async("Step 1: Mix chemicals...")
        if not result.safe:
            # Block the response
    """

    LLAMA_GUARD_MODEL = "meta-llama/llama-guard-4-12b"

    def __init__(self, api_key: str | None = None):
        """Initialize the output safety classifier.

        Args:
            api_key: Groq API key. Falls back to GROQ_API_KEY env var.
        """
        self._api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self._available = False

        try:
            import groq  # noqa: F401
            self._available = bool(self._api_key)
        except ImportError:
            pass

        if self._available:
            log.info(
                "shield.output_safety",
                f"OutputSafetyClassifier initialized "
                f"(model={self.LLAMA_GUARD_MODEL})",
            )
        else:
            log.warn(
                "shield.output_safety",
                "OutputSafetyClassifier disabled — "
                "groq not installed or GROQ_API_KEY not set",
            )

    @property
    def is_available(self) -> bool:
        """Whether the classifier is available."""
        return self._available

    async def classify_async(
        self,
        response_text: str,
        user_prompt: str = "",
    ) -> OutputSafetyResult:
        """Classify an LLM response for dangerous content (async).

        Args:
            response_text: The LLM's response to evaluate.
            user_prompt: The original user prompt (provides context).

        Returns:
            OutputSafetyResult with safety status and categories.
        """
        if not self._available:
            return OutputSafetyResult(
                safe=True,
                categories=[],
                category_names=[],
                raw_response="classifier_unavailable",
            )

        if not response_text or not response_text.strip():
            return OutputSafetyResult(
                safe=True,
                categories=[],
                category_names=[],
                raw_response="empty_input",
            )

        try:
            import groq

            async_client = groq.AsyncGroq(api_key=self._api_key)

            # LLaMA Guard expects the conversation format:
            # user message + assistant response to evaluate
            messages = []
            if user_prompt:
                messages.append({"role": "user", "content": user_prompt})
            messages.append({"role": "assistant", "content": response_text})

            resp = await async_client.chat.completions.create(
                model=self.LLAMA_GUARD_MODEL,
                messages=messages,
                temperature=0.0,
                max_tokens=50,
            )

            raw = resp.choices[0].message.content.strip()
            return self._parse_result(raw)

        except Exception as exc:
            log.error(
                "shield.output_safety",
                f"LLaMA Guard classification failed: {exc}",
            )
            # Fail open — don't block if the classifier errors
            return OutputSafetyResult(
                safe=True,
                categories=[],
                category_names=[],
                raw_response=f"error: {exc}",
            )

    def classify(
        self,
        response_text: str,
        user_prompt: str = "",
    ) -> OutputSafetyResult:
        """Classify an LLM response for dangerous content (sync).

        Args:
            response_text: The LLM's response to evaluate.
            user_prompt: The original user prompt (provides context).

        Returns:
            OutputSafetyResult with safety status and categories.
        """
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in an async context, run in executor
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run,
                        self.classify_async(response_text, user_prompt),
                    )
                    return future.result(timeout=30)
            else:
                return loop.run_until_complete(
                    self.classify_async(response_text, user_prompt),
                )
        except Exception:
            return asyncio.run(
                self.classify_async(response_text, user_prompt),
            )

    def _parse_result(self, raw: str) -> OutputSafetyResult:
        """Parse LLaMA Guard's response.

        LLaMA Guard returns either:
        - "safe" — content is safe
        - "unsafe\\nS1,S9" — content is unsafe with category codes
        """
        lines = raw.strip().split("\n")
        is_safe = lines[0].strip().lower() == "safe"

        categories: list[str] = []
        if not is_safe and len(lines) > 1:
            # Parse category codes like "S1", "S9", "S2"
            for part in lines[1].split(","):
                code = part.strip().upper()
                if code.startswith("S") and len(code) <= 3:
                    categories.append(code)

        category_names = [
            _CATEGORY_NAMES.get(c, f"Unknown ({c})")
            for c in categories
        ]

        if not is_safe:
            log.warn(
                "shield.output_safety",
                f"OUTPUT UNSAFE: categories={categories} "
                f"({', '.join(category_names)})",
            )
        else:
            log.debug("shield.output_safety", "Output classified as safe")

        return OutputSafetyResult(
            safe=is_safe,
            categories=categories,
            category_names=category_names,
            raw_response=raw,
        )

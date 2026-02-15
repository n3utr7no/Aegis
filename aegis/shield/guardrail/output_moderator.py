"""
Output Moderator — Rules-based output guardrail for LLM responses.

Evaluates LLM responses for leaked system instructions, injected code,
and disallowed content patterns. Follows the OpenAI G-Eval moderation
pattern: score content from 1-5, flag anything above threshold.

Design decisions:
- Rules-based (no ML dependency) so it works everywhere
- Complements the canary detector (which catches specific tokens)
  with broader content pattern detection
- Configurable severity threshold for false-positive tuning
- Extensible criteria system for domain-specific moderation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.utils.logging import log


# ── Moderation Result ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ModerationResult:
    """Result of moderating an LLM response.

    Attributes:
        score: Severity score from 1 (clean) to 5 (highly suspicious).
        flagged: Whether the score exceeded the threshold.
        reasons: List of reasons for the score.
        patterns_found: Specific patterns that were detected.
    """
    score: int
    flagged: bool
    reasons: list[str]
    patterns_found: list[str]


# ── Moderation Criteria ───────────────────────────────────────────────────


@dataclass
class ModerationCriteria:
    """A single moderation check with a severity weight.

    Attributes:
        name: Human-readable name for this criterion.
        patterns: Regex patterns to detect (case-insensitive).
        severity: How many points to add when detected (1-3).
        description: What this criterion checks for.
    """
    name: str
    patterns: list[str]
    severity: int
    description: str


# Built-in criteria for LLM security moderation
BUILTIN_CRITERIA: list[ModerationCriteria] = [
    ModerationCriteria(
        name="system_prompt_leak",
        patterns=[
            r"(?:my|the)\s+system\s+(?:prompt|instructions?)\s+(?:is|are|says?)",
            r"(?:i\s+was|i\s+am)\s+(?:told|instructed|programmed)\s+to",
            r"here\s+(?:is|are)\s+my\s+(?:original|full|complete)\s+instructions?",
            r"my\s+(?:initial|original)\s+prompt\s+(?:is|was|reads?)",
        ],
        severity=3,
        description="Detects leaked system prompt or instructions.",
    ),
    ModerationCriteria(
        name="role_override",
        patterns=[
            r"(?:i\s+am|i'm)\s+now\s+(?:DAN|acting\s+as|pretending)",
            r"(?:sure|okay|alright),?\s+(?:i'll|i\s+will)\s+(?:ignore|bypass|override)",
            r"as\s+(?:DAN|an?\s+unrestricted)",
            r"(?:jailbreak|jailbroken)\s+mode",
        ],
        severity=3,
        description="Detects when the LLM appears to adopt an override persona.",
    ),
    ModerationCriteria(
        name="harmful_instructions",
        patterns=[
            r"(?:here(?:'s|\s+is)\s+how\s+to\s+(?:hack|exploit|bypass|attack))",
            r"(?:step\s+\d+[.:]\s*(?:inject|exploit|override|bypass))",
            r"(?:malicious|exploit)\s+(?:code|script|payload)",
        ],
        severity=2,
        description="Detects harmful/attack instructions in the response.",
    ),
    ModerationCriteria(
        name="encoded_content",
        patterns=[
            r"(?:base64|hex|rot13)\s*(?:encoded?|version|output)\s*[:=]",
            r"(?:decoded?|decrypted?)\s+(?:system|prompt|instructions?)",
        ],
        severity=2,
        description="Detects encoded or obfuscated content leaks.",
    ),
    ModerationCriteria(
        name="internal_markers",
        patterns=[
            r"\[INTERNAL",
            r"\[SYSTEM\s*PROMPT\]",
            r"<\s*system\s*>",
            r"<<\s*SYS\s*>>",
        ],
        severity=2,
        description="Detects internal system markers in the response.",
    ),
]


# ── Output Moderator ──────────────────────────────────────────────────────


class OutputModerator:
    """Rules-based output guardrail for LLM responses.

    Evaluates response content against a set of moderation criteria,
    each with regex patterns and a severity weight. Scores are summed
    and clamped to [1, 5]. Responses scoring at or above the threshold
    are flagged.

    This complements the canary detector: the canary catches specific
    token leaks, while the moderator catches broader patterns like
    system prompt disclosure, role override adoption, and harmful
    instruction generation.

    Usage:
        moderator = OutputModerator()
        result = moderator.moderate("Here is my system prompt: ...")
        if result.flagged:
            # Block or warn

    Args:
        threshold: Score at which to flag (default: 3, range: 1-5).
        criteria: Custom criteria list. Uses built-in if None.
    """

    def __init__(
        self,
        threshold: int = 3,
        criteria: list[ModerationCriteria] | None = None,
    ):
        self._threshold = max(1, min(5, threshold))
        self._criteria = criteria or BUILTIN_CRITERIA

        # Pre-compile all patterns for performance
        self._compiled: list[tuple[ModerationCriteria, list[re.Pattern]]] = []
        for criterion in self._criteria:
            compiled_patterns = [
                re.compile(p, re.IGNORECASE) for p in criterion.patterns
            ]
            self._compiled.append((criterion, compiled_patterns))

        log.info(
            "shield.guardrail",
            f"OutputModerator initialized "
            f"(threshold={self._threshold}, "
            f"criteria={len(self._criteria)})",
        )

    def moderate(self, response_text: str) -> ModerationResult:
        """Evaluate an LLM response against moderation criteria.

        Args:
            response_text: The LLM's response text.

        Returns:
            ModerationResult with score, flagged status, and reasons.
        """
        if not response_text or not response_text.strip():
            return ModerationResult(
                score=1,
                flagged=False,
                reasons=[],
                patterns_found=[],
            )

        total_severity = 0
        reasons: list[str] = []
        patterns_found: list[str] = []

        for criterion, compiled_patterns in self._compiled:
            for pattern in compiled_patterns:
                match = pattern.search(response_text)
                if match:
                    total_severity += criterion.severity
                    reasons.append(
                        f"{criterion.name}: {criterion.description}"
                    )
                    patterns_found.append(match.group(0))
                    break  # one match per criterion is enough

        # Clamp score to [1, 5]
        score = max(1, min(5, 1 + total_severity))
        flagged = score >= self._threshold

        result = ModerationResult(
            score=score,
            flagged=flagged,
            reasons=reasons,
            patterns_found=patterns_found,
        )

        # Log the decision
        if flagged:
            log.warn(
                "shield.guardrail",
                f"Output moderation FLAGGED: score={score}, "
                f"reasons={reasons}",
            )
        else:
            log.debug(
                "shield.guardrail",
                f"Output moderation passed: score={score}",
            )

        return result

    @property
    def threshold(self) -> int:
        """Return the configured threshold."""
        return self._threshold

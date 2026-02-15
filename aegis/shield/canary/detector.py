"""
Canary Detector — Detects canary token leaks in LLM responses.

Checks for the canary string in multiple representations to catch
encoding-based bypass attempts (base64, hex, reversed, ROT13).
"""

import base64
import codecs
from dataclasses import dataclass, field

from aegis.utils.logging import log


@dataclass(frozen=True)
class CanaryCheckResult:
    """Result of a canary leak check.

    Attributes:
        leaked: Whether the canary was found in any form.
        detection_method: How the canary was detected (e.g., 'plaintext', 'base64').
        matched_fragment: The fragment of text that matched (for logging).
    """
    leaked: bool
    detection_method: str = ""
    matched_fragment: str = ""


class CanaryDetector:
    """Detects canary token leaks in LLM response text.

    Checks for the canary in multiple encodings to catch bypass attempts:
    - Plaintext (direct string match)
    - Base64-encoded
    - Hex-encoded
    - Reversed string
    - ROT13-encoded

    Usage:
        detector = CanaryDetector()
        result = detector.check("Some LLM response text", "AEGIS-CANARY-abc")
        if result.leaked:
            print(f"LEAK via {result.detection_method}!")
    """

    def __init__(self, check_partial: bool = True):
        """Initialize the canary detector.

        Args:
            check_partial: If True, also check for partial canary matches
                          (at least 16 chars). Helps catch truncated leaks.
        """
        self._check_partial = check_partial
        log.debug("canary.detector", f"Initialized (check_partial={check_partial})")

    def check(self, response_text: str, canary: str) -> CanaryCheckResult:
        """Check if a canary token appears in the response text.

        Runs all detection methods and returns on the first match.

        Args:
            response_text: The LLM's response text.
            canary: The canary token to search for.

        Returns:
            CanaryCheckResult with leak status and detection details.
        """
        if not response_text or not canary:
            return CanaryCheckResult(leaked=False)

        # Normalize for comparison
        response_lower = response_text.lower()

        # 1. Plaintext check
        if canary.lower() in response_lower:
            log.error("canary.detector", "CANARY LEAK DETECTED: plaintext match")
            return CanaryCheckResult(
                leaked=True,
                detection_method="plaintext",
                matched_fragment=canary,
            )

        # 2. Base64-encoded check
        try:
            canary_b64 = base64.b64encode(canary.encode()).decode()
            if canary_b64.lower() in response_lower:
                log.error("canary.detector", "CANARY LEAK DETECTED: base64 encoding")
                return CanaryCheckResult(
                    leaked=True,
                    detection_method="base64",
                    matched_fragment=canary_b64,
                )
        except Exception:
            pass  # Skip if encoding fails

        # 3. Hex-encoded check
        try:
            canary_hex = canary.encode().hex()
            if canary_hex.lower() in response_lower:
                log.error("canary.detector", "CANARY LEAK DETECTED: hex encoding")
                return CanaryCheckResult(
                    leaked=True,
                    detection_method="hex",
                    matched_fragment=canary_hex,
                )
        except Exception:
            pass

        # 4. Reversed string check
        canary_reversed = canary[::-1]
        if canary_reversed.lower() in response_lower:
            log.error("canary.detector", "CANARY LEAK DETECTED: reversed string")
            return CanaryCheckResult(
                leaked=True,
                detection_method="reversed",
                matched_fragment=canary_reversed,
            )

        # 5. ROT13 check
        try:
            canary_rot13 = codecs.encode(canary, "rot_13")
            if canary_rot13.lower() in response_lower:
                log.error("canary.detector", "CANARY LEAK DETECTED: ROT13 encoding")
                return CanaryCheckResult(
                    leaked=True,
                    detection_method="rot13",
                    matched_fragment=canary_rot13,
                )
        except Exception:
            pass

        # 6. Partial match check (for truncated leaks)
        if self._check_partial and len(canary) >= 16:
            # Check if a significant portion (16+ chars) appears
            partial = canary[:16]
            if partial.lower() in response_lower:
                log.warn(
                    "canary.detector",
                    f"Partial canary match detected (first 16 chars)",
                )
                return CanaryCheckResult(
                    leaked=True,
                    detection_method="partial",
                    matched_fragment=partial,
                )

        log.debug("canary.detector", "No canary leak detected")
        return CanaryCheckResult(leaked=False)

"""
Unit tests for aegis.shield.canary.detector — Canary Leak Detection.

Tests cover:
- Plaintext leak detection
- Base64 encoded leak
- Hex encoded leak
- Reversed string leak
- ROT13 encoded leak
- Partial match detection
- No false positives on clean text
- Case insensitivity
"""

import base64
import codecs

from aegis.shield.canary.detector import CanaryDetector


CANARY = "AEGIS-CANARY-a1b2c3d4-e5f6-7890-abcd-ef1234567890"


class TestPlaintextDetection:
    """Test direct plaintext leak detection."""

    def test_plaintext_leak(self):
        detector = CanaryDetector()
        response = f"Here is the secret: {CANARY}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "plaintext"

    def test_plaintext_case_insensitive(self):
        detector = CanaryDetector()
        response = f"Leaked: {CANARY.lower()}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "plaintext"

    def test_no_leak_clean_text(self):
        detector = CanaryDetector()
        response = "This is a perfectly clean response with no secrets."
        result = detector.check(response, CANARY)
        assert result.leaked is False


class TestBase64Detection:
    """Test base64-encoded leak detection."""

    def test_base64_leak(self):
        detector = CanaryDetector()
        encoded = base64.b64encode(CANARY.encode()).decode()
        response = f"Encoded: {encoded}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "base64"


class TestHexDetection:
    """Test hex-encoded leak detection."""

    def test_hex_leak(self):
        detector = CanaryDetector()
        hex_encoded = CANARY.encode().hex()
        response = f"Hex: {hex_encoded}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "hex"


class TestReversedDetection:
    """Test reversed string leak detection."""

    def test_reversed_leak(self):
        detector = CanaryDetector()
        reversed_canary = CANARY[::-1]
        response = f"Reversed: {reversed_canary}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "reversed"


class TestROT13Detection:
    """Test ROT13-encoded leak detection."""

    def test_rot13_leak(self):
        detector = CanaryDetector()
        rot13_canary = codecs.encode(CANARY, "rot_13")
        response = f"ROT13: {rot13_canary}"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "rot13"


class TestPartialDetection:
    """Test partial canary match detection."""

    def test_partial_leak_first_16_chars(self):
        detector = CanaryDetector(check_partial=True)
        partial = CANARY[:16]
        response = f"Found fragment: {partial} in the text"
        result = detector.check(response, CANARY)
        assert result.leaked is True
        assert result.detection_method == "partial"

    def test_partial_disabled(self):
        detector = CanaryDetector(check_partial=False)
        partial = CANARY[:16]
        # Without partial check, only first 16 chars shouldn't trigger
        response = f"Fragment: {partial} only"
        result = detector.check(response, CANARY)
        # May or may not match depending on other checks, but partial shouldn't fire
        if result.leaked:
            assert result.detection_method != "partial"


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_response(self):
        detector = CanaryDetector()
        result = detector.check("", CANARY)
        assert result.leaked is False

    def test_empty_canary(self):
        detector = CanaryDetector()
        result = detector.check("Some response", "")
        assert result.leaked is False

    def test_both_empty(self):
        detector = CanaryDetector()
        result = detector.check("", "")
        assert result.leaked is False

    def test_canary_not_in_response(self):
        detector = CanaryDetector()
        result = detector.check(
            "Completely unrelated text about weather.",
            CANARY,
        )
        assert result.leaked is False
        assert result.detection_method == ""

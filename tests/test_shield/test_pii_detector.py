"""
Unit tests for aegis.shield.pii.detector — PII Detection.

Tests cover:
- Individual PII type detection (email, phone, SSN, credit card, IP, DOB)
- No false positives on clean text
- Multiple PII entities in a single string
- Overlap deduplication
- Configurable type filtering
- Custom patterns
"""

import re

import pytest

from aegis.shield.pii.detector import PIIDetector, PIIMatch


# ── Email Detection ──────────────────────────────────────────────────────

class TestEmailDetection:
    """Test email address detection."""

    def test_simple_email(self):
        detector = PIIDetector(enabled_types={"EMAIL"})
        matches = detector.detect("Contact john.doe@example.com for info")
        assert len(matches) == 1
        assert matches[0].entity_type == "EMAIL"
        assert matches[0].value == "john.doe@example.com"

    def test_email_with_plus(self):
        detector = PIIDetector(enabled_types={"EMAIL"})
        matches = detector.detect("Send to user+tag@gmail.com")
        assert len(matches) == 1
        assert matches[0].value == "user+tag@gmail.com"

    def test_multiple_emails(self):
        detector = PIIDetector(enabled_types={"EMAIL"})
        text = "CC alice@test.org and bob@company.co.uk"
        matches = detector.detect(text)
        assert len(matches) == 2
        values = {m.value for m in matches}
        assert "alice@test.org" in values
        assert "bob@company.co.uk" in values

    def test_no_email_in_clean_text(self):
        detector = PIIDetector(enabled_types={"EMAIL"})
        matches = detector.detect("Hello world, this is a test.")
        assert len(matches) == 0


# ── Phone Detection ──────────────────────────────────────────────────────

class TestPhoneDetection:
    """Test phone number detection."""

    def test_us_phone_dashes(self):
        detector = PIIDetector(enabled_types={"PHONE"})
        matches = detector.detect("Call 555-123-4567 now")
        assert len(matches) == 1
        assert matches[0].entity_type == "PHONE"

    def test_us_phone_dots(self):
        detector = PIIDetector(enabled_types={"PHONE"})
        matches = detector.detect("Phone: 555.123.4567")
        assert len(matches) == 1

    def test_us_phone_with_parens(self):
        detector = PIIDetector(enabled_types={"PHONE"})
        matches = detector.detect("Reach me at (555) 123-4567")
        assert len(matches) == 1

    def test_us_phone_with_country_code(self):
        detector = PIIDetector(enabled_types={"PHONE"})
        matches = detector.detect("Call +1-555-123-4567")
        assert len(matches) == 1

    def test_no_phone_in_clean_text(self):
        detector = PIIDetector(enabled_types={"PHONE"})
        matches = detector.detect("The year is 2026 and counting.")
        assert len(matches) == 0


# ── SSN Detection ────────────────────────────────────────────────────────

class TestSSNDetection:
    """Test Social Security Number detection."""

    def test_standard_ssn(self):
        detector = PIIDetector(enabled_types={"SSN"})
        matches = detector.detect("SSN: 123-45-6789")
        assert len(matches) == 1
        assert matches[0].value == "123-45-6789"
        assert matches[0].entity_type == "SSN"

    def test_no_ssn_without_dashes(self):
        detector = PIIDetector(enabled_types={"SSN"})
        # Without dashes, it should NOT match as SSN
        matches = detector.detect("Number: 123456789")
        assert len(matches) == 0


# ── Credit Card Detection ───────────────────────────────────────────────

class TestCreditCardDetection:
    """Test credit card number detection."""

    def test_visa(self):
        detector = PIIDetector(enabled_types={"CREDIT_CARD"})
        matches = detector.detect("Card: 4532015112830366")
        assert len(matches) == 1
        assert matches[0].entity_type == "CREDIT_CARD"

    def test_visa_with_spaces(self):
        detector = PIIDetector(enabled_types={"CREDIT_CARD"})
        matches = detector.detect("Visa: 4532 0151 1283 0366")
        assert len(matches) == 1

    def test_mastercard(self):
        detector = PIIDetector(enabled_types={"CREDIT_CARD"})
        matches = detector.detect("MC: 5425233430109903")
        assert len(matches) == 1

    def test_no_cc_in_clean_text(self):
        detector = PIIDetector(enabled_types={"CREDIT_CARD"})
        matches = detector.detect("The price is $1,234.56")
        assert len(matches) == 0


# ── IP Address Detection ────────────────────────────────────────────────

class TestIPDetection:
    """Test IP address detection."""

    def test_ipv4(self):
        detector = PIIDetector(enabled_types={"IP_ADDRESS"})
        matches = detector.detect("Server at 192.168.1.100")
        assert len(matches) == 1
        assert matches[0].value == "192.168.1.100"

    def test_localhost(self):
        detector = PIIDetector(enabled_types={"IP_ADDRESS"})
        matches = detector.detect("Localhost is 127.0.0.1")
        assert len(matches) == 1

    def test_no_ip_in_version_string(self):
        """Version strings like 'v2.0.0' should not match."""
        detector = PIIDetector(enabled_types={"IP_ADDRESS"})
        matches = detector.detect("Running version 2.0.0 of the app")
        assert len(matches) == 0


# ── Date of Birth Detection ─────────────────────────────────────────────

class TestDOBDetection:
    """Test date of birth pattern detection."""

    def test_mm_dd_yyyy(self):
        detector = PIIDetector(enabled_types={"DATE_OF_BIRTH"})
        matches = detector.detect("Born on 01/15/1990")
        assert len(matches) == 1

    def test_yyyy_mm_dd(self):
        detector = PIIDetector(enabled_types={"DATE_OF_BIRTH"})
        matches = detector.detect("DOB: 1990-01-15")
        assert len(matches) == 1


# ── Multi-Type Detection ────────────────────────────────────────────────

class TestMultiTypeDetection:
    """Test detection of multiple PII types in one text."""

    def test_email_and_phone(self):
        detector = PIIDetector(enable_ner=False)
        text = "Email john@test.com or call 555-111-2222"
        matches = detector.detect(text)
        types = {m.entity_type for m in matches}
        assert "EMAIL" in types
        assert "PHONE" in types

    def test_all_clean(self):
        detector = PIIDetector(enable_ner=False)
        text = "The quick brown fox jumps over the lazy dog."
        matches = detector.detect(text)
        assert len(matches) == 0

    def test_empty_text(self):
        detector = PIIDetector(enable_ner=False)
        assert detector.detect("") == []


# ── Overlap Deduplication ────────────────────────────────────────────────

class TestOverlapDeduplication:
    """Test that overlapping detections are handled correctly."""

    def test_no_duplicate_for_same_span(self):
        """A phone number embedded in a credit card should not double-match."""
        detector = PIIDetector(enable_ner=False)
        text = "Card: 4532015112830366"
        matches = detector.detect(text)
        # Should not report the last 10 digits as a phone number
        starts = [m.start for m in matches]
        assert len(starts) == len(set(starts))  # all unique starts


# ── Configuration ────────────────────────────────────────────────────────

class TestDetectorConfiguration:
    """Test detector configuration options."""

    def test_filter_enabled_types(self):
        detector = PIIDetector(enabled_types={"EMAIL"})
        text = "Call 555-111-2222 or email test@foo.com"
        matches = detector.detect(text)
        assert all(m.entity_type == "EMAIL" for m in matches)

    def test_custom_pattern(self):
        custom = [("CUSTOM_ID", re.compile(r"ID-\d{6}"))]
        detector = PIIDetector(custom_patterns=custom)
        matches = detector.detect("Reference: ID-123456")
        types = {m.entity_type for m in matches}
        assert "CUSTOM_ID" in types

    def test_pattern_count(self):
        detector = PIIDetector(enable_ner=False)
        assert detector.pattern_count == 6  # 6 built-in patterns

    def test_pattern_count_with_filter(self):
        detector = PIIDetector(enabled_types={"EMAIL", "PHONE"}, enable_ner=False)
        assert detector.pattern_count == 2


# ── NER Detection ────────────────────────────────────────────────────────

class TestNERDetection:
    """Test spaCy NER-based entity detection."""

    def test_person_name_detected(self):
        detector = PIIDetector(enable_ner=True)
        matches = detector.detect("My name is John Smith and I need help.")
        types = {m.entity_type for m in matches}
        assert "PERSON" in types
        names = [m.value for m in matches if m.entity_type == "PERSON"]
        assert any("John" in n for n in names)

    def test_org_detected(self):
        detector = PIIDetector(enable_ner=True)
        matches = detector.detect("I work at Microsoft in their Azure team.")
        types = {m.entity_type for m in matches}
        assert "ORG" in types

    def test_location_detected(self):
        detector = PIIDetector(enable_ner=True)
        matches = detector.detect("I live in San Francisco, California.")
        types = {m.entity_type for m in matches}
        assert "GPE" in types

    def test_mixed_regex_and_ner(self):
        detector = PIIDetector(enable_ner=True)
        text = "My name is John Smith, email is john@test.com"
        matches = detector.detect(text)
        types = {m.entity_type for m in matches}
        assert "PERSON" in types
        assert "EMAIL" in types

    def test_ner_disabled_no_names(self):
        detector = PIIDetector(enable_ner=False)
        matches = detector.detect("My name is John Smith and I need help.")
        # Without NER, no person names should be detected
        types = {m.entity_type for m in matches}
        assert "PERSON" not in types

    def test_ner_graceful_degradation(self):
        """NER flag on but model name is invalid — should degrade to regex-only."""
        detector = PIIDetector(enable_ner=True, ner_model="nonexistent_model")
        # Should not raise, just fall back to regex
        matches = detector.detect("My name is John Smith, email is john@test.com")
        types = {m.entity_type for m in matches}
        assert "EMAIL" in types  # Regex still works

"""
Unit tests for aegis.utils.text — Text processing utilities.

Tests cover:
- Truncation behavior
- Safe decoding of bytes
- Whitespace normalization
- Unicode category counting
"""

from aegis.utils.text import (
    count_unicode_categories,
    normalize_whitespace,
    safe_decode,
    truncate_for_log,
)


class TestTruncateForLog:
    """Test text truncation for log output."""

    def test_short_text_unchanged(self):
        assert truncate_for_log("hello", 100) == "hello"

    def test_exact_length_unchanged(self):
        text = "x" * 100
        assert truncate_for_log(text, 100) == text

    def test_long_text_truncated(self):
        text = "x" * 150
        result = truncate_for_log(text, 100)
        assert len(result) == 103  # 100 + "..."
        assert result.endswith("...")

    def test_default_max_length(self):
        text = "x" * 200
        result = truncate_for_log(text)
        assert len(result) == 103  # default is 100

    def test_empty_string(self):
        assert truncate_for_log("") == ""


class TestSafeDecode:
    """Test safe byte decoding."""

    def test_utf8_bytes(self):
        data = "Hello, World!".encode("utf-8")
        assert safe_decode(data) == "Hello, World!"

    def test_latin1_fallback(self):
        # Bytes invalid in UTF-8 but valid in Latin-1
        data = bytes([0xC0, 0xC1, 0xF5])
        result = safe_decode(data)
        assert len(result) == 3  # decoded via latin-1

    def test_unicode_chars(self):
        data = "日本語テスト".encode("utf-8")
        assert safe_decode(data) == "日本語テスト"


class TestNormalizeWhitespace:
    """Test whitespace normalization."""

    def test_multiple_spaces(self):
        assert normalize_whitespace("a   b   c") == "a b c"

    def test_tabs_and_newlines(self):
        assert normalize_whitespace("a\t\nb\r\nc") == "a b c"

    def test_leading_trailing(self):
        assert normalize_whitespace("  hello  ") == "hello"

    def test_already_normalized(self):
        assert normalize_whitespace("a b c") == "a b c"

    def test_empty_string(self):
        assert normalize_whitespace("") == ""


class TestCountUnicodeCategories:
    """Test Unicode category counting."""

    def test_basic_ascii(self):
        cats = count_unicode_categories("Hello")
        assert cats.get("Lu", 0) == 1   # 'H' is uppercase letter
        assert cats.get("Ll", 0) == 4   # 'ello' are lowercase

    def test_digits(self):
        cats = count_unicode_categories("abc123")
        assert cats.get("Nd", 0) == 3   # 3 decimal digits

    def test_empty_string(self):
        cats = count_unicode_categories("")
        assert cats == {}

    def test_mixed_scripts(self):
        cats = count_unicode_categories("Hеllo")  # 'е' is Cyrillic
        assert cats.get("Ll", 0) >= 3  # at least 'llo' + Cyrillic 'е'

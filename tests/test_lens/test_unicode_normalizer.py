"""
Unit tests for aegis.lens.unicode_normalizer — Unicode Normalization.

Tests cover:
- Zero-width character stripping
- Homoglyph flattening (Cyrillic → Latin)
- NFKC normalization
- Space normalization (exotic whitespace → regular)
- Suspicious character detection
- No modification of clean ASCII text
"""

from aegis.lens.unicode_normalizer import UnicodeNormalizer


class TestInvisibleCharStripping:
    """Test removal of zero-width and invisible characters."""

    def test_zero_width_space(self):
        normalizer = UnicodeNormalizer()
        text = "Hel\u200Blo"  # Zero Width Space in "Hello"
        result = normalizer.normalize(text)
        assert result == "Hello"

    def test_zero_width_joiner(self):
        normalizer = UnicodeNormalizer()
        text = "te\u200Dst"  # Zero Width Joiner
        result = normalizer.normalize(text)
        assert result == "test"

    def test_byte_order_mark(self):
        normalizer = UnicodeNormalizer()
        text = "\uFEFFHello"  # BOM
        result = normalizer.normalize(text)
        assert result == "Hello"

    def test_bidi_override(self):
        normalizer = UnicodeNormalizer()
        text = "normal\u202Etext"  # Right-to-Left Override
        result = normalizer.normalize(text)
        assert result == "normaltext"

    def test_multiple_invisible_chars(self):
        normalizer = UnicodeNormalizer()
        text = "\u200BH\u200Ce\u200Dl\u200Bl\uFEFFo"
        result = normalizer.normalize(text)
        assert result == "Hello"


class TestHomoglyphFlattening:
    """Test homoglyph → ASCII mapping."""

    def test_cyrillic_a(self):
        normalizer = UnicodeNormalizer()
        text = "H\u0435llo"  # Cyrillic е → Latin e
        result = normalizer.normalize(text)
        assert result == "Hello"

    def test_cyrillic_c(self):
        normalizer = UnicodeNormalizer()
        text = "\u0441at"  # Cyrillic с → Latin c
        result = normalizer.normalize(text)
        assert result == "cat"

    def test_cyrillic_o(self):
        normalizer = UnicodeNormalizer()
        text = "g\u043Eod"  # Cyrillic о → Latin o
        result = normalizer.normalize(text)
        assert result == "good"

    def test_mixed_scripts(self):
        normalizer = UnicodeNormalizer()
        # "Hello" with Cyrillic Н and е
        text = "\u041D\u0435llo"  # Cyrillic Н→H, е→e
        result = normalizer.normalize(text)
        assert result == "Hello"


class TestExoticWhitespace:
    """Test normalization of exotic whitespace characters."""

    def test_non_breaking_space(self):
        normalizer = UnicodeNormalizer()
        text = "hello\u00A0world"
        result = normalizer.normalize(text)
        assert result == "hello world"

    def test_em_space(self):
        normalizer = UnicodeNormalizer()
        text = "a\u2003b"  # Em Space
        result = normalizer.normalize(text)
        assert result == "a b"

    def test_ideographic_space(self):
        normalizer = UnicodeNormalizer()
        text = "a\u3000b"  # Ideographic Space
        result = normalizer.normalize(text)
        assert result == "a b"


class TestCleanText:
    """Test that clean text is not modified."""

    def test_ascii_unchanged(self):
        normalizer = UnicodeNormalizer()
        text = "Hello, World! 123"
        assert normalizer.normalize(text) == text

    def test_empty_string(self):
        normalizer = UnicodeNormalizer()
        assert normalizer.normalize("") == ""

    def test_simple_unicode_unchanged(self):
        """Common Unicode like emoji shouldn't be stripped."""
        normalizer = UnicodeNormalizer()
        text = "Hello 🛡️"
        result = normalizer.normalize(text)
        assert "Hello" in result


class TestSuspiciousDetection:
    """Test detection without modification."""

    def test_detect_invisible(self):
        normalizer = UnicodeNormalizer()
        text = "Hel\u200Blo"
        result = normalizer.detect_suspicious(text)
        assert result["invisible_count"] == 1

    def test_detect_homoglyphs(self):
        normalizer = UnicodeNormalizer()
        text = "\u0435\u0430"  # two Cyrillic chars
        result = normalizer.detect_suspicious(text)
        assert result["homoglyph_count"] == 2

    def test_clean_text_no_suspicion(self):
        normalizer = UnicodeNormalizer()
        result = normalizer.detect_suspicious("Hello world")
        assert result["invisible_count"] == 0
        assert result["homoglyph_count"] == 0


class TestConfiguration:
    """Test normalizer configuration."""

    def test_disable_invisible_stripping(self):
        normalizer = UnicodeNormalizer(strip_invisible=False)
        text = "Hel\u200Blo"
        result = normalizer.normalize(text)
        assert "\u200B" in result

    def test_disable_homoglyph_flattening(self):
        normalizer = UnicodeNormalizer(flatten_homoglyphs=False)
        text = "\u0435"  # Cyrillic е
        result = normalizer.normalize(text)
        # Should still be Cyrillic
        assert result == "\u0435"

    def test_extra_homoglyphs(self):
        normalizer = UnicodeNormalizer(extra_homoglyphs={"ꜱ": "s"})
        text = "teꜱt"
        result = normalizer.normalize(text)
        assert result == "test"

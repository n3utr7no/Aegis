"""
Unit tests for aegis.lens.pipeline — Lens Pipeline Orchestrator.

Tests cover:
- Full pipeline processing (normalization + flattening)
- Statistics tracking
- Clean text passthrough
- Handling of text with both invisible chars and code
"""

from aegis.lens.pipeline import LensPipeline


class TestFullPipeline:
    """Test the complete Lens processing chain."""

    def test_strips_invisible_and_code(self):
        pipeline = LensPipeline()
        text = "\u200BHe\u200Cllo<script>alert(1)</script> world"
        result = pipeline.process(text)

        assert "alert" not in result.sanitized_text
        assert "Hello" in result.sanitized_text or "He" in result.sanitized_text
        assert "world" in result.sanitized_text

    def test_flattens_homoglyphs_and_strips_code(self):
        pipeline = LensPipeline()
        # Cyrillic 'с' used as 'c' in "cat" + a hidden script
        text = "\u0441at<style>body{display:none}</style>"
        result = pipeline.process(text)

        assert "cat" in result.sanitized_text
        assert "display:none" not in result.sanitized_text

    def test_clean_text_unchanged(self):
        pipeline = LensPipeline()
        text = "This is perfectly clean text."
        result = pipeline.process(text)
        assert result.sanitized_text == text

    def test_empty_text(self):
        pipeline = LensPipeline()
        result = pipeline.process("")
        assert result.sanitized_text == ""


class TestPipelineStats:
    """Test that processing statistics are tracked."""

    def test_stats_for_invisible_chars(self):
        pipeline = LensPipeline()
        text = "He\u200Bllo\u200C"
        result = pipeline.process(text)
        assert result.stats.get("invisible_chars_found", 0) >= 1

    def test_stats_for_code_constructs(self):
        pipeline = LensPipeline()
        text = "<script>x()</script>Text"
        result = pipeline.process(text)
        assert result.stats.get("code_constructs_found", 0) >= 1

    def test_stats_clean_text_zeros(self):
        pipeline = LensPipeline()
        result = pipeline.process("Clean text only")
        assert result.stats.get("invisible_chars_found", 0) == 0


class TestLensResult:
    """Test LensResult structure."""

    def test_result_fields(self):
        pipeline = LensPipeline()
        result = pipeline.process("Hello")
        assert hasattr(result, "sanitized_text")
        assert hasattr(result, "ocr_alerts")
        assert hasattr(result, "stats")
        assert isinstance(result.ocr_alerts, list)
        assert isinstance(result.stats, dict)

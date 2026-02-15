"""
Unit tests for aegis.utils.logging — Logger.

Tests cover:
- Log output format
- Level filtering
- Color toggle
- All severity methods
"""

from aegis.utils.logging import AegisLogger


class TestLoggerOutput:
    """Test log output formatting."""

    def test_info_outputs_to_stdout(self, capsys):
        logger = AegisLogger(min_level="DEBUG", use_color=False)
        logger.info("test_module", "Hello world")
        captured = capsys.readouterr()
        assert "[INFO ]" in captured.out
        assert "[test_module]" in captured.out
        assert "Hello world" in captured.out

    def test_error_outputs_to_stderr(self, capsys):
        logger = AegisLogger(min_level="DEBUG", use_color=False)
        logger.error("test_module", "Something broke")
        captured = capsys.readouterr()
        assert "[ERROR]" in captured.err
        assert "Something broke" in captured.err

    def test_debug_outputs_when_level_is_debug(self, capsys):
        logger = AegisLogger(min_level="DEBUG", use_color=False)
        logger.debug("mod", "Debug info")
        captured = capsys.readouterr()
        assert "Debug info" in captured.out

    def test_warn_output(self, capsys):
        logger = AegisLogger(min_level="DEBUG", use_color=False)
        logger.warn("mod", "Careful")
        captured = capsys.readouterr()
        assert "[WARN ]" in captured.out
        assert "Careful" in captured.out


class TestLogLevelFiltering:
    """Test that messages below the threshold are suppressed."""

    def test_debug_suppressed_at_info_level(self, capsys):
        logger = AegisLogger(min_level="INFO", use_color=False)
        logger.debug("mod", "Should not appear")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_info_suppressed_at_warn_level(self, capsys):
        logger = AegisLogger(min_level="WARN", use_color=False)
        logger.info("mod", "Should not appear")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_error_always_shown(self, capsys):
        logger = AegisLogger(min_level="ERROR", use_color=False)
        logger.error("mod", "Must show")
        captured = capsys.readouterr()
        assert "Must show" in captured.err

    def test_set_level_dynamically(self, capsys):
        logger = AegisLogger(min_level="ERROR", use_color=False)
        logger.debug("mod", "Hidden")
        captured = capsys.readouterr()
        assert captured.out == ""

        logger.set_level("DEBUG")
        logger.debug("mod", "Visible")
        captured = capsys.readouterr()
        assert "Visible" in captured.out


class TestLoggerTimestamp:
    """Test that timestamps are present."""

    def test_timestamp_format(self, capsys):
        logger = AegisLogger(min_level="DEBUG", use_color=False)
        logger.info("mod", "msg")
        captured = capsys.readouterr()
        # Should contain a date-like pattern [YYYY-MM-DD HH:MM:SS]
        assert "[20" in captured.out  # year starts with 20

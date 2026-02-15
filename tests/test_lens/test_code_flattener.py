"""
Unit tests for aegis.lens.code_flattener — Code Flattening.

Tests cover:
- Script tag removal
- Style tag removal
- HTML comment removal
- Event handler stripping
- Data URI removal
- Clean text preservation
- Code detection without modification
"""

from aegis.lens.code_flattener import CodeFlattener


class TestScriptRemoval:
    """Test <script> tag stripping."""

    def test_inline_script(self):
        flattener = CodeFlattener()
        text = "<p>Hello</p><script>alert('xss')</script><p>World</p>"
        result = flattener.flatten(text)
        assert "alert" not in result
        assert "Hello" in result
        assert "World" in result

    def test_script_with_src(self):
        flattener = CodeFlattener()
        text = '<script src="evil.js"></script>Normal text'
        result = flattener.flatten(text)
        assert "evil.js" not in result
        assert "Normal text" in result

    def test_multiple_scripts(self):
        flattener = CodeFlattener()
        text = (
            "<script>one()</script>"
            "middle"
            "<script>two()</script>"
        )
        result = flattener.flatten(text)
        assert "one()" not in result
        assert "two()" not in result
        assert "middle" in result


class TestStyleRemoval:
    """Test <style> tag stripping."""

    def test_inline_style(self):
        flattener = CodeFlattener()
        text = "<style>body{color:red}</style><p>Content</p>"
        result = flattener.flatten(text)
        assert "color:red" not in result
        assert "Content" in result


class TestCommentRemoval:
    """Test HTML comment stripping."""

    def test_html_comment(self):
        flattener = CodeFlattener()
        text = "Before<!-- secret instructions -->After"
        result = flattener.flatten(text)
        assert "secret instructions" not in result
        assert "Before" in result
        assert "After" in result


class TestEventHandlerRemoval:
    """Test on* event attribute stripping."""

    def test_onclick(self):
        flattener = CodeFlattener()
        text = 'Click this button onclick="alert(1)" to continue'
        result = flattener.flatten(text)
        assert "onclick" not in result
        assert "Click" in result

    def test_onerror(self):
        flattener = CodeFlattener()
        text = '<img onerror="fetch(\'evil.com\')" src="x">'
        result = flattener.flatten(text)
        assert "onerror" not in result


class TestDataURIRemoval:
    """Test data: URI stripping."""

    def test_data_uri_base64(self):
        flattener = CodeFlattener()
        text = 'src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="'
        result = flattener.flatten(text)
        assert "base64" not in result
        assert "[DATA_URI_REMOVED]" in result


class TestCleanText:
    """Test that clean text passes through unchanged."""

    def test_plain_text(self):
        flattener = CodeFlattener()
        text = "This is perfectly clean text."
        result = flattener.flatten(text)
        assert result == text

    def test_empty_string(self):
        flattener = CodeFlattener()
        assert flattener.flatten("") == ""


class TestCodeDetection:
    """Test detection without modification."""

    def test_detect_scripts(self):
        flattener = CodeFlattener()
        text = "<script>x()</script><style>y</style>"
        result = flattener.detect_code(text)
        assert result["script_tags"] == 1
        assert result["style_tags"] == 1

    def test_detect_clean_text(self):
        flattener = CodeFlattener()
        result = flattener.detect_code("No code here")
        assert all(v == 0 for v in result.values())

    def test_detect_event_handler(self):
        flattener = CodeFlattener()
        text = '<div onclick="x()" onerror="y()">Text</div>'
        result = flattener.detect_code(text)
        assert result["event_handlers"] == 2

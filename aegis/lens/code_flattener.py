"""
Code Flattener — Neutralizes executable code hidden in text content.

Defends against attacks where malicious instructions are hidden in:
- HTML <script> tags
- CSS <style> tags
- HTML comments (<!-- -->)
- Event handler attributes (onclick, onerror, etc.)
- Data URIs with executable content
"""

import re

from bs4 import BeautifulSoup, Comment

from aegis.utils.logging import log


# Regex patterns for code constructs not caught by BeautifulSoup
_EVENT_HANDLER_RE = re.compile(
    r'\b(on\w+)\s*=\s*["\'][^"\']*["\']',
    re.IGNORECASE,
)

_DATA_URI_RE = re.compile(
    r'data:\s*\w+/\w+\s*;?\s*base64\s*,\s*[A-Za-z0-9+/=]+',
    re.IGNORECASE,
)

_MARKDOWN_CODE_BLOCK_RE = re.compile(
    r'```[\s\S]*?```',
)


class CodeFlattener:
    """Neutralizes executable code hidden in text content.

    Uses BeautifulSoup for HTML parsing and regex for additional patterns.
    The goal is to prevent LLMs from accidentally executing code
    embedded in user-provided content.

    Usage:
        flattener = CodeFlattener()
        clean = flattener.flatten("<script>alert('xss')</script>Hello")
        # "Hello"
    """

    def __init__(
        self,
        strip_scripts: bool = True,
        strip_styles: bool = True,
        strip_comments: bool = True,
        strip_event_handlers: bool = True,
        strip_data_uris: bool = True,
    ):
        """Initialize the code flattener.

        Args:
            strip_scripts: Remove <script> tags and content.
            strip_styles: Remove <style> tags and content.
            strip_comments: Remove HTML comments.
            strip_event_handlers: Remove on* event attributes.
            strip_data_uris: Remove data: URIs.
        """
        self._strip_scripts = strip_scripts
        self._strip_styles = strip_styles
        self._strip_comments = strip_comments
        self._strip_event_handlers = strip_event_handlers
        self._strip_data_uris = strip_data_uris

        log.debug("lens.code_flattener", "Initialized CodeFlattener")

    def flatten(self, text: str) -> str:
        """Neutralize executable code in text.

        If the text contains HTML-like content, it's parsed with
        BeautifulSoup and dangerous elements are removed. Otherwise,
        only regex-based patterns are applied.

        Args:
            text: Input text that may contain hidden code.

        Returns:
            Text with executable code constructs removed.
        """
        if not text:
            return text

        stripped_count = 0

        # Check if text contains HTML-like content
        if self._looks_like_html(text):
            text, stripped_count = self._strip_html_dangers(text)

        # Apply regex-based stripping regardless
        if self._strip_event_handlers:
            text, count = self._remove_event_handlers(text)
            stripped_count += count

        if self._strip_data_uris:
            text, count = self._remove_data_uris(text)
            stripped_count += count

        if stripped_count > 0:
            log.info(
                "lens.code_flattener",
                f"Flattened {stripped_count} code constructs from text",
            )
        else:
            log.debug("lens.code_flattener", "No code constructs found")

        return text.strip()

    def _looks_like_html(self, text: str) -> bool:
        """Check if text contains HTML-like tags or comments."""
        return bool(re.search(r'<\s*\w+[\s>]|<!--', text))

    def _strip_html_dangers(self, text: str) -> tuple[str, int]:
        """Remove dangerous HTML elements using BeautifulSoup."""
        count = 0

        try:
            soup = BeautifulSoup(text, "lxml")
        except Exception:
            # Fallback to html.parser if lxml not available
            soup = BeautifulSoup(text, "html.parser")

        # Remove <script> tags
        if self._strip_scripts:
            for tag in soup.find_all("script"):
                tag.decompose()
                count += 1

        # Remove <style> tags
        if self._strip_styles:
            for tag in soup.find_all("style"):
                tag.decompose()
                count += 1

        # Remove HTML comments
        if self._strip_comments:
            for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
                comment.extract()
                count += 1

        # Get text content
        result = soup.get_text(separator=" ")
        # Collapse whitespace
        result = re.sub(r'\s+', ' ', result)

        return result, count

    def _remove_event_handlers(self, text: str) -> tuple[str, int]:
        """Remove on* event handler attributes."""
        matches = _EVENT_HANDLER_RE.findall(text)
        cleaned = _EVENT_HANDLER_RE.sub("", text)
        return cleaned, len(matches)

    def _remove_data_uris(self, text: str) -> tuple[str, int]:
        """Remove data: URIs."""
        matches = _DATA_URI_RE.findall(text)
        cleaned = _DATA_URI_RE.sub("[DATA_URI_REMOVED]", text)
        return cleaned, len(matches)

    def detect_code(self, text: str) -> dict[str, int]:
        """Detect code constructs without modifying text.

        Args:
            text: Text to analyze.

        Returns:
            Dict with counts of each code construct type found.
        """
        results = {
            "script_tags": 0,
            "style_tags": 0,
            "html_comments": 0,
            "event_handlers": 0,
            "data_uris": 0,
        }

        if self._looks_like_html(text):
            try:
                soup = BeautifulSoup(text, "lxml")
            except Exception:
                soup = BeautifulSoup(text, "html.parser")

            results["script_tags"] = len(soup.find_all("script"))
            results["style_tags"] = len(soup.find_all("style"))
            results["html_comments"] = len(
                soup.find_all(string=lambda s: isinstance(s, Comment))
            )

        results["event_handlers"] = len(_EVENT_HANDLER_RE.findall(text))
        results["data_uris"] = len(_DATA_URI_RE.findall(text))

        return results

"""
Unicode Normalizer — Strips invisible characters and flattens homoglyphs.

Defends against attacks that use:
- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
- Homoglyph substitution (Cyrillic 'а' looks like Latin 'a')
- Combining characters used to disguise text
- Bidirectional override characters (used to reverse text direction)
"""

import re
import unicodedata

from aegis.utils.logging import log


# ── Zero-width and invisible characters to strip ─────────────────────────
_INVISIBLE_CHARS: set[int] = {
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0xFEFF,  # Byte Order Mark / Zero Width No-Break Space
    0x00AD,  # Soft Hyphen
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x202A,  # Left-to-Right Embedding
    0x202B,  # Right-to-Left Embedding
    0x202C,  # Pop Directional Formatting
    0x202D,  # Left-to-Right Override
    0x202E,  # Right-to-Left Override
    0x2060,  # Word Joiner
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
    0x2066,  # Left-to-Right Isolate
    0x2067,  # Right-to-Left Isolate
    0x2068,  # First Strong Isolate
    0x2069,  # Pop Directional Isolate
    0x180E,  # Mongolian Vowel Separator
}

# ── Common Homoglyph mappings (Cyrillic → Latin, Greek → Latin) ──────────
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041D": "H",  # Н
    "\u041A": "K",  # К
    "\u041C": "M",  # М
    "\u041E": "O",  # О
    "\u0420": "P",  # Р
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043E": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    "\u0443": "y",  # у
    "\u0456": "i",  # і (Ukrainian)
    # Greek → Latin
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0396": "Z",  # Ζ
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039A": "K",  # Κ
    "\u039C": "M",  # Μ
    "\u039D": "N",  # Ν
    "\u039F": "O",  # Ο
    "\u03A1": "P",  # Ρ
    "\u03A4": "T",  # Τ
    "\u03A5": "Y",  # Υ
    "\u03A7": "X",  # Χ
    "\u03BF": "o",  # ο
    # Common confusables
    "\u00A0": " ",  # Non-breaking space → regular space
    "\u2000": " ",  # En Quad
    "\u2001": " ",  # Em Quad
    "\u2002": " ",  # En Space
    "\u2003": " ",  # Em Space
    "\u2004": " ",  # Three-per-em Space
    "\u2005": " ",  # Four-per-em Space
    "\u2006": " ",  # Six-per-em Space
    "\u2007": " ",  # Figure Space
    "\u2008": " ",  # Punctuation Space
    "\u2009": " ",  # Thin Space
    "\u200A": " ",  # Hair Space
    "\u205F": " ",  # Medium Mathematical Space
    "\u3000": " ",  # Ideographic Space
}


class UnicodeNormalizer:
    """Normalizes text to strip hidden characters and flatten homoglyphs.

    Processing order:
        1. NFKC Unicode normalization (canonical decomposition + composition)
        2. Strip zero-width / invisible characters
        3. Flatten homoglyphs (Cyrillic/Greek → Latin lookalikes)

    Usage:
        normalizer = UnicodeNormalizer()
        clean = normalizer.normalize("Hеllo")  # Cyrillic 'е' → Latin 'e'
    """

    def __init__(
        self,
        strip_invisible: bool = True,
        flatten_homoglyphs: bool = True,
        extra_homoglyphs: dict[str, str] | None = None,
    ):
        """Initialize the normalizer.

        Args:
            strip_invisible: Whether to remove zero-width chars.
            flatten_homoglyphs: Whether to map lookalike chars to ASCII.
            extra_homoglyphs: Additional char→replacement mappings to use.
        """
        self._strip_invisible = strip_invisible
        self._flatten_homoglyphs = flatten_homoglyphs

        self._homoglyph_map = dict(_HOMOGLYPH_MAP)
        if extra_homoglyphs:
            self._homoglyph_map.update(extra_homoglyphs)

        log.debug(
            "lens.unicode",
            f"Initialized UnicodeNormalizer "
            f"(invisible={strip_invisible}, homoglyphs={flatten_homoglyphs}, "
            f"map_size={len(self._homoglyph_map)})",
        )

    def normalize(self, text: str) -> str:
        """Normalize text by stripping invisible chars and flattening homoglyphs.

        Args:
            text: The input text to normalize.

        Returns:
            Cleaned text with normalized Unicode.
        """
        if not text:
            return text

        original_len = len(text)

        # 1. NFKC normalization
        result = unicodedata.normalize("NFKC", text)

        # 2. Strip invisible characters
        if self._strip_invisible:
            result = self._remove_invisible(result)

        # 3. Flatten homoglyphs
        if self._flatten_homoglyphs:
            result = self._apply_homoglyph_map(result)

        chars_removed = original_len - len(result)
        if chars_removed > 0:
            log.info(
                "lens.unicode",
                f"Normalized text: removed {chars_removed} invisible/homoglyph chars",
            )
        else:
            log.debug("lens.unicode", "Text already clean, no changes needed")

        return result

    def _remove_invisible(self, text: str) -> str:
        """Remove zero-width and invisible characters."""
        return "".join(
            ch for ch in text
            if ord(ch) not in _INVISIBLE_CHARS
        )

    def _apply_homoglyph_map(self, text: str) -> str:
        """Replace homoglyph characters with their ASCII equivalents."""
        result = []
        for ch in text:
            result.append(self._homoglyph_map.get(ch, ch))
        return "".join(result)

    def detect_suspicious(self, text: str) -> dict[str, int]:
        """Detect potentially suspicious characters without modifying text.

        Returns counts of invisible characters and homoglyphs found.

        Args:
            text: Text to analyze.

        Returns:
            Dict with 'invisible_count' and 'homoglyph_count'.
        """
        invisible = sum(1 for ch in text if ord(ch) in _INVISIBLE_CHARS)
        homoglyphs = sum(1 for ch in text if ch in self._homoglyph_map)
        return {
            "invisible_count": invisible,
            "homoglyph_count": homoglyphs,
        }

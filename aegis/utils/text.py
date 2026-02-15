"""
Aegis shared text processing utilities.

Common text helpers used across multiple modules.
"""

import unicodedata


def truncate_for_log(text: str, max_length: int = 100) -> str:
    """Truncate text for log output, appending '...' if truncated.

    Args:
        text: The text to truncate.
        max_length: Maximum number of characters before truncation.

    Returns:
        The original text if short enough, otherwise truncated with ellipsis.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def safe_decode(data: bytes, fallback_encoding: str = "utf-8") -> str:
    """Safely decode bytes to string, falling back to latin-1 if needed.

    Args:
        data: Raw bytes to decode.
        fallback_encoding: Primary encoding to try.

    Returns:
        The decoded string.
    """
    try:
        return data.decode(fallback_encoding)
    except (UnicodeDecodeError, AttributeError):
        return data.decode("latin-1")


def normalize_whitespace(text: str) -> str:
    """Collapse all whitespace runs to single spaces and strip edges.

    Args:
        text: Input text with potentially irregular whitespace.

    Returns:
        Text with normalized whitespace.
    """
    return " ".join(text.split())


def count_unicode_categories(text: str) -> dict[str, int]:
    """Count characters by their Unicode general category.

    Useful for detecting anomalous character distributions
    (e.g., high proportion of format/control characters).

    Args:
        text: The text to analyze.

    Returns:
        Dict mapping Unicode category codes (e.g., 'Lu', 'Cf') to counts.
    """
    categories: dict[str, int] = {}
    for char in text:
        cat = unicodedata.category(char)
        categories[cat] = categories.get(cat, 0) + 1
    return categories

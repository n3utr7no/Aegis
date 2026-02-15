"""
PII Detector — Identifies personally identifiable information in text.

Uses compiled regex patterns for structured PII types:
- Email addresses
- Phone numbers (US/international formats)
- Social Security Numbers (SSN)
- Credit card numbers
- IP addresses (v4)
- Date of birth patterns

Optionally uses spaCy NER for unstructured PII types:
- Person names (PERSON)
- Organizations (ORG)
- Locations (GPE)

Each detection returns a PIIMatch with entity type, value, and position.
"""

import re
from dataclasses import dataclass

from aegis.utils.logging import log


# Check if spaCy is available
_SPACY_AVAILABLE = False
try:
    import spacy
    _SPACY_AVAILABLE = True
except ImportError:
    pass


@dataclass(frozen=True)
class PIIMatch:
    """A single PII detection result."""
    entity_type: str
    value: str
    start: int
    end: int


# ── Compiled Regex Patterns ──────────────────────────────────────────────
# Each pattern is a tuple of (entity_type, compiled_regex)

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "EMAIL",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    ),
    (
        "PHONE",
        re.compile(
            r"(?<!\d)"                     # not preceded by digit
            r"(?:"
            r"\+?1[-.\s]?"                 # optional country code
            r")?"
            r"\(?\d{3}\)?[-.\s]?"          # area code
            r"\d{3}[-.\s]?"                # exchange
            r"\d{4}"                       # subscriber
            r"(?!\d)",                     # not followed by digit
        ),
    ),
    (
        "SSN",
        re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b"
        ),
    ),
    (
        "CREDIT_CARD",
        re.compile(
            r"\b"
            r"(?:"
            r"4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"   # Visa
            r"|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # Mastercard
            r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"          # Amex
            r"|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"  # Discover
            r")"
            r"\b",
        ),
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b"
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"\b"
        ),
    ),
    (
        "DATE_OF_BIRTH",
        re.compile(
            r"\b"
            r"(?:"
            r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"   # MM/DD/YYYY or DD-MM-YYYY
            r"|\d{4}[/-]\d{1,2}[/-]\d{1,2}"    # YYYY-MM-DD
            r")"
            r"\b"
        ),
    ),
]

# spaCy entity labels we care about
_NER_ENTITY_TYPES = {"PERSON", "ORG", "GPE"}


class PIIDetector:
    """Detects personally identifiable information in text.

    The detector uses a bank of compiled regex patterns for structured
    PII (email, phone, SSN, etc.) and optionally uses spaCy NER for
    unstructured PII (names, organizations, locations).

    Usage:
        detector = PIIDetector()
        matches = detector.detect("Email john@example.com for John Smith")
        # [PIIMatch(entity_type='EMAIL', ...), PIIMatch(entity_type='PERSON', ...)]
    """

    def __init__(
        self,
        enabled_types: set[str] | None = None,
        custom_patterns: list[tuple[str, re.Pattern]] | None = None,
        enable_ner: bool = True,
        ner_model: str = "en_core_web_sm",
    ):
        """Initialize the PII detector.

        Args:
            enabled_types: If provided, only detect these entity types.
                           Defaults to all types.
            custom_patterns: Additional (entity_type, regex) patterns to use.
            enable_ner: Whether to use spaCy NER for name/org/location
                        detection. Defaults to True. Gracefully degrades
                        if spaCy is not installed.
            ner_model: spaCy model name to use. Defaults to 'en_core_web_sm'.
        """
        self._patterns: list[tuple[str, re.Pattern]] = []

        for entity_type, pattern in _PII_PATTERNS:
            if enabled_types is None or entity_type in enabled_types:
                self._patterns.append((entity_type, pattern))

        if custom_patterns:
            self._patterns.extend(custom_patterns)

        # NER setup — lazy-loaded on first detect() call
        # Disable NER when enabled_types explicitly excludes NER types
        self._enabled_types = enabled_types
        ner_types_requested = (
            enabled_types is None
            or bool(enabled_types & _NER_ENTITY_TYPES)
        )
        self._enable_ner = enable_ner and _SPACY_AVAILABLE and ner_types_requested
        self._ner_model_name = ner_model
        self._nlp = None  # Loaded lazily
        self._ner_loaded = False

        enabled_names = [p[0] for p in self._patterns]
        if self._enable_ner:
            enabled_names.append("NER(PERSON,ORG,GPE)")
        log.debug("pii.detector", f"Initialized with patterns: {enabled_names}")

        if enable_ner and not _SPACY_AVAILABLE:
            log.warn(
                "pii.detector",
                "spaCy not installed — name/org/location detection disabled. "
                "Install with: pip install spacy && python -m spacy download en_core_web_sm",
            )

    def _ensure_ner(self) -> None:
        """Lazily load the spaCy NER model on first use."""
        if self._ner_loaded or not self._enable_ner:
            return

        self._ner_loaded = True
        try:
            self._nlp = spacy.load(self._ner_model_name)
            log.info(
                "pii.detector",
                f"spaCy NER model '{self._ner_model_name}' loaded",
            )
        except OSError:
            log.warn(
                "pii.detector",
                f"spaCy model '{self._ner_model_name}' not found. "
                f"Download with: python -m spacy download {self._ner_model_name}",
            )
            self._enable_ner = False
            self._nlp = None

    def detect(self, text: str) -> list[PIIMatch]:
        """Scan text for PII entities.

        Args:
            text: The input text to scan.

        Returns:
            A list of PIIMatch objects, sorted by start position.
            Overlapping matches are deduplicated (longest match wins).
        """
        if not text:
            return []

        raw_matches: list[PIIMatch] = []

        # 1. Regex-based detection
        for entity_type, pattern in self._patterns:
            for match in pattern.finditer(text):
                raw_matches.append(
                    PIIMatch(
                        entity_type=entity_type,
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                    )
                )

        # 2. NER-based detection (names, orgs, locations)
        if self._enable_ner:
            self._ensure_ner()
            if self._nlp is not None:
                doc = self._nlp(text)
                for ent in doc.ents:
                    if ent.label_ in _NER_ENTITY_TYPES:
                        # Skip very short entities (likely false positives)
                        if len(ent.text.strip()) < 2:
                            continue
                        raw_matches.append(
                            PIIMatch(
                                entity_type=ent.label_,
                                value=ent.text,
                                start=ent.start_char,
                                end=ent.end_char,
                            )
                        )

        # Deduplicate overlapping spans — keep the longest match
        deduplicated = self._deduplicate_overlaps(raw_matches)

        # Sort by position
        deduplicated.sort(key=lambda m: m.start)

        if deduplicated:
            log.info(
                "pii.detector",
                f"Detected {len(deduplicated)} PII entities: "
                f"{[m.entity_type for m in deduplicated]}",
            )

        return deduplicated

    def _deduplicate_overlaps(self, matches: list[PIIMatch]) -> list[PIIMatch]:
        """Remove overlapping matches, preferring longer spans.

        When two detections overlap in text position, keep the one
        with the larger span (end - start). If equal, keep the first.

        Args:
            matches: Raw list of PIIMatch objects (may overlap).

        Returns:
            Deduplicated list with no overlapping spans.
        """
        if not matches:
            return []

        # Sort by start, then by negative span length
        sorted_matches = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))

        result: list[PIIMatch] = [sorted_matches[0]]

        for current in sorted_matches[1:]:
            last = result[-1]
            # If current overlaps with the last kept match, skip it
            if current.start < last.end:
                continue
            result.append(current)

        return result

    @property
    def pattern_count(self) -> int:
        """Return the number of active detection patterns."""
        return len(self._patterns)

    @property
    def ner_available(self) -> bool:
        """Whether NER detection is available."""
        return self._enable_ner


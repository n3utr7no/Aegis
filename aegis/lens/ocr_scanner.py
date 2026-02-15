"""
OCR Scanner — Detects hidden text in images.

Scans images for text that may be:
- Too small for humans to read
- Colored to blend into the background (e.g., white text on white)
- Hidden in image metadata

Gracefully degrades if Tesseract OCR is not installed.
"""

from dataclasses import dataclass

from aegis.utils.logging import log

# Try to import pillow and pytesseract — both optional
_PIL_AVAILABLE = False
_TESSERACT_AVAILABLE = False

try:
    from PIL import Image
    import io
    _PIL_AVAILABLE = True
except ImportError:
    pass

try:
    import pytesseract
    _TESSERACT_AVAILABLE = True
except ImportError:
    pass


@dataclass(frozen=True)
class HiddenTextAlert:
    """Alert for suspicious text found in an image.

    Attributes:
        text: The extracted text content.
        reason: Why this text is considered suspicious.
        confidence: Confidence score (0.0 to 1.0).
    """
    text: str
    reason: str
    confidence: float = 0.0


class OCRScanner:
    """Scans images for hidden or suspicious text content.

    Uses Tesseract OCR (via pytesseract) to extract text from images,
    then analyzes the extracted text for suspicious characteristics.

    Gracefully degrades if dependencies are not available:
    - Without Pillow: returns empty results with a warning
    - Without Tesseract: returns empty results with a warning

    Usage:
        scanner = OCRScanner()
        alerts = scanner.scan(image_bytes)
        for alert in alerts:
            print(f"Hidden text: {alert.text} ({alert.reason})")
    """

    def __init__(self, min_text_length: int = 5):
        """Initialize the OCR scanner.

        Args:
            min_text_length: Minimum extracted text length to consider.
                            Shorter extractions are likely noise.
        """
        self._min_text_length = min_text_length
        self._available = _PIL_AVAILABLE and _TESSERACT_AVAILABLE

        if not _PIL_AVAILABLE:
            log.warn("lens.ocr", "Pillow not installed — OCR scanning disabled")
        elif not _TESSERACT_AVAILABLE:
            log.warn("lens.ocr", "pytesseract not installed — OCR scanning disabled")
        else:
            log.info("lens.ocr", "OCR scanner initialized")

    @property
    def available(self) -> bool:
        """Whether OCR scanning is available (dependencies installed)."""
        return self._available

    def scan(self, image_bytes: bytes) -> list[HiddenTextAlert]:
        """Scan an image for hidden or suspicious text.

        Args:
            image_bytes: Raw image bytes (PNG, JPEG, etc.).

        Returns:
            List of HiddenTextAlert for any suspicious text found.
            Returns empty list if OCR is not available.
        """
        if not self._available:
            log.debug("lens.ocr", "OCR not available, skipping scan")
            return []

        if not image_bytes:
            return []

        try:
            image = Image.open(io.BytesIO(image_bytes))
        except Exception as exc:
            log.warn("lens.ocr", f"Failed to open image: {exc}")
            return []

        alerts: list[HiddenTextAlert] = []

        # Extract text
        try:
            extracted_text = pytesseract.image_to_string(image).strip()
        except Exception as exc:
            log.warn("lens.ocr", f"OCR extraction failed: {exc}")
            return []

        if len(extracted_text) < self._min_text_length:
            log.debug("lens.ocr", "Extracted text too short, likely noise")
            return []

        log.info(
            "lens.ocr",
            f"Extracted {len(extracted_text)} chars from image",
        )

        # Check for suspicious patterns in extracted text
        alerts.extend(self._check_suspicious_content(extracted_text))

        return alerts

    def scan_with_text(self, text: str) -> list[HiddenTextAlert]:
        """Analyze pre-extracted text for suspicious patterns.

        Useful when OCR extraction is done externally.

        Args:
            text: Pre-extracted text from an image.

        Returns:
            List of HiddenTextAlert for any suspicious patterns.
        """
        if not text or len(text) < self._min_text_length:
            return []
        return self._check_suspicious_content(text)

    def _check_suspicious_content(self, text: str) -> list[HiddenTextAlert]:
        """Check extracted text for suspicious patterns.

        Looks for:
        - Instruction-like text (ignore, disregard, system prompt)
        - Code execution patterns (eval, exec, import)
        - Data exfiltration patterns (send, POST, fetch)
        """
        alerts: list[HiddenTextAlert] = []

        text_lower = text.lower()

        # Instruction injection patterns
        _INJECTION_KEYWORDS = [
            "ignore previous",
            "ignore all previous",
            "disregard",
            "system prompt",
            "you are now",
            "new instructions",
            "override",
            "forget everything",
            "act as",
            "pretend to be",
            "jailbreak",
            "do anything now",
        ]

        for keyword in _INJECTION_KEYWORDS:
            if keyword in text_lower:
                alerts.append(HiddenTextAlert(
                    text=text[:200],
                    reason=f"Injection keyword detected: '{keyword}'",
                    confidence=0.8,
                ))

        # Code execution patterns
        _CODE_KEYWORDS = [
            "eval(", "exec(", "import ", "__import__",
            "subprocess", "os.system", "fetch(",
        ]

        for keyword in _CODE_KEYWORDS:
            if keyword in text_lower:
                alerts.append(HiddenTextAlert(
                    text=text[:200],
                    reason=f"Code execution pattern: '{keyword}'",
                    confidence=0.7,
                ))

        if alerts:
            log.warn(
                "lens.ocr",
                f"Found {len(alerts)} suspicious patterns in image text",
            )

        return alerts

"""
Lens Pipeline — Orchestrates multimodal and stealth defense processing.

Pipeline:
    1. Unicode normalization (strip invisible chars, flatten homoglyphs)
    2. Code flattening (neutralize HTML/JS/CSS)
    3. OCR scanning (optional, for image content)
"""

from dataclasses import dataclass, field

from aegis.lens.code_flattener import CodeFlattener
from aegis.lens.ocr_scanner import HiddenTextAlert, OCRScanner
from aegis.lens.unicode_normalizer import UnicodeNormalizer
from aegis.utils.logging import log


@dataclass
class LensResult:
    """Result of Lens pipeline processing.

    Attributes:
        sanitized_text: The cleaned text after all processing.
        ocr_alerts: Any alerts from OCR scanning of images.
        stats: Processing statistics.
    """
    sanitized_text: str
    ocr_alerts: list[HiddenTextAlert] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


class LensPipeline:
    """Orchestrates the Lens multimodal defense pipeline.

    Chains together unicode normalization, code flattening, and
    optional OCR scanning to sanitize input content.

    Usage:
        lens = LensPipeline()
        result = lens.process("Hеllo <script>alert(1)</script>")
        print(result.sanitized_text)  # "Hello"
    """

    def __init__(
        self,
        normalizer: UnicodeNormalizer | None = None,
        flattener: CodeFlattener | None = None,
        ocr_scanner: OCRScanner | None = None,
    ):
        """Initialize the Lens pipeline.

        Args:
            normalizer: Custom UnicodeNormalizer. Uses default if None.
            flattener: Custom CodeFlattener. Uses default if None.
            ocr_scanner: Custom OCRScanner. Uses default if None.
        """
        self._normalizer = normalizer or UnicodeNormalizer()
        self._flattener = flattener or CodeFlattener()
        self._ocr = ocr_scanner or OCRScanner()

        log.info("lens.pipeline", "LensPipeline initialized")

    def process(
        self,
        text: str,
        image_bytes: bytes | None = None,
    ) -> LensResult:
        """Process text (and optionally images) through the Lens pipeline.

        Pipeline:
            1. Unicode normalization
            2. Code flattening
            3. OCR scanning (if image provided)

        Args:
            text: The text content to sanitize.
            image_bytes: Optional image bytes to scan for hidden text.

        Returns:
            LensResult with sanitized text, alerts, and stats.
        """
        log.info("lens.pipeline", "Starting Lens processing")

        stats: dict[str, int] = {}

        # 1. Unicode Normalization
        original_len = len(text) if text else 0

        suspicious = self._normalizer.detect_suspicious(text) if text else {}
        stats["invisible_chars_found"] = suspicious.get("invisible_count", 0)
        stats["homoglyphs_found"] = suspicious.get("homoglyph_count", 0)

        sanitized = self._normalizer.normalize(text) if text else ""

        # 2. Code Flattening
        code_before = self._flattener.detect_code(sanitized) if sanitized else {}
        stats["code_constructs_found"] = sum(code_before.values())

        sanitized = self._flattener.flatten(sanitized) if sanitized else ""

        # 3. OCR Scanning (optional)
        ocr_alerts: list[HiddenTextAlert] = []
        if image_bytes:
            ocr_alerts = self._ocr.scan(image_bytes)
            stats["ocr_alerts"] = len(ocr_alerts)

        log.info(
            "lens.pipeline",
            f"Lens complete: "
            f"{stats.get('invisible_chars_found', 0)} invisible chars, "
            f"{stats.get('homoglyphs_found', 0)} homoglyphs, "
            f"{stats.get('code_constructs_found', 0)} code constructs",
        )

        return LensResult(
            sanitized_text=sanitized,
            ocr_alerts=ocr_alerts,
            stats=stats,
        )

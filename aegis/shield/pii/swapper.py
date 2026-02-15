"""
Semantic Swapper — Replaces real PII with synthetic data while preserving context.

The swapper orchestrates detection and generation to produce sanitized text.
It maintains a bidirectional swap map for later restoration of original values.
"""

from dataclasses import dataclass, field

from aegis.shield.pii.detector import PIIDetector, PIIMatch
from aegis.shield.pii.generators import SyntheticGenerator
from aegis.utils.logging import log


@dataclass
class SwapMap:
    """Bidirectional mapping between real and synthetic PII values.

    Attributes:
        real_to_synthetic: Maps real PII values to their synthetic replacements.
        synthetic_to_real: Maps synthetic replacements back to real values.
        entity_types: Maps real PII values to their entity types.
    """
    real_to_synthetic: dict[str, str] = field(default_factory=dict)
    synthetic_to_real: dict[str, str] = field(default_factory=dict)
    entity_types: dict[str, str] = field(default_factory=dict)

    def add(self, real_value: str, synthetic_value: str, entity_type: str) -> None:
        """Add a mapping pair."""
        self.real_to_synthetic[real_value] = synthetic_value
        self.synthetic_to_real[synthetic_value] = real_value
        self.entity_types[real_value] = entity_type

    def __len__(self) -> int:
        return len(self.real_to_synthetic)


class SemanticSwapper:
    """Performs semantic swapping of PII in text.

    Detects PII using the PIIDetector, generates synthetic replacements
    using SyntheticGenerator, and provides swap/restore operations.

    Usage:
        swapper = SemanticSwapper()
        sanitized, swap_map = swapper.swap("Email john@test.com for info")
        # sanitized: "Email fake@example.com for info"
        restored = swapper.restore(sanitized, swap_map)
        # restored: "Email john@test.com for info"
    """

    def __init__(
        self,
        detector: PIIDetector | None = None,
        generator: SyntheticGenerator | None = None,
    ):
        """Initialize the semantic swapper.

        Args:
            detector: Custom PIIDetector instance. Uses default if None.
            generator: Custom SyntheticGenerator instance. Uses default if None.
        """
        self._detector = detector or PIIDetector()
        self._generator = generator or SyntheticGenerator()
        log.info("pii.swapper", "SemanticSwapper initialized")

    def swap(self, text: str) -> tuple[str, SwapMap]:
        """Replace all detected PII in text with synthetic values.

        Processes matches from right to left to preserve string positions
        during replacement.

        Args:
            text: The input text potentially containing PII.

        Returns:
            A tuple of (sanitized_text, swap_map).
            The swap_map can be used later with `restore()` to recover originals.
        """
        if not text:
            return text, SwapMap()

        matches = self._detector.detect(text)
        if not matches:
            log.debug("pii.swapper", "No PII detected, text unchanged")
            return text, SwapMap()

        swap_map = SwapMap()
        sanitized = text

        # Process from right to left to preserve positions
        for match in reversed(matches):
            # Reuse existing synthetic value if we've seen this PII before
            if match.value in swap_map.real_to_synthetic:
                synthetic = swap_map.real_to_synthetic[match.value]
            else:
                synthetic = self._generator.generate(match.entity_type)
                swap_map.add(match.value, synthetic, match.entity_type)

            sanitized = (
                sanitized[:match.start]
                + synthetic
                + sanitized[match.end:]
            )

        log.info(
            "pii.swapper",
            f"Swapped {len(swap_map)} PII entities: "
            f"{list(swap_map.entity_types.values())}",
        )

        return sanitized, swap_map

    def restore(self, text: str, swap_map: SwapMap) -> str:
        """Restore original PII values from synthetic replacements.

        Performs a direct string replacement for each synthetic→real mapping.
        Logs warnings for any synthetic values not found in the text
        (possible if the LLM modified the synthetic data).

        Args:
            text: The text containing synthetic PII values.
            swap_map: The SwapMap from a previous `swap()` call.

        Returns:
            Text with synthetic values replaced by originals.
        """
        if not text or not swap_map:
            return text

        restored = text
        restored_count = 0
        missed: list[str] = []

        for synthetic, real in swap_map.synthetic_to_real.items():
            if synthetic in restored:
                restored = restored.replace(synthetic, real)
                restored_count += 1
            else:
                missed.append(synthetic)

        if restored_count > 0:
            log.info("pii.swapper", f"Restored {restored_count} PII values")

        if missed:
            log.warn(
                "pii.swapper",
                f"Could not restore {len(missed)} synthetic values "
                f"(LLM may have modified them): {missed}",
            )

        return restored

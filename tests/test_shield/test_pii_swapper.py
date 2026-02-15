"""
Unit tests for aegis.shield.pii.swapper — Semantic Swapping.

Tests cover:
- Basic swap and restore round-trip
- Multiple PII values in a single text
- Duplicate PII value reuse
- Empty text handling
- Restore with missing synthetic values (LLM modification scenario)
"""

import pytest

from aegis.shield.pii.detector import PIIDetector
from aegis.shield.pii.generators import SyntheticGenerator
from aegis.shield.pii.swapper import SemanticSwapper, SwapMap


class TestSwapMap:
    """Test the SwapMap data structure."""

    def test_add_and_len(self):
        sm = SwapMap()
        assert len(sm) == 0

        sm.add("real@test.com", "fake@test.com", "EMAIL")
        assert len(sm) == 1

    def test_bidirectional_mapping(self):
        sm = SwapMap()
        sm.add("real@test.com", "fake@test.com", "EMAIL")
        assert sm.real_to_synthetic["real@test.com"] == "fake@test.com"
        assert sm.synthetic_to_real["fake@test.com"] == "real@test.com"
        assert sm.entity_types["real@test.com"] == "EMAIL"


class TestSemanticSwap:
    """Test the swap operation."""

    def test_swap_single_email(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL"}),
            generator=SyntheticGenerator(seed=42),
        )
        text = "Contact user@example.com for help"
        sanitized, swap_map = swapper.swap(text)

        # The original email should not appear in sanitized text
        assert "user@example.com" not in sanitized
        # A synthetic email should be in its place
        assert len(swap_map) == 1
        assert swap_map.entity_types["user@example.com"] == "EMAIL"

    def test_swap_multiple_pii(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL", "SSN"}),
            generator=SyntheticGenerator(seed=42),
        )
        text = "SSN: 123-45-6789, email: alice@test.org"
        sanitized, swap_map = swapper.swap(text)

        assert "123-45-6789" not in sanitized
        assert "alice@test.org" not in sanitized
        assert len(swap_map) == 2

    def test_swap_duplicate_pii_reuses_synthetic(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL"}),
            generator=SyntheticGenerator(seed=42),
        )
        text = "Email user@example.com. Again: user@example.com"
        sanitized, swap_map = swapper.swap(text)

        # Only one mapping should exist (deduped)
        assert len(swap_map) == 1
        # The synthetic should appear twice in the output
        synthetic = swap_map.real_to_synthetic["user@example.com"]
        assert sanitized.count(synthetic) == 2

    def test_swap_empty_text(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enable_ner=False),
        )
        sanitized, swap_map = swapper.swap("")
        assert sanitized == ""
        assert len(swap_map) == 0

    def test_swap_clean_text_unchanged(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enable_ner=False),
        )
        text = "Hello, this is perfectly clean text."
        sanitized, swap_map = swapper.swap(text)
        assert sanitized == text
        assert len(swap_map) == 0


class TestSemanticRestore:
    """Test the restore operation."""

    def test_restore_round_trip(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL"}),
            generator=SyntheticGenerator(seed=42),
        )
        original = "Contact user@example.com for help"
        sanitized, swap_map = swapper.swap(original)

        restored = swapper.restore(sanitized, swap_map)
        assert restored == original

    def test_restore_multiple_pii_round_trip(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enabled_types={"EMAIL", "SSN"}),
            generator=SyntheticGenerator(seed=42),
        )
        original = "SSN: 123-45-6789, email: alice@test.org"
        sanitized, swap_map = swapper.swap(original)

        restored = swapper.restore(sanitized, swap_map)
        assert "123-45-6789" in restored
        assert "alice@test.org" in restored

    def test_restore_empty_text(self):
        swapper = SemanticSwapper(
            detector=PIIDetector(enable_ner=False),
        )
        assert swapper.restore("", SwapMap()) == ""

    def test_restore_with_missing_synthetic(self, capsys):
        """If the LLM modified a synthetic value, restore should warn."""
        swapper = SemanticSwapper(
            detector=PIIDetector(enable_ner=False),
        )

        swap_map = SwapMap()
        swap_map.add("real@test.com", "fake@test.com", "EMAIL")

        # The text has been modified by the LLM — synthetic is NOT present
        text = "The LLM changed fake@test.com to something else entirely."
        # Replace the fake email to simulate LLM modification
        modified_text = text.replace("fake@test.com", "modified@llm.com")
        result = swapper.restore(modified_text, swap_map)

        # The original should NOT be restored (synthetic wasn't found)
        assert "real@test.com" not in result

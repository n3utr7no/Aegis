"""
Unit tests for aegis.shield.canary.generator — Canary Token Generation.

Tests cover:
- Token format (prefix + UUID4)
- Uniqueness across multiple generations
- Format validation
- Custom prefix
"""

from aegis.shield.canary.generator import CanaryGenerator


class TestCanaryGeneration:
    """Test canary token generation."""

    def test_default_format(self):
        gen = CanaryGenerator()
        canary = gen.generate()
        assert canary.startswith("AEGIS-CANARY-")
        # UUID4 part should be 36 chars (8-4-4-4-12 with dashes)
        uuid_part = canary[len("AEGIS-CANARY-"):]
        assert len(uuid_part) == 36

    def test_uniqueness(self):
        gen = CanaryGenerator()
        canaries = {gen.generate() for _ in range(100)}
        assert len(canaries) == 100  # all 100 should be unique

    def test_custom_prefix(self):
        gen = CanaryGenerator(prefix="MY-SECRET")
        canary = gen.generate()
        assert canary.startswith("MY-SECRET-")

    def test_prefix_property(self):
        gen = CanaryGenerator(prefix="CUSTOM")
        assert gen.prefix == "CUSTOM"


class TestCanaryValidation:
    """Test canary format validation."""

    def test_valid_canary(self):
        gen = CanaryGenerator()
        canary = gen.generate()
        assert gen.validate_format(canary) is True

    def test_invalid_canary_wrong_prefix(self):
        gen = CanaryGenerator()
        assert gen.validate_format("WRONG-PREFIX-abc-123") is False

    def test_invalid_canary_no_uuid(self):
        gen = CanaryGenerator()
        assert gen.validate_format("AEGIS-CANARY-not-a-uuid") is False

    def test_invalid_canary_empty(self):
        gen = CanaryGenerator()
        assert gen.validate_format("") is False

    def test_valid_with_custom_prefix(self):
        gen = CanaryGenerator(prefix="TEST")
        canary = gen.generate()
        assert gen.validate_format(canary) is True

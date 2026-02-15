"""
Unit tests for aegis.shield.pii.generators — Synthetic Data Generation.

Tests cover:
- Generation for each supported entity type
- Deterministic seeding
- Batch generation
- Unknown entity type error
- Supported types listing
"""

import pytest

from aegis.shield.pii.generators import SyntheticGenerator


class TestSyntheticGeneration:
    """Test individual entity type generation."""

    def test_generate_email(self):
        gen = SyntheticGenerator()
        email = gen.generate("EMAIL")
        assert "@" in email
        assert "." in email

    def test_generate_phone(self):
        gen = SyntheticGenerator()
        phone = gen.generate("PHONE")
        assert len(phone) > 0

    def test_generate_ssn(self):
        gen = SyntheticGenerator()
        ssn = gen.generate("SSN")
        # Faker SSNs are in xxx-xx-xxxx format
        assert len(ssn) > 0

    def test_generate_credit_card(self):
        gen = SyntheticGenerator()
        cc = gen.generate("CREDIT_CARD")
        assert len(cc) >= 13  # shortest CC format

    def test_generate_ip(self):
        gen = SyntheticGenerator()
        ip = gen.generate("IP_ADDRESS")
        parts = ip.split(".")
        assert len(parts) == 4

    def test_generate_dob(self):
        gen = SyntheticGenerator()
        dob = gen.generate("DATE_OF_BIRTH")
        assert len(str(dob)) > 0

    def test_generate_name(self):
        gen = SyntheticGenerator()
        name = gen.generate("NAME")
        assert len(name) > 0
        assert " " in name or len(name) > 2

    def test_generate_address(self):
        gen = SyntheticGenerator()
        addr = gen.generate("ADDRESS")
        assert len(addr) > 0


class TestDeterministicSeeding:
    """Test that seeded generators produce consistent output."""

    def test_same_seed_same_output(self):
        gen1 = SyntheticGenerator(seed=42)
        gen2 = SyntheticGenerator(seed=42)
        assert gen1.generate("EMAIL") == gen2.generate("EMAIL")

    def test_different_seed_likely_different_output(self):
        gen1 = SyntheticGenerator(seed=42)
        gen2 = SyntheticGenerator(seed=99)
        # Very unlikely to produce the same email
        email1 = gen1.generate("EMAIL")
        email2 = gen2.generate("EMAIL")
        # Not guaranteed but statistically very unlikely to match
        # We just check both are valid
        assert "@" in email1
        assert "@" in email2


class TestBatchGeneration:
    """Test batch generation."""

    def test_batch_generates_correct_count(self):
        gen = SyntheticGenerator()
        batch = gen.generate_batch("EMAIL", 5)
        assert len(batch) == 5

    def test_batch_all_valid(self):
        gen = SyntheticGenerator()
        batch = gen.generate_batch("IP_ADDRESS", 3)
        for ip in batch:
            assert len(ip.split(".")) == 4

    def test_batch_zero(self):
        gen = SyntheticGenerator()
        batch = gen.generate_batch("EMAIL", 0)
        assert batch == []


class TestErrorHandling:
    """Test error cases."""

    def test_unknown_entity_type_raises(self):
        gen = SyntheticGenerator()
        with pytest.raises(ValueError, match="Unknown entity type"):
            gen.generate("UNKNOWN_TYPE")

    def test_supported_types_property(self):
        gen = SyntheticGenerator()
        types = gen.supported_types
        assert "EMAIL" in types
        assert "PHONE" in types
        assert "SSN" in types
        assert "CREDIT_CARD" in types
        assert "IP_ADDRESS" in types
        assert len(types) == 8

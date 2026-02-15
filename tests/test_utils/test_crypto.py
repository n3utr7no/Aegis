"""
Unit tests for aegis.utils.crypto — Fernet encryption helpers.

Tests cover:
- Encrypt/decrypt round-trip
- Key generation
- Empty key error
- Invalid key error
- Wrong key decryption failure
"""

import pytest
from cryptography.fernet import Fernet, InvalidToken

from aegis.utils.crypto import decrypt_value, encrypt_value, generate_key


class TestEncryptDecryptRoundTrip:
    """Test that encrypt → decrypt produces the original value."""

    def test_basic_round_trip(self, encryption_key):
        plaintext = "john.doe@example.com"
        encrypted = encrypt_value(plaintext, encryption_key)
        decrypted = decrypt_value(encrypted, encryption_key)
        assert decrypted == plaintext

    def test_round_trip_with_special_chars(self, encryption_key):
        plaintext = "Hello, World! 🛡️ SSN: 123-45-6789"
        encrypted = encrypt_value(plaintext, encryption_key)
        decrypted = decrypt_value(encrypted, encryption_key)
        assert decrypted == plaintext

    def test_encrypted_differs_from_plaintext(self, encryption_key):
        plaintext = "secret"
        encrypted = encrypt_value(plaintext, encryption_key)
        assert encrypted != plaintext

    def test_empty_string_round_trip(self, encryption_key):
        encrypted = encrypt_value("", encryption_key)
        decrypted = decrypt_value(encrypted, encryption_key)
        assert decrypted == ""


class TestKeyGeneration:
    """Test Fernet key generation."""

    def test_generated_key_is_valid(self):
        key = generate_key()
        # Should not raise
        Fernet(key.encode())

    def test_generated_keys_are_unique(self):
        key1 = generate_key()
        key2 = generate_key()
        assert key1 != key2


class TestErrorHandling:
    """Test error cases."""

    def test_encrypt_empty_key_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            encrypt_value("test", "")

    def test_decrypt_empty_key_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            decrypt_value("test", "")

    def test_encrypt_invalid_key_raises(self):
        with pytest.raises(ValueError, match="Invalid Fernet key"):
            encrypt_value("test", "not-a-valid-key")

    def test_decrypt_wrong_key_raises(self):
        key1 = Fernet.generate_key().decode()
        key2 = Fernet.generate_key().decode()

        encrypted = encrypt_value("secret", key1)
        with pytest.raises(InvalidToken):
            decrypt_value(encrypted, key2)

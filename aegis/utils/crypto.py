"""
Aegis cryptographic utilities.

Provides Fernet symmetric encryption wrappers for the PII vault.
The encryption key should be loaded from AEGIS_VAULT_KEY env var.

Usage:
    from aegis.utils.crypto import encrypt_value, decrypt_value

    key = Fernet.generate_key().decode()
    encrypted = encrypt_value("secret-pii", key)
    original = decrypt_value(encrypted, key)
"""

from cryptography.fernet import Fernet, InvalidToken

from aegis.utils.logging import log


def generate_key() -> str:
    """Generate a new Fernet encryption key.

    Returns:
        A URL-safe base64-encoded 32-byte key as a string.
    """
    key = Fernet.generate_key().decode()
    log.info("crypto", "Generated new Fernet encryption key")
    return key


def encrypt_value(plaintext: str, key: str) -> str:
    """Encrypt a plaintext string using Fernet symmetric encryption.

    Args:
        plaintext: The string to encrypt.
        key: Fernet key as a string.

    Returns:
        The encrypted value as a URL-safe base64-encoded string.

    Raises:
        ValueError: If the key is empty or invalid.
    """
    if not key:
        raise ValueError("Encryption key must not be empty")

    try:
        fernet = Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise ValueError(f"Invalid Fernet key: {exc}") from exc

    encrypted = fernet.encrypt(plaintext.encode())
    return encrypted.decode()


def decrypt_value(ciphertext: str, key: str) -> str:
    """Decrypt a Fernet-encrypted string.

    Args:
        ciphertext: The encrypted string (URL-safe base64).
        key: Fernet key as a string.

    Returns:
        The decrypted plaintext string.

    Raises:
        ValueError: If the key is empty or invalid.
        cryptography.fernet.InvalidToken: If decryption fails (wrong key or corrupted data).
    """
    if not key:
        raise ValueError("Encryption key must not be empty")

    try:
        fernet = Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise ValueError(f"Invalid Fernet key: {exc}") from exc

    decrypted = fernet.decrypt(ciphertext.encode())
    return decrypted.decode()

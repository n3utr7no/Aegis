"""Shared pytest fixtures for Aegis tests."""

import pytest
from cryptography.fernet import Fernet

from aegis.config import reset_config


@pytest.fixture(autouse=True)
def _reset_global_config():
    """Reset global config before each test to avoid state leakage."""
    reset_config()
    yield
    reset_config()


@pytest.fixture
def encryption_key() -> str:
    """Provide a fresh Fernet encryption key for tests."""
    return Fernet.generate_key().decode()

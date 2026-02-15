"""
Unit tests for aegis.shield.pii.vault — Encrypted PII Vault.

Tests cover:
- Store and retrieve swap maps
- Purge single session
- Purge all sessions
- Encryption verification (data is not plaintext in DB)
- Empty session handling
- Context manager usage
"""

import json
import sqlite3

import pytest
from cryptography.fernet import Fernet

from aegis.shield.pii.swapper import SwapMap
from aegis.shield.pii.vault import PIIVault


@pytest.fixture
def vault(encryption_key):
    """Create an in-memory vault for testing."""
    v = PIIVault(db_path=":memory:", encryption_key=encryption_key)
    yield v
    v.close()


@pytest.fixture
def sample_swap_map() -> SwapMap:
    """Create a sample SwapMap for testing."""
    sm = SwapMap()
    sm.add("john@real.com", "alice@fake.com", "EMAIL")
    sm.add("555-123-4567", "555-999-8888", "PHONE")
    return sm


class TestVaultStoreRetrieve:
    """Test basic store and retrieve operations."""

    def test_store_and_retrieve(self, vault, sample_swap_map):
        vault.store("session-1", sample_swap_map)
        retrieved = vault.retrieve("session-1")

        assert retrieved is not None
        assert len(retrieved) == 2
        assert retrieved.real_to_synthetic["john@real.com"] == "alice@fake.com"
        assert retrieved.synthetic_to_real["alice@fake.com"] == "john@real.com"

    def test_retrieve_nonexistent_session(self, vault):
        result = vault.retrieve("nonexistent")
        assert result is None

    def test_store_replaces_existing(self, vault, sample_swap_map):
        vault.store("session-1", sample_swap_map)

        new_map = SwapMap()
        new_map.add("new@real.com", "new@fake.com", "EMAIL")
        vault.store("session-1", new_map)

        retrieved = vault.retrieve("session-1")
        assert len(retrieved) == 1
        assert "new@real.com" in retrieved.real_to_synthetic

    def test_multiple_sessions(self, vault):
        map1 = SwapMap()
        map1.add("a@real.com", "a@fake.com", "EMAIL")

        map2 = SwapMap()
        map2.add("b@real.com", "b@fake.com", "EMAIL")

        vault.store("session-1", map1)
        vault.store("session-2", map2)

        r1 = vault.retrieve("session-1")
        r2 = vault.retrieve("session-2")

        assert r1 is not None and "a@real.com" in r1.real_to_synthetic
        assert r2 is not None and "b@real.com" in r2.real_to_synthetic


class TestVaultPurge:
    """Test purge operations."""

    def test_purge_existing_session(self, vault, sample_swap_map):
        vault.store("session-1", sample_swap_map)
        deleted = vault.purge("session-1")
        assert deleted is True
        assert vault.retrieve("session-1") is None

    def test_purge_nonexistent_session(self, vault):
        deleted = vault.purge("nonexistent")
        assert deleted is False

    def test_purge_all(self, vault):
        map1 = SwapMap()
        map1.add("a@r.com", "a@f.com", "EMAIL")
        map2 = SwapMap()
        map2.add("b@r.com", "b@f.com", "EMAIL")

        vault.store("s1", map1)
        vault.store("s2", map2)

        count = vault.purge_all()
        assert count == 2
        assert vault.retrieve("s1") is None
        assert vault.retrieve("s2") is None


class TestVaultEncryption:
    """Test that stored data is actually encrypted."""

    def test_data_is_encrypted_in_db(self, encryption_key):
        vault = PIIVault(db_path=":memory:", encryption_key=encryption_key)

        sm = SwapMap()
        sm.add("secret@real.com", "fake@test.com", "EMAIL")
        vault.store("session-1", sm)

        # Read raw data from the database
        cursor = vault._conn.execute(
            "SELECT mapping_data FROM swap_mappings WHERE session_id = ?",
            ("session-1",),
        )
        raw_data = cursor.fetchone()[0]

        # The raw data should NOT contain the plaintext PII
        assert "secret@real.com" not in raw_data
        # It should be a Fernet token (starts with 'gA')
        assert raw_data.startswith("gA")

        vault.close()

    def test_plaintext_mode_warning(self, capsys):
        """Vault without encryption key should warn but still work."""
        vault = PIIVault(db_path=":memory:", encryption_key="")

        sm = SwapMap()
        sm.add("plain@real.com", "plain@fake.com", "EMAIL")
        vault.store("session-1", sm)

        retrieved = vault.retrieve("session-1")
        assert retrieved is not None
        assert "plain@real.com" in retrieved.real_to_synthetic

        vault.close()


class TestVaultEdgeCases:
    """Test edge cases."""

    def test_empty_session_id_raises(self, vault, sample_swap_map):
        with pytest.raises(ValueError, match="session_id must not be empty"):
            vault.store("", sample_swap_map)

    def test_context_manager(self, encryption_key):
        with PIIVault(db_path=":memory:", encryption_key=encryption_key) as vault:
            sm = SwapMap()
            sm.add("ctx@real.com", "ctx@fake.com", "EMAIL")
            vault.store("session-1", sm)
            retrieved = vault.retrieve("session-1")
            assert retrieved is not None

    def test_empty_swap_map(self, vault):
        vault.store("empty-session", SwapMap())
        retrieved = vault.retrieve("empty-session")
        assert retrieved is not None
        assert len(retrieved) == 0

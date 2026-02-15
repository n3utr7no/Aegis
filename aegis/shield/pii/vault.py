"""
PII Vault — Encrypted SQLite storage for PII swap mappings.

Stores the bidirectional mapping between real and synthetic PII
values, encrypted with Fernet. Each mapping is scoped to a session ID.
"""

import json
import sqlite3
from pathlib import Path

from aegis.shield.pii.swapper import SwapMap
from aegis.utils.crypto import decrypt_value, encrypt_value
from aegis.utils.logging import log


class PIIVault:
    """Encrypted SQLite vault for storing PII swap mappings.

    All PII values are encrypted before storage using Fernet symmetric
    encryption. The vault is scoped by session ID, allowing multiple
    concurrent sessions to maintain independent swap maps.

    Usage:
        vault = PIIVault(db_path=":memory:", encryption_key="<fernet-key>")
        vault.store("session-123", swap_map)
        recovered = vault.retrieve("session-123")
        vault.purge("session-123")
    """

    def __init__(self, db_path: str = "aegis_vault.db", encryption_key: str = ""):
        """Initialize the PII vault.

        Args:
            db_path: Path to the SQLite database file.
                     Use ':memory:' for in-memory (testing).
            encryption_key: Fernet encryption key for PII values.
                           If empty, values are stored in plaintext
                           (not recommended for production).
        """
        self._db_path = db_path
        self._encryption_key = encryption_key
        self._conn: sqlite3.Connection | None = None

        self._init_db()

        if not encryption_key:
            log.warn(
                "pii.vault",
                "No encryption key provided — PII will be stored in PLAINTEXT. "
                "Set AEGIS_VAULT_KEY for production use.",
            )
        else:
            log.info("pii.vault", f"Vault initialized (db={db_path})")

    def _init_db(self) -> None:
        """Create the database and table if they don't exist."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS swap_mappings (
                session_id TEXT NOT NULL,
                mapping_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (session_id)
            )
            """
        )
        self._conn.commit()
        log.debug("pii.vault", "Database table initialized")

    def _encrypt(self, data: str) -> str:
        """Encrypt data if an encryption key is available."""
        if self._encryption_key:
            return encrypt_value(data, self._encryption_key)
        return data

    def _decrypt(self, data: str) -> str:
        """Decrypt data if an encryption key is available."""
        if self._encryption_key:
            return decrypt_value(data, self._encryption_key)
        return data

    def store(self, session_id: str, swap_map: SwapMap) -> None:
        """Store a swap map for a session, replacing any existing one.

        Args:
            session_id: Unique identifier for the session.
            swap_map: The SwapMap to store.
        """
        if not session_id:
            raise ValueError("session_id must not be empty")

        # Serialize the swap map to JSON
        mapping_json = json.dumps({
            "real_to_synthetic": swap_map.real_to_synthetic,
            "synthetic_to_real": swap_map.synthetic_to_real,
            "entity_types": swap_map.entity_types,
        })

        encrypted = self._encrypt(mapping_json)

        assert self._conn is not None
        self._conn.execute(
            """
            INSERT OR REPLACE INTO swap_mappings (session_id, mapping_data)
            VALUES (?, ?)
            """,
            (session_id, encrypted),
        )
        self._conn.commit()

        log.info(
            "pii.vault",
            f"Stored swap map for session '{session_id}' "
            f"({len(swap_map)} mappings)",
        )

    def retrieve(self, session_id: str) -> SwapMap | None:
        """Retrieve the swap map for a session.

        Args:
            session_id: Unique identifier for the session.

        Returns:
            The SwapMap if found, None otherwise.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT mapping_data FROM swap_mappings WHERE session_id = ?",
            (session_id,),
        )
        row = cursor.fetchone()

        if row is None:
            log.debug("pii.vault", f"No mapping found for session '{session_id}'")
            return None

        decrypted = self._decrypt(row[0])
        data = json.loads(decrypted)

        swap_map = SwapMap(
            real_to_synthetic=data["real_to_synthetic"],
            synthetic_to_real=data["synthetic_to_real"],
            entity_types=data["entity_types"],
        )

        log.info(
            "pii.vault",
            f"Retrieved swap map for session '{session_id}' "
            f"({len(swap_map)} mappings)",
        )

        return swap_map

    def purge(self, session_id: str) -> bool:
        """Delete the swap map for a session.

        Args:
            session_id: Unique identifier for the session.

        Returns:
            True if a mapping was deleted, False if none existed.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "DELETE FROM swap_mappings WHERE session_id = ?",
            (session_id,),
        )
        self._conn.commit()

        deleted = cursor.rowcount > 0
        if deleted:
            log.info("pii.vault", f"Purged swap map for session '{session_id}'")
        else:
            log.debug("pii.vault", f"No mapping to purge for session '{session_id}'")

        return deleted

    def purge_all(self) -> int:
        """Delete all stored swap maps.

        Returns:
            The number of mappings deleted.
        """
        assert self._conn is not None
        cursor = self._conn.execute("DELETE FROM swap_mappings")
        self._conn.commit()
        count = cursor.rowcount
        log.info("pii.vault", f"Purged all swap maps ({count} total)")
        return count

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            log.debug("pii.vault", "Database connection closed")

    def __enter__(self) -> "PIIVault":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

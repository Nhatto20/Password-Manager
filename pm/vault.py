"""SQLite storage layer.

This module is deliberately "dumb": it stores and retrieves opaque encrypted
blobs and never sees plaintext secrets or keys. All encryption happens a layer
up (session.py). Writes that touch multiple rows run in a single transaction.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from pm.models import EntryRecord, UserRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    salt        BLOB NOT NULL,
    kdf_params  TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service      TEXT NOT NULL,
    enc_username BLOB NOT NULL,
    enc_password BLOB NOT NULL,
    enc_url      BLOB NOT NULL,
    enc_notes    BLOB NOT NULL,
    gen_policy   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE (user_id, service)
);
"""


def default_vault_path() -> Path:
    """%APPDATA%\\pm\\vault.db on Windows, ~/.local/share/pm/vault.db elsewhere.

    Overridable by the PM_VAULT environment variable.
    """
    env = os.environ.get("PM_VAULT")
    if env:
        return Path(env)
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home() / ".local" / "share"
    return base / "pm" / "vault.db"


class Vault:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- users ---------------------------------------------------------------
    def add_user(
        self,
        username: str,
        salt: bytes,
        kdf_params: dict[str, Any],
        wrapped_dek: bytes,
        created_at: str,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO users (username, salt, kdf_params, wrapped_dek, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, salt, json.dumps(kdf_params), wrapped_dek, created_at),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_user(self, username: str) -> UserRecord | None:
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return None
        return UserRecord(
            id=row["id"],
            username=row["username"],
            salt=row["salt"],
            kdf_params=json.loads(row["kdf_params"]),
            wrapped_dek=row["wrapped_dek"],
            created_at=row["created_at"],
        )

    def list_users(self) -> list[str]:
        rows = self.conn.execute("SELECT username FROM users ORDER BY username")
        return [r["username"] for r in rows]

    def update_user_wrapping(
        self, user_id: int, salt: bytes, kdf_params: dict[str, Any], wrapped_dek: bytes
    ) -> None:
        """Used by `passwd`: replace salt/params/wrapped_dek atomically."""
        self.conn.execute(
            "UPDATE users SET salt = ?, kdf_params = ?, wrapped_dek = ? WHERE id = ?",
            (salt, json.dumps(kdf_params), wrapped_dek, user_id),
        )
        self.conn.commit()

    # --- entries -------------------------------------------------------------
    def add_entry(self, rec: EntryRecord) -> int:
        cur = self.conn.execute(
            "INSERT INTO entries (user_id, service, enc_username, enc_password,"
            " enc_url, enc_notes, gen_policy, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.user_id,
                rec.service,
                rec.enc_username,
                rec.enc_password,
                rec.enc_url,
                rec.enc_notes,
                rec.gen_policy,
                rec.created_at,
                rec.updated_at,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_entry(self, user_id: int, service: str) -> EntryRecord | None:
        row = self.conn.execute(
            "SELECT * FROM entries WHERE user_id = ? AND service = ?",
            (user_id, service),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def update_entry(self, rec: EntryRecord) -> None:
        self.conn.execute(
            "UPDATE entries SET enc_username = ?, enc_password = ?, enc_url = ?,"
            " enc_notes = ?, gen_policy = ?, updated_at = ? WHERE id = ?",
            (
                rec.enc_username,
                rec.enc_password,
                rec.enc_url,
                rec.enc_notes,
                rec.gen_policy,
                rec.updated_at,
                rec.id,
            ),
        )
        self.conn.commit()

    def delete_entry(self, user_id: int, service: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM entries WHERE user_id = ? AND service = ?", (user_id, service)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def list_entries(self, user_id: int) -> list[tuple[str, str, str]]:
        """Returns (service, created_at, updated_at) — never any secret."""
        rows = self.conn.execute(
            "SELECT service, created_at, updated_at FROM entries"
            " WHERE user_id = ? ORDER BY service",
            (user_id,),
        )
        return [(r["service"], r["created_at"], r["updated_at"]) for r in rows]

    def all_entries(self, user_id: int) -> list[EntryRecord]:
        rows = self.conn.execute(
            "SELECT * FROM entries WHERE user_id = ? ORDER BY service", (user_id,)
        )
        return [self._row_to_entry(r) for r in rows]

    def rekey(
        self, user_id: int, records: list[EntryRecord], wrapped_dek: bytes
    ) -> None:
        """Re-encrypt all entries AND re-wrap the new DEK, in one transaction.

        Either everything lands or nothing does — so a crash mid-rekey can't
        leave entries encrypted under a DEK the stored wrapping can't recover.
        """
        with self.conn:  # transaction: commit on success, rollback on error
            for rec in records:
                self.conn.execute(
                    "UPDATE entries SET enc_username = ?, enc_password = ?,"
                    " enc_url = ?, enc_notes = ? WHERE id = ?",
                    (
                        rec.enc_username,
                        rec.enc_password,
                        rec.enc_url,
                        rec.enc_notes,
                        rec.id,
                    ),
                )
            self.conn.execute(
                "UPDATE users SET wrapped_dek = ? WHERE id = ?", (wrapped_dek, user_id)
            )

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> EntryRecord:
        return EntryRecord(
            id=row["id"],
            user_id=row["user_id"],
            service=row["service"],
            enc_username=row["enc_username"],
            enc_password=row["enc_password"],
            enc_url=row["enc_url"],
            enc_notes=row["enc_notes"],
            gen_policy=row["gen_policy"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

"""Plain data structures shared across modules.

`UserRecord` and `EntryRecord` are the *encrypted* forms as stored in SQLite.
`Credential` is the *decrypted* view handed back to the CLI after unlock.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pm.generator import Policy


@dataclass
class UserRecord:
    id: int
    username: str
    salt: bytes
    kdf_params: dict[str, Any]
    wrapped_dek: bytes
    created_at: str


@dataclass
class EntryRecord:
    """An entry exactly as stored: every secret field is a GCM blob."""

    id: int
    user_id: int
    service: str
    enc_username: bytes
    enc_password: bytes
    enc_url: bytes
    enc_notes: bytes
    gen_policy: str  # JSON text ("" if the password was entered manually)
    created_at: str
    updated_at: str


@dataclass
class Credential:
    """Decrypted entry returned to the CLI for a single command's lifetime."""

    service: str
    username: str
    password: str
    url: str
    notes: str
    policy: Policy | None
    created_at: str
    updated_at: str

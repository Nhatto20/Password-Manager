"""Encrypted whole-vault backup / restore.

The vault DB stores passwords encrypted, but service names, usernames of the
local users, and timestamps are plaintext metadata. A backup therefore encrypts
the *entire file* under a key derived from a separate backup passphrase, so the
backup leaks nothing — not even which services you have.
"""

from __future__ import annotations

from pathlib import Path

from pm import crypto

MAGIC = b"PMBK1\n"


def export_encrypted(vault_path: str | Path, out_path: str | Path, passphrase: bytes) -> None:
    data = Path(vault_path).read_bytes()
    salt = crypto.generate_salt()
    params = dict(crypto.DEFAULT_KDF_PARAMS)
    key = crypto.derive_kek(passphrase, salt, params)
    blob = crypto.encrypt(key, data, MAGIC)
    Path(out_path).write_bytes(MAGIC + salt + blob)


def import_encrypted(backup_path: str | Path, out_path: str | Path, passphrase: bytes) -> None:
    raw = Path(backup_path).read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError("not a pm backup file")
    body = raw[len(MAGIC):]
    salt, blob = body[: crypto.SALT_SIZE], body[crypto.SALT_SIZE:]
    params = dict(crypto.DEFAULT_KDF_PARAMS)
    key = crypto.derive_kek(passphrase, salt, params)
    data = crypto.decrypt(key, blob, MAGIC)  # DecryptionError == wrong passphrase
    Path(out_path).write_bytes(data)

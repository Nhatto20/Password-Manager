"""Cryptographic core — pure, no I/O.

Layered-key design (see docs/how-it-works.md):

    master password + salt --Argon2id--> KEK --AES-GCM--> wraps the DEK
    DEK --AES-GCM--> encrypts each entry field

Nothing here touches the database or the filesystem; everything is a pure
function of its inputs, which keeps it easy to test and reason about.
"""

from __future__ import annotations

import os
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- sizes (bytes) -----------------------------------------------------------
KEY_SIZE = 32      # 256-bit keys (KEK and DEK)
SALT_SIZE = 16     # per-user KDF salt
NONCE_SIZE = 12    # AES-GCM standard nonce

# --- Argon2id defaults -------------------------------------------------------
# Stored per user so they can be raised later without breaking old vaults.
# 64 MiB / 3 passes is a reasonable interactive-use baseline in 2026.
DEFAULT_KDF_PARAMS: dict[str, int] = {
    "time_cost": 3,
    "memory_cost": 65536,  # KiB == 64 MiB
    "parallelism": 4,
}


class DecryptionError(Exception):
    """Raised when authenticated decryption fails.

    Means one of: wrong key (wrong master password), corrupted data, or a
    tampered ciphertext (including one moved out of its bound AAD context).
    The caller cannot tell which — and must not, to avoid leaking detail.
    """


# --- randomness --------------------------------------------------------------
def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_dek() -> bytes:
    """A fresh random Data Encryption Key."""
    return os.urandom(KEY_SIZE)


# --- key derivation ----------------------------------------------------------
def derive_kek(master_password: bytes, salt: bytes, params: dict[str, Any]) -> bytes:
    """Derive the Key-Encryption-Key from the master password via Argon2id.

    `master_password` is raw bytes (UTF-8 encoded by the caller). The result
    is never stored; it lives only long enough to wrap/unwrap the DEK.
    """
    return hash_secret_raw(
        secret=master_password,
        salt=salt,
        time_cost=int(params["time_cost"]),
        memory_cost=int(params["memory_cost"]),
        parallelism=int(params["parallelism"]),
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


# --- authenticated encryption ------------------------------------------------
def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM. Returns nonce ‖ ciphertext ‖ tag as one blob.

    A fresh random nonce is generated per call — never reuse a nonce with the
    same key. `aad` is authenticated but not encrypted; it binds the ciphertext
    to its context (e.g. user+service+field) so it cannot be relocated.
    """
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Inverse of `encrypt`. Raises DecryptionError on any auth failure."""
    if len(blob) < NONCE_SIZE:
        raise DecryptionError("ciphertext too short")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc


# --- DEK wrapping ------------------------------------------------------------
def wrap_dek(kek: bytes, dek: bytes, aad: bytes) -> bytes:
    """Encrypt the DEK under the KEK (what we store as `wrapped_dek`)."""
    return encrypt(kek, dek, aad)


def unwrap_dek(kek: bytes, wrapped: bytes, aad: bytes) -> bytes:
    """Recover the DEK. DecryptionError here == wrong master password."""
    return decrypt(kek, wrapped, aad)


# --- AAD helpers -------------------------------------------------------------
def dek_aad(username: str) -> bytes:
    """AAD binding a wrapped DEK to its owner."""
    return f"dek:{username}".encode("utf-8")


def field_aad(user_id: int, service: str, field: str) -> bytes:
    """AAD binding an entry-field ciphertext to user+service+field.

    Stops an attacker with write access to the DB from moving a ciphertext to
    another entry/field/user: the AAD won't match and decryption will fail.
    """
    return f"field:{user_id}:{service}:{field}".encode("utf-8")

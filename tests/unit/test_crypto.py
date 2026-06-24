"""Unit tests for the pure crypto core."""

import pytest

from pm import crypto

pytestmark = pytest.mark.unit


# --- AEAD round-trips --------------------------------------------------------
def test_encrypt_decrypt_roundtrip():
    key = crypto.generate_dek()
    blob = crypto.encrypt(key, b"secret", b"ctx")
    assert crypto.decrypt(key, blob, b"ctx") == b"secret"


def test_empty_plaintext_roundtrip():
    key = crypto.generate_dek()
    blob = crypto.encrypt(key, b"", b"")
    assert crypto.decrypt(key, blob, b"") == b""


def test_large_plaintext_roundtrip():
    key = crypto.generate_dek()
    data = b"x" * 100_000
    assert crypto.decrypt(key, crypto.encrypt(key, data, b""), b"") == data


def test_blob_layout_is_nonce_plus_ciphertext():
    key = crypto.generate_dek()
    blob = crypto.encrypt(key, b"hi", b"")
    # nonce(12) + ciphertext(2) + GCM tag(16)
    assert len(blob) == crypto.NONCE_SIZE + 2 + 16


# --- nonce / non-determinism -------------------------------------------------
def test_nonce_is_unique_per_encryption():
    key = crypto.generate_dek()
    blobs = {crypto.encrypt(key, b"x", b"") for _ in range(100)}
    assert len(blobs) == 100  # every ciphertext differs (fresh nonces)


# --- failure modes -----------------------------------------------------------
def test_wrong_key_fails():
    blob = crypto.encrypt(crypto.generate_dek(), b"secret", b"")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(crypto.generate_dek(), blob, b"")


def test_wrong_aad_fails():
    key = crypto.generate_dek()
    blob = crypto.encrypt(key, b"secret", b"context-A")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, blob, b"context-B")


def test_truncated_blob_raises():
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(crypto.generate_dek(), b"short", b"")


def test_corrupted_ciphertext_fails():
    key = crypto.generate_dek()
    blob = bytearray(crypto.encrypt(key, b"secret", b""))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, bytes(blob), b"")


# --- sizes -------------------------------------------------------------------
def test_key_and_salt_sizes():
    assert len(crypto.generate_dek()) == crypto.KEY_SIZE == 32
    assert len(crypto.generate_salt()) == crypto.SALT_SIZE == 16


# --- KDF ---------------------------------------------------------------------
def test_kdf_is_deterministic_for_same_inputs():
    salt = crypto.generate_salt()
    a = crypto.derive_kek(b"master", salt, crypto.DEFAULT_KDF_PARAMS)
    b = crypto.derive_kek(b"master", salt, crypto.DEFAULT_KDF_PARAMS)
    assert a == b and len(a) == crypto.KEY_SIZE


def test_kdf_differs_with_salt():
    a = crypto.derive_kek(b"master", crypto.generate_salt(), crypto.DEFAULT_KDF_PARAMS)
    b = crypto.derive_kek(b"master", crypto.generate_salt(), crypto.DEFAULT_KDF_PARAMS)
    assert a != b


def test_kdf_differs_with_password():
    salt = crypto.generate_salt()
    a = crypto.derive_kek(b"master-1", salt, crypto.DEFAULT_KDF_PARAMS)
    b = crypto.derive_kek(b"master-2", salt, crypto.DEFAULT_KDF_PARAMS)
    assert a != b


# --- DEK wrapping ------------------------------------------------------------
def test_dek_wrap_unwrap():
    salt = crypto.generate_salt()
    kek = crypto.derive_kek(b"master", salt, crypto.DEFAULT_KDF_PARAMS)
    dek = crypto.generate_dek()
    wrapped = crypto.wrap_dek(kek, dek, crypto.dek_aad("alice"))
    assert crypto.unwrap_dek(kek, wrapped, crypto.dek_aad("alice")) == dek


def test_unwrap_with_wrong_master_fails():
    salt = crypto.generate_salt()
    good = crypto.derive_kek(b"master", salt, crypto.DEFAULT_KDF_PARAMS)
    bad = crypto.derive_kek(b"wrong", salt, crypto.DEFAULT_KDF_PARAMS)
    wrapped = crypto.wrap_dek(good, crypto.generate_dek(), crypto.dek_aad("a"))
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_dek(bad, wrapped, crypto.dek_aad("a"))


def test_unwrap_with_wrong_username_aad_fails():
    salt = crypto.generate_salt()
    kek = crypto.derive_kek(b"master", salt, crypto.DEFAULT_KDF_PARAMS)
    wrapped = crypto.wrap_dek(kek, crypto.generate_dek(), crypto.dek_aad("alice"))
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_dek(kek, wrapped, crypto.dek_aad("bob"))


# --- AAD helpers -------------------------------------------------------------
def test_field_aad_is_distinct_per_slot():
    assert crypto.field_aad(1, "github", "password") != crypto.field_aad(1, "github", "username")
    assert crypto.field_aad(1, "github", "password") != crypto.field_aad(2, "github", "password")
    assert crypto.field_aad(1, "github", "password") != crypto.field_aad(1, "gitlab", "password")

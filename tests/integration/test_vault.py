"""Integration tests for the SQLite storage layer."""

import sqlite3

import pytest

from pm import crypto
from pm.models import EntryRecord
from pm.vault import Vault, default_vault_path

pytestmark = pytest.mark.integration


def _entry(user_id, service):
    return EntryRecord(
        id=0, user_id=user_id, service=service,
        enc_username=b"u", enc_password=b"p", enc_url=b"r", enc_notes=b"n",
        gen_policy="", created_at="t0", updated_at="t0",
    )


def _add_user(vault, name="alice"):
    return vault.add_user(name, crypto.generate_salt(), {"t": 1}, b"wrapped", "t0")


def test_add_and_get_user(vault):
    uid = _add_user(vault)
    u = vault.get_user("alice")
    assert u.id == uid and u.username == "alice" and u.kdf_params == {"t": 1}


def test_get_missing_user_returns_none(vault):
    assert vault.get_user("ghost") is None


def test_list_users_sorted(vault):
    _add_user(vault, "carol")
    _add_user(vault, "alice")
    _add_user(vault, "bob")
    assert vault.list_users() == ["alice", "bob", "carol"]


def test_duplicate_username_rejected(vault):
    _add_user(vault, "alice")
    with pytest.raises(sqlite3.IntegrityError):
        _add_user(vault, "alice")


def test_entry_crud(vault):
    uid = _add_user(vault)
    vault.add_entry(_entry(uid, "github"))
    got = vault.get_entry(uid, "github")
    assert got.enc_password == b"p"

    got.enc_password = b"updated"
    got.updated_at = "t1"
    vault.update_entry(got)
    assert vault.get_entry(uid, "github").enc_password == b"updated"

    assert vault.delete_entry(uid, "github") is True
    assert vault.get_entry(uid, "github") is None
    assert vault.delete_entry(uid, "github") is False


def test_unique_user_service(vault):
    uid = _add_user(vault)
    vault.add_entry(_entry(uid, "github"))
    with pytest.raises(sqlite3.IntegrityError):
        vault.add_entry(_entry(uid, "github"))


def test_same_service_different_users_allowed(vault):
    a = _add_user(vault, "alice")
    b = _add_user(vault, "bob")
    vault.add_entry(_entry(a, "github"))
    vault.add_entry(_entry(b, "github"))  # no conflict
    assert vault.get_entry(a, "github") is not None
    assert vault.get_entry(b, "github") is not None


def test_list_entries_returns_no_secrets(vault):
    uid = _add_user(vault)
    vault.add_entry(_entry(uid, "b-service"))
    vault.add_entry(_entry(uid, "a-service"))
    rows = vault.list_entries(uid)
    assert [r[0] for r in rows] == ["a-service", "b-service"]  # sorted, services only
    assert all(len(r) == 3 for r in rows)


def test_foreign_key_cascade(vault):
    uid = _add_user(vault)
    vault.add_entry(_entry(uid, "github"))
    vault.conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    vault.conn.commit()
    assert vault.get_entry(uid, "github") is None  # cascaded away


def test_persistence_across_reopen(vault_path):
    v1 = Vault(vault_path)
    uid = v1.add_user("alice", crypto.generate_salt(), {"t": 1}, b"w", "t0")
    v1.add_entry(_entry(uid, "github"))
    v1.close()

    v2 = Vault(vault_path)
    assert v2.get_user("alice") is not None
    assert v2.get_entry(uid, "github") is not None
    v2.close()


def test_default_vault_path_respects_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PM_VAULT", str(tmp_path / "custom.db"))
    assert default_vault_path() == tmp_path / "custom.db"

"""Integration tests for the unlock flow and per-user operations."""

import pytest

from pm import generator
from pm.crypto import DecryptionError
from pm.session import (
    AuthError,
    NoSuchUserError,
    UserExistsError,
    create_user,
    unlock,
)

pytestmark = pytest.mark.integration


def test_create_unlock_and_roundtrip(session_factory):
    s = session_factory()
    s.add_credential("github", "alice", "hunter2", "https://github.com", "note", None)
    cred = s.get_credential("github")
    assert (cred.username, cred.password, cred.url, cred.notes) == (
        "alice", "hunter2", "https://github.com", "note",
    )


def test_unicode_fields_roundtrip(session_factory):
    s = session_factory()
    s.add_credential("svc", "üser", "pä$$wörd—🔑", "", "café — notɇ", None)
    cred = s.get_credential("svc")
    assert cred.password == "pä$$wörd—🔑"
    assert cred.notes == "café — notɇ"


def test_empty_optional_fields(session_factory):
    s = session_factory()
    s.add_credential("svc", "", "pw", "", "", None)
    cred = s.get_credential("svc")
    assert cred.username == "" and cred.url == "" and cred.notes == ""


def test_get_missing_entry_returns_none(session_factory):
    assert session_factory().get_credential("nope") is None


def test_duplicate_user_rejected(vault):
    create_user(vault, "alice", b"correct horse battery staple")
    with pytest.raises(UserExistsError):
        create_user(vault, "alice", b"another good password here")


def test_wrong_password_raises(vault):
    create_user(vault, "alice", b"correct horse battery staple")
    with pytest.raises(AuthError):
        unlock(vault, "alice", b"the wrong password entirely")


def test_unknown_user_raises(vault):
    with pytest.raises(NoSuchUserError):
        unlock(vault, "ghost", b"whatever password goes here")


def test_multi_user_isolation(vault):
    create_user(vault, "alice", b"alice password goes here")
    create_user(vault, "bob", b"bob password goes here xx")
    a = unlock(vault, "alice", b"alice password goes here")
    b = unlock(vault, "bob", b"bob password goes here xx")
    a.add_credential("github", "alice", "alice-secret", "", "", None)
    b.add_credential("github", "bob", "bob-secret", "", "", None)
    assert a.get_credential("github").password == "alice-secret"
    assert b.get_credential("github").password == "bob-secret"


def test_other_users_dek_cannot_decrypt(vault):
    """Lower-level proof of isolation: Bob's DEK can't read Alice's blob."""
    create_user(vault, "alice", b"alice password goes here")
    create_user(vault, "bob", b"bob password goes here xx")
    a = unlock(vault, "alice", b"alice password goes here")
    a.add_credential("github", "alice", "secret", "", "", None)
    rec = vault.get_entry(a.user.id, "github")

    b = unlock(vault, "bob", b"bob password goes here xx")
    from pm import crypto

    with pytest.raises(DecryptionError):
        crypto.decrypt(b._dek, rec.enc_password, crypto.field_aad(a.user.id, "github", "password"))


def test_aad_blocks_moving_ciphertext_between_entries(vault, session_factory):
    s = session_factory()
    s.add_credential("a", "", "secret-a", "", "", None)
    s.add_credential("b", "", "secret-b", "", "", None)
    rec_a = vault.get_entry(s.user.id, "a")
    rec_b = vault.get_entry(s.user.id, "b")

    # Attacker swaps a's password blob into b's row.
    rec_b.enc_password = rec_a.enc_password
    vault.update_entry(rec_b)

    with pytest.raises(DecryptionError):  # AAD for b:password != a:password
        s.get_credential("b")


def test_change_password_keeps_entries(vault):
    create_user(vault, "alice", b"old password goes here x")
    s = unlock(vault, "alice", b"old password goes here x")
    s.add_credential("github", "alice", "hunter2", "", "", None)
    s.change_password(b"new password goes here xx")

    with pytest.raises(AuthError):
        unlock(vault, "alice", b"old password goes here x")
    s2 = unlock(vault, "alice", b"new password goes here xx")
    assert s2.get_credential("github").password == "hunter2"


def test_rekey_changes_ciphertext_but_not_plaintext(vault):
    create_user(vault, "alice", b"alice password goes here")
    s = unlock(vault, "alice", b"alice password goes here")
    s.add_credential("github", "alice", "hunter2", "", "", None)
    before_blob = vault.get_entry(s.user.id, "github").enc_password
    before_wrap = vault.get_user("alice").wrapped_dek

    s.rekey()

    after_blob = vault.get_entry(s.user.id, "github").enc_password
    assert after_blob != before_blob  # re-encrypted under new DEK
    assert vault.get_user("alice").wrapped_dek != before_wrap  # DEK re-wrapped
    s2 = unlock(vault, "alice", b"alice password goes here")
    assert s2.get_credential("github").password == "hunter2"  # still readable


def test_passwd_then_rekey(vault):
    create_user(vault, "alice", b"old password goes here x")
    s = unlock(vault, "alice", b"old password goes here x")
    s.add_credential("github", "alice", "hunter2", "", "", None)
    s.change_password(b"new password goes here xx")
    s.rekey()
    s2 = unlock(vault, "alice", b"new password goes here xx")
    assert s2.get_credential("github").password == "hunter2"


def test_update_missing_entry_returns_false(session_factory):
    assert session_factory().update_credential("nope", "", "", "", "", None) is False


def test_rotate_preserves_policy_and_metadata(session_factory):
    s = session_factory()
    policy = generator.preset("pin")
    s.add_credential("bank", "acct", generator.generate(policy), "u", "n", policy)
    cred = s.get_credential("bank")
    assert cred.policy.length == policy.length and cred.password.isdigit()
    # rotate-equivalent: keep username/url/notes, new password under same policy
    s.update_credential("bank", cred.username, generator.generate(policy), cred.url, cred.notes, policy)
    rotated = s.get_credential("bank")
    assert rotated.username == "acct" and rotated.url == "u" and rotated.password.isdigit()

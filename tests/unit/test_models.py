"""Unit tests for plain data structures."""

import pytest

from pm.generator import ClassSpec, Policy
from pm.models import Credential, EntryRecord, UserRecord

pytestmark = pytest.mark.unit


def test_user_record_fields():
    u = UserRecord(id=1, username="alice", salt=b"s", kdf_params={"t": 1}, wrapped_dek=b"w", created_at="t0")
    assert u.username == "alice" and u.kdf_params["t"] == 1


def test_entry_record_is_mutable_for_reencryption():
    rec = EntryRecord(
        id=1, user_id=1, service="github",
        enc_username=b"a", enc_password=b"b", enc_url=b"c", enc_notes=b"d",
        gen_policy="", created_at="t0", updated_at="t0",
    )
    rec.enc_password = b"new"  # rekey mutates these in place
    assert rec.enc_password == b"new"


def test_credential_carries_policy():
    policy = Policy(length=8, classes={"digits": ClassSpec(min=1)})
    cred = Credential(
        service="s", username="u", password="p", url="", notes="",
        policy=policy, created_at="t0", updated_at="t0",
    )
    assert cred.policy.length == 8

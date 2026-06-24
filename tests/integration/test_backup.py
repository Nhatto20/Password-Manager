"""Integration tests for encrypted whole-vault backup / restore."""

import pytest

from pm import backup
from pm.crypto import DecryptionError
from pm.session import create_user, unlock
from pm.vault import Vault

pytestmark = pytest.mark.integration


def _seed_vault(path):
    v = Vault(path)
    create_user(v, "alice", b"alice password goes here")
    unlock(v, "alice", b"alice password goes here").add_credential(
        "github", "alice", "hunter2", "", "secret-note", None
    )
    v.close()


def test_backup_restore_roundtrip(tmp_path):
    vpath = tmp_path / "vault.db"
    _seed_vault(vpath)

    bpath = tmp_path / "vault.pmbackup"
    backup.export_encrypted(vpath, bpath, b"backup-pass")

    restored = tmp_path / "restored.db"
    backup.import_encrypted(bpath, restored, b"backup-pass")

    v2 = Vault(restored)
    assert unlock(v2, "alice", b"alice password goes here").get_credential("github").password == "hunter2"
    v2.close()


def test_backup_file_leaks_no_metadata(tmp_path):
    vpath = tmp_path / "vault.db"
    _seed_vault(vpath)
    bpath = tmp_path / "vault.pmbackup"
    backup.export_encrypted(vpath, bpath, b"backup-pass")

    raw = bpath.read_bytes()
    # service name and username are plaintext metadata in the DB, but the
    # backup encrypts the whole file, so they must not appear.
    assert b"github" not in raw
    assert b"alice" not in raw


def test_restore_wrong_passphrase_fails(tmp_path):
    vpath = tmp_path / "vault.db"
    Vault(vpath).close()
    bpath = tmp_path / "b.pmbackup"
    backup.export_encrypted(vpath, bpath, b"right-pass")
    with pytest.raises(DecryptionError):
        backup.import_encrypted(bpath, tmp_path / "out.db", b"wrong-pass")


def test_restore_rejects_non_backup(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a backup file at all")
    with pytest.raises(ValueError):
        backup.import_encrypted(junk, tmp_path / "out.db", b"x")

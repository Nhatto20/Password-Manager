"""End-to-end CLI tests.

getpass reads from the console (not stdin), so we patch getpass + input to feed
scripted answers. This drives the real argparse dispatch, policy-from-flags,
strength checks, confirmations, and clipboard handling.
"""

import pytest

from pm import cli

pytestmark = pytest.mark.integration

PW = "correcthorsebattery1"


@pytest.fixture
def run(vault_path, monkeypatch):
    def _run(argv, *, secrets=(), inputs=()):
        secret_iter = iter(secrets)
        input_iter = iter(inputs)
        monkeypatch.setattr(cli.getpass, "getpass", lambda *_a, **_k: next(secret_iter))
        monkeypatch.setattr(cli, "input", lambda *_a, **_k: next(input_iter), raising=False)
        return cli.main(["--vault", str(vault_path), *argv])

    return _run


@pytest.fixture
def alice(run):
    assert run(["user", "add", "alice"], secrets=[PW, PW]) == 0
    return run


# --- gen (no auth) -----------------------------------------------------------
def test_gen(run, capsys):
    assert run(["gen", "--len", "12", "--no-symbols"]) == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 12 and not (set(out) & set("!@#$%^&*-_=+"))


def test_gen_infeasible_exits_1(run, capsys):
    assert run(["gen", "--len", "2", "--digits-min", "5"]) == 1
    assert "error" in capsys.readouterr().err


# --- user management ---------------------------------------------------------
def test_weak_master_rejected(run):
    assert run(["user", "add", "bob"], secrets=["short"]) == 1


def test_master_mismatch_rejected(run):
    assert run(["user", "add", "bob"], secrets=[PW, "differentpw123456"]) == 1


def test_duplicate_user_rejected(alice):
    assert alice(["user", "add", "alice"], secrets=[PW, PW]) == 1


# --- entry lifecycle ---------------------------------------------------------
def test_add_get_list(alice, capsys):
    assert alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW]) == 0
    capsys.readouterr()
    assert alice(["--user", "alice", "get", "github"], secrets=[PW]) == 0
    assert "password:" in capsys.readouterr().out
    assert alice(["--user", "alice", "list"], secrets=[PW]) == 0
    out = capsys.readouterr().out
    assert "github" in out


def test_add_duplicate_rejected(alice):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    assert alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW]) == 1


def test_add_manual_password(alice, capsys):
    assert alice(["--user", "alice", "add", "wifi", "--manual"], secrets=[PW, "my-typed-pass"]) == 0
    capsys.readouterr()
    alice(["--user", "alice", "get", "wifi"], secrets=[PW])
    assert "my-typed-pass" in capsys.readouterr().out


def test_get_missing_exits_1(alice):
    assert alice(["--user", "alice", "get", "nope"], secrets=[PW]) == 1


def test_list_empty(alice, capsys):
    assert alice(["--user", "alice", "list"], secrets=[PW]) == 0
    assert "(no entries)" in capsys.readouterr().out


def test_rotate_changes_password(alice, capsys):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    alice(["--user", "alice", "get", "github"], secrets=[PW])
    first = [l for l in capsys.readouterr().out.splitlines() if l.startswith("password:")][0]
    alice(["--user", "alice", "rotate", "github"], secrets=[PW], inputs=["y"])
    alice(["--user", "alice", "get", "github"], secrets=[PW])
    second = [l for l in capsys.readouterr().out.splitlines() if l.startswith("password:")][0]
    assert first != second


def test_rotate_abort_keeps_password(alice, capsys):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    alice(["--user", "alice", "get", "github"], secrets=[PW])
    first = [l for l in capsys.readouterr().out.splitlines() if l.startswith("password:")][0]
    alice(["--user", "alice", "rotate", "github"], secrets=[PW], inputs=["n"])
    alice(["--user", "alice", "get", "github"], secrets=[PW])
    second = [l for l in capsys.readouterr().out.splitlines() if l.startswith("password:")][0]
    assert first == second


def test_edit_keeps_unspecified_fields(alice, capsys):
    alice(["--user", "alice", "add", "github", "--username", "old@x.com", "--policy", "compat"], secrets=[PW])
    # blank username keeps it, set a new url, blank notes
    alice(["--user", "alice", "edit", "github"], secrets=[PW], inputs=["", "https://new", ""])
    capsys.readouterr()
    alice(["--user", "alice", "get", "github"], secrets=[PW])
    out = capsys.readouterr().out
    assert "old@x.com" in out and "https://new" in out


def test_rm_declined_keeps_entry(alice):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    alice(["--user", "alice", "rm", "github"], secrets=[PW], inputs=["n"])
    assert alice(["--user", "alice", "get", "github"], secrets=[PW]) == 0


def test_rm_confirmed_deletes(alice):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    assert alice(["--user", "alice", "rm", "github"], secrets=[PW], inputs=["y"]) == 0
    assert alice(["--user", "alice", "get", "github"], secrets=[PW]) == 1


# --- master password / dek lifecycle ----------------------------------------
def test_passwd_then_old_fails(alice):
    new = "brandnewmaster123"
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    assert alice(["--user", "alice", "passwd"], secrets=[PW, new, new]) == 0
    # old password fails (3 attempts), new works
    assert alice(["--user", "alice", "get", "github"], secrets=[PW, PW, PW]) == 1
    assert alice(["--user", "alice", "get", "github"], secrets=[new]) == 0


def test_rekey_keeps_access(alice, capsys):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    assert alice(["--user", "alice", "rekey"], secrets=[PW], inputs=["y"]) == 0
    assert alice(["--user", "alice", "get", "github"], secrets=[PW]) == 0


# --- backup / restore via CLI ------------------------------------------------
def test_backup_and_restore(alice, tmp_path, vault_path):
    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    bfile = tmp_path / "out.pmbackup"
    assert alice(["backup", str(bfile)], secrets=["bpass", "bpass"]) == 0
    assert bfile.exists()

    restored = tmp_path / "restored.db"
    assert alice(["--vault", str(restored), "restore", str(bfile)], secrets=["bpass"]) == 0
    assert alice(["--vault", str(restored), "--user", "alice", "get", "github"], secrets=[PW]) == 0


def test_restore_wrong_passphrase_exits_1(alice, tmp_path):
    bfile = tmp_path / "out.pmbackup"
    alice(["backup", str(bfile)], secrets=["bpass", "bpass"])
    restored = tmp_path / "restored.db"
    assert alice(["--vault", str(restored), "restore", str(bfile)], secrets=["wrongpass"]) == 1


# --- auth failure ------------------------------------------------------------
def test_wrong_master_password_exits_1(alice):
    assert alice(["--user", "alice", "list"], secrets=["nope1", "nope2", "nope3"]) == 1


def test_unknown_user_exits_1(run):
    assert run(["--user", "ghost", "list"], secrets=["whatever12345"]) == 1


# --- clipboard, prompts, helpers --------------------------------------------
def test_get_copy_clears_clipboard(alice, monkeypatch, capsys):
    import pyperclip

    store = {"v": "sentinel"}
    monkeypatch.setattr(pyperclip, "copy", lambda v: store.__setitem__("v", v))
    monkeypatch.setattr(pyperclip, "paste", lambda: store["v"])
    monkeypatch.setattr(cli.time, "sleep", lambda *_a: None)  # don't actually wait

    alice(["--user", "alice", "add", "github", "--policy", "compat"], secrets=[PW])
    capsys.readouterr()
    assert alice(["--user", "alice", "get", "github", "--copy"], secrets=[PW]) == 0
    out = capsys.readouterr().out
    assert "Copied to clipboard" in out and "cleared" in out
    assert store["v"] == ""  # password wiped after the timeout


def test_user_prompted_when_flag_omitted(alice):
    # no --user: cmd_add calls input("User: "); feed "alice" then the master pw
    assert alice(["add", "github", "--policy", "compat"], secrets=[PW], inputs=["alice"]) == 0


def test_format_age():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    assert cli._format_age(now.isoformat()) == "today"
    assert cli._format_age((now - timedelta(days=1)).isoformat()) == "1 day"
    assert cli._format_age((now - timedelta(days=5)).isoformat()) == "5 days"
    assert cli._format_age("not-a-timestamp") == "?"


def test_gen_with_symbol_count_overrides(run, capsys):
    assert run(["gen", "--len", "16", "--digits-min", "2", "--symbols-min", "1", "--symbols-max", "3"]) == 0
    pw = capsys.readouterr().out.strip()
    assert len(pw) == 16
    assert sum(c.isdigit() for c in pw) >= 2
    assert 1 <= sum(c in "!@#$%^&*-_=+" for c in pw) <= 3

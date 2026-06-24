"""Command-line interface — argument parsing, prompts, dispatch.

This is the only layer that does interactive I/O (getpass, confirmations,
clipboard). It composes session.py (unlock + operations), generator.py
(passwords), and backup.py (encrypted backups).
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import sys
import time
from datetime import datetime, timezone

from pm import backup, generator
from pm.generator import ClassSpec, Policy, PolicyError
from pm.session import (
    AuthError,
    NoSuchUserError,
    Session,
    UserExistsError,
    create_user,
    unlock,
)
from pm.vault import Vault, default_vault_path

CLIPBOARD_CLEAR_SECONDS = 15
MAX_UNLOCK_ATTEMPTS = 3


# --- small helpers -----------------------------------------------------------
def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def _confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def _open_vault(args: argparse.Namespace) -> Vault:
    return Vault(args.vault or default_vault_path())


def _resolve_user(args: argparse.Namespace) -> str:
    return args.user or input("User: ").strip()


def password_strength_problem(pw: str) -> str | None:
    """Return a reason the master password is too weak, or None if acceptable."""
    if len(pw) < 12:
        return "master password must be at least 12 characters"
    classes = sum(
        bool(set(pw) & set(s)) for s in generator.DEFAULT_SETS.values()
    ) + bool(set(pw) - set("".join(generator.DEFAULT_SETS.values())))
    if len(pw) < 16 and classes < 3:
        return "use 16+ characters, or mix at least 3 character types"
    return None


def _unlock_interactive(vault: Vault, username: str) -> Session:
    """Prompt for the master password with escalating backoff on failure."""
    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        pw = getpass.getpass("Master password: ").encode("utf-8")
        try:
            return unlock(vault, username, pw)
        except NoSuchUserError:
            raise
        except AuthError:
            if attempt == MAX_UNLOCK_ATTEMPTS:
                break
            delay = 0.5 * (2 ** (attempt - 1))  # 0.5s, 1s, 2s, ...
            print(f"wrong master password; retrying in {delay:g}s", file=sys.stderr)
            time.sleep(delay)
    raise AuthError(username)


def _copy_with_clear(text: str, seconds: int = CLIPBOARD_CLEAR_SECONDS) -> None:
    import pyperclip

    pyperclip.copy(text)
    print(f"Copied to clipboard. Clearing in {seconds}s (Ctrl-C to clear now)...")
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pyperclip.copy("")
    print("Clipboard cleared.")


def _format_age(iso_ts: str) -> str:
    try:
        then = datetime.fromisoformat(iso_ts)
    except ValueError:
        return "?"
    days = (datetime.now(timezone.utc) - then).days
    if days <= 0:
        return "today"
    if days == 1:
        return "1 day"
    return f"{days} days"


# --- policy construction from CLI flags --------------------------------------
def _policy_from_args(args: argparse.Namespace) -> Policy:
    policy = generator.preset(getattr(args, "policy", None) or "default")
    classes = dict(policy.classes)

    if getattr(args, "no_symbols", False):
        classes.pop("symbols", None)

    def _adjust(name: str, *, mn: int | None, mx: int | None, missing_default_min: int) -> None:
        if mn is None and mx is None:
            return
        spec = classes.get(name, ClassSpec(min=missing_default_min))
        classes[name] = dataclasses.replace(
            spec,
            min=spec.min if mn is None else mn,
            max=spec.max if mx is None else mx,
        )

    _adjust("digits", mn=args.digits_min, mx=args.digits_max, missing_default_min=1)
    _adjust("symbols", mn=args.symbols_min, mx=args.symbols_max, missing_default_min=1)

    return dataclasses.replace(
        policy,
        length=args.len if args.len is not None else policy.length,
        classes=classes,
        exclude_chars=args.exclude if args.exclude is not None else policy.exclude_chars,
        avoid_ambiguous=args.avoid_ambiguous or policy.avoid_ambiguous,
    )


def _add_policy_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", choices=generator.PRESET_NAMES, help="start from a preset")
    p.add_argument("--len", type=int, help="password length")
    p.add_argument("--no-symbols", action="store_true", help="drop the symbol class")
    p.add_argument("--digits-min", type=int)
    p.add_argument("--digits-max", type=int)
    p.add_argument("--symbols-min", type=int)
    p.add_argument("--symbols-max", type=int)
    p.add_argument("--exclude", help="characters to forbid")
    p.add_argument("--avoid-ambiguous", action="store_true")


# --- commands ----------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    print(f"Vault ready at {vault.path}")
    vault.close()
    return 0


def cmd_user_add(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        pw = getpass.getpass("New master password: ")
        problem = password_strength_problem(pw)
        if problem:
            return _err(problem)
        if getpass.getpass("Confirm master password: ") != pw:
            return _err("passwords did not match")
        create_user(vault, args.name, pw.encode("utf-8"))
        print(f"User {args.name!r} created.")
        return 0
    except UserExistsError:
        return _err(f"user {args.name!r} already exists")
    finally:
        vault.close()


def cmd_add(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        if session.get_credential(args.service) is not None:
            return _err(f"entry {args.service!r} already exists (use rotate/edit)")

        policy: Policy | None
        if args.manual:
            password = getpass.getpass("Password to store: ")
            policy = None
        else:
            policy = _policy_from_args(args)
            password = generator.generate(policy)

        session.add_credential(
            service=args.service,
            username=args.username or "",
            password=password,
            url=args.url or "",
            notes=args.notes or "",
            policy=policy,
        )
        print(f"Stored {args.service!r}.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    except PolicyError as exc:
        return _err(str(exc))
    finally:
        vault.close()


def cmd_get(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        cred = session.get_credential(args.service)
        if cred is None:
            return _err(f"no entry {args.service!r}")
        if args.copy:
            _copy_with_clear(cred.password)
        else:
            print(f"service : {cred.service}")
            if cred.username:
                print(f"username: {cred.username}")
            print(f"password: {cred.password}")
            if cred.url:
                print(f"url     : {cred.url}")
            if cred.notes:
                print(f"notes   : {cred.notes}")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_list(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        rows = vault.list_entries(session.user.id)
        if not rows:
            print("(no entries)")
            return 0
        width = max(len(s) for s, _, _ in rows)
        for service, _created, updated in rows:
            print(f"{service.ljust(width)}   {_format_age(updated)}")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_rotate(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        cred = session.get_credential(args.service)
        if cred is None:
            return _err(f"no entry {args.service!r}")
        policy = cred.policy or generator.preset("default")
        if not _confirm(f"Generate a new password for {args.service!r}?"):
            print("aborted.")
            return 0
        new_password = generator.generate(policy)
        session.update_credential(
            args.service, cred.username, new_password, cred.url, cred.notes, policy
        )
        print(f"Rotated {args.service!r}.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_edit(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        cred = session.get_credential(args.service)
        if cred is None:
            return _err(f"no entry {args.service!r}")
        print("Leave blank to keep the current value.")
        new_username = input(f"username [{cred.username}]: ").strip() or cred.username
        new_url = input(f"url [{cred.url}]: ").strip() or cred.url
        new_notes = input(f"notes [{cred.notes}]: ").strip() or cred.notes
        session.update_credential(
            args.service, new_username, cred.password, new_url, new_notes, cred.policy
        )
        print(f"Updated {args.service!r}.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_rm(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        if vault.get_entry(session.user.id, args.service) is None:
            return _err(f"no entry {args.service!r}")
        if not _confirm(f"Delete {args.service!r}? This cannot be undone."):
            print("aborted.")
            return 0
        vault.delete_entry(session.user.id, args.service)
        print(f"Deleted {args.service!r}.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_gen(args: argparse.Namespace) -> int:
    try:
        print(generator.generate(_policy_from_args(args)))
        return 0
    except PolicyError as exc:
        return _err(str(exc))


def cmd_passwd(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)  # verifies the OLD password
        new_pw = getpass.getpass("New master password: ")
        problem = password_strength_problem(new_pw)
        if problem:
            return _err(problem)
        if getpass.getpass("Confirm new master password: ") != new_pw:
            return _err("passwords did not match")
        session.change_password(new_pw.encode("utf-8"))
        print("Master password changed.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_rekey(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    try:
        username = _resolve_user(args)
        session = _unlock_interactive(vault, username)
        if not _confirm("Rotate the data key and re-encrypt all entries?"):
            print("aborted.")
            return 0
        session.rekey()
        print("Re-keyed. Old vault copies can no longer be decrypted.")
        return 0
    except (AuthError, NoSuchUserError):
        return _err("authentication failed")
    finally:
        vault.close()


def cmd_backup(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    path = vault.path
    vault.close()
    pw = getpass.getpass("Backup passphrase: ")
    if getpass.getpass("Confirm backup passphrase: ") != pw:
        return _err("passphrases did not match")
    backup.export_encrypted(path, args.file, pw.encode("utf-8"))
    print(f"Encrypted backup written to {args.file}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    target = args.vault or default_vault_path()
    pw = getpass.getpass("Backup passphrase: ")
    try:
        backup.import_encrypted(args.file, target, pw.encode("utf-8"))
    except ValueError as exc:
        return _err(str(exc))
    except Exception:
        return _err("wrong passphrase or corrupt backup")
    print(f"Restored vault to {target}")
    return 0


# --- parser ------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pm", description="Local CLI password manager")
    parser.add_argument("--vault", help="vault file path (default: PM_VAULT or app data dir)")
    parser.add_argument("--user", help="username (prompted if omitted)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the vault file").set_defaults(func=cmd_init)

    pu = sub.add_parser("user", help="user management")
    pusub = pu.add_subparsers(dest="user_command", required=True)
    pua = pusub.add_parser("add", help="register a new user")
    pua.add_argument("name")
    pua.set_defaults(func=cmd_user_add)

    pa = sub.add_parser("add", help="add an entry")
    pa.add_argument("service")
    pa.add_argument("--username")
    pa.add_argument("--url")
    pa.add_argument("--notes")
    pa.add_argument("--manual", action="store_true", help="type the password instead of generating")
    _add_policy_flags(pa)
    pa.set_defaults(func=cmd_add)

    pg = sub.add_parser("get", help="show or copy an entry")
    pg.add_argument("service")
    pg.add_argument("--copy", action="store_true", help="copy password to clipboard, auto-clear")
    pg.set_defaults(func=cmd_get)

    sub.add_parser("list", help="list services + ages").set_defaults(func=cmd_list)

    pr = sub.add_parser("rotate", help="generate a new password for an entry")
    pr.add_argument("service")
    pr.set_defaults(func=cmd_rotate)

    pe = sub.add_parser("edit", help="edit username/url/notes")
    pe.add_argument("service")
    pe.set_defaults(func=cmd_edit)

    prm = sub.add_parser("rm", help="delete an entry")
    prm.add_argument("service")
    prm.set_defaults(func=cmd_rm)

    pgen = sub.add_parser("gen", help="generate a one-off password (not stored)")
    _add_policy_flags(pgen)
    pgen.set_defaults(func=cmd_gen)

    sub.add_parser("passwd", help="change master password").set_defaults(func=cmd_passwd)
    sub.add_parser("rekey", help="rotate data key, re-encrypt all entries").set_defaults(func=cmd_rekey)

    pb = sub.add_parser("backup", help="write an encrypted backup")
    pb.add_argument("file")
    pb.set_defaults(func=cmd_backup)

    prs = sub.add_parser("restore", help="restore from an encrypted backup")
    prs.add_argument("file")
    prs.set_defaults(func=cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

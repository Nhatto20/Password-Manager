# pm — local CLI password manager

A small, offline, multi-user password manager for your terminal. It generates
strong site-valid passwords, stores them encrypted, and shows them again only
when you supply your master password. No cloud, no network — ever.

> **Where to run it:** run `pm` on a **personal device you trust**. If you need
> passwords for a managed/work machine, look them up here and type them over —
> keep your master password and vault off any machine you don't control. See the
> threat model in [docs](docs/) and the design spec.

## Install

Requires Python 3.11+. Recommended via [pipx](https://pipx.pypa.io) so `pm` is on
your PATH everywhere without activating a virtualenv:

```powershell
python -m pip install --user pipx
python -m pipx ensurepath          # restart your terminal afterwards
pipx install --editable C:\Users\japan\utils\password_manager
```

Or in a plain virtualenv:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Quick start

```console
pm init                              # create the vault
pm user add alice                    # set a master password (asked twice)
pm add github --username alice@example.com --policy compat
pm get github --copy                 # copy password; clipboard auto-clears in 15s
pm list                              # services + ages, never passwords
pm rotate github                     # new password, same site rules
```

## Commands

| Command | What it does |
|---------|--------------|
| `pm init` | Create the vault file |
| `pm user add <name>` | Register a user (strength-checked master password) |
| `pm add <service>` | Generate (or `--manual`) and store a password |
| `pm get <service> [--copy]` | Show, or copy-to-clipboard with auto-clear |
| `pm list` | Service names + age only |
| `pm rotate <service>` | New password using the entry's stored policy |
| `pm edit <service>` | Change username / url / notes |
| `pm rm <service>` | Delete (asks to confirm) |
| `pm gen` | One-off password, not stored |
| `pm passwd` | Change master password (entries untouched) |
| `pm rekey` | Rotate data key + re-encrypt all entries |
| `pm backup <file>` / `pm restore <file>` | Encrypted whole-vault backup |

### Password policy flags (`add`, `gen`)

```
--policy {default,compat,alphanumeric,pin}   start from a preset
--len N            --no-symbols
--digits-min N     --digits-max N
--symbols-min N    --symbols-max N
--exclude CHARS    --avoid-ambiguous
```

Example — a site that needs 16 chars, at least 2 digits, at most 4 symbols from
`!@#$`:

```console
pm gen --len 16 --digits-min 2 --symbols-min 1 --symbols-max 4 --exclude '%^&*-_=+'
```

## Security in one paragraph

Your master password is run through **Argon2id** to derive a key (KEK) that
**wraps** a random data key (DEK); the DEK encrypts each field with
**AES-256-GCM** bound to its slot via AAD. The master password and keys are never
stored — only a salt, the wrapped DEK, and ciphertext. Each user is isolated by
their own key. Full explanation in **[docs/how-it-works.md](docs/how-it-works.md)**
and **[docs/feature-tech.md](docs/feature-tech.md)**.

There is **no master-password recovery** — forget it and that vault is gone. Use
`pm backup` as your safety net.

## Tests

```powershell
pip install -e ".[dev]"
pytest                              # all 96 tests
pytest -m unit                      # fast, pure-module tests only
pytest -m integration               # storage / session / CLI flows
pytest --cov=pm --cov-report=term-missing   # coverage (~93%)
```

Layout:

```
tests/
  conftest.py            # shared fixtures (fast KDF, vault, session factory)
  unit/                  # pure modules, no DB — incl. hypothesis property tests
    test_crypto.py  test_generator.py  test_models.py
  integration/           # real SQLite vault end-to-end
    test_vault.py  test_session_flows.py  test_backup.py  test_cli.py
```

The generator is checked with **property-based tests** (hypothesis): for any
feasible policy, the output always has the right length, uses only allowed
characters, and respects every per-class min/max. Multi-user isolation, AAD
tamper-resistance, master-password change, and DEK rotation each have dedicated
integration tests.

## Vault location

Defaults to `%APPDATA%\pm\vault.db` (Windows). Override with `--vault <path>` or
the `PM_VAULT` environment variable — handy for keeping the vault on personal
storage.

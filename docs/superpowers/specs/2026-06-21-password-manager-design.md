# Design Spec: `pm` — Multi-User Password Manager (CLI)

**Date:** 2026-06-21
**Status:** Draft for review

---

## 1. Purpose

A local, offline command-line password manager that:

- **Generates** strong passwords on demand, with per-site rules.
- **Stores** them encrypted, viewable later only with the owner's master password.
- Supports **multiple users**, each cryptographically isolated from the others.
- Makes **rotation** painless (services force changes every 3–6 months) without the user
  having to remember any per-service state — the vault is the memory.

### Threat model (decided during design)

The user runs this on a **personal laptop they trust**. The company laptop is treated as
**untrusted** and is deliberately kept out of scope: the master password and vault never
touch it. The tool defends against:

- Passive exposure of stored data (disk backups, file scans) → defeated by encryption at rest.
- One user reading another user's secrets → defeated by per-user keys.
- Tampering with the vault file (swapping ciphertexts between entries/users) → defeated by AAD binding.

**Out of scope (cannot be defended by software on the device):** an attacker with active
code execution / keylogging on the machine where the master password is typed. The mitigation
for that is operational (run only on the trusted personal laptop), not cryptographic.

**No recovery:** zero-knowledge by design. A forgotten master password means that user's
vault is unrecoverable. The `backup` command is the safety net.

---

## 2. Cryptographic design

### Layered keys (KEK / DEK)

```
random DEK (32 bytes) ──encrypts──▶ all of a user's entry fields
master password + salt ──Argon2id──▶ KEK ──encrypts──▶ DEK

Stored on disk:   salt,  wrapped_DEK (= DEK encrypted under KEK),  encrypted entries
NEVER stored:     master password,  KEK,  DEK (in plaintext)
```

- **DEK (Data Encryption Key):** random 32 bytes, generated once per user, encrypts the entries.
- **KEK (Key Encryption Key):** derived from the master password via **Argon2id** (salted).
- **Wrapping:** `wrapped_DEK = Encrypt(DEK, KEK)`. On disk we keep the wrapped DEK, never the bare DEK.

### Why this shape

- **Change master password** = re-derive KEK from the new password and **re-wrap only the DEK**.
  Entries are untouched → instant, and every stored password remains accessible.
- **Raise Argon2 cost later** = same: re-wrap the DEK, no entry re-encryption.
- **`rekey`** (optional, for suspected compromise) = generate a *new* DEK and re-encrypt all
  entries, invalidating any old exfiltrated vault copy.

### Primitives

| Concern | Choice | Notes |
|---|---|---|
| KDF | **Argon2id** (`argon2-cffi`) | Memory-hard; params stored per user so they can be raised later |
| Symmetric encryption | **AES-256-GCM** (`cryptography`) | Authenticated; detects tampering and wrong key |
| Nonce | **Fresh random 12 bytes per encryption** | Stored with ciphertext. Never reused with the same key |
| AAD (anti-tamper) | `user_id ‖ service ‖ field_name` | Binds each ciphertext to its slot; blocks cut-and-paste in the DB |
| CSPRNG | `secrets` / `os.urandom` | For DEK, salt, nonce, generated passwords |
| Wrong-password handling | GCM auth-tag failure + **escalating backoff** | Slows offline brute force |

---

## 3. Password generator

### Policy model — per-class min/max counts

Stored as JSON alongside each entry, so rotation reproduces a site-valid password.

```json
{
  "length": 16,
  "classes": {
    "lowercase": { "min": 1, "max": null, "set": "a-z" },
    "uppercase": { "min": 1, "max": null },
    "digits":    { "min": 2, "max": null },
    "symbols":   { "min": 1, "max": 4, "set": "!@#$%" }
  },
  "exclude_chars": "",
  "avoid_ambiguous": false
}
```

Expresses the full range of real site rules:
- "at least N" → `min: N`; "exactly N" → `min:N max:N`; "at most N" → `min:0 max:N`;
  "between M and N" → `min:M max:N`; class forbidden → omit / `max:0`; custom allowed set → per-class `set`.

Classes are **disjoint** (lower / upper / digit / symbol), so counting a generated char is unambiguous.

### Generation algorithm — guarantee-then-fill

```
1. For each class: pick exactly `min` chars from that class      → guarantees all minimums
2. remaining = length - sum(all mins)
3. Fill `remaining` from union of classes not yet at `max`
   (when a class hits its max, drop it from the eligible pool)   → enforces all maximums
4. CSPRNG-shuffle the whole list                                 → guaranteed chars aren't positional
5. Validate against the policy; regenerate on the rare miss
```

Uses `secrets`, never `random`. Pure function `policy → password`, fully unit-testable.

### Feasibility validation (up front, friendly errors)

- `sum(mins) ≤ length`
- `length ≤ sum(maxes)` (unbounded max = length)
- every class with `min > 0` has a non-empty set after `exclude_chars`

### Presets (convenience layer)

Pre-filled versions of the model, overridable per entry via flags:

| Preset | Shape |
|---|---|
| `default` | each class `min:1`, length 20 |
| `compat` | lower/upper/digit `min:1`, symbols `min:1 max:4 set:!@#$%`, length 16 |
| `alphanumeric` | no symbols |
| `pin` | digits `min:4 max:6`, no other classes |

### Out of scope (YAGNI)

Positional rules ("can't start with a symbol"), "no 3 repeated/sequential", dictionary checks.
Added later only as post-generation rejection checks if a real site demands them.

---

## 4. Data model (SQLite)

```
users(
  id INTEGER PK,
  username TEXT UNIQUE,
  salt BLOB,
  kdf_params TEXT,          -- Argon2id memory/time/parallelism (JSON)
  wrapped_dek BLOB,         -- DEK encrypted under KEK (nonce+ct+tag)
  created_at TEXT
)

entries(
  id INTEGER PK,
  user_id INTEGER FK,
  service TEXT,
  enc_username BLOB,        -- all enc_* are GCM blobs: nonce+ciphertext+tag
  enc_password BLOB,
  enc_url BLOB,
  enc_notes BLOB,
  gen_policy TEXT,          -- JSON policy used to generate (for valid rotation)
  created_at TEXT,
  updated_at TEXT,
  UNIQUE(user_id, service)
)
```

No plaintext secret is ever stored. The master password is never stored (verifier is implicit:
if the DEK unwrap's auth tag validates, the password was correct).

---

## 5. Commands

| Command | Behavior |
|---|---|
| `pm init` | Create the vault file if missing |
| `pm user add <name>` | Register user; prompt master pw twice; **strength-check**; generate DEK; store salt + wrapped_DEK |
| `pm add <service> [--policy P] [--len N --digits-min 2 ...]` | Generate (or accept manual) password; store username/url/notes encrypted |
| `pm get <service> [--copy]` | Decrypt; `--copy` → clipboard + **auto-clear ~15s** (blocks, no terminal print); else print |
| `pm list` | Service names + **age** only — never passwords |
| `pm rotate <service>` | Generate a new password using the entry's stored policy; **confirm** overwrite |
| `pm edit <service>` | Update username / url / notes / policy |
| `pm rm <service>` | **Confirm** before delete |
| `pm gen [--len --symbols ...]` | One-off generator, no storage |
| `pm passwd` | Change master password: re-wrap DEK (entries untouched) |
| `pm rekey` | (Optional) rotate DEK + re-encrypt all entries — compromise recovery |
| `pm backup <file>` | Write an encrypted backup copy |
| `pm restore <file>` | Restore from an encrypted backup |

- Master password is always a hidden `getpass` prompt — **never** a CLI argument.
- All multi-row writes (`passwd`, `rekey`, `restore`) run in a single transaction (crash-safe).

---

## 6. Module structure

| Module | Responsibility | Pure? |
|---|---|---|
| `crypto.py` | Argon2id KDF, AES-GCM encrypt/decrypt, DEK gen, wrap/unwrap | ✅ no I/O |
| `generator.py` | Policy model + guarantee-then-fill generation | ✅ pure |
| `models.py` | Dataclasses: `User`, `Entry`, `Policy` | ✅ |
| `vault.py` | SQLite schema + CRUD + transactions | I/O |
| `session.py` | Prompt master pw → KEK → unwrap DEK; hold DEK for one command | I/O |
| `cli.py` | Arg parsing, dispatch, getpass, confirmations, clipboard | I/O |

The two pure modules hold all the tricky logic and are unit-testable without a database.

### Vault location

Default `%APPDATA%\pm\vault.db` on Windows; overridable with `--vault <path>` or `PM_VAULT` env var
(so it can point at personal storage).

---

## 7. Packaging / usage

- `pyproject.toml` declares a console-script entry point: `pm = "pm.cli:main"`.
- Installed via **pipx** (`pipx install --editable .`) so `pm` is on the global PATH with no venv activation.
- Dependencies: `cryptography`, `argon2-cffi`, `pyperclip`. Python 3.11+. SQLite is stdlib.
- The tool makes **zero network calls** — fully offline.

---

## 8. Educational documentation (deliverable)

Alongside the code, a `docs/` set written for a reader who wants to understand *how and why*:

- **`docs/how-it-works.md`** — the KEK/DEK flow, the unlock path, setup vs use, with diagrams.
- **`docs/feature-tech.md`** — per feature, the technology behind it and why it was chosen:
  master password → Argon2id → KEK (why Argon2id, not a plain hash); AES-GCM + nonce + AAD;
  guarantee-then-fill generator with `secrets`; clipboard auto-clear and the short-lived-process
  tradeoff; multi-user isolation via per-user DEK; rotation = overwrite stored entry.

---

## 9. Testing

- `crypto`: encrypt/decrypt round-trip; wrong-key rejection; wrap/unwrap; AAD mismatch fails.
- `generator`: every min/max/exclude honored; infeasible policy raises; only uses allowed pool.
- `vault`: CRUD; `UNIQUE(user_id, service)` enforced.
- **Isolation:** user A cannot decrypt user B's entries.
- `passwd`: re-wrap leaves entries readable with the new password, not the old.
- `rekey`: DEK actually changes; entries still readable.
- `backup`/`restore`: round-trip.

---

## 10. Build order

1. `crypto.py` (+ tests) — foundation.
2. `generator.py` (+ tests).
3. `models.py`, `vault.py` (+ tests).
4. `session.py` — KEK/DEK unlock flow.
5. `cli.py` — commands.
6. Cross-cutting: clipboard auto-clear, backoff, confirmations.
7. Educational docs.

Estimated ~600–1000 lines across modules + tests.

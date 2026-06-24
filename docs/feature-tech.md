# Feature → technology → why

For each feature, the technology that powers it and the reasoning behind the
choice. Companion to [how-it-works.md](how-it-works.md).

---

## Deriving a key from your master password
**Technology:** Argon2id (`argon2-cffi`), with a random 16-byte salt, default
cost 64 MiB memory / 3 passes / parallelism 4. Implemented in
`crypto.derive_kek`.

**Why:** A master password is low-entropy compared to a random key, so an
attacker who copies the vault will try to brute-force it offline. A plain hash
(SHA-256) is billions/sec on a GPU. Argon2id is **memory-hard** — it forces each
guess to allocate 64 MiB, which collapses the parallelism that makes GPU/ASIC
attacks cheap. It won the Password Hashing Competition and is the current
recommended default. The cost parameters are stored *per user*, so we can raise
them later (on a faster machine) without breaking existing vaults.

## Encrypting passwords and entry fields
**Technology:** AES-256-GCM (`cryptography`), a fresh random 12-byte nonce per
encryption, stored as `nonce ‖ ciphertext ‖ tag`. In `crypto.encrypt/decrypt`.

**Why:** GCM is *authenticated* encryption: it both hides the data and detects
any modification (the tag won't verify). That gives us tamper detection for free
and makes wrong-password detection clean — a wrong key simply fails the tag.
The non-negotiable rule with GCM is **never reuse a nonce with the same key**, so
every encryption draws a fresh random nonce from the OS CSPRNG.

## Tamper-proofing the database layout
**Technology:** GCM Additional Authenticated Data (AAD). Each field is bound to
`user_id : service : field` (`crypto.field_aad`); the wrapped DEK is bound to the
username (`crypto.dek_aad`).

**Why:** Encryption alone doesn't stop someone with write access to the DB file
from *moving* ciphertext around — e.g. copying your bank password blob over your
throwaway-site entry. AAD is authenticated but not encrypted: decryption only
succeeds if the same context is supplied. Move a blob to a different
slot/user/field and the tag fails. Cheap, and closes a real cut-and-paste hole.

## Changing the master password without re-encrypting everything
**Technology:** The KEK/DEK split (`session.change_password`).

**Why:** Because entries are encrypted with the DEK — not directly with a
password-derived key — changing your password only needs to re-wrap the DEK (one
tiny operation). If we'd encrypted entries directly from the password, every
change would re-encrypt the whole vault. The indirection also lets us raise
Argon2 cost later the same cheap way.

## Compromise recovery
**Technology:** DEK rotation in a single SQLite transaction (`session.rekey` +
`vault.rekey`).

**Why:** Re-wrapping (above) protects the *current* file but not copies an
attacker already took — the DEK is unchanged, so an old copy + old password still
decrypts. `rekey` generates a brand-new DEK and re-encrypts every entry under it,
so old copies become useless. Entry re-encryption and the new wrapped-DEK are
written in one transaction, so a crash can't leave the two out of sync.

## Generating site-valid passwords
**Technology:** `secrets` (CSPRNG) + a count-based policy + a "guarantee-then-fill"
algorithm (`generator.generate`).

**Why:** Sites disagree on rules (min length, "must contain 2 digits", forbidden
symbols). The policy models each character class with `min`/`max` counts. The
algorithm places every required minimum first, fills the rest from classes not
yet at their max, then CSPRNG-shuffles — so the result satisfies the rules *by
construction* instead of by slow trial-and-error. `secrets` (not `random`) is
used because `random` is a predictable PRNG unsuitable for secrets. The policy is
stored with the entry, so `rotate` reproduces a still-valid password.

## Rotation without remembering anything
**Technology:** The stored vault + `gen_policy` per entry.

**Why:** Your original instinct (vary a "date" input) only existed to cope with
having no storage. Here the vault *is* the memory: `pm rotate` generates a new
random password using the entry's stored policy and overwrites it. You memorize
nothing — not a date, not a counter, not the password.

## Showing a password safely
**Technology:** `pyperclip` clipboard copy with a timed auto-clear
(`cli._copy_with_clear`, default 15s).

**Why:** Printing a password to the terminal leaves it in scrollback and history.
`--copy` puts it on the clipboard instead and wipes it after 15s. **Tradeoff worth
knowing:** a CLI is short-lived, so to clear the clipboard 15s *later* the process
must stay alive that long — `--copy` therefore blocks for 15s, then clears and
exits (Ctrl-C clears immediately). This is the simple, dependency-light choice
versus spawning a detached background clearer.

## Resisting password guessing
**Technology:** GCM auth-tag failure for detection + escalating sleep
(`cli._unlock_interactive`, 0.5s → 1s → 2s) + the Argon2 cost itself.

**Why:** Two layers. Interactively, the backoff slows someone typing guesses at
your terminal. The *real* defense against an offline attack on a stolen vault is
Argon2's per-guess cost — the backoff is a UX deterrent, not the primary control.

## Multiple users, cryptographically separated
**Technology:** Per-user salt + per-user DEK (`session`, `vault.users` table).

**Why:** No key is shared between users, so isolation is enforced by cryptography,
not by access-control checks that could be bypassed. User A's password can't
derive a key that unwraps user B's DEK.

## Encrypted backups
**Technology:** Whole-file encryption under a separate passphrase
(`backup.export_encrypted`): `Argon2id(passphrase) → key`, `AES-GCM(file_bytes)`.

**Why:** The DB encrypts passwords but leaves *metadata* in the clear — service
names, the local usernames, timestamps. Encrypting the entire file under a backup
passphrase means a backup leaks nothing, not even which services you use.

## Storage
**Technology:** SQLite (stdlib `sqlite3`), `UNIQUE(user_id, service)`, foreign
keys on.

**Why:** Zero-dependency, single-file, transactional, and ubiquitous. Multi-row
operations (`rekey`, restore) get atomicity for free, which matters for not
corrupting the vault mid-operation.

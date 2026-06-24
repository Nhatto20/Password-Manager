# How `pm` works

This explains the moving parts in plain language. For the *why* behind each
technology choice, see [feature-tech.md](feature-tech.md).

## The big idea: two layers of keys

Your passwords are encrypted with a random key called the **DEK** (Data
Encryption Key). The DEK itself is encrypted ("wrapped") with a second key, the
**KEK** (Key Encryption Key), which is derived from your **master password**.

```
master password ──Argon2id(+salt)──▶  KEK  ──AES-GCM──▶  wrapped DEK
                                                              │
                                          (unwrap with KEK)   ▼
                                                             DEK  ──AES-GCM──▶  your entries
```

What lives on disk: the **salt**, the **wrapped DEK**, and the **encrypted
entries**. What never touches disk: your master password, the KEK, and the bare
DEK. They exist only in memory, only while a command runs.

### The safe-and-lockbox analogy

- Your passwords are documents in a **safe**.
- The **DEK** is the key to the safe.
- You keep that key inside a **lockbox**, never lying around.
- The **KEK** (made from your master password) opens the lockbox.
- On disk: the safe (encrypted entries) + the locked lockbox (wrapped DEK) + the salt.

## What happens when you...

### ...create a user (`pm user add`)
1. Generate a random **salt** and a random **DEK**.
2. Derive the **KEK** from your master password + salt (Argon2id).
3. Wrap the DEK with the KEK.
4. Store `username, salt, kdf_params, wrapped_dek`. The master password is *not* stored.

### ...unlock (every command that reads/writes)
1. You type your master password.
2. Re-derive the KEK from the password + stored salt.
3. Decrypt (unwrap) the DEK. If the password is wrong, the authentication tag
   fails and you get "authentication failed" — there is no stored password to
   compare against; correctness is proven by decryption succeeding.

### ...store an entry (`pm add`)
Each field (username, password, url, notes) is encrypted separately with the
DEK and a context tag (AAD) of `user_id : service : field`, then saved.

### ...change your master password (`pm passwd`)
Only the **lockbox** changes: derive a new KEK from the new password + a fresh
salt, re-wrap the *same* DEK. Entries are untouched, so every stored password
stays accessible. The old master password stops working on the current vault.

### ...rotate the data key (`pm rekey`)
The **safe key** changes: generate a new DEK, decrypt every entry with the old
DEK and re-encrypt with the new one, then re-wrap the new DEK — all in one
database transaction. Use this if you think your old master password leaked: any
old copy of the vault becomes undecryptable even to someone who knows it.

## Multi-user isolation

Each user has their own salt and their own DEK. One user's master password can
only ever unwrap *their* DEK, which can only decrypt *their* entries. There is no
shared key, so user A literally cannot decrypt user B's data — even though both
live in the same database file.

## Module map

| File | Role |
|------|------|
| `pm/crypto.py` | KDF, AES-GCM, DEK wrap/unwrap. Pure functions, no I/O. |
| `pm/generator.py` | Password policy + generation. Pure functions. |
| `pm/models.py` | Plain data structures (records and the decrypted view). |
| `pm/vault.py` | SQLite storage. Stores opaque encrypted blobs; never sees plaintext. |
| `pm/session.py` | The unlock flow; ties crypto + storage together per user. |
| `pm/backup.py` | Whole-file encrypted backup / restore. |
| `pm/cli.py` | Argument parsing, prompts, clipboard, dispatch. |

The two **pure** modules (`crypto`, `generator`) hold the security-critical
logic and are tested in isolation without any database.

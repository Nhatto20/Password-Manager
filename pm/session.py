"""Unlock flow and per-user operations.

A Session represents one unlocked user for the lifetime of a single command:
it holds the DEK (recovered by unwrapping with the KEK derived from the master
password) and uses it to encrypt/decrypt entry fields. It binds together the
pure crypto layer and the dumb storage layer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pm import crypto
from pm.generator import Policy, policy_from_dict, policy_to_dict
from pm.models import Credential, EntryRecord, UserRecord
from pm.vault import Vault


class AuthError(Exception):
    """Wrong master password (or tampered/corrupt user record)."""


class UserExistsError(Exception):
    pass


class NoSuchUserError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_user(vault: Vault, username: str, master_password: bytes) -> None:
    """Register a new user: fresh salt + DEK, wrap DEK under the KEK."""
    if vault.get_user(username) is not None:
        raise UserExistsError(username)
    salt = crypto.generate_salt()
    params = dict(crypto.DEFAULT_KDF_PARAMS)
    dek = crypto.generate_dek()
    kek = crypto.derive_kek(master_password, salt, params)
    wrapped = crypto.wrap_dek(kek, dek, crypto.dek_aad(username))
    vault.add_user(username, salt, params, wrapped, _now())


def unlock(vault: Vault, username: str, master_password: bytes) -> "Session":
    """Derive the KEK and unwrap the DEK. Raises AuthError on a bad password."""
    user = vault.get_user(username)
    if user is None:
        raise NoSuchUserError(username)
    kek = crypto.derive_kek(master_password, user.salt, user.kdf_params)
    try:
        dek = crypto.unwrap_dek(kek, user.wrapped_dek, crypto.dek_aad(username))
    except crypto.DecryptionError as exc:
        raise AuthError(username) from exc
    return Session(vault, user, kek, dek)


class Session:
    def __init__(self, vault: Vault, user: UserRecord, kek: bytes, dek: bytes):
        self.vault = vault
        self.user = user
        self._kek = kek
        self._dek = dek

    # --- field crypto --------------------------------------------------------
    def _enc(self, service: str, field: str, value: str) -> bytes:
        aad = crypto.field_aad(self.user.id, service, field)
        return crypto.encrypt(self._dek, value.encode("utf-8"), aad)

    def _dec(self, service: str, field: str, blob: bytes) -> str:
        aad = crypto.field_aad(self.user.id, service, field)
        return crypto.decrypt(self._dek, blob, aad).decode("utf-8")

    # --- entries -------------------------------------------------------------
    def add_credential(
        self,
        service: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        policy: Policy | None,
    ) -> None:
        now = _now()
        rec = EntryRecord(
            id=0,
            user_id=self.user.id,
            service=service,
            enc_username=self._enc(service, "username", username),
            enc_password=self._enc(service, "password", password),
            enc_url=self._enc(service, "url", url),
            enc_notes=self._enc(service, "notes", notes),
            gen_policy=json.dumps(policy_to_dict(policy)) if policy else "",
            created_at=now,
            updated_at=now,
        )
        self.vault.add_entry(rec)

    def get_credential(self, service: str) -> Credential | None:
        rec = self.vault.get_entry(self.user.id, service)
        if rec is None:
            return None
        policy = policy_from_dict(json.loads(rec.gen_policy)) if rec.gen_policy else None
        return Credential(
            service=rec.service,
            username=self._dec(service, "username", rec.enc_username),
            password=self._dec(service, "password", rec.enc_password),
            url=self._dec(service, "url", rec.enc_url),
            notes=self._dec(service, "notes", rec.enc_notes),
            policy=policy,
            created_at=rec.created_at,
            updated_at=rec.updated_at,
        )

    def update_credential(
        self,
        service: str,
        username: str,
        password: str,
        url: str,
        notes: str,
        policy: Policy | None,
    ) -> bool:
        rec = self.vault.get_entry(self.user.id, service)
        if rec is None:
            return False
        rec.enc_username = self._enc(service, "username", username)
        rec.enc_password = self._enc(service, "password", password)
        rec.enc_url = self._enc(service, "url", url)
        rec.enc_notes = self._enc(service, "notes", notes)
        rec.gen_policy = json.dumps(policy_to_dict(policy)) if policy else ""
        rec.updated_at = _now()
        self.vault.update_entry(rec)
        return True

    # --- master password / DEK lifecycle ------------------------------------
    def change_password(self, new_master_password: bytes) -> None:
        """Re-wrap the SAME DEK under a key from the new password + fresh salt.

        Entries are untouched, so every stored password stays accessible.
        """
        new_salt = crypto.generate_salt()
        new_params = dict(crypto.DEFAULT_KDF_PARAMS)
        new_kek = crypto.derive_kek(new_master_password, new_salt, new_params)
        wrapped = crypto.wrap_dek(new_kek, self._dek, crypto.dek_aad(self.user.username))
        self.vault.update_user_wrapping(self.user.id, new_salt, new_params, wrapped)
        self.user.salt, self.user.kdf_params, self.user.wrapped_dek = (
            new_salt,
            new_params,
            wrapped,
        )
        self._kek = new_kek

    def rekey(self) -> None:
        """Generate a NEW DEK and re-encrypt every entry under it.

        For suspected-compromise recovery: invalidates any old vault copy held
        by someone who knows the old master password.
        """
        new_dek = crypto.generate_dek()
        records = self.vault.all_entries(self.user.id)
        for rec in records:
            # decrypt with the current DEK, re-encrypt with the new one
            rec.enc_username = self._reencrypt(new_dek, rec, "username", rec.enc_username)
            rec.enc_password = self._reencrypt(new_dek, rec, "password", rec.enc_password)
            rec.enc_url = self._reencrypt(new_dek, rec, "url", rec.enc_url)
            rec.enc_notes = self._reencrypt(new_dek, rec, "notes", rec.enc_notes)
        wrapped = crypto.wrap_dek(self._kek, new_dek, crypto.dek_aad(self.user.username))
        self.vault.rekey(self.user.id, records, wrapped)
        self._dek = new_dek
        self.user.wrapped_dek = wrapped

    def _reencrypt(
        self, new_dek: bytes, rec: EntryRecord, field: str, blob: bytes
    ) -> bytes:
        aad = crypto.field_aad(self.user.id, rec.service, field)
        plain = crypto.decrypt(self._dek, blob, aad)
        return crypto.encrypt(new_dek, plain, aad)

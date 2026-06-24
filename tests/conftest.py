"""Shared fixtures for the whole suite."""

import pytest

from pm import crypto
from pm.session import create_user, unlock
from pm.vault import Vault


@pytest.fixture(autouse=True)
def fast_kdf():
    """Use cheap Argon2 params in tests so they run quickly.

    Production uses crypto.DEFAULT_KDF_PARAMS unchanged — security is unaffected.
    """
    original = dict(crypto.DEFAULT_KDF_PARAMS)
    crypto.DEFAULT_KDF_PARAMS.update(time_cost=1, memory_cost=8, parallelism=1)
    yield
    crypto.DEFAULT_KDF_PARAMS.clear()
    crypto.DEFAULT_KDF_PARAMS.update(original)


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.db"


@pytest.fixture
def vault(vault_path):
    v = Vault(vault_path)
    yield v
    v.close()


@pytest.fixture
def session_factory(vault):
    """Create-and-unlock a user; returns a function (name, pw) -> Session."""

    def _make(name="alice", pw=b"correct horse battery staple"):
        create_user(vault, name, pw)
        return unlock(vault, name, pw)

    return _make

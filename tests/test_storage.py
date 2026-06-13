"""Vault persistence, round-trip, and permissions."""

from __future__ import annotations

import os
import stat

import pytest

from bnet_auth_tool.crypto import EncryptionManager
from bnet_auth_tool.errors import DecryptionError
from bnet_auth_tool.storage import Vault

ENTRY = {
    "serial": "US-1234",
    "restoreCode": "ABCD-EFGH",
    "deviceSecret": "deadbeef",
    "base32Secret": "32W353Y",
    "totpUrl": "otpauth://totp/Battle.net:US-1234?secret=32W353Y",
}


def _vault(tmp_path, passphrase, settings):
    mgr = EncryptionManager(passphrase, settings.crypto)
    return Vault(mgr, tmp_path / "vault.json")


def test_add_save_load_round_trip(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    assert v.add(ENTRY) is True
    v.save()

    reopened = _vault(tmp_path, "pw", settings).load()
    assert reopened.serials() == ["US-1234"]
    assert reopened.get("US-1234")["deviceSecret"] == "deadbeef"
    assert "addedAt" in reopened.get("US-1234")


def test_add_no_overwrite(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    v.add(ENTRY)
    assert v.add(ENTRY) is False
    assert v.add({**ENTRY, "deviceSecret": "new"}, overwrite=True) is True
    assert v.get("US-1234")["deviceSecret"] == "new"


def test_remove(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    v.add(ENTRY)
    assert v.remove("US-1234") is True
    assert v.remove("US-1234") is False
    assert len(v) == 0


def test_wrong_passphrase_fails_to_load(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    v.add(ENTRY)
    v.save()
    with pytest.raises(DecryptionError):
        _vault(tmp_path, "wrong", settings).load()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_vault_file_is_owner_only(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    v.add(ENTRY)
    v.save()
    mode = stat.S_IMODE(os.stat(v.path).st_mode)
    assert mode == 0o600


def test_empty_vault_loads(tmp_path, settings):
    v = _vault(tmp_path, "pw", settings).load()
    assert len(v) == 0
    assert v.serials() == []

"""Legacy file discovery and migration into the vault."""

from __future__ import annotations

import json

from bnet_auth_tool.crypto import EncryptionManager
from bnet_auth_tool.migrate import (
    discover_legacy_files,
    migrate_files,
    normalise_entry,
)
from bnet_auth_tool.storage import Vault

PLAIN = {
    "serial": "US-1111",
    "restoreCode": "AAAA-BBBB",
    "deviceSecret": "deadbeef",
    "base32Secret": "32W353Y",
    "totpUrl": "otpauth://totp/Battle.net:US-1111?secret=32W353Y",
    "timestamp": "2024-01-01T00:00:00+00:00",
}


def _vault(tmp_path, settings, passphrase="pw"):
    return Vault(EncryptionManager(passphrase, settings.crypto), tmp_path / "vault.json").load()


def test_discover_matches_expected_names(tmp_path):
    (tmp_path / "battlenet_authenticator_US-1.json").write_text("{}")
    (tmp_path / "reconstructed_US-2.json").write_text("{}")
    (tmp_path / "unrelated.json").write_text("{}")
    names = {p.name for p in discover_legacy_files(tmp_path)}
    assert names == {"battlenet_authenticator_US-1.json", "reconstructed_US-2.json"}


def test_normalise_derives_missing_fields(settings):
    entry = normalise_entry({"serial": "US-9", "deviceSecret": "deadbeef"}, settings)
    assert entry["base32Secret"] == "32W353Y"
    assert entry["totpUrl"].startswith("otpauth://totp/Battle.net:US-9")


def test_migrate_plaintext_file(tmp_path, settings):
    f = tmp_path / "battlenet_authenticator_US-1111.json"
    f.write_text(json.dumps(PLAIN))
    vault = _vault(tmp_path, settings)

    outcomes = migrate_files([f], vault, settings, lambda p: None)
    vault.save()

    assert outcomes[0].status == "imported"
    assert vault.get("US-1111")["deviceSecret"] == "deadbeef"
    assert vault.get("US-1111")["addedAt"] == PLAIN["timestamp"]


def test_migrate_encrypted_file(tmp_path, settings):
    f = tmp_path / "battlenet_authenticator_US-2222.json"
    blob = EncryptionManager("filepw", settings.crypto).encrypt({**PLAIN, "serial": "US-2222"})
    f.write_bytes(blob)
    vault = _vault(tmp_path, settings)

    outcomes = migrate_files([f], vault, settings, lambda p: "filepw")
    vault.save()

    assert outcomes[0].status == "imported"
    assert vault.get("US-2222") is not None


def test_migrate_skips_without_passphrase(tmp_path, settings):
    f = tmp_path / "battlenet_authenticator_US-3333.json"
    f.write_bytes(EncryptionManager("x", settings.crypto).encrypt({**PLAIN, "serial": "US-3333"}))
    vault = _vault(tmp_path, settings)

    outcomes = migrate_files([f], vault, settings, lambda p: None)
    assert outcomes[0].status == "skipped"
    assert len(vault) == 0


def test_migrate_no_overwrite_existing(tmp_path, settings):
    f = tmp_path / "battlenet_authenticator_US-1111.json"
    f.write_text(json.dumps(PLAIN))
    vault = _vault(tmp_path, settings)
    vault.add({"serial": "US-1111", "deviceSecret": "old"})

    outcomes = migrate_files([f], vault, settings, lambda p: None)
    assert outcomes[0].status == "skipped"
    assert vault.get("US-1111")["deviceSecret"] == "old"

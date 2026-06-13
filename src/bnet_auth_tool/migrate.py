"""Conversion tool: import legacy loose JSON backups into the vault.

Older versions of this tool wrote one ``battlenet_authenticator_<serial>.json``
per authenticator into the working directory — either plaintext or encrypted
with PBKDF2 (100k legacy or 600k). This module discovers those files, decrypts
them if needed, normalises them, and imports them into the encrypted vault.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .config import Settings
from .crypto import EncryptionManager, looks_encrypted
from .errors import DecryptionError
from .storage import Vault
from .totp import build_totp_url, hex_secret_to_base32

# Callback that, given a file path, returns the passphrase for it (or None to
# skip). Lets the CLI prompt interactively without coupling migrate to I/O.
PassphraseProvider = Callable[[Path], Optional[str]]

_LEGACY_GLOBS = ("battlenet_authenticator_*.json", "reconstructed_*.json")


@dataclass
class MigrationOutcome:
    path: Path
    serial: str | None = None
    status: str = "imported"  # imported | skipped | replaced | error
    detail: str = ""


def discover_legacy_files(directory: Path) -> list[Path]:
    """Find loose authenticator JSON files in ``directory`` (non-recursive)."""
    directory = Path(directory)
    found: set[Path] = set()
    for pattern in _LEGACY_GLOBS:
        found.update(p for p in directory.glob(pattern) if p.is_file())
    return sorted(found)


def normalise_entry(data: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Coerce a raw legacy record into a canonical vault entry.

    Derives ``base32Secret``/``totpUrl`` from ``deviceSecret`` when missing.
    """
    serial = data.get("serial")
    if not serial:
        raise ValueError("record has no 'serial'")

    base32_secret = data.get("base32Secret")
    device_secret = data.get("deviceSecret")
    if not base32_secret and device_secret:
        base32_secret = hex_secret_to_base32(device_secret)

    totp_url = data.get("totpUrl")
    if not totp_url and base32_secret:
        totp_url = build_totp_url(serial, base32_secret, settings.totp)

    entry = {
        "serial": serial,
        "restoreCode": data.get("restoreCode"),
        "deviceSecret": device_secret,
        "base32Secret": base32_secret,
        "totpUrl": totp_url,
    }
    if "timestamp" in data:
        entry["addedAt"] = data["timestamp"]
    return entry


def _read_record(
    path: Path, settings: Settings, passphrase_provider: PassphraseProvider
) -> dict[str, Any] | None:
    """Return the decoded record from a legacy file, or None to skip it."""
    import json

    raw = path.read_bytes()
    if looks_encrypted(raw):
        passphrase = passphrase_provider(path)
        if not passphrase:
            return None
        with EncryptionManager(passphrase, settings.crypto) as manager:
            return manager.decrypt(raw)
    return json.loads(raw.decode("utf-8"))


def migrate_files(
    files: list[Path],
    vault: Vault,
    settings: Settings,
    passphrase_provider: PassphraseProvider,
    *,
    overwrite: bool = False,
) -> list[MigrationOutcome]:
    """Import each file into ``vault`` (caller is responsible for ``vault.save()``)."""
    import json

    outcomes: list[MigrationOutcome] = []
    for path in files:
        try:
            record = _read_record(path, settings, passphrase_provider)
            if record is None:
                outcomes.append(MigrationOutcome(path, status="skipped", detail="no passphrase"))
                continue
            entry = normalise_entry(record, settings)
            existed = vault.get(entry["serial"]) is not None
            added = vault.add(entry, overwrite=overwrite)
            if not added:
                outcomes.append(
                    MigrationOutcome(path, entry["serial"], "skipped", "already in vault")
                )
            else:
                status = "replaced" if existed else "imported"
                outcomes.append(MigrationOutcome(path, entry["serial"], status))
        except (DecryptionError, ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
            outcomes.append(MigrationOutcome(path, status="error", detail=str(exc)))
    return outcomes

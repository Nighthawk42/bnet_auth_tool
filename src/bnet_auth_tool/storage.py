"""Encrypted vault: a single file holding all saved authenticators.

The vault lives in the per-user data directory (see :func:`config.vault_path`)
and is encrypted as a whole with :class:`crypto.EncryptionManager`. Each entry
is keyed by authenticator serial. Writes are atomic and permission-hardened.

Vault plaintext shape::

    {
      "version": 1,
      "entries": {
        "<serial>": {
          "serial": "...", "restoreCode": "...", "deviceSecret": "...",
          "base32Secret": "...", "totpUrl": "...", "addedAt": "<iso8601>"
        },
        ...
      }
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings, vault_path
from .crypto import EncryptionManager
from .errors import StorageError
from .fileio import atomic_write_bytes

VAULT_VERSION = 1


class Vault:
    """An on-disk encrypted collection of authenticator entries."""

    def __init__(self, manager: EncryptionManager, path: Path | None = None):
        self._manager = manager
        self._path = Path(path) if path else vault_path()
        self._entries: dict[str, dict[str, Any]] = {}

    # -- lifecycle ---------------------------------------------------------- #
    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.is_file()

    def load(self) -> Vault:
        """Decrypt the vault from disk into memory. New if the file is absent."""
        if not self.exists():
            self._entries = {}
            return self
        raw = self._path.read_bytes()
        data = self._manager.decrypt(raw)
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            raise StorageError("Vault is malformed: 'entries' is not a mapping.")
        self._entries = entries
        return self

    def save(self) -> None:
        """Encrypt and atomically persist the vault to disk."""
        payload = {"version": VAULT_VERSION, "entries": self._entries}
        atomic_write_bytes(self._path, self._manager.encrypt(payload), secret=True)

    # -- entry operations --------------------------------------------------- #
    def list(self) -> list[dict[str, Any]]:
        return [dict(v) for v in self._entries.values()]

    def serials(self) -> list[str]:
        return sorted(self._entries.keys())

    def get(self, serial: str) -> dict[str, Any] | None:
        entry = self._entries.get(serial)
        return dict(entry) if entry is not None else None

    def add(self, entry: dict[str, Any], *, overwrite: bool = False) -> bool:
        """Add/replace an entry. Returns False if it exists and overwrite=False."""
        serial = entry.get("serial")
        if not serial:
            raise StorageError("Cannot store an entry without a 'serial'.")
        if serial in self._entries and not overwrite:
            return False
        record = dict(entry)
        record.setdefault("addedAt", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self._entries[serial] = record
        return True

    def remove(self, serial: str) -> bool:
        return self._entries.pop(serial, None) is not None

    def __len__(self) -> int:
        return len(self._entries)


def open_vault(passphrase: str, settings: Settings, path: Path | None = None) -> Vault:
    """Convenience: build an EncryptionManager and load (or init) the vault."""
    manager = EncryptionManager(passphrase, settings.crypto)
    return Vault(manager, path).load()

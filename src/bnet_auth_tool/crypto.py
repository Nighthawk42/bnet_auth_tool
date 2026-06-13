"""Authenticated encryption for vault and backup data.

New data is encrypted with scrypt (memory-hard KDF) + AES-256-GCM and a
versioned, self-describing header. Decryption auto-detects the scheme so that
files produced by older versions keep working:

* ``format: 2`` packages declare their own ``kdf`` ("scrypt" or "pbkdf2").
* Legacy v1.x packages have no ``format``/``kdf`` key — they are PBKDF2-HMAC-
  SHA256, using the embedded ``kdf_iterations`` when present, or the configured
  legacy iteration count (100k) when the field is missing entirely.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import CryptoConfig
from .errors import DecryptionError, EncryptionError

FORMAT_VERSION = 2
SALT_SIZE = 16
NONCE_SIZE = 12
AES_KEY_SIZE = 32  # AES-256


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


class EncryptionManager:
    """Encrypts/decrypts JSON-serialisable mappings with a passphrase."""

    def __init__(self, passphrase: str, crypto: CryptoConfig):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        # Keep the passphrase as a mutable bytearray so it can be scrubbed.
        self._passphrase = bytearray(passphrase.encode("utf-8"))
        self._cfg = crypto

    # -- key derivation ----------------------------------------------------- #
    def _derive_scrypt(self, salt: bytes, n: int, r: int, p: int) -> bytes:
        kdf = Scrypt(salt=salt, length=AES_KEY_SIZE, n=n, r=r, p=p)
        return kdf.derive(bytes(self._passphrase))

    def _derive_pbkdf2(self, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(bytes(self._passphrase))

    # -- public API --------------------------------------------------------- #
    def encrypt(self, data: dict[str, Any]) -> bytes:
        """Encrypt a mapping, returning the JSON package as UTF-8 bytes."""
        try:
            plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
            salt = os.urandom(SALT_SIZE)
            nonce = os.urandom(NONCE_SIZE)

            package: dict[str, Any] = {
                "format": FORMAT_VERSION,
                "kdf": self._cfg.kdf,
                "salt": _b64e(salt),
                "nonce": _b64e(nonce),
            }

            if self._cfg.kdf == "scrypt":
                n, r, p = self._cfg.scrypt_n, self._cfg.scrypt_r, self._cfg.scrypt_p
                key = self._derive_scrypt(salt, n, r, p)
                package["scrypt"] = {"n": n, "r": r, "p": p}
            elif self._cfg.kdf == "pbkdf2":
                iterations = self._cfg.pbkdf2_iterations
                key = self._derive_pbkdf2(salt, iterations)
                package["kdf_iterations"] = iterations
            else:
                raise EncryptionError(f"Unsupported KDF: {self._cfg.kdf!r}")

            ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
            package["ciphertext"] = _b64e(ciphertext)
            return json.dumps(package, indent=2).encode("utf-8")
        except EncryptionError:
            raise
        except Exception as exc:  # noqa: BLE001 - wrap any crypto/serialisation failure
            raise EncryptionError(f"Encryption failed: {exc}") from exc

    def decrypt(self, encrypted_bytes: bytes) -> dict[str, Any]:
        """Decrypt a package produced by any supported version of this tool."""
        try:
            package = json.loads(encrypted_bytes.decode("utf-8"))
            salt = _b64d(package["salt"])
            nonce = _b64d(package["nonce"])
            ciphertext = _b64d(package["ciphertext"])
            key = self._derive_key_for(package, salt)
        except InvalidTag:  # pragma: no cover - raised below, kept for clarity
            raise
        except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
            raise DecryptionError(
                f"Decryption failed: invalid data format or content. {exc}"
            ) from exc

        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode("utf-8"))
        except InvalidTag as exc:
            raise DecryptionError(
                "Decryption failed: authentication tag mismatch. "
                "Check the passphrase or data integrity."
            ) from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise DecryptionError(f"Decryption failed: corrupt plaintext. {exc}") from exc

    def _derive_key_for(self, package: dict[str, Any], salt: bytes) -> bytes:
        """Pick the KDF based on the package header and derive the AES key."""
        kdf = package.get("kdf")

        if kdf == "scrypt":
            params = package.get("scrypt", {})
            return self._derive_scrypt(
                salt,
                int(params["n"]),
                int(params["r"]),
                int(params["p"]),
            )

        if kdf == "pbkdf2" or "format" in package:
            iterations = int(package.get("kdf_iterations", self._cfg.pbkdf2_iterations))
            return self._derive_pbkdf2(salt, iterations)

        # Legacy v1.x package: no format/kdf header -> PBKDF2.
        if "kdf_iterations" in package:
            iterations = int(package["kdf_iterations"])
        else:
            iterations = self._cfg.pbkdf2_legacy_iterations
        return self._derive_pbkdf2(salt, iterations)

    # -- hygiene ------------------------------------------------------------ #
    def close(self) -> None:
        """Best-effort scrub of the in-memory passphrase."""
        for i in range(len(self._passphrase)):
            self._passphrase[i] = 0

    def __enter__(self) -> EncryptionManager:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def looks_encrypted(raw: bytes) -> bool:
    """Heuristic: does ``raw`` look like one of our encryption packages?"""
    try:
        package = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(package, dict) and {"salt", "nonce", "ciphertext"} <= package.keys()

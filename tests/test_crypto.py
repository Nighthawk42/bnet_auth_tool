"""Crypto round-trips and legacy-format back-compat."""

from __future__ import annotations

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bnet_auth_tool.crypto import EncryptionManager, looks_encrypted
from bnet_auth_tool.errors import DecryptionError

SAMPLE = {"serial": "US-1234", "deviceSecret": "deadbeef", "nested": {"a": [1, 2, 3]}}


def _legacy_pbkdf2_package(data: dict, passphrase: str, iterations: int, *, include_iters: bool):
    """Reproduce the v1.x encryption package format for back-compat tests."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), None)
    package = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    if include_iters:
        package["kdf_iterations"] = iterations
    return json.dumps(package).encode("utf-8")


def test_scrypt_round_trip(settings):
    mgr = EncryptionManager("correct horse", settings.crypto)
    blob = mgr.encrypt(SAMPLE)
    assert looks_encrypted(blob)
    assert json.loads(blob)["kdf"] == "scrypt"
    assert mgr.decrypt(blob) == SAMPLE


def test_pbkdf2_round_trip(settings):
    cfg = settings.crypto
    object.__setattr__(cfg, "kdf", "pbkdf2")
    mgr = EncryptionManager("pw", cfg)
    blob = mgr.encrypt(SAMPLE)
    assert json.loads(blob)["kdf"] == "pbkdf2"
    assert mgr.decrypt(blob) == SAMPLE


def test_wrong_passphrase_raises(settings):
    blob = EncryptionManager("right", settings.crypto).encrypt(SAMPLE)
    with pytest.raises(DecryptionError):
        EncryptionManager("wrong", settings.crypto).decrypt(blob)


def test_legacy_with_explicit_iterations(settings):
    # A modern PBKDF2 file embeds its own count; decrypt must honour it
    # regardless of the configured default. Small count keeps the test fast.
    blob = _legacy_pbkdf2_package(SAMPLE, "pw", 7777, include_iters=True)
    mgr = EncryptionManager("pw", settings.crypto)
    assert mgr.decrypt(blob) == SAMPLE


def test_legacy_missing_iterations_uses_legacy_count(settings):
    # Simulate a pre-v1.3 file: no kdf_iterations field. The manager must assume
    # the configured legacy iteration count to decrypt it.
    iters = settings.crypto.pbkdf2_legacy_iterations
    blob = _legacy_pbkdf2_package(SAMPLE, "pw", iters, include_iters=False)
    mgr = EncryptionManager("pw", settings.crypto)
    assert mgr.decrypt(blob) == SAMPLE


def test_corrupt_data_raises(settings):
    with pytest.raises(DecryptionError):
        EncryptionManager("pw", settings.crypto).decrypt(b"not json")


def test_passphrase_scrub(settings):
    mgr = EncryptionManager("secret", settings.crypto)
    mgr.close()
    assert all(b == 0 for b in mgr._passphrase)


def test_looks_encrypted_false_for_plain():
    assert not looks_encrypted(json.dumps(SAMPLE).encode())

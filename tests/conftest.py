"""Shared test fixtures."""

from __future__ import annotations

import pytest

from bnet_auth_tool.config import (
    ApiConfig,
    CryptoConfig,
    Settings,
    TotpConfig,
)


@pytest.fixture
def settings() -> Settings:
    """Settings with cheap scrypt params so tests stay fast."""
    return Settings(
        api=ApiConfig(
            host="https://example.test",
            attach_path="/v1/authenticator",
            device_path="/v2/authenticator/device",
            sso_url="https://oauth.example.test/sso",
            client_id="test-client",
            timeout=5,
            region_prefixes=["US-", "EU-"],
        ),
        totp=TotpConfig(algorithm="SHA1", digits=8, period=30, issuer="Battle.net"),
        crypto=CryptoConfig(
            kdf="scrypt",
            scrypt_n=1024,  # small N for fast tests
            scrypt_r=8,
            scrypt_p=1,
            pbkdf2_iterations=1000,
            pbkdf2_legacy_iterations=100,
        ),
    )

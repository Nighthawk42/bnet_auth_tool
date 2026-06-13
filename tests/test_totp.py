"""TOTP secret conversion and otpauth URL building."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from bnet_auth_tool.totp import build_totp_url, hex_secret_to_base32


def test_hex_to_base32_known_value():
    # "deadbeef" -> bytes de ad be ef -> base32 (unpadded)
    assert hex_secret_to_base32("deadbeef") == "32W353Y"


def test_hex_to_base32_rejects_bad_hex():
    with pytest.raises(ValueError):
        hex_secret_to_base32("nothex!!")


def test_build_totp_url(settings):
    url = build_totp_url("US-1234", "JBSWY3DPEHPK3PXP", settings.totp)
    parsed = urlparse(url)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert parsed.path == "/Battle.net:US-1234"
    qs = parse_qs(parsed.query)
    assert qs["secret"] == ["JBSWY3DPEHPK3PXP"]
    assert qs["issuer"] == ["Battle.net"]
    assert qs["digits"] == ["8"]
    assert qs["algorithm"] == ["SHA1"]
    assert qs["period"] == ["30"]

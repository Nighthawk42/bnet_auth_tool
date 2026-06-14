"""TOTP secret conversion and otpauth URL building."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from bnet_auth_tool.config import TotpConfig
from bnet_auth_tool.totp import (
    build_totp_url,
    current_code,
    hex_secret_to_base32,
    seconds_remaining,
)

# RFC 6238 Appendix B reference: ASCII secret "12345678901234567890".
_RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_RFC_TOTP = TotpConfig(algorithm="SHA1", digits=8, period=30, issuer="Test")


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


def test_current_code_rfc6238_vector():
    # RFC 6238 Appendix B: SHA1, 8 digits, T=59s -> 94287082.
    assert current_code(_RFC_SECRET_B32, _RFC_TOTP, at=59) == "94287082"
    # T=1111111109 -> 07081804.
    assert current_code(_RFC_SECRET_B32, _RFC_TOTP, at=1111111109) == "07081804"


def test_current_code_accepts_unpadded_secret():
    # Battle.net secrets are stored unpadded; must still decode.
    assert current_code("32W353Y", _RFC_TOTP, at=0).isdigit()


def test_seconds_remaining():
    assert seconds_remaining(_RFC_TOTP, at=0) == 30
    assert seconds_remaining(_RFC_TOTP, at=29) == 1
    assert seconds_remaining(_RFC_TOTP, at=30) == 30

"""TOTP helpers: secret conversion, otpauth URL building, and QR codes."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from urllib.parse import quote, urlencode

from .config import TotpConfig
from .fileio import _harden


def hex_secret_to_base32(hex_secret: str) -> str:
    """Convert a raw hex device secret to an unpadded Base32 TOTP secret."""
    try:
        secret_bytes = binascii.unhexlify(hex_secret)
    except (binascii.Error, TypeError) as exc:
        raise ValueError(f"Invalid hex secret: {exc}") from exc
    return base64.b32encode(secret_bytes).decode("ascii").rstrip("=")


def build_totp_url(serial: str, base32_secret: str, totp: TotpConfig) -> str:
    """Build an ``otpauth://totp/`` URL for the given serial and secret."""
    # Keep the issuer:account separator as a literal colon (otpauth convention).
    label = quote(f"{totp.issuer}:{serial}", safe=":")
    params = urlencode(
        {
            "secret": base32_secret,
            "issuer": totp.issuer,
            "digits": totp.digits,
            "algorithm": totp.algorithm,
            "period": totp.period,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def generate_qr_code(totp_url: str, out_path: Path) -> Path:
    """Render ``totp_url`` to a PNG QR code at ``out_path`` (perm-hardened)."""
    import qrcode

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(totp_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(out_path))
    _harden(out_path)
    return out_path

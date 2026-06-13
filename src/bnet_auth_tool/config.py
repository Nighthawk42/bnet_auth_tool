"""Configuration loading and per-user path resolution.

The bundled ``settings.yaml`` (shipped inside the package) holds defaults. On
first use a copy is written to the user's config directory; values found there
are overlaid on top of the defaults, so users can edit endpoints/KDF/TOTP
parameters without touching the installed package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from platformdirs import user_config_dir, user_data_dir

from .errors import ConfigError

APP_NAME = "bnet_auth_tool"
APP_AUTHOR = "Nighthawk42"
SETTINGS_FILENAME = "settings.yaml"
VAULT_FILENAME = "vault.json"


# --------------------------------------------------------------------------- #
# Path helpers
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    """Directory holding the user-editable settings file."""
    return Path(user_config_dir(APP_NAME, APP_AUTHOR))


def data_dir() -> Path:
    """Directory holding the encrypted vault."""
    return Path(user_data_dir(APP_NAME, APP_AUTHOR))


def user_settings_path() -> Path:
    return config_dir() / SETTINGS_FILENAME


def vault_path() -> Path:
    return data_dir() / VAULT_FILENAME


def _bundled_settings_text() -> str:
    return resources.files(APP_NAME).joinpath(SETTINGS_FILENAME).read_text(encoding="utf-8")


def ensure_user_settings() -> Path:
    """Copy the bundled defaults into the user config dir if absent.

    Returns the path to the user settings file.
    """
    dest = user_settings_path()
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(_bundled_settings_text(), encoding="utf-8")
    return dest


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively overlay ``overlay`` onto ``base`` (returns a new dict)."""
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# --------------------------------------------------------------------------- #
# Typed config sections
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ApiConfig:
    host: str
    attach_path: str
    device_path: str
    sso_url: str
    client_id: str
    timeout: int
    region_prefixes: list[str] = field(default_factory=list)

    @property
    def attach_url(self) -> str:
        return f"{self.host}{self.attach_path}"

    @property
    def device_url(self) -> str:
        return f"{self.host}{self.device_path}"


@dataclass(frozen=True)
class TotpConfig:
    algorithm: str
    digits: int
    period: int
    issuer: str


@dataclass(frozen=True)
class CryptoConfig:
    kdf: str
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    pbkdf2_iterations: int
    pbkdf2_legacy_iterations: int


@dataclass(frozen=True)
class Settings:
    api: ApiConfig
    totp: TotpConfig
    crypto: CryptoConfig

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Settings:
        try:
            api = raw["api"]
            totp = raw["totp"]
            crypto = raw["crypto"]
            scrypt = crypto["scrypt"]
            pbkdf2 = crypto["pbkdf2"]
            return cls(
                api=ApiConfig(
                    host=api["host"].rstrip("/"),
                    attach_path=api["attach_path"],
                    device_path=api["device_path"],
                    sso_url=api["sso_url"],
                    client_id=api["client_id"],
                    timeout=int(api.get("timeout", 20)),
                    region_prefixes=list(api.get("region_prefixes", [])),
                ),
                totp=TotpConfig(
                    algorithm=str(totp["algorithm"]).upper(),
                    digits=int(totp["digits"]),
                    period=int(totp["period"]),
                    issuer=str(totp["issuer"]),
                ),
                crypto=CryptoConfig(
                    kdf=str(crypto.get("kdf", "scrypt")).lower(),
                    scrypt_n=int(scrypt["n"]),
                    scrypt_r=int(scrypt["r"]),
                    scrypt_p=int(scrypt["p"]),
                    pbkdf2_iterations=int(pbkdf2["iterations"]),
                    pbkdf2_legacy_iterations=int(pbkdf2["legacy_iterations"]),
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid settings file: {exc}") from exc


def load_settings() -> Settings:
    """Load bundled defaults overlaid with the user's settings file."""
    defaults = yaml.safe_load(_bundled_settings_text()) or {}
    merged = defaults

    user_path = user_settings_path()
    if user_path.exists():
        try:
            overlay = yaml.safe_load(user_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Could not parse {user_path}: {exc}") from exc
        if not isinstance(overlay, dict):
            raise ConfigError(f"{user_path} must contain a YAML mapping at the top level.")
        merged = _deep_merge(defaults, overlay)

    return Settings.from_dict(merged)

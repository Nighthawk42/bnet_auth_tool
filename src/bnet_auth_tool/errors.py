"""Exception hierarchy for bnet_auth_tool."""

from __future__ import annotations


class BnetAuthError(Exception):
    """Base class for all errors raised by this package."""


class AuthenticatorError(BnetAuthError):
    """A problem talking to the Battle.net authenticator API."""


class EncryptionError(BnetAuthError):
    """Encryption of vault/backup data failed."""


class DecryptionError(BnetAuthError):
    """Decryption failed (wrong passphrase, corrupt data, or bad format)."""


class ConfigError(BnetAuthError):
    """The settings file is missing required values or is malformed."""


class StorageError(BnetAuthError):
    """The vault could not be read or written."""

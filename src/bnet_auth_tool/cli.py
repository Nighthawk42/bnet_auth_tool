"""Command-line interface: interactive menu plus scriptable subcommands.

Run without arguments for the interactive menu, or use a subcommand, e.g.::

    bnet-auth list
    bnet-auth migrate --dir .
    bnet-auth reconstruct US-1234-...
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __author__, __license__, __version__
from .api import BattleNetAuthenticator
from .config import (
    Settings,
    config_dir,
    data_dir,
    ensure_user_settings,
    load_settings,
    user_settings_path,
    vault_path,
)
from .crypto import EncryptionManager
from .errors import BnetAuthError
from .migrate import discover_legacy_files, migrate_files
from .storage import Vault
from .totp import build_totp_url, generate_qr_code, hex_secret_to_base32

TITLE = "Battle.net Authenticator Tool"


# --------------------------------------------------------------------------- #
# Small I/O helpers
# --------------------------------------------------------------------------- #
def _print_header() -> None:
    print(f"\n=== {TITLE} ===")
    print(f"Version {__version__} · Author {__author__} · License {__license__}")
    print(f"Vault: {vault_path()}")
    print("-" * 60)


def _prompt(text: str) -> str | None:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return None


def _confirm(text: str) -> bool:
    answer = _prompt(f"{text} (y/n): ")
    return (answer or "").lower() == "y"


def _prompt_passphrase(message: str, *, confirm: bool) -> str | None:
    try:
        while True:
            passphrase = getpass.getpass(message)
            if not passphrase:
                print("Passphrase cannot be empty.")
                continue
            if not confirm:
                return passphrase
            if passphrase == getpass.getpass("Confirm passphrase: "):
                return passphrase
            print("Passphrases do not match. Try again.")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return None


def _open_vault(settings: Settings, *, for_write: bool) -> Vault | None:
    """Open the vault, prompting for the master passphrase.

    Creating a new vault requires passphrase confirmation; opening an existing
    one does not.
    """
    exists = vault_path().is_file()
    if not exists and not for_write:
        print(f"No vault yet at {vault_path()}.")
        return None

    if not exists:
        print("No vault exists. Creating a new encrypted vault.")
    passphrase = _prompt_passphrase("Vault passphrase: ", confirm=not exists)
    if passphrase is None:
        return None

    manager = EncryptionManager(passphrase, settings.crypto)
    try:
        return Vault(manager).load()
    except BnetAuthError as exc:
        print(f"Error opening vault: {exc}", file=sys.stderr)
        return None


def _store_entry(vault: Vault, device_info: dict, settings: Settings) -> dict:
    """Build a vault entry from raw device info, store it, and return it."""
    serial = device_info["serial"]
    base32_secret = hex_secret_to_base32(device_info["deviceSecret"])
    totp_url = build_totp_url(serial, base32_secret, settings.totp)
    entry = {
        "serial": serial,
        "restoreCode": device_info.get("restoreCode"),
        "deviceSecret": device_info["deviceSecret"],
        "base32Secret": base32_secret,
        "totpUrl": totp_url,
        "addedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    vault.add(entry, overwrite=True)
    vault.save()
    return entry


def _print_entry(entry: dict) -> None:
    print("\n" + "-" * 40)
    print(f"  Serial:       {entry.get('serial')}")
    print(f"  Restore Code: {entry.get('restoreCode')}")
    print(f"  Base32:       {entry.get('base32Secret')}")
    print(f"  otpauth URL:  {entry.get('totpUrl')}")
    print("  TOTP params:  SHA1, 8 digits, 30s period")
    print("-" * 40)


# --------------------------------------------------------------------------- #
# Online flows (UNVERIFIED against live Blizzard backend)
# --------------------------------------------------------------------------- #
_SESSION_TOKEN_HELP = """
--- How to get a Session Token ---
1. In a private browser window go to:
   https://account.battle.net/login/en/?ref=localhost
2. Log in; you'll land on a 'Page Not Found' at localhost.
3. From the URL, copy the token that looks like 'ST=US-...' (the value after ST=).
----------------------------------"""


def _get_session_token(settings: Settings) -> str | None:
    print(_SESSION_TOKEN_HELP)
    token = _prompt("Enter your Session Token (or blank to cancel): ")
    if not token:
        return None
    prefixes = settings.api.region_prefixes
    if prefixes and (not any(token.startswith(p) for p in prefixes) or len(token) < 20):
        print("Warning: token format looks unusual; ensure you copied the full value.")
    return token


def action_attach(settings: Settings) -> None:
    print("\nNOTE: online flows are unverified against the current Blizzard API.")
    token = _get_session_token(settings)
    if not token:
        return
    vault = _open_vault(settings, for_write=True)
    if vault is None:
        return
    client = BattleNetAuthenticator(settings.api)
    try:
        print("Requesting bearer token...")
        client.get_bearer_token(token)
        print("Attaching a new authenticator...")
        device_info = client.attach_authenticator()
    except BnetAuthError as exc:
        print(f"\nAttach failed: {exc}", file=sys.stderr)
        return
    entry = _store_entry(vault, device_info, settings)
    print("Authenticator attached and saved to the vault.")
    _print_entry(entry)
    _maybe_export_qr(entry)


def action_retrieve(settings: Settings) -> None:
    print("\nNOTE: online flows are unverified against the current Blizzard API.")
    account = _prompt("Account email or phone number: ")
    serial = _prompt("Authenticator serial: ")
    restore_code = _prompt("Authenticator restore code: ")
    if not (account and serial and restore_code):
        print("Account identifier, serial, and restore code are all required.")
        return
    vault = _open_vault(settings, for_write=True)
    if vault is None:
        return
    client = BattleNetAuthenticator(settings.api)
    try:
        print(f"Retrieving secret for serial {serial}...")
        retrieved = client.retrieve_device_secret(account, serial, restore_code)
    except BnetAuthError as exc:
        print(f"\nRetrieve failed: {exc}", file=sys.stderr)
        return
    device_info = {
        "serial": serial,
        "restoreCode": restore_code,
        "deviceSecret": retrieved["deviceSecret"],
    }
    entry = _store_entry(vault, device_info, settings)
    print("Device secret retrieved and saved to the vault.")
    _print_entry(entry)
    _maybe_export_qr(entry)


# --------------------------------------------------------------------------- #
# Offline flows
# --------------------------------------------------------------------------- #
def action_list(settings: Settings) -> None:
    vault = _open_vault(settings, for_write=False)
    if vault is None:
        return
    if len(vault) == 0:
        print("Vault is empty.")
        return
    print(f"\n{len(vault)} authenticator(s) in the vault:")
    for entry in vault.list():
        print(f"  - {entry.get('serial')}  (added {entry.get('addedAt', 'unknown')})")


def action_reconstruct(settings: Settings, serial: str | None = None) -> None:
    vault = _open_vault(settings, for_write=False)
    if vault is None:
        return
    serials = vault.serials()
    if not serials:
        print("Vault is empty.")
        return
    if serial is None:
        serial = _choose(serials, "Select an authenticator")
        if serial is None:
            return
    entry = vault.get(serial)
    if entry is None:
        print(f"No entry for serial '{serial}'.")
        return
    if not entry.get("totpUrl"):
        base32 = entry.get("base32Secret") or hex_secret_to_base32(entry.get("deviceSecret", ""))
        entry["totpUrl"] = build_totp_url(serial, base32, settings.totp)
    _print_entry(entry)
    _maybe_export_qr(entry)


def action_migrate(settings: Settings, directory: Path, overwrite: bool) -> None:
    files = discover_legacy_files(directory)
    if not files:
        print(f"No legacy authenticator JSON files found in {directory}.")
        return
    print(f"\nFound {len(files)} legacy file(s) in {directory}:")
    for f in files:
        print(f"  - {f.name}")
    vault = _open_vault(settings, for_write=True)
    if vault is None:
        return

    def provider(path: Path) -> str | None:
        print(f"\n'{path.name}' is encrypted.")
        return _prompt_passphrase(f"Passphrase for '{path.name}': ", confirm=False)

    outcomes = migrate_files(files, vault, settings, provider, overwrite=overwrite)
    vault.save()

    print("\nMigration summary:")
    for o in outcomes:
        suffix = f" ({o.detail})" if o.detail else ""
        print(f"  [{o.status}] {o.path.name} -> {o.serial or '?'}{suffix}")
    imported = sum(1 for o in outcomes if o.status in ("imported", "replaced"))
    print(f"\n{imported} entr(y/ies) now in the vault.")
    if imported:
        print("Securely delete the original plaintext files once you've verified the vault.")


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _choose(options: list[str], prompt: str) -> str | None:
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    raw = _prompt(f"{prompt} (number, or blank to cancel): ")
    if not raw:
        return None
    try:
        idx = int(raw) - 1
    except ValueError:
        print("Invalid selection.")
        return None
    if 0 <= idx < len(options):
        return options[idx]
    print("Invalid selection.")
    return None


def _maybe_export_qr(entry: dict) -> None:
    if not entry.get("totpUrl"):
        return
    if not _confirm("\nGenerate a QR-code PNG (contains your secret)?"):
        return
    out = Path.cwd() / f"bnet_{entry['serial']}.png"
    try:
        path = generate_qr_code(entry["totpUrl"], out)
    except Exception as exc:  # noqa: BLE001 - qrcode/Pillow failure shouldn't crash CLI
        print(f"Could not generate QR code: {exc}", file=sys.stderr)
        return
    print(f"QR code written to {path}")
    print("WARNING: this PNG contains your TOTP secret. Delete it after importing.")


def action_paths(settings: Settings) -> None:
    print(f"\nConfig dir:    {config_dir()}")
    print(f"Settings file: {user_settings_path()}")
    print(f"Data dir:      {data_dir()}")
    print(f"Vault file:    {vault_path()}")


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
_MENU = [
    ("Attach a new authenticator (online)", lambda s: action_attach(s)),
    ("Retrieve an existing device secret (online)", lambda s: action_retrieve(s)),
    ("Reconstruct TOTP / QR from the vault", lambda s: action_reconstruct(s)),
    ("List authenticators in the vault", lambda s: action_list(s)),
    ("Migrate legacy JSON files into the vault", lambda s: action_migrate(s, Path.cwd(), False)),
    ("Show file paths", lambda s: action_paths(s)),
]


def interactive(settings: Settings) -> None:
    _print_header()
    while True:
        print("\nChoose an action:")
        for i, (label, _) in enumerate(_MENU, 1):
            print(f"  {i}. {label}")
        print(f"  {len(_MENU) + 1}. Exit")

        choice = _prompt("Enter choice: ")
        if choice is None:
            break
        if choice == str(len(_MENU) + 1) or choice.lower() in ("exit", "q"):
            break
        try:
            idx = int(choice) - 1
        except ValueError:
            print("Invalid choice.")
            continue
        if 0 <= idx < len(_MENU):
            try:
                _MENU[idx][1](settings)
            except BnetAuthError as exc:
                print(f"\nError: {exc}", file=sys.stderr)
        else:
            print("Invalid choice.")
    print("\nExiting. Keep your vault and passphrase backed up securely.")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bnet-auth", description=TITLE)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("attach", help="attach a new authenticator (online, unverified)")
    sub.add_parser("retrieve", help="retrieve an existing device secret (online, unverified)")
    sub.add_parser("list", help="list authenticators stored in the vault")

    p_recon = sub.add_parser("reconstruct", help="reconstruct TOTP/QR from the vault")
    p_recon.add_argument("serial", nargs="?", help="authenticator serial (prompts if omitted)")

    p_mig = sub.add_parser("migrate", help="import legacy JSON backups into the vault")
    p_mig.add_argument("--dir", default=".", help="directory to scan (default: current)")
    p_mig.add_argument("--overwrite", action="store_true", help="replace existing vault entries")

    sub.add_parser("paths", help="show config/data/vault locations")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    ensure_user_settings()
    try:
        settings = load_settings()
    except BnetAuthError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "attach":
            action_attach(settings)
        elif args.command == "retrieve":
            action_retrieve(settings)
        elif args.command == "list":
            action_list(settings)
        elif args.command == "reconstruct":
            action_reconstruct(settings, args.serial)
        elif args.command == "migrate":
            action_migrate(settings, Path(args.dir), args.overwrite)
        elif args.command == "paths":
            action_paths(settings)
        else:
            interactive(settings)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except BnetAuthError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

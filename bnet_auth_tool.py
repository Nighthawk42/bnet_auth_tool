# -*- coding: utf-8 -*-
"""
Battle.net Authenticator Tool
Version: 1.4.0
Author: Nighthawk42
License: MIT
Github: https://github.com/Nighthawk42/bnet_auth_tool
"""

import json
import base64
import binascii
import sys
import os
import getpass
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List

try:
    import requests
    import qrcode
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
except ImportError as e:
    print(f"Error: Missing required library. {e}")
    print("Install: pip install requests qrcode[pil] cryptography")
    sys.exit(1)

if platform.system() == "Windows":
    import ctypes


class AppInfo:
    TITLE = "Battle.net Authenticator Tool"
    VERSION = "1.4.0"
    AUTHOR = "Nighthawk42"
    LICENSE = "MIT"
    GITHUB = "https://github.com/Nighthawk42/bnet_auth_tool"


class Security:
    LEGACY_PBKDF2_ITERATIONS = 100_000
    DEFAULT_PBKDF2_ITERATIONS = 600_000
    SALT_SIZE = 16
    NONCE_SIZE = 12
    AES_KEY_SIZE = 32


class Endpoints:
    CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a"
    SSO_URLS = [
        "https://oauth.battle.net/oauth/sso",
        "https://us.oauth.battle.net/oauth/sso",
        "https://eu.oauth.battle.net/oauth/sso",
    ]
    API_URLS = [
        "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator",
        "https://us.authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator",
        "https://eu.authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator",
    ]


class CookieHints:
    CANDIDATE_KEYS = [
        "BA-tassadar",            # preferred
        "BA-tassadar-cl",
        "BA-tassadar-loginKey",
        "login.key",
        "cl",
        "SESSIONID",
    ]


class AuthenticatorError(Exception):
    pass


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


def set_console_title(title: str = AppInfo.TITLE) -> None:
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()
    except Exception:
        pass


def graceful_exit(code: int = 0) -> None:
    print("\nExiting. Back up your data.")
    sys.exit(code)


def print_header() -> None:
    print(f"{AppInfo.TITLE}")
    print(f"Version: {AppInfo.VERSION}")
    print(f"Author: {AppInfo.AUTHOR}")
    print(f"License: {AppInfo.LICENSE}")
    print(f"GitHub Repo: {AppInfo.GITHUB}")
    print("-" * 40)


class EncryptionManager:
    def __init__(self, passphrase: str):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        self.passphrase = passphrase.encode("utf-8")
        self.backend = default_backend()
        self.default_iterations = Security.DEFAULT_PBKDF2_ITERATIONS

    def _derive_key(self, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=Security.AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=self.backend,
        )
        return kdf.derive(self.passphrase)

    def encrypt(self, data: Dict[str, Any]) -> bytes:
        try:
            b = json.dumps(data, ensure_ascii=False).encode("utf-8")
            salt = os.urandom(Security.SALT_SIZE)
            key = self._derive_key(salt, self.default_iterations)
            nonce = os.urandom(Security.NONCE_SIZE)
            ct = AESGCM(key).encrypt(nonce, b, None)
            pkg = {
                "salt": base64.b64encode(salt).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ct).decode("utf-8"),
                "kdf_iterations": self.default_iterations,
            }
            return json.dumps(pkg, indent=4).encode("utf-8")
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_bytes: bytes) -> Dict[str, Any]:
        missing = False
        try:
            obj = json.loads(encrypted_bytes.decode("utf-8"))
            salt = base64.b64decode(obj["salt"])
            nonce = base64.b64decode(obj["nonce"])
            ct = base64.b64decode(obj["ciphertext"])
            if "kdf_iterations" in obj:
                iters = int(obj["kdf_iterations"])
            else:
                missing = True
                iters = Security.LEGACY_PBKDF2_ITERATIONS
                print(f"Warning: 'kdf_iterations' missing. Using legacy {iters}.")
            key = self._derive_key(salt, iters)
            pt = AESGCM(key).decrypt(nonce, ct, None)
            return json.loads(pt.decode("utf-8"))
        except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as e:
            extra = " (legacy iterations assumed)" if missing else ""
            raise DecryptionError(f"Decryption failed: Invalid data. {e}{extra}") from e
        except InvalidTag:
            raise DecryptionError("Decryption failed: Auth tag mismatch.")
        except Exception as e:
            raise DecryptionError(f"Unexpected decryption error: {e}") from e


class BattleNetAuthenticator:
    def __init__(self):
        self.bearer_token: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"{AppInfo.TITLE}/{AppInfo.VERSION}"})

    @staticmethod
    def _join(base: str, path: Optional[str]) -> str:
        if not path:
            return base
        return f"{base.rstrip('/')}/{path.lstrip('/')}"

    def _make_request(self, method: str, url: str, headers: Optional[Dict] = None,
                      data: Optional[Any] = None, json_payload: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            h = self.session.headers.copy()
            if headers:
                h.update(headers)
            resp = self.session.request(method, url, headers=h, data=data, json=json_payload, timeout=20)
            resp.raise_for_status()
            if resp.status_code == 204:
                return {}
            if "application/json" in resp.headers.get("Content-Type", ""):
                return resp.json()
            raise AuthenticatorError(f"Unexpected content type from {url}")
        except requests.exceptions.Timeout as e:
            raise AuthenticatorError(f"Timeout {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise AuthenticatorError(f"Network error {url}: {e}") from e
        except requests.exceptions.HTTPError as e:
            try:
                body = resp.json()
                detail = f" Server: {json.dumps(body)}"
            except Exception:
                detail = f" Server: {resp.text[:500]}..."
            raise AuthenticatorError(f"HTTP {resp.status_code} {url}: {e}.{detail}") from e
        except requests.exceptions.RequestException as e:
            raise AuthenticatorError(f"Request failed {url}: {e}") from e
        except json.JSONDecodeError as e:
            raise AuthenticatorError(f"JSON decode error {url}: {e}") from e

    def _with_fallback(self, method: str, bases: List[str], path: Optional[str] = None,
                       headers: Optional[Dict] = None, data: Optional[Any] = None,
                       json_payload: Optional[Dict] = None) -> Dict[str, Any]:
        last = None
        for base in bases:
            url = self._join(base, path)
            try:
                return self._make_request(method, url, headers=headers, data=data, json_payload=json_payload)
            except AuthenticatorError as e:
                print(f"Warning: {e}")
                last = e
        if last:
            raise last
        raise AuthenticatorError("No URLs to try.")

    def get_bearer_token(self, token_value: str) -> None:
        payload = {
            "client_id": Endpoints.CLIENT_ID,
            "grant_type": "client_sso",
            "scope": "auth.authenticator",
            "token": token_value,
        }
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        print("Requesting Bearer Token (SSO fallback)...")
        data = self._with_fallback("POST", Endpoints.SSO_URLS, headers=headers, data=payload)
        access = data.get("access_token")
        if not access:
            raise AuthenticatorError("Missing 'access_token' in SSO response.")
        self.session.headers["Authorization"] = f"Bearer {access}"
        self.bearer_token = access
        print("Bearer Token obtained.")

    def attach_authenticator(self) -> Dict[str, Any]:
        if "Authorization" not in self.session.headers:
            raise AuthenticatorError("Bearer token not set.")
        print("Attaching authenticator (API fallback)...")
        data = self._with_fallback("POST", Endpoints.API_URLS, headers={"accept": "application/json"})
        for k in ("serial", "restoreCode", "deviceSecret"):
            if k not in data:
                raise AuthenticatorError(f"API response missing '{k}'.")
        print("Authenticator attached.")
        return data

    def retrieve_device_secret(self, serial: str, restore_code: str) -> Dict[str, Any]:
        if "Authorization" not in self.session.headers:
            raise AuthenticatorError("Bearer token not set.")
        print(f"Retrieving device secret for {serial} (API fallback)...")
        data = self._with_fallback(
            "POST",
            Endpoints.API_URLS,
            path="device",
            headers={"accept": "application/json", "Content-Type": "application/json"},
            json_payload={"serial": serial, "restoreCode": restore_code},
        )
        if "deviceSecret" not in data:
            raise AuthenticatorError("API response missing 'deviceSecret'.")
        print("Device secret retrieved.")
        return data

    @staticmethod
    def save_json(filename: str, data: Dict[str, Any], enc: Optional[EncryptionManager] = None) -> None:
        p = Path(filename)
        if p.exists():
            while True:
                try:
                    o = input(f"'{filename}' exists. Overwrite? (y/n): ").strip().lower()
                except EOFError:
                    print("\nCancelled.")
                    return
                if o == "y":
                    break
                if o == "n":
                    print("Not saved.")
                    return
                print("Enter 'y' or 'n'.")
        try:
            if enc:
                payload = enc.encrypt(data)
                with open(p, "wb") as f:
                    f.write(payload)
                print(f"Encrypted file saved: {filename}")
            else:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                print(f"File saved: {filename}")
            print("Backup this file and remember your passphrase if encrypted.")
        except IOError as e:
            raise IOError(f"Write failed '{filename}': {e}") from e

    @staticmethod
    def load_json(filename: str, enc: Optional[EncryptionManager] = None) -> Dict[str, Any]:
        p = Path(filename)
        if not p.is_file():
            raise FileNotFoundError(f"Not found: '{filename}'")
        try:
            if enc:
                with open(p, "rb") as f:
                    b = f.read()
                data = enc.decrypt(b)
                print(f"Decrypted: {filename}")
                return data
            else:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                print(f"Loaded: {filename}")
                return data
        except IOError as e:
            raise IOError(f"Read failed '{filename}': {e}") from e

    @staticmethod
    def convert_secret_to_base32(hex_secret: str) -> str:
        try:
            if len(hex_secret) % 2 != 0:
                raise binascii.Error("Odd-length hex")
            b = binascii.unhexlify(hex_secret)
            return base64.b32encode(b).decode("utf-8").rstrip("=")
        except (binascii.Error, TypeError) as e:
            raise ValueError(f"Invalid hex secret: {e}") from e

    @staticmethod
    def generate_qr_code(totp_url: str, filename_base: str) -> None:
        name = f"{filename_base}.png"
        try:
            print(f"Generating QR: {name}")
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(totp_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(name)
            print(f"QR saved: {name}")
        except IOError as e:
            raise IOError(f"QR save failed '{name}': {e}") from e
        except Exception as e:
            raise Exception(f"QR generation error: {e}") from e


class CLI:
    def __init__(self):
        self.auth = BattleNetAuthenticator()

    @staticmethod
    def show_cookie_instructions() -> None:
        print("\nHow to get your cookie token (localhost flow):")
        print("1) Open an browser window.")
        print("2) Go to: https://account.battle.net/login/en/?ref=localhost and log in.")
        print("3) You will land on a localhost error page—this is expected.")
        print("4) You *might* be redirected, if so return to https://account.battle.net/login/en/?ref=localhost")
        print("Follow the proper directions for whichever browser you are using.")
        print("\nChromium (Chrome / Edge / Brave):")
        print("  - F12 → Application → Storage → Cookies → select the current site")
        print("  - Copy the cookie value from one of:", ", ".join(CookieHints.CANDIDATE_KEYS))
        print("  - Or Console: document.cookie")
        print("\nFirefox:")
        print("  - F12 → Storage → Cookies → select the site")
        print("  - Copy the cookie value from one of the keys above")
        print("  - Or Console: document.cookie")
        print("\nSafari (macOS):")
        print("  - Safari → Settings… → Advanced → enable ‘Show Develop menu’")
        print("  - Develop → Show Web Inspector → Storage → Cookies (or Console: document.cookie)")
        print("\nPaste EXACTLY the value of the cookie (no quotes).")
        print("-" * 40)

    @staticmethod
    def prompt_token() -> Optional[str]:
        CLI.show_cookie_instructions()
        try:
            tok = input("Paste ONE cookie token value (or 'exit' to cancel): ").strip()
            if tok.lower() in ("exit", "q"):
                return None
            if not tok:
                print("Token cannot be empty.")
                return None
            return tok
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return None

    @staticmethod
    def prompt_encrypt() -> bool:
        print("\nOptional: encrypt saved JSON.")
        while True:
            try:
                c = input("Encrypt output file? (y/n): ").strip().lower()
                if c in ("y", "n"):
                    return c == "y"
                print("Enter 'y' or 'n'.")
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.")
                return False

    @staticmethod
    def prompt_passphrase(msg: str) -> Optional[EncryptionManager]:
        while True:
            try:
                pw = getpass.getpass(msg)
                if not pw:
                    print("Passphrase cannot be empty.")
                    continue
                pw2 = getpass.getpass("Confirm passphrase: ")
                if pw == pw2:
                    return EncryptionManager(pw)
                print("Passphrases do not match.")
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.")
                return None

    def process_and_save(self, device_info: Dict[str, Any], enc: Optional[EncryptionManager]) -> None:
        serial = device_info.get("serial")
        restore = device_info.get("restoreCode")
        secret_hex = device_info.get("deviceSecret")
        if not all([serial, restore, secret_hex]):
            raise ValueError("Incomplete device info.")

        print("-" * 30)
        print("Authenticator:")
        print(f"  Serial: {serial}")
        print(f"  Restore Code: {restore}")
        print("-" * 30)

        base32_secret = self.auth.convert_secret_to_base32(secret_hex)
        label = f"Battle.net:{serial}"
        totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"

        print("\nTOTP:")
        print(f"  Base32: {base32_secret}")
        print(f"  URL: {totp_url}")
        print("  Algorithm: SHA1 | Digits: 8 | Period: 30s")

        data = {
            "serial": serial,
            "restoreCode": restore,
            "deviceSecret": secret_hex,
            "base32Secret": base32_secret,
            "totpUrl": totp_url,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

        base = f"battlenet_authenticator_{serial}"
        self.auth.save_json(f"{base}.json", data, enc)
        self.auth.generate_qr_code(totp_url, base)

    # Actions
    def handle_attach(self) -> None:
        token = self.prompt_token()
        if not token:
            return
        enc = self.prompt_encrypt()
        enc_mgr = self.prompt_passphrase("Passphrase for new file: ") if enc else None
        try:
            self.auth.get_bearer_token(token)
            device = self.auth.attach_authenticator()
            self.process_and_save(device, enc_mgr)
        except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
            print(f"\nAttach error: {e}", file=sys.stderr)

    def handle_retrieve(self) -> None:
        token = self.prompt_token()
        if not token:
            return
        enc = self.prompt_encrypt()
        enc_mgr = self.prompt_passphrase("Passphrase for retrieved file: ") if enc else None
        try:
            serial = input("Authenticator Serial: ").strip()
            restore = input("Restore Code: ").strip()
            if not serial or not restore:
                print("Serial and Restore Code required.")
                return
            self.auth.get_bearer_token(token)
            info = self.auth.retrieve_device_secret(serial, restore)
            device = {"serial": serial, "restoreCode": restore, "deviceSecret": info["deviceSecret"]}
            self.process_and_save(device, enc_mgr)
        except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
            print(f"\nRetrieve error: {e}", file=sys.stderr)

    def handle_reconstruct(self) -> None:
        p = self.select_json_file("Select JSON to reconstruct from")
        if not p:
            return
        enc_mgr: Optional[EncryptionManager] = None
        try:
            if self.is_encrypted(p):
                print(f"'{p.name}' looks encrypted.")
                enc_mgr = self.prompt_passphrase(f"Passphrase for '{p.name}': ")
                if not enc_mgr:
                    return
            data = self.auth.load_json(str(p), enc_mgr)
        except (FileNotFoundError, IOError, DecryptionError, json.JSONDecodeError) as e:
            print(f"\nLoad error: {e}", file=sys.stderr)
            return
        except Exception as e:
            print(f"\nUnexpected: {e}", file=sys.stderr)
            return

        serial = data.get("serial") or input("Serial missing. Enter Serial: ").strip()
        if not serial:
            print("Serial required.")
            return

        totp_url = data.get("totpUrl")
        base32_secret = data.get("base32Secret")
        hex_secret = data.get("deviceSecret")
        if not totp_url:
            if base32_secret:
                label = f"Battle.net:{serial}"
                totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"
            elif hex_secret:
                try:
                    base32_secret = self.auth.convert_secret_to_base32(hex_secret)
                    label = f"Battle.net:{serial}"
                    totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"
                except ValueError as e:
                    print(f"Secret conversion error: {e}", file=sys.stderr)
                    return
            else:
                print("No totpUrl/base32Secret/deviceSecret found.")
                return

        print("\nReconstructed TOTP:")
        if base32_secret:
            print(f"  Base32: {base32_secret}")
        print(f"  URL: {totp_url}")
        print("  Algorithm: SHA1 | Digits: 8 | Period: 30s")

        try:
            self.auth.generate_qr_code(totp_url, f"reconstructed_{serial}")
        except (IOError, Exception) as e:
            print(f"QR error: {e}", file=sys.stderr)

        input("\nPress Enter to continue...")

    def handle_encrypt_files(self) -> None:
        files = sorted([p for p in Path('.').glob('*.json') if p.is_file()])
        if not files:
            print("No JSON files found.")
            return
        plain = []
        for p in files:
            if not self.is_encrypted(p):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        json.load(f)
                    plain.append(p)
                except Exception:
                    pass
        if not plain:
            print("No plain JSON files to encrypt.")
            return
        print("\nPlain JSON files:")
        for i, p in enumerate(plain, 1):
            print(f"{i}. {p.name}")
        enc_mgr = self.prompt_passphrase("Passphrase for encryption: ")
        if not enc_mgr:
            return
        for p in plain:
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                BattleNetAuthenticator.save_json(str(p), data, enc_mgr)
            except Exception as e:
                print(f"Encrypt '{p.name}' failed: {e}", file=sys.stderr)

    def handle_decrypt_file(self) -> None:
        p = self.select_json_file("Select encrypted JSON to decrypt")
        if not p:
            return
        if not self.is_encrypted(p):
            print("Warning: File does not look encrypted; attempting anyway.")
        enc_mgr = self.prompt_passphrase(f"Passphrase for '{p.name}': ")
        if not enc_mgr:
            return
        try:
            data = self.auth.load_json(str(p), enc_mgr)
            while True:
                try:
                    c = input("Decryption OK. (V)iew, (S)ave decrypted copy, (C)ontinue: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\nCancelled.")
                    break
                if c == 'v':
                    print(json.dumps(data, indent=4, ensure_ascii=False))
                elif c == 's':
                    base = input("Base name for decrypted file (e.g. decrypted_data): ").strip()
                    if not base:
                        print("Name required.")
                        continue
                    out = f"{base}.json"
                    if Path(out).exists():
                        o = input(f"'{out}' exists. Overwrite? (y/n): ").strip().lower()
                        if o != 'y':
                            continue
                    try:
                        BattleNetAuthenticator.save_json(out, data, None)
                        break
                    except Exception as e:
                        print(f"Save failed: {e}", file=sys.stderr)
                elif c == 'c':
                    break
                else:
                    print("Choose V/S/C.")
        except Exception as e:
            print(f"Decrypt failed: {e}", file=sys.stderr)

    # Helpers
    @staticmethod
    def select_json_file(prompt: str) -> Optional[Path]:
        files = sorted([p for p in Path(".").glob("*.json") if p.is_file()])
        if not files:
            print("No JSON files found.")
            return None
        print("\nJSON files:")
        for i, f in enumerate(files, 1):
            print(f"{i}. {f.name}")
        while True:
            try:
                s = input(f"{prompt} (number or 'c' to cancel): ").strip().lower()
                if s == "c":
                    return None
                idx = int(s) - 1
                if 0 <= idx < len(files):
                    return files[idx]
                print(f"Enter 1..{len(files)}")
            except (ValueError, EOFError, KeyboardInterrupt):
                print("\nCancelled.")
                return None

    @staticmethod
    def is_encrypted(p: Path) -> bool:
        try:
            with open(p, "rb") as f:
                b = f.read(1024)
            obj = json.loads(b.decode("utf-8"))
            return isinstance(obj, dict) and all(k in obj for k in ("salt", "nonce", "ciphertext"))
        except Exception:
            return False

    def run(self) -> None:
        set_console_title()
        print_header()
        actions = {
            "1": ("Attach a new authenticator", self.handle_attach),
            "2": ("Retrieve existing device secret", self.handle_retrieve),
            "3": ("Reconstruct TOTP from JSON", self.handle_reconstruct),
            "4": ("Encrypt existing plain JSON file(s)", self.handle_encrypt_files),
            "5": ("Decrypt an encrypted JSON file", self.handle_decrypt_file),
            "6": ("Exit", lambda: graceful_exit()),
        }
        while True:
            print("\nChoose an action:")
            for k, (d, _) in actions.items():
                print(f"{k}. {d}")
            try:
                c = input("Choice: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                graceful_exit()
            sel = actions.get(c)
            if sel:
                _, fn = sel
                try:
                    fn()
                except KeyboardInterrupt:
                    print("\nCancelled by user.")
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    try:
        CLI().run()
    except KeyboardInterrupt:
        print()
        graceful_exit()
    except Exception as e:
        print(f"\nFATAL: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        graceful_exit(1)

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
    print("Please install dependencies using: pip install requests qrcode[pil] cryptography")
    sys.exit(1)

if platform.system() == "Windows":
    import ctypes

class AppConfig:
    TITLE = "Battle.net Authenticator Tool"
    VERSION = "1.3.1"
    AUTHOR = "Nighthawk42"
    LICENSE = "MIT"
    GITHUB_URL = "https://github.com/Nighthawk42/bnet_auth_tool"
    
    BASE_URL = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator"
    SSO_URL = "https://oauth.battle.net/oauth/sso"
    CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a"

    LEGACY_PBKDF2_ITERATIONS = 100_000
    DEFAULT_PBKDF2_ITERATIONS = 600_000
    SALT_SIZE = 16
    NONCE_SIZE = 12
    AES_KEY_SIZE = 32

class AuthenticatorError(Exception):
    pass

class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

def set_console_title(title: str = AppConfig.TITLE) -> None:
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()
    except Exception as e:
        print(f"Warning: Could not set console title - {e}", file=sys.stderr)

def graceful_exit(exit_code: int = 0) -> None:
    print("\nExiting the program. Ensure you have securely backed up your data.")
    sys.exit(exit_code)

def print_header() -> None:
    print(r"""
 ____          _    _    _                        _
| __ )   __ _ | |_ | |_ | |  ___     _ __    ___ | |_
|  _ \  / _` || __|| __|| | / _ \   | '_ \  / _ \| __|
| |_) || (_| || |_ | |_ | ||  __/ _ | | | ||  __/| |_
|____/  \__,_| \__| \__||_| \___|(_)|_| |_| \___| \__|


    _            _    _                   _    _               _
   / \    _   _ | |_ | |__    ___  _ __  | |_ (_)  ___   __ _ | |_   ___   _ __
  / _ \  | | | || __|| '_ \  / _ \| '_ \ | __|| | / __| / _` || __| / _ \ | '__|
 / ___ \ | |_| || |_ | | | ||  __/| | | || |_ | || (__ | (_| || |_ | (_) || |
/_/   \_\ \__,_| \__||_| |_| \___||_| |_| \__||_| \___| \__,_| \__| \___/ |_|


 _____                _
|_   _|  ___    ___  | |
  | |   / _ \  / _ \ | |
  | |  | (_) || (_) || |
  |_|   \___/  \___/ |_|

    """)
    print(f"{AppConfig.TITLE}")
    print(f"Version: {AppConfig.VERSION}")
    print(f"Author: {AppConfig.AUTHOR}")
    print(f"License: {AppConfig.LICENSE}")
    print(f"Github: {AppConfig.GITHUB_URL}")
    print("-" * 40)

class EncryptionManager:
    def __init__(self, passphrase: str):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        self.passphrase = passphrase.encode('utf-8')
        self.backend = default_backend()
        self.default_iterations = AppConfig.DEFAULT_PBKDF2_ITERATIONS

    def _derive_key(self, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AppConfig.AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(self.passphrase)

    def encrypt(self, data: Dict[str, Any]) -> bytes:
        try:
            json_data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
            salt = os.urandom(AppConfig.SALT_SIZE)
            key = self._derive_key(salt, self.default_iterations)
            aesgcm = AESGCM(key)
            nonce = os.urandom(AppConfig.NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, json_data_bytes, None)

            encrypted_package = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'kdf_iterations': self.default_iterations
            }
            return json.dumps(encrypted_package, indent=4).encode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_bytes: bytes) -> Dict[str, Any]:
        missing_iterations_field = False
        try:
            encrypted_data = json.loads(encrypted_bytes.decode('utf-8'))
            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])

            if 'kdf_iterations' in encrypted_data:
                stored_iterations = int(encrypted_data['kdf_iterations'])
            else:
                missing_iterations_field = True
                stored_iterations = AppConfig.LEGACY_PBKDF2_ITERATIONS
                print(f"Warning: 'kdf_iterations' field missing. Assuming legacy count ({AppConfig.LEGACY_PBKDF2_ITERATIONS}). Re-encrypt for better security.")

            key = self._derive_key(salt, stored_iterations)
            aesgcm = AESGCM(key)
            decrypted_data_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_data_bytes.decode('utf-8'))
        except InvalidTag:
            raise DecryptionError("Decryption failed: Authentication tag mismatch. Check passphrase or data integrity.")
        except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as e:
            extra_info = " (Note: Assumed legacy KDF iterations as field was missing)." if missing_iterations_field else ""
            raise DecryptionError(f"Decryption failed: Invalid data format or content. {e}{extra_info}") from e
        except Exception as e:
            raise DecryptionError(f"An unexpected error occurred during decryption: {e}") from e

class BattleNetAuthenticator:
    def __init__(self):
        self.bearer_token: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': f'{AppConfig.TITLE}/{AppConfig.VERSION}'})

    def _make_request(self, method: str, url: str, headers: Optional[Dict] = None,
                      data: Optional[Any] = None, json_payload: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)

            response = self.session.request(method, url, headers=request_headers, data=data, json=json_payload, timeout=20)
            response.raise_for_status()

            if response.status_code == 204:
                return {}
            
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                return response.json()
            else:
                raise AuthenticatorError(f"Unexpected content type '{content_type}' received from {url}.")

        except requests.exceptions.HTTPError as e:
            error_details = f" Server Response: {e.response.text[:500]}"
            raise AuthenticatorError(f"HTTP error {e.response.status_code} from {url}.{error_details}") from e
        except requests.exceptions.RequestException as e:
            raise AuthenticatorError(f"Request failed for {url}: {e}") from e
        except json.JSONDecodeError as e:
            raise AuthenticatorError(f"Failed to decode JSON response from {url}: {e}") from e

    def get_bearer_token(self, session_token: str) -> None:
        payload = {
            "client_id": AppConfig.CLIENT_ID,
            "grant_type": "client_sso",
            "scope": "auth.authenticator",
            "token": session_token,
        }
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        
        print("Requesting Bearer Token...")
        response_data = self._make_request("POST", AppConfig.SSO_URL, headers=headers, data=payload)

        access_token = response_data.get("access_token")
        if not access_token:
            raise AuthenticatorError("Bearer token not found in SSO response.")

        self.session.headers['Authorization'] = f"Bearer {access_token}"
        self.bearer_token = access_token
        print("Bearer Token obtained successfully.")

    def attach_authenticator(self) -> Dict[str, Any]:
        if 'Authorization' not in self.session.headers:
            raise AuthenticatorError("Bearer token not set. Call get_bearer_token first.")
        
        print("Attempting to attach a new authenticator...")
        response_data = self._make_request("POST", AppConfig.BASE_URL, headers={"accept": "application/json"})

        if not all(key in response_data for key in ["serial", "restoreCode", "deviceSecret"]):
            raise AuthenticatorError(f"API response missing expected keys. Got: {response_data.keys()}")

        print("Authenticator attached successfully.")
        return response_data

    def retrieve_device_secret(self, serial: str, restore_code: str) -> Dict[str, Any]:
        if 'Authorization' not in self.session.headers:
            raise AuthenticatorError("Bearer token not set. Call get_bearer_token first.")
        
        payload = {"serial": serial, "restoreCode": restore_code}
        url = f"{AppConfig.BASE_URL}/device"

        print(f"Attempting to retrieve secret for serial {serial}...")
        response_data = self._make_request("POST", url, json_payload=payload)

        if "deviceSecret" not in response_data:
            raise AuthenticatorError(f"API response missing 'deviceSecret'. Got: {response_data.keys()}")

        print("Device secret retrieved successfully.")
        return response_data

    @staticmethod
    def save_json(filename: str, data: Dict[str, Any], encryption_manager: Optional[EncryptionManager] = None) -> None:
        file_path = Path(filename)
        if file_path.exists():
            while True:
                try:
                    overwrite = input(f"'{filename}' already exists. Overwrite? (y/n): ").strip().lower()
                    if overwrite == "y": break
                    if overwrite == "n": print("Data not saved."); return
                    print("Invalid input.")
                except EOFError:
                    print("\nOperation cancelled."); return

        try:
            if encryption_manager:
                encrypted_data = encryption_manager.encrypt(data)
                file_path.write_bytes(encrypted_data)
                print(f"Encrypted data saved to '{filename}'.")
            else:
                file_path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding='utf-8')
                print(f"Data successfully saved to '{filename}'.")
            print("IMPORTANT: Securely back up this file and your passphrase if encrypted!")
        except IOError as e:
            raise IOError(f"Failed to write to '{filename}': {e}") from e

    @staticmethod
    def load_json(filename: str, encryption_manager: Optional[EncryptionManager] = None) -> Dict[str, Any]:
        file_path = Path(filename)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: '{filename}'")

        try:
            if encryption_manager:
                encrypted_bytes = file_path.read_bytes()
                data = encryption_manager.decrypt(encrypted_bytes)
                print(f"Decrypted data loaded from '{filename}'.")
                return data
            else:
                data = json.loads(file_path.read_text(encoding='utf-8'))
                print(f"Data loaded from '{filename}'.")
                return data
        except IOError as e:
            raise IOError(f"Failed to read from '{filename}': {e}") from e

    @staticmethod
    def convert_secret_to_base32(hex_secret: str) -> str:
        try:
            secret_bytes = binascii.unhexlify(hex_secret)
            return base64.b32encode(secret_bytes).decode("utf-8").rstrip("=")
        except (binascii.Error, TypeError) as e:
            raise ValueError(f"Failed to convert secret to Base32: Invalid hex input. ({e})") from e

    @staticmethod
    def generate_qr_code(totp_url: str, filename_base: str) -> None:
        filename = f"{filename_base}.png"
        try:
            print(f"Generating QR code '{filename}'...")
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(totp_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color='black', back_color='white')
            img.save(filename)
            print(f"QR code saved successfully as '{filename}'.")
        except IOError as e:
            raise IOError(f"Failed to save QR code image to '{filename}': {e}") from e
        except Exception as e:
            raise Exception(f"Error generating QR code image: {e}") from e

def _prompt_for_encryption() -> bool:
    print("\nEncryption adds a layer of security. You MUST remember your passphrase.")
    while True:
        try:
            choice = input("Encrypt the saved JSON file? (y/n): ").strip().lower()
            if choice in ['y', 'n']: return choice == 'y'
            print("Invalid input.")
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return False

def _prompt_for_passphrase(prompt_message: str = "Enter encryption passphrase: ") -> Optional[EncryptionManager]:
    while True:
        try:
            passphrase = getpass.getpass(prompt_message)
            if not passphrase:
                print("Passphrase cannot be empty.")
                continue
            if passphrase == getpass.getpass("Confirm passphrase: "):
                return EncryptionManager(passphrase)
            else:
                print("Passphrases do not match.")
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return None

def _get_session_token() -> Optional[str]:
    print("\n--- How to Get the Session Token ---")
    print("1. In a private browser window, navigate to: https://account.battle.net/login/en/?ref=localhost")
    print("2. Log in. You will land on an expected 'Page Not Found' on 'localhost'.")
    print("3. From the URL, copy the token value that looks like `ST=XX-...` (e.g., 'US-abc...').")
    print("-" * 36)
    try:
        session_token = input("Enter your Session Token (or 'exit'): ").strip()
        if session_token.lower() == "exit": return None
        if not session_token:
            print("Error: Session Token cannot be empty.")
            return None
        if not any(session_token.startswith(p) for p in ["US-", "EU-", "KR-", "TW-", "CN-"]) or len(session_token) < 20:
             print("Warning: Token format looks unusual. Ensure you copied the full value.")
        return session_token
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return None

def _process_and_save_results(authenticator: BattleNetAuthenticator, device_info: Dict[str, Any], encryption_manager: Optional[EncryptionManager]) -> None:
    serial = device_info.get("serial")
    restore_code = device_info.get("restoreCode")
    device_secret = device_info.get("deviceSecret")

    if not all([serial, restore_code, device_secret]):
        raise ValueError("Incomplete device information from API.")

    print("\n" + "-" * 30)
    print("Authenticator Details:")
    print(f"  Serial: {serial}")
    print(f"  Restore Code: {restore_code}")
    print("-" * 30)

    print("Generating TOTP Information...")
    base32_secret = authenticator.convert_secret_to_base32(device_secret)
    label = f"Battle.net:{serial}"
    totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"

    print("\n--- TOTP Key Details ---")
    print(f"Base32 Secret: {base32_secret}")
    print(f"TOTP URL: {totp_url}")
    print("\nApp Settings: Type=TOTP, Algorithm=SHA1, Digits=8, Period=30s")
    print("-" * 24)

    data_to_save = {
        "serial": serial,
        "restoreCode": restore_code,
        "deviceSecret": device_secret,
        "base32Secret": base32_secret,
        "totpUrl": totp_url,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds')
    }

    filename_base = f"battlenet_authenticator_{serial}"
    json_filename = f"{filename_base}.json"

    authenticator.save_json(json_filename, data_to_save, encryption_manager)
    authenticator.generate_qr_code(totp_url, filename_base)

def _handle_attach_action(authenticator: BattleNetAuthenticator) -> None:
    session_token = _get_session_token()
    if not session_token: return

    encryption_manager = _prompt_for_passphrase("Enter passphrase to encrypt new file: ") if _prompt_for_encryption() else None
    if _prompt_for_encryption() and not encryption_manager: return

    try:
        authenticator.get_bearer_token(session_token)
        device_info = authenticator.attach_authenticator()
        _process_and_save_results(authenticator, device_info, encryption_manager)
    except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
        print(f"\nError during attach process: {e}", file=sys.stderr)

def _handle_retrieve_action(authenticator: BattleNetAuthenticator) -> None:
    session_token = _get_session_token()
    if not session_token: return

    encryption_manager = _prompt_for_passphrase("Enter passphrase to encrypt retrieved file: ") if _prompt_for_encryption() else None
    if _prompt_for_encryption() and not encryption_manager: return

    try:
        serial = input("Enter the Authenticator Serial number: ").strip()
        restore_code = input("Enter the Authenticator Restore Code: ").strip()
        if not serial or not restore_code:
            print("Error: Serial and Restore Code are required.")
            return

        authenticator.get_bearer_token(session_token)
        retrieved_info = authenticator.retrieve_device_secret(serial, restore_code)
        device_info = {"serial": serial, "restoreCode": restore_code, "deviceSecret": retrieved_info["deviceSecret"]}
        _process_and_save_results(authenticator, device_info, encryption_manager)
    except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
        print(f"\nError during retrieve process: {e}", file=sys.stderr)

def _select_json_file(prompt: str) -> Optional[Path]:
    json_files = sorted([p for p in Path('.').glob('*.json') if p.is_file()])
    if not json_files:
        print("No JSON files found in the current directory.")
        return None

    print("\nFound the following JSON files:")
    for i, file in enumerate(json_files, 1):
        print(f"{i}. {file.name}")

    while True:
        try:
            choice = input(f"{prompt} (number or 'c' to cancel): ").strip().lower()
            if choice == 'c': return None
            index = int(choice) - 1
            if 0 <= index < len(json_files): return json_files[index]
            else: print(f"Invalid selection. Enter a number between 1 and {len(json_files)}.")
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nInvalid input or operation cancelled.")
            return None

def _is_file_likely_encrypted(file_path: Path) -> bool:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        data = json.loads(content[:1024])
        return isinstance(data, dict) and all(k in data for k in ('salt', 'nonce', 'ciphertext'))
    except (IOError, json.JSONDecodeError, ValueError):
        return False

def _handle_reconstruct_action(authenticator: BattleNetAuthenticator) -> None:
    selected_file = _select_json_file("Select JSON file to reconstruct from")
    if not selected_file: return

    encryption_manager: Optional[EncryptionManager] = None
    try:
        if _is_file_likely_encrypted(selected_file):
            print(f"File '{selected_file.name}' appears to be encrypted.")
            encryption_manager = _prompt_for_passphrase(f"Enter passphrase for '{selected_file.name}': ")
            if not encryption_manager: return

        data = authenticator.load_json(str(selected_file), encryption_manager)
    except (FileNotFoundError, IOError, DecryptionError, json.JSONDecodeError) as e:
        print(f"\nError loading file: {e}", file=sys.stderr)
        return

    serial = data.get("serial")
    if not serial:
        print("Could not find 'serial' in the JSON file.")
        return

    totp_url = data.get("totpUrl")
    if not totp_url:
        base32_secret = data.get("base32Secret") or authenticator.convert_secret_to_base32(data.get("deviceSecret", ""))
        if not base32_secret:
            print("Error: Could not find or derive a secret from the JSON file.")
            return
        label = f"Battle.net:{serial}"
        totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"
        print(f"Reconstructed TOTP URL: {totp_url}")

    print("\n--- Reconstructed TOTP Details ---")
    print(f"URL: {totp_url}")
    print("App Settings: Algorithm=SHA1, Digits=8, Period=30s")
    
    try:
        authenticator.generate_qr_code(totp_url, f"reconstructed_{serial}")
    except (IOError, Exception) as e:
        print(f"Error generating QR code: {e}", file=sys.stderr)
    
    input("\nPress Enter to return to the main menu...")

def _handle_encrypt_files_action(authenticator: BattleNetAuthenticator) -> None:
    json_files = sorted([p for p in Path('.').glob('*.json') if p.is_file()])
    if not json_files:
        print("No JSON files found to encrypt."); return

    plain_files = []
    print("\nChecking JSON files:")
    for file_path in json_files:
        if not _is_file_likely_encrypted(file_path):
            try:
                json.loads(file_path.read_text(encoding='utf-8'))
                plain_files.append(file_path)
                print(f" - {file_path.name} (Plain Text)")
            except (json.JSONDecodeError, IOError):
                print(f" - {file_path.name} (Not a valid plain JSON, skipping)")
        else:
            print(f" - {file_path.name} (Already Encrypted)")
    
    if not plain_files:
        print("\nNo plain text JSON files found to encrypt."); return

    encryption_manager = _prompt_for_passphrase("Enter passphrase for encryption: ")
    if not encryption_manager: return

    success, fail = 0, 0
    for file_path in plain_files:
        print(f"\nEncrypting '{file_path.name}'...")
        try:
            plain_data = json.loads(file_path.read_text(encoding='utf-8'))
            authenticator.save_json(str(file_path), plain_data, encryption_manager)
            success += 1
        except (IOError, EncryptionError, json.JSONDecodeError) as e:
            print(f"Error encrypting '{file_path.name}': {e}", file=sys.stderr)
            fail += 1
    print(f"\nEncryption complete. {success} succeeded, {fail} failed.")

def _handle_decrypt_file_action(authenticator: BattleNetAuthenticator) -> None:
    selected_file = _select_json_file("Select JSON file to decrypt")
    if not selected_file: return

    if not _is_file_likely_encrypted(selected_file):
        print(f"Warning: File '{selected_file.name}' may not be encrypted. Proceeding anyway.")

    encryption_manager = _prompt_for_passphrase(f"Enter passphrase for '{selected_file.name}': ")
    if not encryption_manager: return

    try:
        decrypted_data = authenticator.load_json(str(selected_file), encryption_manager)
        print("\nDecryption successful.")
        print(json.dumps(decrypted_data, indent=4, ensure_ascii=False))
        
        if input("\nSave decrypted data to a new file? (y/n): ").strip().lower() == 'y':
            new_filename = input("Enter new filename (e.g., decrypted.json): ").strip()
            if new_filename:
                authenticator.save_json(new_filename, decrypted_data, None)
            else:
                print("Invalid filename. Save cancelled.")

    except (IOError, DecryptionError, json.JSONDecodeError) as e:
        print(f"\nError during decryption: {e}", file=sys.stderr)

def interactive_cli() -> None:
    set_console_title()
    print_header()
    authenticator = BattleNetAuthenticator()

    actions = {
        "1": ("Attach a new authenticator", _handle_attach_action),
        "2": ("Retrieve existing device secret", _handle_retrieve_action),
        "3": ("Reconstruct TOTP from JSON", _handle_reconstruct_action),
        "4": ("Encrypt existing plain JSON file(s)", _handle_encrypt_files_action),
        "5": ("Decrypt an encrypted JSON file", _handle_decrypt_file_action),
        "6": ("Exit", lambda _: graceful_exit()),
    }

    while True:
        print("\nChoose an action:")
        for key, (desc, _) in actions.items():
            print(f"{key}. {desc}")

        try:
            choice = input("Enter your choice: ").strip()
            if choice in actions:
                actions[choice][1](authenticator)
            else:
                print("Invalid choice.")
        except (EOFError, KeyboardInterrupt):
            graceful_exit()

if __name__ == "__main__":
    try:
        interactive_cli()
    except Exception as e:
        print(f"\nFATAL ERROR: An unhandled exception occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        graceful_exit(1)

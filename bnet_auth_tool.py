# -*- coding: utf-8 -*-

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

print("Battle.net Authenticator Tool\nVersion 1.3.0 (04/01/2025)\nAuthor: Nighthawk42\nLicense: MIT\nGithub:https://github.com/Nighthawk42/bnet_auth_tool")

# --- Standard Library Imports ---
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

# --- Third-Party Imports ---
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

# --- Platform Specific Imports ---
if platform.system() == "Windows":
    import ctypes

# --- Constants ---
APP_TITLE = "Battle.net Authenticator Tool"
APP_VERSION = "1.3.0"
LEGACY_PBKDF2_ITERATIONS = 100_000 # Iteration count used in versions prior to 1.3
DEFAULT_PBKDF2_ITERATIONS = 600_000  # Increased iterations for stronger key derivation (OWASP recommendation as of late 2023)
SALT_SIZE = 16  # Bytes for PBKDF2 salt
NONCE_SIZE = 12 # Bytes for AES-GCM nonce
AES_KEY_SIZE = 32 # Bytes for AES-256 key


# --- Custom Exceptions ---
class AuthenticatorError(Exception):
    """Custom exception for Battle.net API related errors."""
    pass

class EncryptionError(Exception):
    """Custom exception for encryption failures."""
    pass

class DecryptionError(Exception):
    """Custom exception for decryption failures, including bad passphrases or format errors."""
    pass


# --- Utility Functions ---
def set_console_title(title: str = APP_TITLE) -> None:
    """Sets the console/window title."""
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            # ANSI escape sequence for other terminals (Linux, macOS)
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()
    except Exception as e:
        # Non-critical error if title setting fails
        print(f"Warning: Could not set console title - {e}", file=sys.stderr)

def graceful_exit(exit_code: int = 0) -> None:
    """Prints a backup reminder and exits the program."""
    print("\nExiting the program. Ensure you have securely backed up your data.")
    sys.exit(exit_code)

def print_header() -> None:
    """Prints the application header."""
    print(f"{APP_TITLE}\nVersion {APP_VERSION}\nAuthor: Nighthawk42\nLicense: MIT")
    print("-" * 40)


# --- Configuration ---
class Config:
    """Stores configuration constants for the Battle.net Authenticator API."""
    BASE_URL = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator" # API endpoint, hopefully Blizzard doesn't change this.
    SSO_URL = "https://oauth.battle.net/oauth/sso" # SSO endpoint for obtaining bearer token, again, hopefully Blizzard doesn't change this.
    CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a" # This Client ID appears publicly known and used by mobile apps. We are still unsure if it is needed. But we will keep it here.


# --- Encryption Logic ---
class EncryptionManager:
    """
    Handles encryption and decryption of data using AES-256-GCM with a key
    derived from a passphrase using PBKDF2-HMAC-SHA256.

    Includes backward compatibility for decrypting files created with older
    versions that used a different PBKDF2 iteration count.

    Security Note: The security of the encrypted data relies heavily on the
    strength and secrecy of the user's passphrase.
    """

    def __init__(self, passphrase: str):
        """
        Initializes the EncryptionManager with the user's passphrase.

        :param passphrase: The passphrase used for key derivation.
        :raises ValueError: If the passphrase is empty.
        """
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        self.passphrase = passphrase.encode('utf-8')
        self.backend = default_backend()
        self.default_iterations = DEFAULT_PBKDF2_ITERATIONS

    def _derive_key(self, salt: bytes, iterations: int) -> bytes:
        """
        Derives a cryptographic key from the passphrase and salt using PBKDF2.

        :param salt: A random salt unique to each encryption operation.
        :param iterations: The number of PBKDF2 iterations to use.
        :return: The derived 32-byte (256-bit) key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(self.passphrase)

    def encrypt(self, data: Dict[str, Any]) -> bytes:
        """
        Encrypts a dictionary using AES-256-GCM.

        Serializes the data to JSON, generates a salt and nonce, derives the key
        using the default high iteration count, encrypts the data, and returns
        a JSON structure containing the salt, nonce, ciphertext, and iteration count,
        all base64 encoded.

        :param data: The dictionary to encrypt.
        :return: Bytes representing the pretty-printed JSON of the encrypted structure.
        :raises EncryptionError: If serialization or encryption fails.
        """
        try:
            json_data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')

            salt = os.urandom(SALT_SIZE)
            key = self._derive_key(salt, self.default_iterations)
            aesgcm = AESGCM(key)
            nonce = os.urandom(NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, json_data_bytes, None) # No Associated Data

            encrypted_package = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                # Store the iterations used for this encryption operation
                'kdf_iterations': self.default_iterations
            }

            # Return pretty-printed JSON bytes for readability in the file
            return json.dumps(encrypted_package, indent=4).encode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_bytes: bytes) -> Dict[str, Any]:
        """
        Decrypts AES-256-GCM encrypted data previously encrypted by this class or older versions.

        Parses the JSON structure, decodes salt, nonce, and ciphertext.
        Determines the correct PBKDF2 iteration count (using stored value if present,
        otherwise defaulting to the legacy count for backward compatibility).
        Re-derives the key using the appropriate settings and decrypts the data.

        :param encrypted_bytes: The bytes containing the JSON encrypted structure.
        :return: The original decrypted dictionary.
        :raises DecryptionError: If parsing, decoding, key derivation, or decryption fails
                                 (e.g., wrong passphrase, corrupted data, invalid tag, iteration mismatch).
        """
        missing_iterations_field = False
        try:
            encrypted_data = json.loads(encrypted_bytes.decode('utf-8'))

            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])

            # --- Backward Compatibility Logic ---
            # Check if 'kdf_iterations' field exists. If not, assume it's from an older
            # version (<= 1.2) and use the LEGACY_PBKDF2_ITERATIONS count.
            if 'kdf_iterations' in encrypted_data:
                stored_iterations = int(encrypted_data['kdf_iterations'])
            else:
                missing_iterations_field = True
                stored_iterations = LEGACY_PBKDF2_ITERATIONS
                print(f"Warning: 'kdf_iterations' field missing in encrypted file. Assuming legacy count ({LEGACY_PBKDF2_ITERATIONS}).\nYou should consider re-encrypting with the latest version for better security.")
            # ------------------------------------

            # Derive the key using the determined iteration count
            key = self._derive_key(salt, stored_iterations)
            aesgcm = AESGCM(key)

            decrypted_data_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_data_bytes.decode('utf-8'))

        except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as e:
            extra_info = ""
            if missing_iterations_field:
                 extra_info = " (Note: Assumed legacy KDF iterations as field was missing)."
            raise DecryptionError(f"Decryption failed: Invalid data format or content. {e}{extra_info}") from e
        except InvalidTag:
            # This specifically indicates authentication failure (likely wrong passphrase or tampered data)
            raise DecryptionError("Decryption failed: Authentication tag mismatch. Check passphrase, data integrity, or KDF iterations used for encryption.")
        except Exception as e:
            raise DecryptionError(f"An unexpected error occurred during decryption: {e}") from e


# --- Battle.net API Interaction ---
class BattleNetAuthenticator:
    """
    Handles interactions with the Battle.net Authenticator REST API and
    manages authenticator data persistence (saving/loading JSON files).
    """

    def __init__(self):
        """Initializes the authenticator handler."""
        self.bearer_token: Optional[str] = None
        self.session = requests.Session() # Use a session for potential connection reuse
        # Add a user-agent for politeness
        self.session.headers.update({'User-Agent': f'{APP_TITLE}/{APP_VERSION}'})

    def _make_request(self, method: str, url: str, headers: Optional[Dict] = None,
                      data: Optional[Any] = None, json_payload: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Internal helper method to make HTTP requests and handle common errors.

        :param method: HTTP method ('GET', 'POST', etc.).
        :param url: The target URL.
        :param headers: Optional dictionary of headers.
        :param data: Optional data payload for form-encoded requests.
        :param json_payload: Optional dictionary payload for JSON requests.
        :return: The JSON response dictionary from the server.
        :raises AuthenticatorError: If the request fails (network error, bad status code, JSON decode error).
        """
        try:
            # Use headers from the session and update with any specific request headers
            request_headers = self.session.headers.copy()
            if headers:
                 request_headers.update(headers)

            response = self.session.request(
                method, url, headers=request_headers, data=data, json=json_payload, timeout=20 # Increased timeout slightly
            )
            response.raise_for_status()  # Raises HTTPError for bad status codes (4xx or 5xx)
            # Handle cases where response might be empty but successful (e.g., 204 No Content)
            if response.status_code == 204:
                 return {} # Return empty dict for no content success
            # Check content type before assuming JSON
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                return response.json()
            else:
                # Handle non-JSON successful responses if necessary, or raise error
                raise AuthenticatorError(f"Unexpected content type '{content_type}' received from {url}. Expected JSON.")

        except requests.exceptions.Timeout as e:
             raise AuthenticatorError(f"Request timed out connecting to {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise AuthenticatorError(f"Network error connecting to {url}: {e}") from e
        except requests.exceptions.HTTPError as e:
            error_details = ""
            try:
                # Try to parse JSON error response if possible
                if 'application/json' in response.headers.get('Content-Type', ''):
                    error_json = response.json()
                    error_details = f" Server Response: {json.dumps(error_json)}"
                else:
                    error_details = f" Server Response (non-JSON): {response.text[:500]}..." # Limit length
            except Exception:
                 error_details = f" Server Response (raw): {response.text[:500]}..." # Limit length

            raise AuthenticatorError(f"HTTP error {response.status_code} from {url}: {e}.{error_details}") from e
        except requests.exceptions.RequestException as e:
            raise AuthenticatorError(f"Request failed for {url}: {e}") from e
        except json.JSONDecodeError as e:
            raise AuthenticatorError(f"Failed to decode JSON response from {url}: {e}. Response text: {response.text[:500]}...") from e


    def get_bearer_token(self, session_token: str) -> None:
        """
        Retrieves a Bearer Token using the provided Battle.net Session Token (ST).

        :param session_token: The Battle.net session token (e.g., 'US-abc...').
        :raises AuthenticatorError: If the request fails or token is not found in response.
        """
        payload = {
            "client_id": Config.CLIENT_ID,
            "grant_type": "client_sso",
            "scope": "auth.authenticator",
            "token": session_token,
        }
        # Use specific headers for this request, not modifying session defaults
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        url = Config.SSO_URL

        print("Requesting Bearer Token...")
        response_data = self._make_request("POST", url, headers=headers, data=payload)

        access_token = response_data.get("access_token")
        if not access_token:
            raise AuthenticatorError("Bearer token ('access_token') not found in SSO response.")

        # Store token in the session headers for subsequent API calls
        self.session.headers['Authorization'] = f"Bearer {access_token}"
        self.bearer_token = access_token # Keep a copy if needed elsewhere
        print("Bearer Token obtained successfully and added to session.")


    def attach_authenticator(self) -> Dict[str, Any]:
        """
        Attaches a new virtual authenticator to the account associated with the bearer token.

        :return: A dictionary containing the new authenticator's 'serial', 'restoreCode', and 'deviceSecret'.
        :raises AuthenticatorError: If the bearer token is not set or the API request fails.
        """
        if 'Authorization' not in self.session.headers:
            raise AuthenticatorError("Bearer token is not set in session. Call get_bearer_token first.")

        headers = {"accept": "application/json"} # Authorization is handled by session
        url = Config.BASE_URL

        print("Attempting to attach a new authenticator...")
        response_data = self._make_request("POST", url, headers=headers)

        required_keys = ["serial", "restoreCode", "deviceSecret"]
        if not all(key in response_data for key in required_keys):
             raise AuthenticatorError(f"API response missing expected keys. Got: {response_data.keys()}")

        print("Authenticator attached successfully.")
        return response_data


    def retrieve_device_secret(self, serial: str, restore_code: str) -> Dict[str, Any]:
        """
        Retrieves the device secret for an existing authenticator using its serial and restore code.

        :param serial: The authenticator serial number.
        :param restore_code: The authenticator restore code.
        :return: A dictionary containing the 'deviceSecret'.
        :raises AuthenticatorError: If the bearer token is not set or the API request fails.
        """
        if 'Authorization' not in self.session.headers:
            raise AuthenticatorError("Bearer token is not set in session. Call get_bearer_token first.")

        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            # Authorization is handled by session
        }
        payload = {"serial": serial, "restoreCode": restore_code}
        url = f"{Config.BASE_URL}/device"

        print(f"Attempting to retrieve secret for serial {serial}...")
        response_data = self._make_request("POST", url, headers=headers, json_payload=payload)

        if "deviceSecret" not in response_data:
            raise AuthenticatorError(f"API response missing 'deviceSecret'. Got: {response_data.keys()}")

        print("Device secret retrieved successfully.")
        return response_data


    @staticmethod
    def save_json(filename: str, data: Dict[str, Any],
                  encryption_manager: Optional[EncryptionManager] = None) -> None:
        """
        Saves data to a JSON file, optionally encrypting it. Prompts to overwrite if the file exists.

        :param filename: The path to the file to save.
        :param data: The dictionary data to save.
        :param encryption_manager: An optional EncryptionManager instance to use for encryption.
                                    If provided, data will be encrypted before saving.
        :raises IOError: If saving the file fails.
        :raises EncryptionError: If encryption fails when requested.
        """
        file_path = Path(filename)
        if file_path.exists():
            while True:
                try:
                    overwrite = input(f"'{filename}' already exists. Overwrite? (y/n): ").strip().lower()
                    if overwrite == "y":
                        break
                    if overwrite == "n":
                        print("Data not saved.")
                        return
                    print("Invalid input. Please enter 'y' or 'n'.")
                except EOFError: # Handle Ctrl+D/Ctrl+Z
                     print("\nOperation cancelled.")
                     return

        try:
            if encryption_manager:
                encrypted_data = encryption_manager.encrypt(data) # Can raise EncryptionError
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
                print(f"Encrypted data successfully saved to '{filename}'.")
            else:
                with open(file_path, "w", encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                print(f"Data successfully saved to '{filename}'.")
            print("IMPORTANT: Ensure you securely back up this file and remember your passphrase if encrypted!")
        except IOError as e:
            # Provide more specific error context if possible
            raise IOError(f"Failed to write data to '{filename}': {e}") from e
        # EncryptionError is implicitly raised by encryption_manager.encrypt


    @staticmethod
    def load_json(filename: str,
                  encryption_manager: Optional[EncryptionManager] = None) -> Dict[str, Any]:
        """
        Loads data from a JSON file, optionally decrypting it using the provided manager.

        :param filename: The path to the file to load.
        :param encryption_manager: An EncryptionManager instance configured with the correct
                                    passphrase if decryption is required. If None, loads as plain JSON.
        :return: The loaded (and potentially decrypted) dictionary data.
        :raises FileNotFoundError: If the file does not exist.
        :raises IOError: If reading the file fails.
        :raises DecryptionError: If decryption fails when requested (passed manager).
        :raises json.JSONDecodeError: If the file content is not valid JSON (when not decrypting).
        """
        file_path = Path(filename)
        if not file_path.is_file(): # More specific check
            raise FileNotFoundError(f"File not found or is not a regular file: '{filename}'")

        try:
            if encryption_manager:
                with open(file_path, "rb") as f:
                    encrypted_bytes = f.read()
                # DecryptionError can be raised here by the manager
                data = encryption_manager.decrypt(encrypted_bytes)
                print(f"Decrypted data loaded successfully from '{filename}'.")
                return data
            else:
                with open(file_path, "r", encoding='utf-8') as f:
                    # json.JSONDecodeError might be raised here
                    data = json.load(f)
                print(f"Data loaded successfully from '{filename}'.")
                return data
        except IOError as e:
            raise IOError(f"Failed to read data from '{filename}': {e}") from e


    @staticmethod
    def convert_secret_to_base32(hex_secret: str) -> str:
        """
        Converts a hexadecimal device secret string to Base32 encoding (RFC 4648, no padding).

        :param hex_secret: The hexadecimal secret string.
        :return: The Base32 encoded secret string without padding ('=').
        :raises ValueError: If the input is not valid hexadecimal or conversion fails.
        """
        try:
            # Ensure hex string has even length for unhexlify
            if len(hex_secret) % 2 != 0:
                raise binascii.Error("Odd-length string")
            secret_bytes = binascii.unhexlify(hex_secret)
            base32_secret = base64.b32encode(secret_bytes).decode("utf-8").rstrip("=")
            return base32_secret
        except (binascii.Error, TypeError) as e:
            raise ValueError(f"Failed to convert secret to Base32: Invalid hex input? ({e})") from e


    @staticmethod
    def generate_qr_code(totp_url: str, filename_base: str) -> None:
        """
        Generates a QR code image for the given TOTP URL and saves it as a PNG file.

        :param totp_url: The 'otpauth://' URL.
        :param filename_base: The base name for the output PNG file (e.g., "authenticator_serial").
        :raises IOError: If saving the QR code image fails.
        :raises Exception: For errors during QR code generation itself.
        """
        filename = f"{filename_base}.png"
        try:
            print(f"Generating QR code '{filename}'...")
            qr = qrcode.QRCode(
                # version=1, # Let library choose appropriate version
                error_correction=qrcode.constants.ERROR_CORRECT_L, # L=Low (7%), M(15%), Q(25%), H(30%) redundancy
                box_size=10, # Size of each box in pixels
                border=4, # Thickness of border in boxes (4 is default)
            )
            qr.add_data(totp_url)
            qr.make(fit=True)

            img = qr.make_image(fill_color='black', back_color='white')
            img.save(filename)
            print(f"QR code saved successfully as '{filename}'.")
        except IOError as e:
            raise IOError(f"Failed to save QR code image to '{filename}': {e}") from e
        except Exception as e: # Catch potential errors from qrcode library
            raise Exception(f"Error generating QR code image: {e}") from e


# --- CLI Helper Functions ---

def _prompt_for_encryption() -> bool:
    """Asks the user if they want to encrypt the output file."""
    print("\nEncryption adds a layer of security to your sensitive authenticator data.")
    print("If you choose to encrypt, you MUST remember your passphrase.")
    while True:
        try:
            choice = input("Do you want to encrypt the saved JSON file? (y/n): ").strip().lower()
            if choice == 'y':
                return True
            if choice == 'n':
                return False
            print("Invalid input. Please enter 'y' or 'n'.")
        except EOFError:
            print("\nOperation cancelled.")
            return False # Default to no encryption if cancelled
        except KeyboardInterrupt:
             print("\nOperation cancelled.")
             return False

def _prompt_for_passphrase(prompt_message: str = "Enter encryption passphrase: ") -> Optional[EncryptionManager]:
    """Prompts the user for an encryption passphrase and confirmation."""
    while True:
        try:
            passphrase = getpass.getpass(prompt_message)
            if not passphrase:
                print("Passphrase cannot be empty. Please try again.")
                continue
            confirm_passphrase = getpass.getpass("Confirm passphrase: ")
            if passphrase == confirm_passphrase:
                try:
                    # Return the manager instance directly
                    return EncryptionManager(passphrase)
                except ValueError as e: # Catch empty passphrase error from EncryptionManager init
                     print(f"Error initializing encryption: {e}")
                     # This shouldn't happen due to the check above, but belt-and-suspenders
                     continue
            else:
                print("Passphrases do not match. Please try again.")
        except EOFError:
            print("\nOperation cancelled.")
            return None
        except KeyboardInterrupt:
             print("\nOperation cancelled.")
             return None


def _get_session_token() -> Optional[str]:
    """Shows instructions and prompts the user for the Battle.net Session Token."""
    print("\n--- How to Get the Session Token ---")
    print("1. Open your web browser (preferably in Incognito/Private mode).")
    print("2. Navigate to: https://account.battle.net/login/en/?ref=localhost")
    print("3. Log in to your Battle.net account.")
    print("4. You should land on a 'Page Not Found' or similar error page on 'localhost'. This is expected.")
    print("5. Look at the full URL in your browser's address bar.")
    print("6. Find the part that looks like `ST=XX-........` (where XX is region like US/EU/KR).")
    print("7. Copy the *entire* token value starting from the region prefix (e.g., 'US-abcdef1234567890abcdef1234567890').")
    print("-" * 36)
    try:
        session_token = input("Enter your Session Token (or type 'exit' to quit): ").strip()
        if session_token.lower() == "exit":
            return None
        if not session_token:
            print("Error: Session Token cannot be empty.")
            return None # Indicate error/cancel
        # Basic validation (starts with region prefix, approx length)
        if not any(session_token.startswith(prefix) for prefix in ["US-", "EU-", "KR-", "TW-", "CN-"]) or len(session_token) < 20: # Increased min length check
             print("Warning: Token format looks unusual. Ensure you copied the full ST= value.")
        return session_token
    except EOFError:
        print("\nOperation cancelled.")
        return None
    except KeyboardInterrupt:
         print("\nOperation cancelled.")
         return None

def _process_and_save_results(authenticator: BattleNetAuthenticator,
                              device_info: Dict[str, Any],
                              encryption_manager: Optional[EncryptionManager]) -> None:
    """
    Processes authenticator results, generates TOTP info, saves JSON, and creates QR code.

    :param authenticator: The BattleNetAuthenticator instance.
    :param device_info: Dictionary containing 'serial', 'restoreCode', 'deviceSecret'.
    :param encryption_manager: Optional EncryptionManager if encryption is enabled.
    :raises ValueError: If required keys are missing in device_info or secret conversion fails.
    :raises IOError: If saving JSON or QR code fails.
    :raises EncryptionError: If JSON encryption fails.
    :raises Exception: For QR code generation errors.
    """
    serial = device_info.get("serial")
    restore_code = device_info.get("restoreCode")
    device_secret = device_info.get("deviceSecret")

    if not all([serial, restore_code, device_secret]):
        raise ValueError("Incomplete device information received from API.")

    print("-" * 30)
    print("Authenticator Details:")
    print(f"  Serial: {serial}")
    print(f"  Restore Code: {restore_code}")
    # Do NOT print the deviceSecret directly unless explicitly debugging
    # print(f"  Device Secret (Hex): {device_secret}")
    print("-" * 30)

    print("Generating TOTP Information...")
    try:
        # Raises ValueError on failure
        base32_secret = authenticator.convert_secret_to_base32(device_secret)
    except ValueError as e:
        print(f"Error converting secret: {e}", file=sys.stderr)
        raise # Re-raise to indicate failure

    # Create TOTP URL (RFC 6238 format)
    # URL Encode the label part which might contain spaces or special chars if user has odd account name
    # For serial numbers this is likely not needed, but good practice.
    label = f"Battle.net:{serial}" # Standard practice label
    # from urllib.parse import quote
    # label_encoded = quote(label)
    totp_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"

    print("\n--- TOTP Key Details ---")
    print(f"Base32 Secret: {base32_secret}")
    print(f"TOTP URL: {totp_url}")
    print("\nIMPORTANT: When adding this to your authenticator app:")
    print("  - Method: Scan QR code OR Enter setup key (Base32)")
    print("  - Account Name/Label: Your choice (e.g., Battle.net, Bnet AccName)")
    print("  - Key: Use the Base32 Secret shown above if entering manually.")
    print("  - Type: TOTP (Time-based)")
    print("  - Algorithm: SHA1")
    print("  - Digits: 8")
    print("  - Period/Interval: 30 seconds")
    print("-" * 24)

    # Prepare data for saving
    data_to_save = {
        "serial": serial,
        "restoreCode": restore_code,
        "deviceSecret": device_secret, # Store the original hex secret
        "base32Secret": base32_secret, # Store the derived base32 for convenience
        "totpUrl": totp_url,           # Store the full URL
        # Store timestamp in UTC timezone, ISO 8601 format
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds')
    }

    # Save data and generate QR code
    filename_base = f"battlenet_authenticator_{serial}"
    json_filename = f"{filename_base}.json"

    # Save JSON (Handles overwrite prompt internally)
    # Raises IOError, EncryptionError
    authenticator.save_json(json_filename, data_to_save, encryption_manager)

    # Generate QR Code
    # Raises IOError, Exception
    authenticator.generate_qr_code(totp_url, filename_base)


def _handle_attach_action(authenticator: BattleNetAuthenticator) -> None:
    """Handles the 'Attach New Authenticator' workflow."""
    session_token = _get_session_token()
    if not session_token:
        return # User cancelled or error

    encrypt = _prompt_for_encryption()
    encryption_manager = None
    if encrypt:
        encryption_manager = _prompt_for_passphrase("Enter passphrase to encrypt new file: ")
        if not encryption_manager:
            return # User cancelled passphrase entry

    try:
        # Order matters: Get token -> Attach -> Process/Save
        authenticator.get_bearer_token(session_token)
        device_info = authenticator.attach_authenticator()
        _process_and_save_results(authenticator, device_info, encryption_manager)

    except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
        # Catch broader exceptions here as QR generation is included
        print(f"\nError during attach process: {e}", file=sys.stderr)


def _handle_retrieve_action(authenticator: BattleNetAuthenticator) -> None:
    """Handles the 'Retrieve Existing Secret' workflow."""
    session_token = _get_session_token()
    if not session_token:
        return

    encrypt = _prompt_for_encryption()
    encryption_manager = None
    if encrypt:
        encryption_manager = _prompt_for_passphrase("Enter passphrase to encrypt retrieved file: ")
        if not encryption_manager:
            return

    try:
        serial = input("Enter the Authenticator Serial number: ").strip()
        restore_code = input("Enter the Authenticator Restore Code: ").strip()

        if not serial or not restore_code:
            print("Error: Serial and Restore Code are required.")
            return

        # Order matters: Get token -> Retrieve -> Process/Save
        authenticator.get_bearer_token(session_token)
        retrieved_info = authenticator.retrieve_device_secret(serial, restore_code)

        # The retrieve endpoint only returns the secret, we need serial/restore from input
        device_info = {
            "serial": serial,
            "restoreCode": restore_code,
            "deviceSecret": retrieved_info["deviceSecret"]
        }
        _process_and_save_results(authenticator, device_info, encryption_manager)

    except (AuthenticatorError, EncryptionError, IOError, ValueError, Exception) as e:
        print(f"\nError during retrieve process: {e}", file=sys.stderr)


def _select_json_file(prompt: str) -> Optional[Path]:
    """Lists JSON files in the current directory and prompts the user to select one."""
    json_files = sorted([p for p in Path('.').glob('*.json') if p.is_file()])
    if not json_files:
        print("No JSON files found in the current directory.")
        return None

    print("\nFound the following JSON files:")
    for i, file in enumerate(json_files, 1):
        print(f"{i}. {file.name}")

    while True:
        try:
            choice = input(f"{prompt} (enter number, or 'c' to cancel): ").strip().lower()
            if choice == 'c':
                return None
            index = int(choice) - 1
            if 0 <= index < len(json_files):
                return json_files[index]
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(json_files)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except EOFError:
            print("\nOperation cancelled.")
            return None
        except KeyboardInterrupt:
             print("\nOperation cancelled.")
             return None


def _is_file_likely_encrypted(file_path: Path) -> bool:
    """Checks if a file appears to be in our encrypted JSON format."""
    try:
        with open(file_path, "rb") as f:
            content_bytes = f.read(1024) # Read only the beginning for efficiency
        potential_json = json.loads(content_bytes.decode('utf-8'))
        return isinstance(potential_json, dict) and all(k in potential_json for k in ('salt', 'nonce', 'ciphertext'))
    except (IOError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return False


def _handle_reconstruct_action(authenticator: BattleNetAuthenticator) -> None:
    """Handles reconstructing TOTP info from a saved JSON file."""
    selected_file = _select_json_file("Enter the number of the JSON file to reconstruct from")
    if not selected_file:
        return

    data: Optional[Dict[str, Any]] = None
    encryption_manager: Optional[EncryptionManager] = None

    try:
        # Determine if file seems encrypted and prompt for passphrase if needed
        is_encrypted = _is_file_likely_encrypted(selected_file)
        if is_encrypted:
            print(f"File '{selected_file.name}' appears to be encrypted.")
            encryption_manager = _prompt_for_passphrase(f"Enter passphrase for '{selected_file.name}': ")
            if not encryption_manager:
                return # User cancelled passphrase

        # Load the file using the determined method (decrypt if manager is present)
        data = authenticator.load_json(str(selected_file), encryption_manager)

    except (FileNotFoundError, IOError, DecryptionError, json.JSONDecodeError) as e:
        print(f"\nError loading or processing file: {e}", file=sys.stderr)
        return
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        return

    if not data:
        print("Failed to load data from the file.")
        return

    # --- Extract Info & Reconstruct ---
    serial = data.get("serial")
    # restore_code = data.get("restoreCode") # Not strictly needed for reconstruct
    device_secret = data.get("deviceSecret")
    base32_secret = data.get("base32Secret")
    totp_url = data.get("totpUrl")

    # Get serial if missing (shouldn't happen with well-formed files)
    if not serial:
        try:
            serial = input("Serial number not found in JSON, please enter manually: ").strip()
            if not serial: print("Serial is required."); return
        except (EOFError, KeyboardInterrupt): print("\nCancelled."); return

    reconstructed_url = None
    if totp_url:
        print("\nReconstructed TOTP URL from file:")
        print(totp_url)
        reconstructed_url = totp_url
    elif base32_secret:
        print("\nReconstructed Base32 Secret from file:")
        print(base32_secret)
        label = f"Battle.net:{serial}" # Reconstruct label if needed
        reconstructed_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"
        print(f"Reconstructed TOTP URL: {reconstructed_url}")
    elif device_secret:
        print("Device Secret (Hex) found, converting to Base32...")
        try:
            base32_secret = authenticator.convert_secret_to_base32(device_secret)
            print(f"Reconstructed Base32 Secret: {base32_secret}")
            label = f"Battle.net:{serial}"
            reconstructed_url = f"otpauth://totp/{label}?secret={base32_secret}&issuer=Battle.net&digits=8&algorithm=SHA1&period=30"
            print(f"Reconstructed TOTP URL: {reconstructed_url}")
        except ValueError as e:
            print(f"Error converting stored device secret: {e}", file=sys.stderr)
            print("Cannot generate TOTP URL or QR code.")
    else:
        print("Error: Could not find 'totpUrl', 'base32Secret', or 'deviceSecret' in the JSON file.")
        return

    print("\n--- TOTP Key Details (Reconstructed) ---")
    print("Ensure your authenticator app uses these settings:")
    print("  - Algorithm: SHA1")
    print("  - Digits: 8")
    print("  - Period/Interval: 30 seconds")
    print("-" * 24)

    # Generate QR if we have a URL
    if reconstructed_url:
        try:
            qr_filename_base = f"reconstructed_{serial}"
            authenticator.generate_qr_code(reconstructed_url, qr_filename_base)
        except (IOError, Exception) as e:
            print(f"Error generating QR code: {e}", file=sys.stderr)

    input("\nPress Enter to return to the main menu...")


def _handle_encrypt_files_action(authenticator: BattleNetAuthenticator) -> None:
    """Handles encrypting existing plain JSON files."""
    all_json_files = sorted([p for p in Path('.').glob('*.json') if p.is_file()])
    if not all_json_files:
        print("No JSON files found to encrypt.")
        return

    print("\nChecking JSON files for encryption status:")
    plain_files: List[Tuple[int, Path]] = []
    file_statuses: List[str] = []

    for i, file_path in enumerate(all_json_files, 1):
        status = ""
        try:
            if _is_file_likely_encrypted(file_path):
                status = " (Already Encrypted)"
            else:
                # Attempt to load as plain JSON to confirm format
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                    status = " (Plain Text JSON)"
                    plain_files.append((i, file_path))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    status = " (Not Plain JSON)"
                except Exception: # Catch other potential loading errors
                    status = " (Error Reading/Parsing)"

        except IOError:
            status = " (Error Accessing)"
        file_statuses.append(f"{i}. {file_path.name}{status}")

    for status_line in file_statuses:
        print(status_line)

    if not plain_files:
         print("\nNo plain JSON files suitable for encryption were found.")
         return

    print("\nSelect plain JSON files to encrypt:")
    plain_file_map = {idx: (num, path) for idx, (num, path) in enumerate(plain_files, 1)}
    for idx, (num, path) in plain_file_map.items():
         print(f"{idx}. {path.name} (Original file #{num})")

    while True:
        try:
            choices_str = input("Enter numbers to encrypt (e.g., 1,3), 'all', or 'c' to cancel: ").strip().lower()
            if choices_str == 'c': return
            files_to_encrypt_paths: List[Path] = []
            if choices_str == 'all':
                files_to_encrypt_paths = [path for _, path in plain_file_map.values()]
                break
            else:
                selected_indices = [int(x.strip()) for x in choices_str.split(',')]
                if all(idx in plain_file_map for idx in selected_indices):
                    files_to_encrypt_paths = [plain_file_map[idx][1] for idx in selected_indices]
                    break
                else:
                    print("Invalid selection number(s). Choose from the list above.")
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas, 'all', or 'c'.")
        except EOFError: print("\nCancelled."); return
        except KeyboardInterrupt: print("\nCancelled."); return

    if not files_to_encrypt_paths:
         print("No files selected for encryption.")
         return

    print("\nPreparing to encrypt the following files:")
    for file_path in files_to_encrypt_paths:
        print(f" - {file_path.name}")

    encryption_manager = _prompt_for_passphrase("Enter passphrase for encryption: ")
    if not encryption_manager:
        print("Encryption cancelled.")
        return

    success_count = 0
    fail_count = 0
    for file_path in files_to_encrypt_paths:
        print(f"\nEncrypting '{file_path.name}'...")
        try:
            # Load plain data (already verified it's likely plain JSON)
            with open(file_path, "r", encoding='utf-8') as f:
                plain_data = json.load(f)

            # Save using the save_json function (handles encryption and overwrite prompt)
            authenticator.save_json(str(file_path), plain_data, encryption_manager)
            success_count += 1
        except (IOError, EncryptionError, json.JSONDecodeError) as e:
            print(f"Error encrypting '{file_path.name}': {e}", file=sys.stderr)
            fail_count += 1
        except Exception as e:
             print(f"Unexpected error encrypting '{file_path.name}': {e}", file=sys.stderr)
             fail_count += 1

    print(f"\nEncryption complete. {success_count} succeeded, {fail_count} failed.")


def _handle_decrypt_file_action(authenticator: BattleNetAuthenticator) -> None:
    """Handles decrypting an encrypted JSON file."""
    selected_file = _select_json_file("Enter the number of the JSON file to decrypt")
    if not selected_file:
        return

    if not _is_file_likely_encrypted(selected_file):
         print(f"Warning: File '{selected_file.name}' does not appear to be in the expected encrypted format. Proceeding anyway...")
         # Allow user to try decrypting anyway, might be useful if check failed

    print(f"\nAttempting to decrypt '{selected_file.name}'...")
    encryption_manager = _prompt_for_passphrase(f"Enter passphrase for '{selected_file.name}': ")
    if not encryption_manager:
        print("Decryption cancelled.")
        return

    try:
        # Load and decrypt
        decrypted_data = authenticator.load_json(str(selected_file), encryption_manager)

        # Prompt user for action
        while True:
            try:
                 action = input("Decryption successful. (V)iew data, (S)ave decrypted to new file, or (C)ontinue? ").strip().lower()
            except (EOFError, KeyboardInterrupt): print("\nCancelled."); break

            if action == 'v':
                print("\n--- Decrypted Data ---")
                print(json.dumps(decrypted_data, indent=4, ensure_ascii=False))
                print("-" * 20)
                # Continue loop after viewing
            elif action == 's':
                saved = False
                while not saved:
                     try:
                          new_filename_base = input("Enter base name for the decrypted file (e.g., decrypted_data) or 'c' to cancel save: ").strip()
                          if new_filename_base.lower() == 'c': break # Cancel saving, go back to v/s/c prompt
                          if new_filename_base:
                               new_filename = f"{new_filename_base}.json"
                               if Path(new_filename).exists():
                                    ovr = input(f"'{new_filename}' exists. Overwrite? (y/n): ").lower()
                                    if ovr != 'y': continue # Ask for filename again
                               try:
                                    # Save using save_json but WITHOUT encryption manager
                                    authenticator.save_json(new_filename, decrypted_data, None)
                                    saved = True # Exit inner loop on success
                               except IOError as e:
                                    print(f"Error saving decrypted file: {e}", file=sys.stderr)
                                    # Stay in loop to ask again or let user cancel
                          else:
                               print("Filename cannot be empty.")
                     except (EOFError, KeyboardInterrupt): print("\nSave cancelled."); break # Break inner loop
                if saved: break # Exit outer loop after successful save
                # If save was cancelled, outer loop continues (v/s/c prompt)

            elif action == 'c':
                break # Exit outer loop
            else:
                print("Invalid choice.")

    except (FileNotFoundError, IOError, DecryptionError, json.JSONDecodeError) as e:
        print(f"\nError during decryption process: {e}", file=sys.stderr)
    except Exception as e:
         print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)


# --- Main Execution ---
def interactive_cli() -> None:
    """Runs the main interactive command-line interface."""
    set_console_title()
    print_header()

    # Create a single authenticator instance for the session
    authenticator = BattleNetAuthenticator()

    actions = {
        "1": ("Attach a new authenticator", _handle_attach_action),
        "2": ("Retrieve existing device secret", _handle_retrieve_action),
        "3": ("Reconstruct TOTP from JSON", _handle_reconstruct_action),
        "4": ("Encrypt existing plain JSON file(s)", _handle_encrypt_files_action),
        "5": ("Decrypt an encrypted JSON file", _handle_decrypt_file_action),
        "6": ("Exit", lambda _: graceful_exit()), # Lambda takes dummy arg
    }

    while True:
        print("\nChoose an action:")
        for key, (desc, _) in actions.items():
            print(f"{key}. {desc}")

        try:
            choice = input("Enter your choice: ").strip()
        except EOFError:
             print() # Newline after Ctrl+D
             graceful_exit()
        except KeyboardInterrupt:
             print() # Newline after Ctrl+C
             graceful_exit()


        selected_action = actions.get(choice)

        if selected_action:
            _, action_func = selected_action
            try:
                 action_func(authenticator) # Pass authenticator instance
            except KeyboardInterrupt:
                 print("\nOperation cancelled by user.")
                 # Continue loop after cancellation within an action
            # Let specific handlers print their errors, loop continues
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    try:
        interactive_cli()
    except KeyboardInterrupt:
        # Catch Ctrl+C in the main loop prompt itself
        print() # Newline after Ctrl+C
        graceful_exit()
    except Exception as e:
        # Catch any truly unexpected errors that weren't handled
        print(f"\nFATAL ERROR: An unhandled exception occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        graceful_exit(1)
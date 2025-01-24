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

print("Battle.net Authenticator Tool\nVersion 1.2 (01/23/2025)\nAuthor: Nighthawk42\nLicense: MIT")

import json
import base64
import binascii
import requests
from pathlib import Path
import sys
import os
import qrcode
from typing import Any, Dict
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class Title:
    """Console/Window Title."""
    if sys.platform == "win32":
        os.system('title Battle.net Authenticator Tool')
    else:
        sys.stdout.write("\x1b]2;Battle.net Authenticator Tool\x07")

class Config:
    """Configuration for Battle.net Authenticator API."""
    BASE_URL = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator"
    SSO_URL = "https://oauth.battle.net/oauth/sso"
    CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a"

class EncryptionManager:
    """Handles encryption and decryption of JSON files using AES-256-GCM."""

    def __init__(self, passphrase: str):
        self.passphrase = passphrase.encode()  # Convert to bytes
        self.backend = default_backend()
        self.iterations = 100_000  # Number of iterations for KDF

    def derive_key(self, salt: bytes) -> bytes:
        """Derives a cryptographic key from the passphrase and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 key size
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(self.passphrase)

    def encrypt(self, data: dict) -> bytes:
        """Encrypts a dictionary and returns the encrypted data."""
        # Serialize the data to JSON and then to bytes
        json_data = json.dumps(data).encode('utf-8')

        # Generate a random salt
        salt = os.urandom(16)

        # Derive key
        key = self.derive_key(salt)

        # Initialize AESGCM with the derived key
        aesgcm = AESGCM(key)

        # Generate a random nonce
        nonce = os.urandom(12)

        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, json_data, None)

        # Store salt, nonce, and ciphertext together with indentation for readability
        encrypted_data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

        # Return pretty-printed JSON bytes
        return json.dumps(encrypted_data, indent=4).encode('utf-8')

    def decrypt(self, encrypted_bytes: bytes) -> dict:
        """Decrypts the encrypted bytes and returns the original dictionary."""
        try:
            # Deserialize the encrypted data
            encrypted_data = json.loads(encrypted_bytes.decode('utf-8'))

            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])

            # Derive key
            key = self.derive_key(salt)

            # Initialize AESGCM with the derived key
            aesgcm = AESGCM(key)

            # Decrypt the data
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

            # Deserialize JSON
            return json.loads(decrypted_data.decode('utf-8'))

        except (KeyError, ValueError, json.JSONDecodeError) as e:
            raise Exception(f"Decryption failed: {e}")

class BattleNetAuthenticator:
    """
    Handles Battle.net Authenticator operations, including attaching an authenticator,
    retrieving device secrets, and generating TOTP keys.
    """

    def __init__(self, encryption_manager: EncryptionManager = None):
        self.bearer_token = None
        self.encryption_manager = encryption_manager

    def save_json(self, filename: str, data: Dict[str, Any], encrypt: bool = False) -> None:
        """
        Saves data to a JSON file with optional encryption, prompting to overwrite if the file exists.
        """
        if Path(filename).exists():
            while True:
                overwrite = input(f"{filename} already exists. Do you want to overwrite it? (y/n): ").strip().lower()
                if overwrite in {"y", "n"}:
                    break
                print("Invalid input. Please enter 'y' or 'n'.")

            if overwrite != "y":
                print("Data not saved.")
                return

        try:
            if encrypt and self.encryption_manager:
                # Encrypt the data before saving
                encrypted_data = self.encryption_manager.encrypt(data)
                with open(filename, "wb") as f:
                    f.write(encrypted_data)
                print(f"Encrypted data saved to {filename}.")
            else:
                # Save plain JSON with indentation for readability
                with open(filename, "w") as f:
                    json.dump(data, f, indent=4)
                print(f"Data saved to {filename}.")
            print("IMPORTANT: Ensure you securely back up this file and its contents.")
        except IOError as e:
            print(f"Failed to save data to {filename}: {e}")
        except Exception as e:
            print(f"Encryption failed: {e}")

    def load_json(self, filename: str, decrypt: bool = False) -> Dict[str, Any]:
        """
        Loads data from a JSON file with optional decryption.
        """
        try:
            if decrypt and self.encryption_manager:
                with open(filename, "rb") as f:
                    encrypted_bytes = f.read()
                data = self.encryption_manager.decrypt(encrypted_bytes)
                return data
            else:
                with open(filename, "r") as f:
                    data = json.load(f)
                return data
        except IOError as e:
            print(f"Failed to load data from {filename}: {e}")
            return {}
        except Exception as e:
            print(f"Decryption failed: {e}")
            return {}

    @staticmethod
    def convert_secret_to_base32(secret: str) -> str:
        """
        Converts a device secret to base32 encoding.
        """
        try:
            hex_secret = binascii.unhexlify(secret)
            return base64.b32encode(hex_secret).decode("utf-8").replace("=", "")
        except (binascii.Error, TypeError) as e:
            raise Exception(f"Failed to convert secret: {e}")

    @staticmethod
    def generate_qr_code(totp_url: str, filename: str) -> None:
        """
        Generates a QR code for the TOTP URL and saves it as an image file.
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        img.save(f"{filename}.png")
        print(f"QR code saved as {filename}.png")

    def reconstruct_totp_from_json(self) -> None:
        """
        Reconstructs the TOTP key and QR code from a JSON file or prompts the user for information.
        """
        json_files = list(Path('.').glob('*.json'))
        if len(json_files) == 1:
            filename = json_files[0]
        elif len(json_files) > 1:
            print("Multiple JSON files found:")
            for i, file in enumerate(json_files, 1):
                print(f"{i}. {file}")
            choice = input("Enter the number of the file to use, or type 'manual' to enter information manually: ").strip()
            if choice.lower() == 'manual':
                filename = None
            else:
                try:
                    index = int(choice) - 1
                    filename = json_files[index]
                except (ValueError, IndexError):
                    print("Invalid choice.")
                    return
        else:
            filename = None

        if filename:
            # Determine if the file is encrypted
            is_encrypted = False
            with open(filename, "rb") as f:
                content = f.read()
                try:
                    encrypted_data = json.loads(content.decode('utf-8'))
                    if all(k in encrypted_data for k in ('salt', 'nonce', 'ciphertext')):
                        is_encrypted = True
                except json.JSONDecodeError:
                    pass  # Not an encrypted JSON

            if is_encrypted:
                print(f"The file {filename} is encrypted.")
                passphrase = getpass.getpass("Enter the encryption passphrase: ")
                encryption_manager = EncryptionManager(passphrase)
                temp_authenticator = BattleNetAuthenticator(encryption_manager)
                data = temp_authenticator.load_json(filename, decrypt=True)
                if not data:
                    print("Failed to decrypt the JSON file. Please ensure the passphrase is correct.")
                    return
            else:
                data = self.load_json(filename)

            if not data:
                print("Failed to load JSON file. Prompting for manual input.")
                data = {}
        else:
            data = {}

        serial = data.get("serial") or input("Enter Serial: ").strip()
        restore_code = data.get("restoreCode") or input("Enter Restore Code: ").strip()
        device_secret = data.get("deviceSecret") or input("Enter Device Secret: ").strip()

        if not serial or not restore_code or not device_secret:
            print("Incomplete data provided.")
            return

        base32_secret = self.convert_secret_to_base32(device_secret)
        totp_url = f"otpauth://totp/Battle.net?secret={base32_secret}&digits=8"
        print(f"TOTP URL: {totp_url}")
        print("\nIMPORTANT: When importing the key, use these settings:")
        print(" - Digits: 8")
        print(" - Algorithm: SHA1")
        print(" - Timeout: 30 seconds")
        self.generate_qr_code(totp_url, f"reconstructed_{serial}")

        input("\nPress any key to return to the main menu...")

    def get_bearer_token(self, session_token):
        """
        Retrieves the Bearer Token using the provided Session Token.
        """
        payload = {
            "client_id": Config.CLIENT_ID,
            "grant_type": "client_sso",
            "scope": "auth.authenticator",
            "token": session_token,
        }
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}

        try:
            response = requests.post(Config.SSO_URL, data=payload, headers=headers)
            response.raise_for_status()
            self.bearer_token = response.json().get("access_token")
            return self.bearer_token
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch bearer token: {e}")

    def attach_authenticator(self):
        """
        Attaches a new authenticator and returns its details.
        """
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        try:
            response = requests.post(Config.BASE_URL, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to attach authenticator: {e}")

    def retrieve_device_secret(self, serial, restore_code):
        """
        Retrieves the device secret for an existing authenticator using its serial and restore code.
        """
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.bearer_token}",
        }
        payload = {"serial": serial, "restoreCode": restore_code}

        try:
            response = requests.post(f"{Config.BASE_URL}/device", headers=headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to retrieve device secret: {e}")

def show_session_token_instructions():
    """
    Displays instructions for retrieving the Battle.net Session Token.
    """
    print("\nHow to Get the Session Token:")
    print("1. Open your web browser and navigate to:")
    print("   https://account.battle.net/login/en/?ref=localhost")
    print("2. Log in to your Battle.net account.")
    print("3. After logging in, you'll see a 404 error page.")
    print("4. Look at the URL in your browser's address bar.")
    print("   The Session Token is the value after `ST=`.")
    print("   Example: US-abcdef12345678 or EU-12345678abcdef")
    print("5. Copy the Session Token and paste it into this tool when prompted.\n")

def graceful_exit():
    """
    Gracefully exits the program with a backup reminder.
    """
    print("\nExiting the program. Ensure you have securely backed up your data.")
    sys.exit(0)

def encrypt_existing_files(authenticator: BattleNetAuthenticator):
    """
    Encrypts existing plain JSON files in the current directory.
    """
    json_files = list(Path('.').glob('*.json'))
    if not json_files:
        print("No JSON files found to encrypt.")
        return

    print("Found the following JSON files:")
    for i, file in enumerate(json_files, 1):
        print(f"{i}. {file}")

    choices = input("Enter the numbers of the files to encrypt separated by commas (e.g., 1,3) or 'all' to encrypt all: ").strip()
    
    if choices.lower() == 'all':
        selected_files = json_files
    else:
        try:
            indices = [int(x.strip()) - 1 for x in choices.split(',')]
            selected_files = [json_files[i] for i in indices if 0 <= i < len(json_files)]
        except (ValueError, IndexError):
            print("Invalid selection.")
            return

    for file in selected_files:
        try:
            # Check if the file is already encrypted by looking for 'salt', 'nonce', 'ciphertext'
            with open(file, "rb") as f:
                content = f.read()
                try:
                    encrypted_data = json.loads(content.decode('utf-8'))
                    if all(k in encrypted_data for k in ('salt', 'nonce', 'ciphertext')):
                        print(f"Skipping {file}: Already encrypted.")
                        continue
                except json.JSONDecodeError:
                    pass  # Not an encrypted JSON, proceed to encrypt

            # Read the plain JSON data
            with open(file, "r") as f:
                data = json.load(f)

            if not data:
                print(f"Skipping {file}: Empty or invalid JSON.")
                continue

            # Prompt user to confirm encryption
            while True:
                confirm = input(f"Do you want to encrypt {file}? (y/n): ").strip().lower()
                if confirm in {"y", "n"}:
                    break
                print("Invalid input. Please enter 'y' or 'n'.")

            if confirm != "y":
                print(f"Skipping {file}: User opted not to encrypt.")
                continue

            # Prompt for passphrase
            print(f"\nEncryption of {file}:")
            while True:
                passphrase = getpass.getpass("Enter encryption passphrase: ")
                confirm_passphrase = getpass.getpass("Confirm passphrase: ")
                if passphrase != confirm_passphrase:
                    print("Passphrases do not match. Please try again.")
                elif not passphrase:
                    print("Passphrase cannot be empty. Please try again.")
                else:
                    break

            encryption_manager = EncryptionManager(passphrase)
            encrypted_data = encryption_manager.encrypt(data)
            with open(file, "wb") as f:
                f.write(encrypted_data)
            print(f"Encrypted {file} successfully.\n")

        except Exception as e:
            print(f"Failed to encrypt {file}: {e}")

def decrypt_json_file():
    """
    Decrypts an encrypted JSON file.
    """
    json_files = list(Path('.').glob('*.json'))
    if not json_files:
        print("No JSON files found to decrypt.")
        return

    print("Found the following JSON files:")
    for i, file in enumerate(json_files, 1):
        print(f"{i}. {file}")

    choice = input("Enter the number of the file to decrypt: ").strip()
    try:
        index = int(choice) - 1
        if not (0 <= index < len(json_files)):
            print("Invalid selection.")
            return
        file_to_decrypt = json_files[index]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    # Verify if the file is encrypted
    with open(file_to_decrypt, "rb") as f:
        content = f.read()
        try:
            encrypted_data = json.loads(content.decode('utf-8'))
            if not all(k in encrypted_data for k in ('salt', 'nonce', 'ciphertext')):
                print(f"The file {file_to_decrypt} is not encrypted.")
                return
        except json.JSONDecodeError:
            print(f"The file {file_to_decrypt} is not a valid JSON file.")
            return

    # Prompt for passphrase
    passphrase = getpass.getpass("Enter encryption passphrase: ")

    # Initialize EncryptionManager
    encryption_manager = EncryptionManager(passphrase)
    temp_authenticator = BattleNetAuthenticator(encryption_manager)

    # Attempt decryption
    try:
        decrypted_data = temp_authenticator.load_json(file_to_decrypt, decrypt=True)
        if not decrypted_data:
            print("Failed to decrypt the JSON file. Please ensure the passphrase is correct.")
            return

        # Option to display or save decrypted data
        while True:
            action = input("Do you want to (v)iew the decrypted data or (s)ave it to a new file? (v/s): ").strip().lower()
            if action in {"v", "s"}:
                break
            print("Invalid input. Please enter 'v' or 's'.")

        if action == "v":
            print("\nDecrypted Data:")
            print(json.dumps(decrypted_data, indent=4))
        elif action == "s":
            new_filename = input("Enter the filename to save the decrypted data (e.g., decrypted.json): ").strip()
            if not new_filename:
                print("Filename cannot be empty.")
                return
            with open(new_filename, "w") as f:
                json.dump(decrypted_data, f, indent=4)
            print(f"Decrypted data saved to {new_filename}.")

    except Exception as e:
        print(f"Error during decryption: {e}")

def interactive_cli():
    """
    Main interactive CLI for the Battle.net Authenticator Tool.
    """
    authenticator = BattleNetAuthenticator()

    while True:
        print("\nChoose an action:")
        print("1. Attach a new authenticator")
        print("2. Retrieve existing device secret")
        print("3. Reconstruct TOTP from JSON")
        print("4. Encrypt existing JSON files")
        print("5. Decrypt a JSON file")
        print("6. Exit")
        choice = input("Enter your choice (1/2/3/4/5/6): ").strip()

        if choice == "1":
            show_session_token_instructions()

            session_token = input("Enter your Session Token (or type 'exit' to quit): ").strip()
            if session_token.lower() == "exit":
                graceful_exit()

            if not session_token:
                print("Session Token is required!")
                continue

            # Ask if the user wants to encrypt the JSON file
            while True:
                encrypt_choice = input("Do you want to encrypt the resulting JSON file? (y/n): ").strip().lower()
                if encrypt_choice in {"y", "n"}:
                    break
                print("Invalid input. Please enter 'y' or 'n'.")

            encrypt = encrypt_choice == "y"

            if encrypt:
                print("\nEncryption is crucial for securing your sensitive TOTP data.")
                print("Please ensure you remember your passphrase/password. Losing it means you cannot decrypt your data.")

            try:
                print("Fetching Bearer Token...")
                bearer_token = authenticator.get_bearer_token(session_token)
                print(f"Bearer Token: {bearer_token}")

                print("Attaching Authenticator...")
                device_info = authenticator.attach_authenticator()
                serial = device_info["serial"]
                restore_code = device_info["restoreCode"]
                device_secret = device_info["deviceSecret"]

                print(f"Serial: {serial}")
                print(f"Restore Code: {restore_code}")

                print("Generating TOTP URL...")
                base32_secret = authenticator.convert_secret_to_base32(device_secret)
                totp_url = f"otpauth://totp/Battle.net?secret={base32_secret}&digits=8"
                print(f"TOTP URL: {totp_url}")
                print("\nIMPORTANT: When importing the key, use these settings:")
                print(" - Digits: 8")
                print(" - Algorithm: SHA1")
                print(" - Timeout: 30 seconds")

                # Prepare data for saving
                data_to_save = {
                    "serial": serial,
                    "restoreCode": restore_code,
                    "deviceSecret": device_secret,
                    "timestamp": datetime.utcnow().isoformat() + "Z"  # Adding ISO 8601 timestamp
                }

                # Save data and generate QR code
                filename = f"authenticator_{serial}.json"
                if encrypt:
                    while True:
                        passphrase = getpass.getpass("Enter encryption passphrase: ")
                        confirm_passphrase = getpass.getpass("Confirm passphrase: ")
                        if passphrase != confirm_passphrase:
                            print("Passphrases do not match. Please try again.")
                        elif not passphrase:
                            print("Passphrase cannot be empty. Please try again.")
                        else:
                            break
                    encryption_manager = EncryptionManager(passphrase)
                    authenticator.encryption_manager = encryption_manager
                else:
                    authenticator.encryption_manager = None

                authenticator.save_json(filename, data_to_save, encrypt=encrypt)
                authenticator.generate_qr_code(totp_url, f"authenticator_{serial}")

            except Exception as e:
                print(f"Error: {e}")
                graceful_exit()

        elif choice == "2":
            show_session_token_instructions()

            session_token = input("Enter your Session Token (or type 'exit' to quit): ").strip()
            if session_token.lower() == "exit":
                graceful_exit()

            if not session_token:
                print("Session Token is required!")
                continue

            # Ask if the user wants to encrypt the JSON file
            while True:
                encrypt_choice = input("Do you want to encrypt the resulting JSON file? (y/n): ").strip().lower()
                if encrypt_choice in {"y", "n"}:
                    break
                print("Invalid input. Please enter 'y' or 'n'.")

            encrypt = encrypt_choice == "y"

            if encrypt:
                print("\nEncryption is crucial for securing your sensitive TOTP data.")
                print("Please ensure you remember your passphrase/password. Losing it means you cannot decrypt your data.")

            try:
                print("Fetching Bearer Token...")
                bearer_token = authenticator.get_bearer_token(session_token)
                print(f"Bearer Token: {bearer_token}")

                serial = input("Enter Serial: ").strip()
                restore_code = input("Enter Restore Code: ").strip()
                if not serial or not restore_code:
                    print("Serial and Restore Code are required!")
                    continue

                print("Retrieving Device Secret...")
                device_info = authenticator.retrieve_device_secret(serial, restore_code)
                device_secret = device_info["deviceSecret"]
                print(f"Device Secret: {device_secret}")

                print("Generating TOTP URL...")
                base32_secret = authenticator.convert_secret_to_base32(device_secret)
                totp_url = f"otpauth://totp/Battle.net?secret={base32_secret}&digits=8"
                print(f"TOTP URL: {totp_url}")
                print("\nIMPORTANT: When importing the key, use these settings:")
                print(" - Digits: 8")
                print(" - Algorithm: SHA1")
                print(" - Timeout: 30 seconds")

                # Prepare data for saving
                data_to_save = {
                    "serial": serial,
                    "restoreCode": restore_code,
                    "deviceSecret": device_secret,
                    "timestamp": datetime.utcnow().isoformat() + "Z"  # Adding ISO 8601 timestamp
                }

                # Save data and generate QR code
                filename = f"authenticator_{serial}.json"
                if encrypt:
                    while True:
                        passphrase = getpass.getpass("Enter encryption passphrase: ")
                        confirm_passphrase = getpass.getpass("Confirm passphrase: ")
                        if passphrase != confirm_passphrase:
                            print("Passphrases do not match. Please try again.")
                        elif not passphrase:
                            print("Passphrase cannot be empty. Please try again.")
                        else:
                            break
                    encryption_manager = EncryptionManager(passphrase)
                    authenticator.encryption_manager = encryption_manager
                else:
                    authenticator.encryption_manager = None

                authenticator.save_json(filename, data_to_save, encrypt=encrypt)
                authenticator.generate_qr_code(totp_url, f"authenticator_{serial}")

            except Exception as e:
                print(f"Error: {e}")
                graceful_exit()

        elif choice == "3":
            authenticator.reconstruct_totp_from_json()

        elif choice == "4":
            encrypt_existing_files(authenticator)

        elif choice == "5":
            decrypt_json_file()

        elif choice == "6":
            graceful_exit()

        else:
            print("Invalid choice!")
            graceful_exit()

if __name__ == "__main__":
    try:
        interactive_cli()
    except KeyboardInterrupt:
        graceful_exit()

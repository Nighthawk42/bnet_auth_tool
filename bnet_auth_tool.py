import json
import base64
import binascii
import requests
from pathlib import Path
import sys
import qrcode

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

print("Battle.net Authenticator Tool - by Nighthawk42")

class Config:
    """Configuration for Battle.net Authenticator API."""
    BASE_URL = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator"
    SSO_URL = "https://oauth.battle.net/oauth/sso"
    CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a"


class BattleNetAuthenticator:
    """
    Handles Battle.net Authenticator operations, including attaching an authenticator,
    retrieving device secrets, and generating TOTP keys.
    """

    def __init__(self):
        self.bearer_token = None

    @staticmethod
    def save_plain_json(filename, data):
        """
        Saves data to a JSON file, prompting to overwrite if the file already exists.
        """
        if Path(filename).exists():
            overwrite = input(f"{filename} already exists. Do you want to overwrite it? (y/n): ").strip().lower()
            if overwrite != "y":
                print("Data not saved.")
                return

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Data saved to {filename}.\n")
        print("IMPORTANT: Ensure you securely back up this file and its contents.")

    @staticmethod
    def generate_qr_code(totp_url, filename):
        """
        Generates a QR code for the given TOTP URL and saves it as an image.
        """
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(totp_url)
        qr.make(fit=True)

        img = qr.make_image(fill="black", back_color="white")
        qr_filename = f"{filename}.png"
        img.save(qr_filename)
        print(f"QR Code saved to {qr_filename}. You can scan this code using your authenticator app.")

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

    @staticmethod
    def convert_secret_to_base32(device_secret):
        """
        Converts the device secret from hex to Base32 format for TOTP.
        """
        try:
            hex_secret = binascii.unhexlify(device_secret)
            return base64.b32encode(hex_secret).decode("utf-8").replace("=", "")
        except (binascii.Error, TypeError) as e:
            raise Exception(f"Failed to convert secret: {e}")


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


def interactive_cli():
    """
    Main interactive CLI for the Battle.net Authenticator Tool.
    """
    authenticator = BattleNetAuthenticator()

    show_session_token_instructions()

    session_token = input("Enter your Session Token (or type 'exit' to quit): ").strip()
    if session_token.lower() == "exit":
        graceful_exit()

    if not session_token:
        print("Session Token is required!")
        return

    try:
        print("Fetching Bearer Token...")
        bearer_token = authenticator.get_bearer_token(session_token)
        print(f"Bearer Token: {bearer_token}")

        print("\nChoose an action:")
        print("1. Attach a new authenticator")
        print("2. Retrieve existing device secret")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
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
            print("\nImportant: When importing the key, use these settings:")
            print(" - Digits: 8")
            print(" - Algorithm: SHA1")
            print(" - Timeout: 30 seconds\n")

            # Save data and generate QR code
            filename = f"authenticator_{serial}"
            authenticator.save_plain_json(f"{filename}.json", device_info)
            authenticator.generate_qr_code(totp_url, filename)

        elif choice == "2":
            serial = input("Enter Serial: ").strip()
            restore_code = input("Enter Restore Code: ").strip()
            if not serial or not restore_code:
                print("Serial and Restore Code are required!")
                return

            print("Retrieving Device Secret...")
            device_info = authenticator.retrieve_device_secret(serial, restore_code)
            device_secret = device_info["deviceSecret"]
            print(f"Device Secret: {device_secret}")

            print("Generating TOTP URL...")
            base32_secret = authenticator.convert_secret_to_base32(device_secret)
            totp_url = f"otpauth://totp/Battle.net?secret={base32_secret}&digits=8"
            print(f"TOTP URL: {totp_url}")
            print("\nImportant: When importing the key, use these settings:")
            print(" - Digits: 8")
            print(" - Algorithm: SHA1")
            print(" - Timeout: 30 seconds\n")

            # Save data and generate QR code
            filename = f"authenticator_{serial}"
            authenticator.save_plain_json(f"{filename}.json", {"serial": serial, "restoreCode": restore_code, "deviceSecret": device_secret})
            authenticator.generate_qr_code(totp_url, filename)

        elif choice == "3":
            graceful_exit()

        else:
            print("Invalid choice!")
            graceful_exit()

    except Exception as e:
        print(f"Error: {e}")
        graceful_exit()


if __name__ == "__main__":
    try:
        interactive_cli()
    except KeyboardInterrupt:
        graceful_exit()

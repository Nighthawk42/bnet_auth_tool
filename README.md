# Battle.net Authenticator Tool

A Python-based tool for managing Battle.net authenticators. This tool allows you to attach new authenticators, retrieve existing device secrets, and generate TOTP keys and QR codes for easy integration with authenticator apps.

## Features

- Attach a new Battle.net authenticator to your account.
- Retrieve existing device secrets using serial and restore codes.
- Generate TOTP URLs and QR codes for use with TOTP-compatible authenticator apps.

## Requirements

- Python 3.7+
- Required libraries:
  - `requests`
  - `pillow`
  - `qrcode`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Nighthawk42/bnet-authenticator-tool.git
   cd battlenet-authenticator-tool

2. Run the script:
   ```bash
   py bnet_auth_tool.py`

4. Follow the instructions from the console window.
    
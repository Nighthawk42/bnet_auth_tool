# Battle.net Authenticator Tool

> Back up Battle.net authenticator TOTP secrets in an encrypted local vault and export
> them to any authenticator app — via CLI or an optional desktop GUI. Offline features
> fully work; online attach/retrieve is unverified against Blizzard's API.

A tool for managing **Battle.net software authenticators**, available as both a CLI
(`bnet-auth`) and an optional desktop GUI (`bnet-auth-gui`). It can attach/retrieve
authenticator secrets online, and — most importantly — keep your TOTP backups in a single
**encrypted local vault** so you can re-import them into any standard authenticator app
(Aegis, Bitwarden, 1Password, Google Authenticator, …).

> [!IMPORTANT]
> **Online status is unverified.** The attach/retrieve flows depend on
> Blizzard's identity API, which has changed before and may be blocked again.
> They are kept here and made configurable, but are **not** guaranteed to work
> against the live backend. The **offline** vault / TOTP / migration features are
> fully tested and work regardless of Blizzard's API.

---

## What it does

* **Attach a new authenticator** (online, unverified) and store the secret in your vault.
* **Retrieve an existing device secret** (online, unverified) from a serial + restore code.
* **Reconstruct TOTP** keys and **QR codes** (RFC 6238: SHA1, 8 digits, 30s) from the vault.
* **Encrypted vault** — all authenticators live in one AES‑256‑GCM file protected by a
  passphrase (scrypt key derivation), stored in your OS user-data directory.
* **Migrate legacy backups** — import old `battlenet_authenticator_*.json` files (plaintext
  or encrypted with the older PBKDF2 scheme) into the vault.
* **Optional GUI** — a small Flet desktop app (`bnet-auth-gui`) with live TOTP codes over
  the same vault, for users who'd rather not use the terminal.

## Security model

| Aspect | Detail |
| --- | --- |
| Cipher | AES‑256‑GCM (authenticated encryption) |
| KDF (new files) | **scrypt** (memory-hard), parameters in `settings.yaml` |
| KDF (legacy files) | PBKDF2‑HMAC‑SHA256 (100k and 600k) — still decryptable |
| Storage | single encrypted vault in the per-user data dir |
| File permissions | vault and QR PNGs written `0600` (owner-only) on POSIX |
| Writes | atomic (temp file + replace) so a crash can't truncate the vault |

> Your vault passphrase is the **only** way to decrypt your secrets. There is no
> recovery if you lose it. QR-code PNGs contain the raw secret — delete them after import.

## Install

### With [uv](https://docs.astral.sh/uv/) (recommended)

```bash
uv tool install .          # install the `bnet-auth` command
# or, for development:
uv sync --extra dev
```

### With pip

```bash
pip install .
# or, using the fallback dependency list:
pip install -r requirements.txt && pip install .
```

Requires **Python 3.9+**.

### GUI (optional)

Prefer a window over a terminal? Install the optional Flet GUI:

```bash
uv tool install ".[gui]"     # or: pip install ".[gui]"
bnet-auth-gui                # or: python -m bnet_auth_tool.gui
```

The GUI uses the **same** encrypted vault, settings, and crypto as the CLI — unlock the
vault, see live rotating TOTP codes, copy a code, view a QR, import legacy backups, and
(online, unverified) attach/retrieve. It's purely an alternative front-end.

## Usage (CLI)

Run with no arguments for the interactive menu:

```bash
bnet-auth
```

Or use scriptable subcommands:

```bash
bnet-auth list                     # list authenticators in the vault
bnet-auth reconstruct US-1234-...  # print TOTP details + optional QR
bnet-auth migrate --dir .          # import legacy JSON backups from a folder
bnet-auth paths                    # show config / data / vault locations
bnet-auth attach                   # online (unverified)
bnet-auth retrieve                 # online (unverified)
```

### Migrating from older versions

Older releases dropped one `battlenet_authenticator_<serial>.json` per authenticator into
the working directory. To pull them into the encrypted vault:

```bash
cd /folder/with/old/json/files
bnet-auth migrate --dir .
```

You'll be prompted for the vault passphrase (creating it on first run) and for each
encrypted legacy file's passphrase. After verifying the vault, **securely delete the old
plaintext files**.

## Configuration

A user-editable `settings.yaml` is created on first run in your config directory
(`bnet-auth paths` shows where). Edit it to change API endpoints, regions, KDF
parameters, or TOTP output — handy if Blizzard moves an endpoint again. Any key you omit
falls back to the bundled default.

## Development

```bash
uv sync --extra dev
uv run pytest        # tests
uv run ruff check .  # lint
```

See [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) for the architecture overview.

## Account recovery

This project has **zero** association with Blizzard and no access to their backend. If you
are locked out of your account, contact
[Blizzard Customer Support](https://us.battle.net/support/en/) — the maintainer cannot
recover accounts.

## License

[MIT](LICENSE) © 2024-2026 Nighthawk42

## Donations

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/P5P21QRW51)

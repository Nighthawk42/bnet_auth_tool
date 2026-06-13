# AGENTS.md

Guidance for AI agents and human contributors working on `bnet_auth_tool`.

## What this is

A Python CLI for managing Battle.net software authenticators. Two halves:

- **Offline (the important, fully-tested half):** an encrypted vault of authenticator
  secrets, TOTP/QR reconstruction, and migration of legacy backups.
- **Online (unverified):** attach/retrieve flows against Blizzard's identity API. These
  may be blocked by Blizzard at any time. **Do not claim they are "fixed"** — keep the
  tempered "unverified" framing in the README and `--help`/menu text.

## Architecture

Source lives under `src/bnet_auth_tool/` (a proper package; there is no top-level script).

| Module | Responsibility |
| --- | --- |
| `config.py` | Load bundled `settings.yaml` + user override; resolve config/data dirs (`platformdirs`). Typed `Settings`/`ApiConfig`/`CryptoConfig`/`TotpConfig`. |
| `crypto.py` | `EncryptionManager`: scrypt+AES‑256‑GCM encrypt; decrypt dispatches on a versioned header (scrypt / PBKDF2 600k / legacy PBKDF2 100k). |
| `storage.py` | `Vault`: single encrypted file keyed by serial; add/list/get/remove. |
| `fileio.py` | Atomic, `0600`-hardened writes (`atomic_write_bytes`, `_harden`). |
| `api.py` | `BattleNetAuthenticator` online client; leak-safe error handling. |
| `totp.py` | hex→base32, `otpauth://` URL builder, QR PNG. |
| `migrate.py` | Discover + import legacy `battlenet_authenticator_*.json` files into the vault. |
| `cli.py` | Interactive menu **and** argparse subcommands; `main()` is the entry point. |
| `errors.py` | Exception hierarchy rooted at `BnetAuthError`. |

`settings.yaml` is shipped inside the package and copied to the user's config dir on first
run. Endpoints/KDF/TOTP params are config, not code — change them there.

## Hard constraints (do not break)

1. **Legacy decryption must keep working.** Files encrypted by v1.x — including pre‑v1.3
   files with *no* `kdf_iterations` field — must still decrypt. Covered by `tests/test_crypto.py`.
2. **Secrets are sensitive.** Never log raw device secrets, restore codes, session tokens,
   or full server error bodies. Vault/QR files are written `0600` and atomically.
3. **Online flows stay labelled unverified.** No optimistic "it works now" claims.

## Conventions

- Python **3.9+**; `from __future__ import annotations` in every module (so `X | None`
  annotations are fine).
- Lint/format with **ruff**; config in `pyproject.toml`.
- Keep crypto parameters fast in tests (small scrypt `n`) — see `tests/conftest.py`.

## Workflow

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run bnet-auth --help
```

When changing the encryption format, bump the `format` header in `crypto.py` and add a
back-compat test rather than mutating the existing decrypt paths.

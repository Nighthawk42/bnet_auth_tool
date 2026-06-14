"""Flet desktop GUI — a friendly front-end over the same vault as the CLI.

Run with ``bnet-auth-gui`` (after ``pip install '.[gui]'``) or
``python -m bnet_auth_tool.gui``. The GUI uses the *same* encrypted vault,
settings, and crypto as the command line; it is purely an alternative UI.

Online attach/retrieve are included but, like the CLI, are **unverified**
against Blizzard's live API. The offline vault/TOTP features are the core.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

try:
    import flet as ft
except ImportError as exc:  # pragma: no cover - only hit without the gui extra
    raise SystemExit(
        "The GUI needs Flet. Install it with:  pip install 'bnet-auth-tool[gui]'"
    ) from exc

from . import __version__
from .api import BattleNetAuthenticator
from .config import Settings, ensure_user_settings, load_settings, vault_path
from .crypto import EncryptionManager
from .errors import BnetAuthError
from .migrate import discover_legacy_files, migrate_files
from .storage import Vault
from .totp import (
    build_totp_url,
    current_code,
    generate_qr_code,
    hex_secret_to_base32,
    seconds_remaining,
)

WINDOW_W, WINDOW_H = 560, 720
_UNVERIFIED = "Online flows are unverified against Blizzard's API and may fail."


class AuthApp:
    """Holds GUI state for one window: the page, settings, and open vault."""

    def __init__(self, page: ft.Page, settings: Settings):
        self.page = page
        self.settings = settings
        self.vault: Vault | None = None
        self.passphrase: str | None = None
        self._ticking = False
        self._code_cells: dict[str, tuple[ft.Text, ft.Text]] = {}
        self._tmpdir = Path(tempfile.mkdtemp(prefix="bnet_qr_"))

    # -- window setup ------------------------------------------------------- #
    def start(self) -> None:
        self.page.title = "Battle.net Authenticator Tool"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.padding = 24
        self.page.window.width = WINDOW_W
        self.page.window.height = WINDOW_H
        self.page.window.min_width = 420
        self.page.window.min_height = 520
        self._show_lock()

    # -- small helpers ------------------------------------------------------ #
    def _swap(self, *controls: ft.Control) -> None:
        self._ticking = False
        self.page.controls.clear()
        self.page.add(*controls)

    def _toast(self, message: str) -> None:
        self.page.show_dialog(
            ft.AlertDialog(
                content=ft.Text(message),
                actions=[ft.TextButton("OK", on_click=lambda e: self.page.pop_dialog())],
            )
        )

    def _header(self, subtitle: str) -> ft.Control:
        return ft.Column(
            spacing=2,
            controls=[
                ft.Text("Battle.net Authenticator", size=22, weight=ft.FontWeight.BOLD),
                ft.Text(subtitle, size=12, color=ft.Colors.ON_SURFACE_VARIANT),
            ],
        )

    # ------------------------------------------------------------------ #
    # Lock screen
    # ------------------------------------------------------------------ #
    def _show_lock(self) -> None:
        exists = vault_path().is_file()
        title = "Unlock your vault" if exists else "Create a new vault"

        pass_field = ft.TextField(
            label="Vault passphrase",
            password=True,
            can_reveal_password=True,
            autofocus=True,
            on_submit=lambda e: do_unlock(e),
        )
        confirm_field = ft.TextField(
            label="Confirm passphrase",
            password=True,
            can_reveal_password=True,
            visible=not exists,
            on_submit=lambda e: do_unlock(e),
        )
        error = ft.Text(color=ft.Colors.ERROR, visible=False)

        def do_unlock(_e: object) -> None:
            error.visible = False
            pw = pass_field.value or ""
            if not pw:
                return self._set_error(error, "Passphrase cannot be empty.")
            if not exists and pw != (confirm_field.value or ""):
                return self._set_error(error, "Passphrases do not match.")
            try:
                manager = EncryptionManager(pw, self.settings.crypto)
                vault = Vault(manager).load()
            except BnetAuthError as exc:
                return self._set_error(error, f"Could not open vault: {exc}")
            self.vault = vault
            self.passphrase = pw
            self._show_vault()

        button_label = "Unlock" if exists else "Create vault"
        self._swap(
            ft.Column(
                spacing=18,
                controls=[
                    self._header(title),
                    ft.Text(
                        f"Vault file: {vault_path()}",
                        size=11,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                        selectable=True,
                    ),
                    pass_field,
                    confirm_field,
                    error,
                    ft.FilledButton(button_label, icon=ft.Icons.LOCK_OPEN, on_click=do_unlock),
                    ft.Text(f"v{__version__}", size=10, color=ft.Colors.ON_SURFACE_VARIANT),
                ],
            )
        )

    def _set_error(self, control: ft.Text, message: str) -> None:
        control.value = message
        control.visible = True
        self.page.update()

    # ------------------------------------------------------------------ #
    # Vault screen
    # ------------------------------------------------------------------ #
    def _show_vault(self) -> None:
        assert self.vault is not None
        self._code_cells = {}

        toolbar = ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                self._header(f"{len(self.vault)} authenticator(s)"),
                ft.Row(
                    controls=[
                        ft.IconButton(
                            ft.Icons.ADD, tooltip="Add (online)", on_click=self._open_add_menu
                        ),
                        ft.IconButton(
                            ft.Icons.UPLOAD_FILE,
                            tooltip="Import legacy files",
                            on_click=lambda e: self._show_migrate(),
                        ),
                        ft.IconButton(
                            ft.Icons.LOCK, tooltip="Lock", on_click=lambda e: self._lock()
                        ),
                    ]
                ),
            ],
        )

        rows = [self._entry_row(entry) for entry in self._sorted_entries()]
        body: ft.Control
        if rows:
            body = ft.ListView(controls=rows, spacing=10, expand=True)
        else:
            body = ft.Container(
                content=ft.Text(
                    "Vault is empty. Use + to add online, or import legacy backups.",
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                alignment=ft.Alignment.CENTER,
                expand=True,
            )

        self.page.controls.clear()
        self.page.add(ft.Column(expand=True, spacing=16, controls=[toolbar, ft.Divider(), body]))
        self._start_ticker()

    def _sorted_entries(self) -> list[dict]:
        assert self.vault is not None
        return sorted(self.vault.list(), key=lambda e: e.get("serial", ""))

    def _entry_row(self, entry: dict) -> ft.Control:
        serial = entry.get("serial", "?")
        code_text = ft.Text("--------", size=26, weight=ft.FontWeight.BOLD, font_family="monospace")
        time_text = ft.Text("", size=11, color=ft.Colors.ON_SURFACE_VARIANT)
        self._code_cells[serial] = (code_text, time_text)
        self._update_code(entry)

        return ft.Card(
            content=ft.Container(
                padding=14,
                content=ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Column(
                            spacing=2,
                            controls=[
                                ft.Text(serial, weight=ft.FontWeight.W_500),
                                ft.Row(spacing=10, controls=[code_text, time_text]),
                            ],
                        ),
                        ft.Row(
                            controls=[
                                ft.IconButton(
                                    ft.Icons.COPY,
                                    tooltip="Copy code",
                                    on_click=lambda e, en=entry: self._copy_code(en),
                                ),
                                ft.IconButton(
                                    ft.Icons.INFO_OUTLINE,
                                    tooltip="Details / QR",
                                    on_click=lambda e, en=entry: self._show_details(en),
                                ),
                            ]
                        ),
                    ],
                ),
            )
        )

    # -- live code ticker --------------------------------------------------- #
    def _start_ticker(self) -> None:
        self._ticking = True
        self.page.run_task(self._tick)

    async def _tick(self) -> None:
        while self._ticking:
            try:
                for entry in self._sorted_entries():
                    self._update_code(entry)
                self.page.update()
            except Exception:  # noqa: BLE001 - never let the ticker kill the app
                pass
            await asyncio.sleep(1)

    def _update_code(self, entry: dict) -> None:
        cells = self._code_cells.get(entry.get("serial", ""))
        if not cells:
            return
        code_text, time_text = cells
        secret = entry.get("base32Secret")
        if not secret:
            code_text.value = "no secret"
            return
        try:
            code_text.value = current_code(secret, self.settings.totp)
            time_text.value = f"{seconds_remaining(self.settings.totp)}s"
        except ValueError:
            code_text.value = "bad secret"

    def _copy_code(self, entry: dict) -> None:
        secret = entry.get("base32Secret")
        if not secret:
            return
        try:
            self.page.clipboard.set(current_code(secret, self.settings.totp))
            self._toast("Current code copied to clipboard.")
        except ValueError as exc:
            self._toast(str(exc))

    # ------------------------------------------------------------------ #
    # Detail dialog (QR / copy / delete)
    # ------------------------------------------------------------------ #
    def _show_details(self, entry: dict) -> None:
        serial = entry.get("serial", "?")
        totp_url = entry.get("totpUrl") or build_totp_url(
            serial, entry.get("base32Secret", ""), self.settings.totp
        )

        rows: list[ft.Control] = [
            self._field("Serial", serial),
            self._field("Restore code", entry.get("restoreCode") or "—"),
            self._field("Base32 secret", entry.get("base32Secret") or "—"),
        ]

        qr_holder = ft.Column(horizontal_alignment=ft.CrossAxisAlignment.CENTER)

        def show_qr(_e: object) -> None:
            try:
                path = generate_qr_code(totp_url, self._tmpdir / f"{serial}.png")
            except Exception as exc:  # noqa: BLE001
                qr_holder.controls = [ft.Text(f"QR error: {exc}", color=ft.Colors.ERROR)]
                self.page.update()
                return
            qr_holder.controls = [
                ft.Image(src=str(path), width=220, height=220),
                ft.Text(
                    "This QR contains your secret — close after scanning.",
                    size=11,
                    color=ft.Colors.ERROR,
                ),
            ]
            self.page.update()

        dialog = ft.AlertDialog(
            title=ft.Text(f"Authenticator {serial}"),
            content=ft.Column(
                tight=True,
                width=360,
                scroll=ft.ScrollMode.AUTO,
                controls=[*rows, ft.Divider(), qr_holder],
            ),
            actions=[
                ft.TextButton("Show QR", icon=ft.Icons.QR_CODE, on_click=show_qr),
                ft.TextButton(
                    "Delete",
                    icon=ft.Icons.DELETE,
                    style=ft.ButtonStyle(color=ft.Colors.ERROR),
                    on_click=lambda e: self._confirm_delete(entry),
                ),
                ft.TextButton("Close", on_click=lambda e: self.page.pop_dialog()),
            ],
        )
        self.page.show_dialog(dialog)

    def _field(self, label: str, value: str) -> ft.Control:
        return ft.Column(
            spacing=0,
            controls=[
                ft.Text(label, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                ft.Text(value, selectable=True, font_family="monospace"),
            ],
        )

    def _confirm_delete(self, entry: dict) -> None:
        serial = entry.get("serial", "?")

        def really_delete(_e: object) -> None:
            assert self.vault is not None
            self.vault.remove(serial)
            self.vault.save()
            self.page.pop_dialog()
            self._show_vault()

        self.page.show_dialog(
            ft.AlertDialog(
                modal=True,
                title=ft.Text(f"Remove {serial}?"),
                content=ft.Text(
                    "This deletes the entry from the vault. Make sure you have a backup "
                    "of the secret — there is no undo."
                ),
                actions=[
                    ft.TextButton(
                        "Delete",
                        style=ft.ButtonStyle(color=ft.Colors.ERROR),
                        on_click=really_delete,
                    ),
                    ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                ],
            )
        )

    # ------------------------------------------------------------------ #
    # Add (online) — attach / retrieve
    # ------------------------------------------------------------------ #
    def _open_add_menu(self, _e: object) -> None:
        self.page.show_dialog(
            ft.AlertDialog(
                title=ft.Text("Add authenticator (online)"),
                content=ft.Text(_UNVERIFIED),
                actions=[
                    ft.TextButton("Attach new", on_click=lambda e: self._show_attach()),
                    ft.TextButton("Retrieve existing", on_click=lambda e: self._show_retrieve()),
                    ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                ],
            )
        )

    def _show_attach(self) -> None:
        token = ft.TextField(label="Session token (ST=...)", autofocus=True)
        error = ft.Text(color=ft.Colors.ERROR, visible=False)

        def run(_e: object) -> None:
            value = (token.value or "").strip()
            if not value:
                return self._set_error(error, "Session token is required.")
            client = BattleNetAuthenticator(self.settings.api)
            try:
                client.get_bearer_token(value)
                device = client.attach_authenticator()
            except BnetAuthError as exc:
                return self._set_error(error, str(exc))
            self._store_device(device)

        self.page.show_dialog(
            ft.AlertDialog(
                title=ft.Text("Attach new authenticator"),
                content=ft.Column(
                    tight=True,
                    width=360,
                    controls=[
                        ft.Text(_UNVERIFIED, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                        token,
                        error,
                    ],
                ),
                actions=[
                    ft.TextButton("Attach", on_click=run),
                    ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                ],
            )
        )

    def _show_retrieve(self) -> None:
        account = ft.TextField(label="Account email or phone", autofocus=True)
        serial = ft.TextField(label="Serial")
        restore = ft.TextField(label="Restore code")
        error = ft.Text(color=ft.Colors.ERROR, visible=False)

        def run(_e: object) -> None:
            if not (account.value and serial.value and restore.value):
                return self._set_error(error, "All three fields are required.")
            client = BattleNetAuthenticator(self.settings.api)
            try:
                retrieved = client.retrieve_device_secret(
                    account.value, serial.value, restore.value
                )
            except BnetAuthError as exc:
                return self._set_error(error, str(exc))
            self._store_device(
                {
                    "serial": serial.value.strip(),
                    "restoreCode": restore.value.strip(),
                    "deviceSecret": retrieved["deviceSecret"],
                }
            )

        self.page.show_dialog(
            ft.AlertDialog(
                title=ft.Text("Retrieve existing secret"),
                content=ft.Column(
                    tight=True,
                    width=360,
                    controls=[
                        ft.Text(_UNVERIFIED, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                        account,
                        serial,
                        restore,
                        error,
                    ],
                ),
                actions=[
                    ft.TextButton("Retrieve", on_click=run),
                    ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                ],
            )
        )

    def _store_device(self, device: dict) -> None:
        assert self.vault is not None
        serial = device["serial"]
        base32_secret = hex_secret_to_base32(device["deviceSecret"])
        entry = {
            "serial": serial,
            "restoreCode": device.get("restoreCode"),
            "deviceSecret": device["deviceSecret"],
            "base32Secret": base32_secret,
            "totpUrl": build_totp_url(serial, base32_secret, self.settings.totp),
        }
        self.vault.add(entry, overwrite=True)
        self.vault.save()
        self.page.pop_dialog()
        self._show_vault()

    # ------------------------------------------------------------------ #
    # Migrate legacy files
    # ------------------------------------------------------------------ #
    def _show_migrate(self) -> None:
        directory = ft.TextField(label="Folder to scan", value=str(Path.cwd()))
        legacy_pw = ft.TextField(
            label="Passphrase for encrypted legacy files (optional)",
            password=True,
            can_reveal_password=True,
        )
        result = ft.Text(visible=False)

        def run(_e: object) -> None:
            assert self.vault is not None
            files = discover_legacy_files(Path(directory.value or "."))
            if not files:
                result.value = "No legacy authenticator JSON files found."
                result.visible = True
                return self.page.update()
            def provider(_path: Path) -> str | None:
                return legacy_pw.value or None

            outcomes = migrate_files(files, self.vault, self.settings, provider, overwrite=False)
            self.vault.save()
            imported = sum(1 for o in outcomes if o.status in ("imported", "replaced"))
            skipped = sum(1 for o in outcomes if o.status == "skipped")
            errored = sum(1 for o in outcomes if o.status == "error")
            result.value = (
                f"Imported {imported}, skipped {skipped}, errors {errored}. "
                "Securely delete the originals once verified."
            )
            result.visible = True
            self.page.update()

        self.page.show_dialog(
            ft.AlertDialog(
                title=ft.Text("Import legacy backups"),
                content=ft.Column(
                    tight=True,
                    width=400,
                    controls=[
                        ft.Text(
                            "Scans a folder for old battlenet_authenticator_*.json files "
                            "and imports them into the vault.",
                            size=11,
                            color=ft.Colors.ON_SURFACE_VARIANT,
                        ),
                        directory,
                        legacy_pw,
                        result,
                    ],
                ),
                actions=[
                    ft.TextButton("Import", on_click=run),
                    ft.TextButton("Done", on_click=lambda e: (self.page.pop_dialog(), self._show_vault())),
                ],
            )
        )

    # ------------------------------------------------------------------ #
    def _lock(self) -> None:
        self._ticking = False
        if self.passphrase is not None:
            self.passphrase = None
        self.vault = None
        self._show_lock()


def _app(page: ft.Page) -> None:
    ensure_user_settings()
    try:
        settings = load_settings()
    except BnetAuthError as exc:
        page.add(ft.Text(f"Configuration error: {exc}", color=ft.Colors.ERROR))
        return
    AuthApp(page, settings).start()


def main() -> None:
    ft.run(_app)


if __name__ == "__main__":
    main()

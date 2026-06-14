"""Build standalone Windows executables for the CLI and GUI.

* CLI  -> PyInstaller (one-file, console).
* GUI  -> ``flet pack`` (PyInstaller under the hood, but with the Flet desktop
  runtime bundled — plain PyInstaller cannot ship a working Flet app).

Both bundle the package's ``settings.yaml`` as data so the frozen binaries can
read their default configuration via ``importlib.resources``.

Usage (from the repo root, in an env with the ``build`` extra installed)::

    uv pip install -e ".[build]"
    python packaging/build_exes.py            # build both + zip
    python packaging/build_exes.py --skip-gui # CLI only
    python packaging/build_exes.py --no-zip   # don't produce the release zip

Artifacts land in ``dist/`` and the zip in ``release/``. All of that is
gitignored.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = REPO_ROOT / "src" / "bnet_auth_tool"
SETTINGS = PKG_DIR / "settings.yaml"
DIST = REPO_ROOT / "dist"
# `flet pack` wipes its --distpath, so give the GUI its own and copy the result
# into dist/ afterwards. That way CLI and GUI builds never clobber each other.
GUI_DIST = REPO_ROOT / "build" / "gui-dist"
RELEASE = REPO_ROOT / "release"
ENTRY_CLI = REPO_ROOT / "packaging" / "pyi_entry_cli.py"
ENTRY_GUI = REPO_ROOT / "packaging" / "pyi_entry_gui.py"

CLI_NAME = "bnet-auth"
GUI_NAME = "bnet-auth-gui"
DATA_SEP = ";" if os.name == "nt" else ":"
EXE_SUFFIX = ".exe" if os.name == "nt" else ""


def _version() -> str:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from bnet_auth_tool import __version__

    return __version__


def _release_label(version: str) -> str:
    # PEP 440 "2.0.0a0" -> human "2.0.0-alpha" for tags/zip names.
    return version.replace("a0", "-alpha").replace("b0", "-beta").replace("rc0", "-rc")


def _run(cmd: list[str]) -> None:
    print(f"\n$ {' '.join(cmd)}\n", flush=True)
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)


def build_cli() -> Path:
    _run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--console",
            "--clean",
            "--noconfirm",
            "--name",
            CLI_NAME,
            "--add-data",
            f"{SETTINGS}{DATA_SEP}bnet_auth_tool",
            str(ENTRY_CLI),
        ]
    )
    return DIST / f"{CLI_NAME}{EXE_SUFFIX}"


def build_gui() -> Path:
    # `flet pack` wraps PyInstaller and bundles the Flet desktop runtime.
    # Its --add-data uses "source:destination"; pass a *relative* source so the
    # drive-letter colon in an absolute Windows path doesn't confuse the parser.
    settings_rel = SETTINGS.relative_to(REPO_ROOT).as_posix()
    _run(
        [
            sys.executable,
            "-m",
            "flet.cli",
            "pack",
            "-y",  # don't prompt to delete the build dir
            str(ENTRY_GUI),
            "--name",
            GUI_NAME,
            "--distpath",
            str(GUI_DIST),
            "--add-data",
            f"{settings_rel}:bnet_auth_tool",
        ]
    )
    # Copy the GUI exe into the shared dist/ so it sits next to the CLI exe.
    built = GUI_DIST / f"{GUI_NAME}{EXE_SUFFIX}"
    DIST.mkdir(exist_ok=True)
    dest = DIST / f"{GUI_NAME}{EXE_SUFFIX}"
    if built.exists():
        shutil.copy2(built, dest)
    return dest


def make_zip(exes: list[Path], version: str) -> Path:
    RELEASE.mkdir(exist_ok=True)
    label = _release_label(version)
    plat = "windows-x64" if os.name == "nt" else os.name
    zip_path = RELEASE / f"bnet-auth-tool-{label}-{plat}.zip"

    readme = (
        f"Battle.net Authenticator Tool {label}\n"
        f"{'=' * 40}\n\n"
        "bnet-auth.exe       - command-line interface (run in a terminal)\n"
        "bnet-auth-gui.exe   - desktop GUI (double-click)\n\n"
        "Both share one encrypted vault in your user data dir. ALPHA build:\n"
        "online attach/retrieve is unverified against Blizzard's API; the\n"
        "offline vault/TOTP/migration features are the supported core.\n\n"
        "Source & docs: https://github.com/Nighthawk42/bnet_auth_tool\n"
    )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for exe in exes:
            zf.write(exe, exe.name)
        zf.writestr("README.txt", readme)
    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CLI/GUI executables.")
    parser.add_argument("--skip-gui", action="store_true", help="build the CLI only")
    parser.add_argument("--skip-cli", action="store_true", help="build the GUI only")
    parser.add_argument("--no-zip", action="store_true", help="skip the release zip")
    args = parser.parse_args()

    version = _version()
    print(f"Building bnet-auth-tool {version} ({_release_label(version)})")

    exes: list[Path] = []
    if not args.skip_cli:
        exes.append(build_cli())
    if not args.skip_gui:
        exes.append(build_gui())

    missing = [str(p) for p in exes if not p.exists()]
    if missing:
        print(f"\nERROR: expected artifacts not found: {missing}", file=sys.stderr)
        return 1

    print("\nBuilt:")
    for exe in exes:
        print(f"  {exe}  ({exe.stat().st_size / 1_000_000:.1f} MB)")

    if not args.no_zip and exes:
        zip_path = make_zip(exes, version)
        print(f"\nPackaged: {zip_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

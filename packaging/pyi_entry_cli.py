"""PyInstaller entry point for the CLI.

A standalone script (not a module) so PyInstaller has a concrete file to freeze;
it simply imports and runs the installed package's CLI entry point.
"""

import sys

from bnet_auth_tool.cli import main

if __name__ == "__main__":
    sys.exit(main())

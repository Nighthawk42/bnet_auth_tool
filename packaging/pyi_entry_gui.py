"""PyInstaller / flet-pack entry point for the GUI.

A standalone script so the packager has a concrete file to freeze; it imports
and runs the installed package's GUI entry point.
"""

from bnet_auth_tool.gui import main

if __name__ == "__main__":
    main()

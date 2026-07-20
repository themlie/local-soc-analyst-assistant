"""
common/console.py — Forces terminal output to UTF-8.

The Windows console defaults to a legacy code page and crashes on some Unicode
characters (arrows, emoji). Importing this module reconfigures stdout/stderr to
UTF-8 and fixes the problem at the root. Imported at the top of every runnable file.
"""

import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass  # some environments lack reconfigure; ignore silently

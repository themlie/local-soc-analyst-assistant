"""
conftest.py — makes the project root importable from tests.

Without this, pytest puts only `tests/` on sys.path and `from ingest.ingest import ...`
fails. Keeping it at the repo root is the standard fix for a flat (non-src) layout.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

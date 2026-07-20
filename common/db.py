"""
common/db.py — Single place for the SQLite connection.

Instead of every module opening the database on its own, everyone calls
`get_connection()`. Benefits:
  - Connection settings (row access by column name) are defined once.
  - Changing the database path later is a one-line edit.
"""

import sqlite3
from config import DB_PATH


def get_connection() -> sqlite3.Connection:
    """Return a configured connection to the project database."""
    conn = sqlite3.connect(DB_PATH)
    # row_factory lets us access results by column name (r["user"]) instead of
    # index numbers — far more readable code.
    conn.row_factory = sqlite3.Row
    return conn

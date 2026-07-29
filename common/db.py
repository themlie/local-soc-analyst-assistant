"""
common/db.py — Single place for the SQLite connection, and for keeping sessions apart.

Everyone calls `get_connection()` instead of opening the database themselves, so
connection settings live in one place and the storage location can change without
touching callers.

WHY SESSIONS EXIST HERE
Ingest rebuilds the events table on every run. With one shared database that is fine
for a single analyst at a terminal, but the web interface can serve several people at
once: whoever uploads second wipes the first person's evidence and then reads results
built from their own logs. In a tool meant for sensitive security telemetry, that is a
data-leak, not just a bug.

Each session therefore gets its OWN database file, selected per thread. The
alternative — one table with a session_id column — was rejected deliberately: it would
require every query in every detector to carry a filter, and a single forgotten WHERE
clause would silently leak one tenant's logs into another's report. Separate files
cannot leak by omission.
"""

import re
import sqlite3
import threading
import time
from pathlib import Path

from config import DB_PATH, SESSION_DIR, SESSION_TTL_SECONDS

# Streamlit runs each user's script in its own thread, so the active session must be
# thread-local; a module-level global would have one user's upload redirect another's.
_local = threading.local()

# Session ids come from us, but validate anyway before building a path from one.
_SESSION_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")


def use_session(session_id: str | None) -> None:
    """Point this thread's connections at a session-scoped database.

    Passing None restores the shared default database, which is what the CLI and the
    test suite use.
    """
    if session_id is None:
        _local.db_path = None
        return
    if not _SESSION_ID.match(session_id):
        raise ValueError(f"Invalid session id: {session_id!r}")
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    _local.db_path = SESSION_DIR / f"{session_id}.db"


def current_db_path() -> Path:
    """The database this thread is reading and writing."""
    return getattr(_local, "db_path", None) or DB_PATH


def get_connection() -> sqlite3.Connection:
    """Return a configured connection to the active database."""
    conn = sqlite3.connect(current_db_path())
    # row_factory lets us access results by column name (r["user"]) instead of
    # index numbers — far more readable code.
    conn.row_factory = sqlite3.Row
    return conn


def purge_stale_sessions(ttl_seconds: int = SESSION_TTL_SECONDS) -> int:
    """Delete session databases nobody has touched recently; return how many.

    Session files hold uploaded security logs, so leaving them on disk indefinitely
    keeps sensitive data around longer than the work that needed it.
    """
    if not SESSION_DIR.exists():
        return 0
    cutoff, removed = time.time() - ttl_seconds, 0
    for path in SESSION_DIR.glob("*.db"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            pass  # in use or already gone; it will be caught on a later sweep
    return removed

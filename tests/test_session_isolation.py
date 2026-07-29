"""
tests/test_session_isolation.py — one analyst's logs must never reach another's report.

Ingest rebuilds the events table on every run, so a single shared database means the
second person to upload wipes the first person's evidence and then reads an analysis
built from their own. These tests pin the isolation that prevents it, including the
concurrent case, which is the one that actually happens in a web interface.
"""

import threading

import pytest

from common.db import use_session, get_connection, current_db_path, purge_stale_sessions
from config import SESSION_DIR, DB_PATH
from ingest.ingest import ingest_events, ingest_file
from detect.correlate import build_incidents


@pytest.fixture(autouse=True)
def restore_default_session():
    yield
    use_session(None)
    ingest_file()


def logon_burst(host: str) -> list[dict]:
    """Three failed logons — enough to trip brute-force detection."""
    return [{
        "time": f"2026-07-03T10:00:{i:02d}", "host": host, "source": "Security",
        "event_id": 4625, "user": "svc", "ip": "185.220.101.7",
    } for i in range(3)]


def test_sessions_do_not_see_each_others_events():
    use_session("alice")
    ingest_events(logon_burst("ALICE-HOST"))

    use_session("bob")
    ingest_events(logon_burst("BOB-HOST"))
    assert {i["host"] for i in build_incidents()} == {"BOB-HOST"}

    use_session("alice")
    hosts = {i["host"] for i in build_incidents()}
    assert hosts == {"ALICE-HOST"}, f"bob's upload reached alice's session: {hosts}"


def test_session_uses_a_separate_file_from_the_default():
    use_session("carol")
    assert current_db_path() != DB_PATH
    assert current_db_path().parent == SESSION_DIR
    use_session(None)
    assert current_db_path() == DB_PATH


def test_concurrent_sessions_stay_isolated():
    """The binding is thread-local, because a global would let one upload redirect
    another user's queries mid-request."""
    seen, errors = {}, []
    barrier = threading.Barrier(2)

    def worker(name: str, host: str):
        try:
            use_session(name)
            ingest_events(logon_burst(host))
            barrier.wait(timeout=10)          # force the two threads to overlap
            seen[name] = {i["host"] for i in build_incidents()}
        except Exception as exc:              # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=a)
               for a in (("dave", "DAVE-HOST"), ("erin", "ERIN-HOST"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, f"worker failed: {errors}"
    assert seen == {"dave": {"DAVE-HOST"}, "erin": {"ERIN-HOST"}}


def test_invalid_session_id_is_rejected():
    """Session ids become file paths, so anything path-like must not be accepted."""
    for bad in ("../../etc/passwd", "a/b", "", "x" * 65):
        with pytest.raises(ValueError):
            use_session(bad)


def test_stale_session_databases_are_purged():
    """Uploaded logs are sensitive; abandoned sessions should not linger on disk."""
    use_session("frank")
    ingest_events(logon_burst("FRANK-HOST"))
    stale = current_db_path()
    assert stale.exists()

    use_session(None)
    purge_stale_sessions(ttl_seconds=-1)   # treat everything as expired
    assert not stale.exists()

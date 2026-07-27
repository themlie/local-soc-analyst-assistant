"""
ingest/ingest.py — Pipeline layer 1: RAW LOG -> NORMALIZED EVENT -> SQLite.

Its job: take raw log lines from different sources (Windows Security, Sysmon, web/WAF
logs...) whose field names differ, normalize them into a single unified schema, and
write them to the database. Every later layer reads this unified schema.

Field names vary a lot across log sources (time vs timestamp, ip vs client_ip,
event_type vs event_id...). To stay robust we resolve each field from a list of
common ALIASES (case-insensitive), instead of requiring one exact name.
"""

import json
import common.console  # noqa: F401
from common.db import get_connection
from common.timeutil import to_canonical
from config import LOG_PATH

# For each unified field, the raw key names we accept (lowercase).
_ALIASES = {
    "time":      ["time", "timestamp", "@timestamp", "eventtime", "datetime"],
    "host":      ["host", "hostname", "computer", "device"],
    "source":    ["source", "log_source", "channel", "provider"],
    "event_id":  ["event_id", "eventid", "eid"],
    "user":      ["user", "username", "targetusername", "subjectusername", "account"],
    "src_ip":    ["ip", "src_ip", "client_ip", "source_ip", "ipaddress", "srcip"],
    "dst_ip":    ["dest_ip", "dst_ip", "destinationip", "dstip"],
    "dst_port":  ["dest_port", "dst_port", "destinationport", "dstport"],
    "process":   ["image", "process", "process_name", "processname"],
    "cmdline":   ["cmdline", "command", "command_line", "commandline"],
    "parent":    ["parent", "parentimage", "parent_image"],
    # Web / application-layer fields
    "category":  ["event_type", "category", "alert_type", "eventtype"],
    "message":   ["message", "msg", "description", "alert"],
    "tool":      ["tool_signature", "tool", "signature", "user_agent"],
}


def _resolve(low: dict, field: str):
    """Return the first present, non-null value among a field's aliases."""
    for alias in _ALIASES[field]:
        v = low.get(alias)
        if v is not None:
            return v
    return None


def normalize_event(raw: dict) -> dict:
    """Convert a raw event from any format into the UNIFIED schema."""
    low = {k.lower(): v for k, v in raw.items()}

    # Nested HTTP request block (web logs), with top-level fallbacks
    http = raw.get("http_request") or {}
    if not isinstance(http, dict):
        http = {}

    ev = {
        # Canonical UTC so that events from different sources (naive JSON vs
        # tz-aware EVTX) can be compared and sorted without special-casing.
        "time": to_canonical(_resolve(low, "time")),
        "host": _resolve(low, "host"),
        "source": _resolve(low, "source"),
        "event_id": _resolve(low, "event_id"),
        "user": _resolve(low, "user"),
        "src_ip": _resolve(low, "src_ip"),
        "dst_ip": _resolve(low, "dst_ip"),
        "dst_port": _resolve(low, "dst_port"),
        "process": _resolve(low, "process"),
        "cmdline": _resolve(low, "cmdline"),
        "parent": _resolve(low, "parent"),
        "category": _resolve(low, "category"),
        "message": _resolve(low, "message"),
        "tool": _resolve(low, "tool"),
        "url": http.get("url") or low.get("url"),
        "http_method": http.get("method") or low.get("http_method"),
        "http_status": http.get("status") or low.get("http_status"),
        # Keep the full raw event so grounding can cross-check the LLM's claims.
        "raw": json.dumps(raw, ensure_ascii=False),
    }

    # Scheduled-task events (4698) have no command line; surface the task name.
    task = low.get("task_name") or low.get("taskname")
    if not ev["cmdline"] and task:
        ev["cmdline"] = f"TaskName={task}"

    return ev


def create_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            time        TEXT,
            host        TEXT,
            source      TEXT,
            event_id    INTEGER,
            user        TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            dst_port    INTEGER,
            process     TEXT,
            cmdline     TEXT,
            parent      TEXT,
            category    TEXT,
            message     TEXT,
            tool        TEXT,
            url         TEXT,
            http_method TEXT,
            http_status INTEGER,
            raw         TEXT
        )
    """)


_COLUMNS = ["time", "host", "source", "event_id", "user", "src_ip", "dst_ip",
            "dst_port", "process", "cmdline", "parent", "category", "message",
            "tool", "url", "http_method", "http_status", "raw"]


def ingest_events(raw_events: list[dict]) -> int:
    """Normalize a LIST of raw events and write them to the database.
    Used by both normal runs and evaluation (loading scenario by scenario).

    Raises ValueError on input that cannot be ingested. Validation and normalization
    both happen before the database is touched: a bad upload must never destroy the
    data that is already there.
    """
    if not isinstance(raw_events, list):
        raise ValueError(
            "Log file must be a JSON array of event objects, "
            f"got {type(raw_events).__name__}."
        )
    bad = [i for i, e in enumerate(raw_events) if not isinstance(e, dict)]
    if bad:
        raise ValueError(
            f"Events at index {bad[:3]} are not objects; every event must be a JSON object."
        )

    normalized = [normalize_event(raw) for raw in raw_events]
    # An event we cannot place in time cannot be correlated, so drop it rather than
    # let it crash a later stage — but a batch with no usable event at all is an error.
    usable = [e for e in normalized if e["time"]]
    if raw_events and not usable:
        raise ValueError(
            "No usable events: none of them carry a parsable timestamp."
        )
    skipped = len(normalized) - len(usable)
    if skipped:
        print(f"[ingest]    warning: skipped {skipped} event(s) with no parsable timestamp.")

    conn = get_connection()
    conn.execute("DROP TABLE IF EXISTS events")  # rebuild fresh (schema may evolve)
    create_table(conn)

    placeholders = ", ".join(f":{c}" for c in _COLUMNS)
    columns = ", ".join(_COLUMNS)
    for ev in usable:
        conn.execute(f"INSERT INTO events ({columns}) VALUES ({placeholders})", ev)

    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return count


def ingest_file(path=LOG_PATH) -> int:
    """Read a JSON log file and write it to the database. Returns the number of events."""
    raw_events = json.loads(path.read_text(encoding="utf-8"))
    return ingest_events(raw_events)


if __name__ == "__main__":
    n = ingest_file()
    print(f"{n} events written to the database.")

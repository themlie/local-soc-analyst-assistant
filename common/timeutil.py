"""
common/timeutil.py — one place that understands log timestamps.

Log sources disagree about time. Real Windows EVTX emits timezone-aware values
("2020-07-22T20:29:27.321769Z"), while most sample and syslog-style feeds are naive
("2026-07-03T14:02:11"). Subtracting one from the other raises TypeError, so mixing
two sources in a single file used to crash the pipeline.

The rule here: normalize at the edge. `to_canonical()` runs during ingest so the
database only ever holds timezone-aware UTC strings; everything downstream then
compares like with like, and plain string ordering matches chronological ordering.

Naive timestamps are assumed to be UTC. That is a deliberate choice — most security
telemetry is collected in UTC — and it is documented in the README.
"""

from datetime import datetime, timezone


def parse_time(value) -> datetime:
    """Parse any supported log timestamp into a timezone-aware UTC datetime."""
    if value is None or not str(value).strip():
        raise ValueError("event has no timestamp")
    # fromisoformat only learned to accept a trailing 'Z' in 3.11; normalize it first
    # so the parser behaves the same across versions.
    dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_canonical(value) -> str | None:
    """Return a canonical UTC ISO-8601 string, or None if the value is unusable.

    Used by ingest: an event we cannot place in time cannot be correlated, so it is
    dropped rather than allowed to crash a later stage.
    """
    try:
        return parse_time(value).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None

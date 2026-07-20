"""
ingest/win_evtx.py — Parser for REAL Windows EVTX logs.

Our synthetic JSON samples were simple. Real Windows Event Logs (.evtx) are a binary
format with a far more complex schema: different field names (TargetUserName,
IpAddress, CommandLine...), nested JSON events, different providers (Security/Sysmon).

This module reads real EVTX records and converts them into the simple raw-log format
the rest of the project understands (same shape as sample_logs.json). That way the
same pipeline works on both synthetic and real data.

Data source: sbousseaden/EVTX-ATTACK-SAMPLES (real logs labeled by ATT&CK).
"""

import json
from evtx import PyEvtxParser


def _event_id(system: dict) -> int | None:
    """EventID is sometimes a plain number, sometimes {'#text': '4625', ...}."""
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    try:
        return int(eid)
    except (TypeError, ValueError):
        return None


def _strip_domain(user: str | None) -> str | None:
    """'EXAMPLE\\Administrator' -> 'Administrator'."""
    if not user:
        return None
    return user.split("\\")[-1]


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_raw_event(record_json: str) -> dict | None:
    """Convert a single EVTX record (JSON) into a simple raw-log dict."""
    try:
        ev = json.loads(record_json)["Event"]
    except (KeyError, json.JSONDecodeError):
        return None

    system = ev.get("System", {}) or {}
    data = ev.get("EventData") or {}
    if not isinstance(data, dict):
        data = {}

    provider = (system.get("Provider", {}) or {}).get("#attributes", {}).get("Name", "")
    channel = system.get("Channel", "")
    source = "Sysmon" if "sysmon" in f"{provider}{channel}".lower() else (channel or "Security")

    return {
        "time": (system.get("TimeCreated", {}) or {}).get("#attributes", {}).get("SystemTime"),
        "host": system.get("Computer"),
        "source": source,
        "event_id": _event_id(system),
        # User: for logon events prefer the target user, otherwise subject/user
        "user": _strip_domain(data.get("TargetUserName")
                              or data.get("SubjectUserName")
                              or data.get("User")),
        "ip": data.get("IpAddress"),
        "dest_ip": data.get("DestinationIp"),
        "dest_port": _safe_int(data.get("DestinationPort")),
        "image": data.get("Image"),
        "cmdline": data.get("CommandLine"),
        "parent": data.get("ParentImage"),
        # Task name for scheduled-task events (4698) — used by the detector
        "task_name": data.get("TaskName"),
    }


def parse_evtx(path: str) -> list[dict]:
    """Parse a .evtx file and return a list of raw-log dicts."""
    parser = PyEvtxParser(str(path))
    events = []
    for record in parser.records_json():
        raw = _to_raw_event(record["data"])
        if raw and raw["event_id"] is not None:
            events.append(raw)
    return events


if __name__ == "__main__":
    import sys
    from collections import Counter
    path = sys.argv[1] if len(sys.argv) > 1 else "data/real/temp_scheduled_task_4698_4699.evtx"
    events = parse_evtx(path)
    print(f"Parsed {len(events)} events: {path}\n")
    counts = Counter((e["source"], e["event_id"]) for e in events)
    for (src, eid), n in counts.most_common():
        print(f"  {src:10} EID {eid}: {n} events")

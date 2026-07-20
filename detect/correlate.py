"""
detect/correlate.py — Correlation layer: SIGNALS -> INCIDENTS.

Detectors produce individual signals ("a brute force happened", "encoded powershell
happened"). But what matters to an analyst is that these happen TOGETHER on the same
machine in a short window — because that points to a single attack chain.

This layer groups signals that pile up on the same host within a time window into a
single "incident". That way we can give the LLM "here is the attack story on this
machine" instead of "here are 4 disconnected alerts".

An INCIDENT has this shape:
    {
      "host": str,
      "start": str, "end": str,      # time range
      "techniques": list[str],        # ATT&CK techniques it contains (in order)
      "severity": "low|medium|high",  # highest signal severity
      "signals": list[dict],          # the signals that make up the incident (time-ordered)
      "event_ids": list[int],         # all related raw event ids
    }
"""

import common.console  # noqa: F401
from datetime import datetime
from config import CORRELATION_WINDOW
from detect.detectors import run_all_detectors

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _parse_time(t: str) -> datetime:
    return datetime.fromisoformat(t)


def correlate(signals: list[dict]) -> list[dict]:
    """Group signals into incidents by host + time window."""
    # Split by host first, then sort each host's signals by time
    by_host: dict[str, list[dict]] = {}
    for s in signals:
        by_host.setdefault(s["host"], []).append(s)
    for host_signals in by_host.values():
        host_signals.sort(key=lambda s: s["time"])

    incidents = []
    for host, host_signals in by_host.items():
        current: list[dict] = []
        for sig in host_signals:
            if not current:
                current = [sig]
                continue
            # If the new signal is within the window of the group's first signal,
            # add it to the same incident; otherwise close the group and start a new one.
            if _parse_time(sig["time"]) - _parse_time(current[0]["time"]) <= CORRELATION_WINDOW:
                current.append(sig)
            else:
                incidents.append(_build_incident(host, current))
                current = [sig]
        if current:
            incidents.append(_build_incident(host, current))

    # Show the most severe incidents first
    incidents.sort(key=lambda i: _SEVERITY_ORDER[i["severity"]], reverse=True)
    return incidents


def _build_incident(host: str, signals: list[dict]) -> dict:
    """Build a single incident object from a group of signals."""
    event_ids = sorted({eid for s in signals for eid in s["event_ids"]})
    techniques = []
    for s in signals:  # preserve order, drop duplicates
        if s["technique"] not in techniques:
            techniques.append(s["technique"])
    severity = max((s["severity"] for s in signals), key=lambda x: _SEVERITY_ORDER[x])
    return {
        "host": host,
        "start": signals[0]["time"],
        "end": signals[-1]["time"],
        "techniques": techniques,
        "severity": severity,
        "signals": signals,
        "event_ids": event_ids,
    }


def build_incidents() -> list[dict]:
    """End-to-end shortcut: run detectors -> group signals into incidents."""
    return correlate(run_all_detectors())


if __name__ == "__main__":
    incidents = build_incidents()
    print(f"{len(incidents)} incident(s) built:\n")
    for idx, inc in enumerate(incidents, 1):
        print(f"INCIDENT #{idx} — {inc['host']} ({inc['severity'].upper()})")
        print(f"  Time: {inc['start']} -> {inc['end']}")
        print(f"  Techniques: {', '.join(inc['techniques'])}")
        print(f"  Signals: {len(inc['signals'])}, raw event ids: {inc['event_ids']}\n")

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
from collections import Counter, defaultdict
from common.db import get_connection
from common.timeutil import parse_time as _parse_time
from config import CORRELATION_WINDOW, CAMPAIGN_WINDOW
from detect.detectors import run_all_detectors

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


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


# --------------------------------------------------------------------------- #
# Campaign linking: incidents on DIFFERENT hosts that belong to one attack
#
# Grouping by host answers "what happened on this machine". It cannot answer "did
# the same intruder move between machines" — and lateral movement is exactly what an
# analyst most needs to see. Two incidents belong to the same campaign when they
# share an entity (a pivot IP, or the same non-generic account) and sit close enough
# in time.
#
# Incidents are LINKED, not merged: per-host triage stays intact, and every layer
# above (validation, reporting, evaluation) keeps working on the same structure.
# --------------------------------------------------------------------------- #

# Accounts that say nothing about *who* is acting — linking on these would tie
# together unrelated machines that merely both have an administrator.
_GENERIC_ACCOUNTS = {
    "root", "system", "localsystem", "administrator", "admin", "-",
    "network service", "local service", "nt authority\\system",
}


def _entities(conn, event_ids: list[int]) -> tuple[set, set]:
    """Return the (ip, account) identifiers an incident touched."""
    if not event_ids:
        return set(), set()
    placeholders = ",".join("?" for _ in event_ids)
    rows = conn.execute(
        f"SELECT src_ip, dst_ip, user FROM events WHERE id IN ({placeholders})",
        event_ids,
    ).fetchall()

    ips, users = set(), set()
    for r in rows:
        for ip in (r["src_ip"], r["dst_ip"]):
            if ip:
                ips.add(ip)
        user = (r["user"] or "").strip().lower()
        if user and user not in _GENERIC_ACCOUNTS:
            users.add(user)
    return ips, users


def _near_in_time(a: dict, b: dict) -> bool:
    """Do two incidents sit within CAMPAIGN_WINDOW of each other?"""
    a_start, a_end = _parse_time(a["start"]), _parse_time(a["end"])
    b_start, b_end = _parse_time(b["start"]), _parse_time(b["end"])
    if a_start <= b_end and b_start <= a_end:
        return True  # overlapping
    gap = b_start - a_end if b_start > a_end else a_start - b_end
    return gap <= CAMPAIGN_WINDOW


def link_campaigns(incidents: list[dict]) -> list[dict]:
    """Tag incidents that belong to one cross-host campaign with a shared id."""
    for inc in incidents:  # defaults, so callers can rely on the keys existing
        inc["campaign_id"] = None
        inc["related_hosts"] = []
        inc["campaign_peers"] = []
    if len(incidents) < 2:
        return incidents

    conn = get_connection()
    entities = [_entities(conn, inc["event_ids"]) for inc in incidents]
    conn.close()

    # An address seen almost everywhere is shared infrastructure (a DNS resolver, a
    # proxy), not evidence of one intruder. Only filter once there are enough
    # incidents for "almost everywhere" to mean anything.
    ip_counts = Counter(ip for ips, _ in entities for ip in ips)
    infrastructure = {ip for ip, n in ip_counts.items()
                      if n >= 4 and n > len(incidents) / 2}

    parent = list(range(len(incidents)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    for i in range(len(incidents)):
        for j in range(i + 1, len(incidents)):
            if incidents[i]["host"] == incidents[j]["host"]:
                continue  # same host is already one incident
            if not _near_in_time(incidents[i], incidents[j]):
                continue
            shared_ips = (entities[i][0] & entities[j][0]) - infrastructure
            shared_users = entities[i][1] & entities[j][1]
            if shared_ips or shared_users:
                union(i, j)

    # Only groups with more than one incident are a campaign worth naming.
    groups = defaultdict(list)
    for idx in range(len(incidents)):
        groups[find(idx)].append(idx)

    campaign_no = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        campaign_no += 1
        members.sort(key=lambda m: incidents[m]["start"])  # chronological = attack order
        hosts = [incidents[m]["host"] for m in members]
        for m in members:
            incidents[m]["campaign_id"] = campaign_no
            incidents[m]["related_hosts"] = [h for h in hosts if h != incidents[m]["host"]]
            # What the other hosts saw, so the reasoning layer can describe the
            # movement between them instead of three disconnected stories.
            incidents[m]["campaign_peers"] = [
                {
                    "host": incidents[p]["host"],
                    "start": incidents[p]["start"],
                    "techniques": list(incidents[p]["techniques"]),
                }
                for p in members if p != m
            ]
    return incidents


def build_incidents() -> list[dict]:
    """End-to-end shortcut: detectors -> per-host incidents -> campaign links."""
    return link_campaigns(correlate(run_all_detectors()))


if __name__ == "__main__":
    incidents = build_incidents()
    print(f"{len(incidents)} incident(s) built:\n")
    for idx, inc in enumerate(incidents, 1):
        print(f"INCIDENT #{idx} — {inc['host']} ({inc['severity'].upper()})")
        print(f"  Time: {inc['start']} -> {inc['end']}")
        print(f"  Techniques: {', '.join(inc['techniques'])}")
        print(f"  Signals: {len(inc['signals'])}, raw event ids: {inc['event_ids']}\n")

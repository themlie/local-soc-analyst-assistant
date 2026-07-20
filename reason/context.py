"""
reason/context.py — Builds the "evidence package" (context) for the LLM.

This is RAG logic in action: we don't ask the LLM a blank question; we assemble all
the evidence RELATED to the incident and hand it over:
  1) Raw logs (with their ids) — so the LLM grounds claims on those ids.
  2) Triggered detector signals — which rule fired and why.
  3) Relevant ATT&CK technique descriptions — to give the model domain knowledge.

The cleaner this package, the more accurate the model's answer.
"""

from common.db import get_connection
from common.attack import describe


def _load_events(event_ids: list[int]) -> list:
    """Fetch the raw events with the given ids from the database."""
    if not event_ids:
        return []
    conn = get_connection()
    placeholders = ",".join("?" for _ in event_ids)
    rows = conn.execute(
        f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY time",
        event_ids,
    ).fetchall()
    conn.close()
    return rows


def build_context(incident: dict) -> str:
    """Produce a text evidence package for one incident."""
    rows = _load_events(incident["event_ids"])
    lines = [
        f"HOST: {incident['host']}",
        f"TIME RANGE: {incident['start']} - {incident['end']}",
        "",
        "EVENTS (raw logs — each has an id):",
    ]

    for r in rows:
        parts = [f"id={r['id']}", r["time"]]
        if r["event_id"]:
            parts.append(f"EID={r['event_id']}")
        if r["user"]:
            parts.append(f"user={r['user']}")
        if r["src_ip"]:
            parts.append(f"src_ip={r['src_ip']}")
        if r["dst_ip"]:
            parts.append(f"dst_ip={r['dst_ip']}:{r['dst_port']}")
        if r["process"]:
            parts.append(f"process={r['process']}")
        if r["cmdline"]:
            parts.append(f"cmdline={r['cmdline']}")
        # Web / application-layer fields
        if r["category"]:
            parts.append(f"category={r['category']}")
        if r["tool"]:
            parts.append(f"tool={r['tool']}")
        if r["url"]:
            parts.append(f"url={r['url']}")
        if r["message"]:
            parts.append(f"message={r['message']}")
        lines.append("  - " + " | ".join(parts))

    lines += ["", "TRIGGERED DETECTION RULES (signals):"]
    for s in incident["signals"]:
        lines.append(
            f"  - {s['technique']} {s['technique_name']}: {s['description']} "
            f"(event ids: {s['event_ids']})"
        )

    lines += ["", "RELEVANT ATT&CK TECHNIQUES (reference):"]
    for t in incident["techniques"]:
        lines.append("  - " + describe(t))

    return "\n".join(lines)

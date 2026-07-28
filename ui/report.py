"""
ui/report.py — Renders results as a readable incident report in the terminal.

Takes the analysis (LLM) and validation (grounding) results and formats them for an
analyst to read. Presentation layer only; contains no business logic.
"""

import common.console  # noqa: F401

_SEV_ICON = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def render_report(incident: dict, report: dict, validation: dict) -> None:
    """Print the analysis + validation result for one incident."""
    # Severity comes from the detectors, never from the model. Detection is
    # deterministic; the model's rating is an opinion, and log text crafted by an
    # attacker must not be able to talk a real incident down to "low".
    sev = str(incident["severity"]).lower()
    icon = _SEV_ICON.get(sev, "⚪")
    model_sev = str(report.get("severity", "")).strip().lower()

    print("=" * 70)
    print(f"{icon}  INCIDENT REPORT — {incident['host']}   [severity: {sev.upper()}]")
    print(f"    Time range: {incident['start']} -> {incident['end']}")
    if incident.get("campaign_id"):
        related = ", ".join(incident.get("related_hosts", []))
        print(f"    🔗 CAMPAIGN #{incident['campaign_id']} — also affects: {related}")
    if model_sev and model_sev != sev:
        print(f"    (model suggested '{model_sev}' — the detector rating stands)")
    print("=" * 70)

    # Summary
    print("\n> SUMMARY")
    print(f"  {report.get('summary', '(no summary)')}")

    # Timeline
    print("\n> TIMELINE")
    for item in report.get("timeline", []) or []:
        if isinstance(item, dict):
            t = item.get("time", "")
            d = item.get("description", "")
            print(f"  - {t}  {d}")
        else:
            print(f"  - {item}")

    # Attack chain
    print("\n> ATTACK CHAIN (ATT&CK)")
    for step in report.get("attack_chain", []) or []:
        if isinstance(step, dict):
            print(f"  - {step.get('technique','')} ({step.get('tactic','')}): "
                  f"{step.get('explanation','')}")
        else:
            print(f"  - {step}")

    # Recommended actions
    print("\n> RECOMMENDED ACTIONS")
    for act in report.get("recommended_actions", []) or []:
        print(f"  - {act}")

    # Validation (hallucination shield)
    print("\n> VALIDATION (grounding)")
    # The score measures how well the reported techniques match the evidence; a report
    # can score well there and still be rejected for something else (a severity
    # downgrade, say), so point at the reasons rather than leaving them looking
    # contradictory.
    mark = "✅ TRUSTWORTHY" if validation["grounded"] else "⚠️  CAUTION — see findings below"
    print(f"  {mark}  |  technique grounding: {validation['trust_score']}")
    if validation["warnings"]:
        for w in validation["warnings"]:
            print(f"    - {w}")
    else:
        print("    - All claims are backed by detection evidence.")
    print()

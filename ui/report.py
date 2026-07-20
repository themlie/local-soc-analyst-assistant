"""
ui/report.py — Renders results as a readable incident report in the terminal.

Takes the analysis (LLM) and validation (grounding) results and formats them for an
analyst to read. Presentation layer only; contains no business logic.
"""

import common.console  # noqa: F401

_SEV_ICON = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def render_report(incident: dict, report: dict, validation: dict) -> None:
    """Print the analysis + validation result for one incident."""
    sev = str(report.get("severity", incident["severity"])).lower()
    icon = _SEV_ICON.get(sev, "⚪")

    print("=" * 70)
    print(f"{icon}  INCIDENT REPORT — {incident['host']}   [severity: {sev.upper()}]")
    print(f"    Time range: {incident['start']} -> {incident['end']}")
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
    mark = "✅ TRUSTWORTHY" if validation["grounded"] else "⚠️  CAUTION"
    print(f"  {mark}  |  trust score: {validation['trust_score']}")
    if validation["warnings"]:
        for w in validation["warnings"]:
            print(f"    - {w}")
    else:
        print("    - All claims are backed by detection evidence.")
    print()

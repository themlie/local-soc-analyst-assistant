"""
validate/grounding.py — Validation layer: THE HALLUCINATION SHIELD.

The LLM is powerful but sometimes "invents" things that aren't in the evidence
(hallucination). In a security tool that is unacceptable. This layer cross-checks the
model's report against the real evidence and flags unreliable claims:

  1) INVENTED TECHNIQUE: did the model cite a non-existent ATT&CK technique ID?
  2) UNSUPPORTED TECHNIQUE: did it assert a technique no detector triggered?
  3) MISSING: is there a detected technique the report never explains?

The output is a "trust" assessment attached to the report. This is what turns the
project from "I just asked an LLM" into "a system that produces validated output".
"""

import common.console  # noqa: F401
from common.attack import is_valid_technique


def validate_report(report: dict, incident: dict) -> dict:
    """Validate the report against the incident's real evidence; produce warnings and a trust score."""
    warnings: list[str] = []

    # If the model produced no valid JSON at all, it's untrustworthy from the start.
    if report.get("_parse_error"):
        return {
            "grounded": False,
            "trust_score": 0.0,
            "warnings": ["Model produced no valid JSON; output is untrustworthy."],
        }

    detected = list(incident["techniques"])          # techniques the detectors actually found
    chain = report.get("attack_chain", []) or []

    used, valid_and_supported = [], 0
    for step in chain:
        tid = step.get("technique") if isinstance(step, dict) else None
        if not tid:
            continue
        used.append(tid)
        if not is_valid_technique(tid):
            warnings.append(f"INVENTED TECHNIQUE: '{tid}' is not a valid ATT&CK technique.")
        elif tid not in detected:
            warnings.append(
                f"UNSUPPORTED TECHNIQUE: '{tid}' is in the report but not backed by any detection signal."
            )
        else:
            valid_and_supported += 1

    # Techniques that were detected but never mentioned in the report (missed context)
    for tid in detected:
        if tid not in used:
            warnings.append(f"MISSING: '{tid}' was detected but not explained in the report.")

    # Trust score: what fraction of the techniques the report asserts are actually supported?
    trust_score = round(valid_and_supported / len(used), 2) if used else 0.0

    # "Grounded" = no invented or unsupported techniques
    grounded = not any(w.startswith(("INVENTED", "UNSUPPORTED")) for w in warnings)

    return {
        "grounded": grounded,
        "trust_score": trust_score,
        "warnings": warnings,
    }

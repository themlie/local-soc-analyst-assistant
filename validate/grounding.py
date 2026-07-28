"""
validate/grounding.py — Validation layer: THE HALLUCINATION SHIELD.

The LLM is useful but it sometimes states things the evidence does not support. In a
security tool that is unacceptable, so every report is cross-checked against what the
detectors actually found before an analyst ever sees it.

What gets checked:
  1) INVENTED TECHNIQUE  — an ATT&CK id that does not exist.
  2) UNSUPPORTED         — a real technique no detector triggered.
  3) WRONG TACTIC        — a real technique filed under the wrong tactic.
  4) UNGROUNDED IOC      — an IP in the prose that appears nowhere in the evidence.
  5) SEVERITY DOWNGRADE  — the model rating the incident lower than the detectors did.
  6) EMPTY / MISSING     — detections the report never explains.

Checks 3-5 exist because verifying the technique id alone is not enough: a report can
name the right technique and still be wrong about everything around it. Check 5 also
covers the case where crafted log text talks the model into calling a real attack
benign — see reason/context.py on the untrusted boundary.
"""

import re
import common.console  # noqa: F401
from common.attack import is_valid_technique, get_technique

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Words too generic to prove two tactic names refer to the same thing.
_TACTIC_STOPWORDS = {"and", "or", "the", "of", "a", "access", "control"}

_IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _tactic_tokens(text: str) -> set[str]:
    """Meaningful lowercase words of a tactic name, for loose comparison."""
    return {w for w in re.split(r"[^a-z]+", text.lower()) if w and w not in _TACTIC_STOPWORDS}


def _free_text(report: dict) -> str:
    """Every prose field the model wrote — where ungrounded claims tend to hide."""
    parts = [str(report.get("summary", ""))]
    parts += [str(x) for x in (report.get("recommended_actions") or [])]
    parts += [str(x) for x in (report.get("timeline") or [])]
    for step in report.get("attack_chain") or []:
        if isinstance(step, dict):
            parts.append(str(step.get("explanation", "")))
    return " ".join(parts)


def validate_report(report: dict, incident: dict, context: str | None = None) -> dict:
    """Validate a report against the incident's evidence; return warnings and a score.

    `context` is the evidence package that was sent to the model. When supplied, the
    prose is additionally checked for indicators that do not appear in it.
    """
    warnings: list[str] = []

    # No valid JSON at all — nothing can be trusted.
    if report.get("_parse_error"):
        return {
            "grounded": False,
            "trust_score": 0.0,
            "warnings": ["Model produced no valid JSON; output is untrustworthy."],
        }

    detected = list(incident["techniques"])
    chain = report.get("attack_chain") or []

    used, supported = [], 0
    for step in chain:
        tid = step.get("technique") if isinstance(step, dict) else None
        if not tid:
            continue
        used.append(tid)

        if not is_valid_technique(tid):
            warnings.append(f"INVENTED TECHNIQUE: '{tid}' is not a valid ATT&CK technique.")
            continue
        if tid not in detected:
            warnings.append(
                f"UNSUPPORTED TECHNIQUE: '{tid}' is in the report but no detection signal backs it."
            )
            continue

        # The id is right; check the model filed it under the right tactic.
        claimed = str(step.get("tactic") or "").strip()
        actual = get_technique(tid)["tactic"]
        if claimed and not (_tactic_tokens(claimed) & _tactic_tokens(actual)):
            warnings.append(
                f"WRONG TACTIC: '{tid}' reported as '{claimed}', ATT&CK says '{actual}'."
            )
            continue
        supported += 1

    # Detections the report never explains.
    for tid in detected:
        if tid not in used:
            warnings.append(f"MISSING: '{tid}' was detected but is not explained in the report.")

    # A report that explains nothing is not a trustworthy report.
    if detected and not used:
        warnings.append("EMPTY REPORT: the model explained no technique despite active detections.")

    # Indicators asserted in prose but absent from the evidence.
    if context:
        haystack = context.lower()
        for ip in set(_IP_PATTERN.findall(_free_text(report))):
            if ip not in haystack:
                warnings.append(
                    f"UNGROUNDED IOC: IP '{ip}' appears in the report but not in the evidence."
                )

    # The detectors are the authority on severity; the model lowering it is a red flag.
    claimed_sev = str(report.get("severity", "")).strip().lower()
    detector_sev = str(incident["severity"]).lower()
    if claimed_sev in _SEVERITY_ORDER and detector_sev in _SEVERITY_ORDER:
        if _SEVERITY_ORDER[claimed_sev] < _SEVERITY_ORDER[detector_sev]:
            warnings.append(
                f"SEVERITY DOWNGRADE: model rated this '{claimed_sev}' but detections say "
                f"'{detector_sev}'; the detector rating stands."
            )

    # fidelity: of what the report claimed, how much holds up.
    # coverage: of what was detected, how much the report actually explained.
    fidelity = supported / len(used) if used else 0.0
    coverage = len(set(used) & set(detected)) / len(detected) if detected else 1.0
    trust_score = round(min(fidelity, coverage), 2) if (used or detected) else 1.0

    disqualifying = ("INVENTED", "UNSUPPORTED", "WRONG TACTIC", "UNGROUNDED IOC",
                     "EMPTY REPORT", "SEVERITY DOWNGRADE")
    grounded = not any(w.startswith(disqualifying) for w in warnings)

    return {
        "grounded": grounded,
        "trust_score": trust_score,
        "warnings": warnings,
    }

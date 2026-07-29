"""
ui/navigator.py — export findings as MITRE ATT&CK Navigator layers.

Navigator (https://mitre-attack.github.io/attack-navigator/) renders the ATT&CK matrix
and colours techniques from a "layer" JSON file. Two layers are produced here, and the
second is the more interesting one:

  - `detected_layer` — what fired in the analysed logs. An incident report as a picture.
  - `coverage_layer` — what the rule set can catch *at all*, and therefore what it
    cannot. Publishing the blank squares alongside the filled ones is the honest way to
    describe a detection capability; a coverage map showing only strengths is marketing.

Neither needs the LLM: both come from the deterministic detection layer.

    python -m ui.navigator            # writes both layers for the sample logs
"""

import json
from collections import Counter

from common.attack import TECHNIQUES, get_technique
from detect.detectors import COVERED_TECHNIQUES

# Navigator upgrades older layers on import, so pinning a conservative, widely
# supported version is safer than chasing the newest one.
_LAYER_VERSIONS = {"attack": "14", "navigator": "4.9.1", "layer": "4.5"}

_COVERED_COLOR = "#2e7d32"      # green: a rule exists
_UNCOVERED_COLOR = "#c62828"    # red: known gap


def _layer(name: str, description: str, techniques: list[dict], **extra) -> dict:
    return {
        "name": name,
        "versions": _LAYER_VERSIONS,
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "sorting": 0,
        "hideDisabled": False,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        **extra,
    }


def detected_layer(incidents: list[dict], name: str = "SOC Assistant — detections") -> dict:
    """A layer of the techniques these incidents actually triggered.

    Scores count how many signals support a technique, so what happened repeatedly
    stands out from what happened once.
    """
    counts: Counter = Counter()
    hosts: dict[str, set] = {}
    for incident in incidents:
        for signal in incident["signals"]:
            counts[signal["technique"]] += 1
            hosts.setdefault(signal["technique"], set()).add(incident["host"])

    techniques = [{
        "techniqueID": tid,
        "score": count,
        "enabled": True,
        "comment": f"{count} signal(s) on: {', '.join(sorted(hosts[tid]))}",
        "metadata": [{"name": "technique", "value": (get_technique(tid) or {}).get("name", "")}],
    } for tid, count in sorted(counts.items())]

    max_score = max(counts.values(), default=1)
    return _layer(
        name,
        f"Techniques detected across {len(incidents)} incident(s). "
        f"Produced by rule-based detection, not by the language model.",
        techniques,
        gradient={"colors": ["#ffe082", "#e65100"], "minValue": 0, "maxValue": max_score},
    )


def coverage_layer(name: str = "SOC Assistant — detection coverage") -> dict:
    """A layer showing which techniques the rule set can catch, and which it cannot.

    Every technique in the local ATT&CK catalogue appears: green where a rule exists,
    red where none does. The red squares are the point — they are the roadmap, stated
    in the same language a SOC uses to describe capability.
    """
    techniques = []
    for tid in sorted(TECHNIQUES):
        covered = tid in COVERED_TECHNIQUES
        techniques.append({
            "techniqueID": tid,
            "color": _COVERED_COLOR if covered else _UNCOVERED_COLOR,
            "enabled": True,
            "comment": "Rule implemented" if covered else "KNOWN GAP — no rule yet",
            "metadata": [{"name": "technique", "value": TECHNIQUES[tid]["name"]}],
        })

    covered_n = len(COVERED_TECHNIQUES)
    return _layer(
        name,
        f"{covered_n} of {len(TECHNIQUES)} catalogued techniques have a detection rule. "
        f"Red squares are documented gaps, not omissions.",
        techniques,
        legendItems=[
            {"label": "Rule implemented", "color": _COVERED_COLOR},
            {"label": "Known gap", "color": _UNCOVERED_COLOR},
        ],
    )


def to_json(layer: dict) -> str:
    return json.dumps(layer, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    import common.console  # noqa: F401
    from ingest.ingest import ingest_file
    from detect.correlate import build_incidents

    ingest_file()
    incidents = build_incidents()

    for filename, layer in (("navigator-detections.json", detected_layer(incidents)),
                            ("navigator-coverage.json", coverage_layer())):
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(to_json(layer))
        print(f"wrote {filename}: {len(layer['techniques'])} technique(s)")
    print("\nUpload either file at https://mitre-attack.github.io/attack-navigator/"
          " → 'Open Existing Layer' → 'Upload from local'.")

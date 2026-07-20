"""
eval/real_eval.py — Evaluation on REAL data.

evaluate.py measures synthetic scenarios. This file uses real-world Windows event logs
(sbousseaden/EVTX-ATTACK-SAMPLES — real EVTX labeled by ATT&CK). Each file is a known
attack sample; its name/folder gives the label.

The goal is an honest measurement: how well does the system do on real data? (It's
normal for the synthetic 100% to drop in the real world — simple rules can't catch
every technique. Those gaps are "future work" and show that the evaluation is doing
its job.)

On first run it downloads the required EVTX files from GitHub (needs internet).
"""

import os
import urllib.request
import urllib.parse
import common.console  # noqa: F401
from config import ROOT
from ingest.win_evtx import parse_evtx
from ingest.ingest import ingest_events, ingest_file
from detect.detectors import run_all_detectors

REAL_DIR = ROOT / "data" / "real"
BASE_URL = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"

# Labeled real samples: (repo path, expected techniques, note)
LABELED = [
    ("Execution/temp_scheduled_task_4698_4699.evtx",
     ["T1053.005"], "Scheduled task creation (Security 4698)"),
    ("Credential Access/kerberos_pwd_spray_4771.evtx",
     ["T1110", "T1070.001"], "Kerberos password spray + log clearing"),
    ("Credential Access/babyshark_mimikatz_powershell.evtx",
     ["T1059.001"], "KNOWN GAP: malicious PowerShell not visible in process cmdline"),
]


def _ensure_downloaded(repo_path: str) -> str:
    """Download the file if missing; return the local path."""
    REAL_DIR.mkdir(parents=True, exist_ok=True)
    local = REAL_DIR / os.path.basename(repo_path)
    if not local.exists():
        url = BASE_URL + urllib.parse.quote(repo_path)
        print(f"  downloading: {os.path.basename(repo_path)}")
        urllib.request.urlretrieve(url, local)
    return str(local)


def run() -> None:
    print("Preparing real EVTX samples...\n")
    total_expected = total_detected = 0

    print("=" * 82)
    print(f"{'FILE':<46} {'EXPECTED':<14} {'FOUND':<14}  RESULT")
    print("=" * 82)

    for repo_path, expected, note in LABELED:
        local = _ensure_downloaded(repo_path)
        events = parse_evtx(local)
        ingest_events(events)
        predicted = {s["technique"] for s in run_all_detectors()}

        exp = set(expected)
        hit = exp & predicted
        total_expected += len(exp)
        total_detected += len(hit)

        name = os.path.basename(repo_path)[:44]
        mark = "OK" if hit == exp else ("~" if hit else "!!")
        print(f"{name:<46} {','.join(sorted(exp)):<14} "
              f"{','.join(sorted(predicted)) or '-':<14}  {mark}")

    recall = total_detected / total_expected if total_expected else 0.0
    print("=" * 82)
    print(f"REAL-DATA RECALL: {recall:.0%} "
          f"({total_detected}/{total_expected} techniques detected)")
    print("Note: what's missed is a 'known gap' — in the real world simple rules can't")
    print("      catch every technique; this is a roadmap for future detectors.")
    print("=" * 82)

    ingest_file()  # restore the demo data


if __name__ == "__main__":
    run()

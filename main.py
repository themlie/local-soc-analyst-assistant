"""
main.py — Orchestrator: runs the whole pipeline end to end.

Flow:
    ingest  ->  detect + correlate  ->  reason (LLM)  ->  validate  ->  report

Usage:
    python main.py                       # default model from config.py
    python main.py --model phi-4-mini    # higher-quality model
    python main.py --evtx <file.evtx>    # analyze a real EVTX file
"""

import argparse
import common.console  # noqa: F401

from ingest.ingest import ingest_file, ingest_events
from detect.correlate import build_incidents
from reason.analyst import analyze_incident
from validate.grounding import validate_report
from ui.report import render_report
from config import CHAT_MODEL


def run(model: str = CHAT_MODEL, evtx: str | None = None, file: str | None = None) -> None:
    # 1) Normalize raw logs and write them to the database
    if evtx:
        from ingest.win_evtx import parse_evtx
        n = ingest_events(parse_evtx(evtx))
        print(f"[ingest]    {n} events (real EVTX): {evtx}")
    elif file:
        from pathlib import Path
        import json as _json
        n = ingest_events(_json.loads(Path(file).read_text(encoding="utf-8")))
        print(f"[ingest]    {n} events (JSON): {file}")
    else:
        n = ingest_file()
        print(f"[ingest]    {n} events written to the database.")

    # 2) Run detectors + group signals into incidents
    incidents = build_incidents()
    print(f"[correlate] {len(incidents)} incident(s) built.\n")

    if not incidents:
        print("No suspicious activity found. Logs look clean.")
        return

    # 3) For each incident: LLM analysis + validation + report
    print(f"[reason]    Loading model: {model} (may download on first run)...\n")
    for incident in incidents:
        try:
            report = analyze_incident(incident, alias=model)
        except Exception as exc:
            # One incident failing (e.g. the model service being busy) should not
            # abort the whole run — report it and move on.
            print(f"⚠️  Could not analyze incident on {incident['host']}: {exc}\n")
            continue
        validation = validate_report(report, incident)
        render_report(incident, report, validation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local SOC Analyst Assistant")
    parser.add_argument("--model", default=CHAT_MODEL,
                        help="Foundry Local model to use (alias)")
    parser.add_argument("--evtx", default=None,
                        help="Analyze a real .evtx file instead of the synthetic data")
    parser.add_argument("--file", default=None,
                        help="Analyze an arbitrary JSON log file")
    args = parser.parse_args()
    run(model=args.model, evtx=args.evtx, file=args.file)

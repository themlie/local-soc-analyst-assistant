"""
eval/grounding_eval.py — LLM GROUNDING (hallucination) evaluation.

evaluate.py measures the deterministic DETECTION layer. This file measures the LLM
itself: how faithful is the model to the evidence? Does it invent techniques?

It runs each malicious scenario end to end (detect -> correlate -> LLM -> validate)
and reports:
  - JSON success rate: in how many scenarios did the model produce valid JSON?
  - Grounding rate: in how many scenarios were there NO invented/unsupported techniques?
  - Total hallucinations: how many invented/unsupported technique claims occurred?
  - Average trust score.

WARNING: this evaluation calls the LLM, so it is SLOW (seconds per scenario on CPU).
Use --limit to run on just a few scenarios.
"""

import json
import argparse
import common.console  # noqa: F401
from config import ROOT, CHAT_MODEL
from ingest.ingest import ingest_events, ingest_file
from detect.correlate import build_incidents
from reason.analyst import analyze_incident
from validate.grounding import validate_report

GOLDEN_PATH = ROOT / "eval" / "golden.json"


def run(model: str = CHAT_MODEL, limit: int | None = None) -> None:
    cases = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    # Only malicious scenarios that produce detections are meaningful (LLM needs an incident)
    malicious = [c for c in cases if c["is_malicious"]]
    if limit:
        malicious = malicious[:limit]

    print(f"Evaluating {len(malicious)} malicious scenario(s) with the LLM "
          f"(model: {model})...\n")

    json_ok = grounded_count = 0
    total_hallucinations = 0
    trust_scores = []
    evaluated = 0

    for case in malicious:
        ingest_events(case["logs"])
        incidents = build_incidents()
        if not incidents:
            print(f"  {case['name']:<32} -> no detection, skipped (known gap)")
            continue

        evaluated += 1
        report = analyze_incident(incidents[0], alias=model)
        validation = validate_report(report, incidents[0])

        parse_ok = not report.get("_parse_error")
        json_ok += int(parse_ok)
        grounded_count += int(validation["grounded"])
        trust_scores.append(validation["trust_score"])
        halluc = sum(1 for w in validation["warnings"]
                     if w.startswith(("INVENTED", "UNSUPPORTED")))
        total_hallucinations += halluc

        mark = "OK" if validation["grounded"] and parse_ok else "!!"
        print(f"  {case['name']:<32} -> JSON:{'y' if parse_ok else 'n'}  "
              f"grounded:{'y' if validation['grounded'] else 'n'}  "
              f"trust:{validation['trust_score']:.2f}  hallucinations:{halluc}  {mark}")

    print("\n" + "=" * 60)
    if evaluated:
        print("LLM GROUNDING RESULTS:")
        print(f"  Scenarios evaluated       : {evaluated}")
        print(f"  Valid JSON rate           : {json_ok/evaluated:.0%}")
        print(f"  Grounding rate (no invent): {grounded_count/evaluated:.0%}")
        print(f"  Total hallucinations      : {total_hallucinations}")
        print(f"  Average trust score       : {sum(trust_scores)/len(trust_scores):.2f}")
    else:
        print("No scenarios to evaluate.")
    print("=" * 60)

    ingest_file()  # restore the demo data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM grounding evaluation")
    parser.add_argument("--model", default=CHAT_MODEL)
    parser.add_argument("--limit", type=int, default=None,
                        help="Evaluate only the first N malicious scenarios (for speed)")
    args = parser.parse_args()
    run(model=args.model, limit=args.limit)

"""
eval/evaluate.py — Evaluation pipeline.

Measures how well the system performs, with numbers. It feeds hand-labeled "golden"
scenarios (eval/golden.json) into the system, compares the ATT&CK techniques the
system finds against the expected ones, and computes standard metrics:

  - Precision: of the techniques the system reported, how many are correct? (few false alarms?)
  - Recall: of the techniques that should be found, how many did it catch? (few misses?)
  - F1: the balanced mean of the two.
  - Classification accuracy: how accurate is the "malicious vs clean" decision?

This measurement is DETERMINISTIC and FAST (needs no LLM) — because it measures the
detection layer. So you can run it as often as you like for regression tracking.
"""

import json
import common.console  # noqa: F401
from config import ROOT
from ingest.ingest import ingest_events, ingest_file
from detect.detectors import run_all_detectors

GOLDEN_PATH = ROOT / "eval" / "golden.json"


def evaluate() -> dict:
    cases = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

    total_tp = total_fp = total_fn = 0
    correct_classification = 0

    print("=" * 82)
    print(f"{'SCENARIO':<28} {'EXPECTED':<12} {'FOUND':<12} {'TP':>3} {'FP':>3} {'FN':>3}  RESULT")
    print("=" * 82)

    for case in cases:
        # 1) Load the scenario's logs and run the detectors
        ingest_events(case["logs"])
        signals = run_all_detectors()

        predicted = {s["technique"] for s in signals}
        expected = set(case["expected_techniques"])

        tp = predicted & expected          # correctly found
        fp = predicted - expected          # false alarms
        fn = expected - predicted          # missed

        total_tp += len(tp)
        total_fp += len(fp)
        total_fn += len(fn)

        # 2) "malicious?" classification: at least one signal = predicted malicious
        predicted_malicious = len(signals) > 0
        classification_ok = (predicted_malicious == case["is_malicious"])
        correct_classification += int(classification_ok)

        # Perfect scenario? (no FP and no FN)
        perfect = not fp and not fn
        mark = "OK" if perfect else "!!"
        exp_str = ",".join(sorted(expected)) or "-"
        pred_str = ",".join(sorted(predicted)) or "-"
        print(f"{case['name']:<28} {exp_str:<12} {pred_str:<12} "
              f"{len(tp):>3} {len(fp):>3} {len(fn):>3}  {mark}")

    # 3) Overall metrics (micro-average)
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    class_acc = correct_classification / len(cases) if cases else 0.0

    print("=" * 82)
    print("OVERALL RESULTS (technique detection, micro-average):")
    print(f"  Precision : {precision:.2%}   (fewer false alarms)")
    print(f"  Recall    : {recall:.2%}   (fewer misses)")
    print(f"  F1 score  : {f1:.2%}")
    print(f"  Classification accuracy (malicious/clean): {class_acc:.2%} "
          f"({correct_classification}/{len(cases)})")
    print("=" * 82)

    # Evaluation mutated the data, so restore the demo data
    ingest_file()

    return {"precision": precision, "recall": recall, "f1": f1,
            "classification_accuracy": class_acc}


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Detection accuracy evaluation")
    # Thresholds turn this script into a regression gate: continuous integration can
    # fail the build when a change quietly makes detection worse, which is the whole
    # reason the evaluation is deterministic and LLM-free.
    parser.add_argument("--min-precision", type=float, default=None)
    parser.add_argument("--min-recall", type=float, default=None)
    args = parser.parse_args()

    metrics = evaluate()

    failures = [
        f"{name} {metrics[name]:.2%} is below the required {floor:.2%}"
        for name, floor in (("precision", args.min_precision), ("recall", args.min_recall))
        if floor is not None and metrics[name] < floor
    ]
    if failures:
        print("\nREGRESSION:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

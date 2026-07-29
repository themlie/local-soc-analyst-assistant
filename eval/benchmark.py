"""
eval/benchmark.py — how long each deterministic stage takes, and how that scales.

"It feels fast on the sample file" is not an answer to how the pipeline behaves on a
real day's telemetry. This measures ingest, detection and correlation separately at
several volumes, so a change that quietly makes detection quadratic shows up as a
number instead of as a complaint months later.

The LLM stage is deliberately excluded: it is bounded by the model runtime, varies by
machine, and is measured separately by eval/grounding_eval.py.

    python -m eval.benchmark             # default sizes
    python -m eval.benchmark 1000 20000  # custom sizes
"""

import sys
import time
import common.console  # noqa: F401
from ingest.ingest import ingest_events, ingest_file
from detect.detectors import run_all_detectors
from detect.correlate import correlate

DEFAULT_SIZES = (1_000, 5_000, 20_000)


def synth_events(n: int) -> list[dict]:
    """A realistic-ish mix: mostly ordinary activity, with one noisy attacker.

    The concentrated burst of failed logons matters — brute-force detection groups by
    host+user+source address, so a single busy group is the case that exposes any
    quadratic behaviour. Spreading every event evenly would flatter the benchmark.
    """
    events = []
    for i in range(n):
        minute, second = divmod(i, 60)
        stamp = f"2026-07-03T{10 + minute // 60:02d}:{minute % 60:02d}:{second:02d}"
        host = f"HOST{i % 50:02d}"

        if i % 5 == 0:
            # the burst: same host, user and source address throughout
            events.append({"time": stamp, "host": "SRV-TARGET", "source": "Security",
                           "event_id": 4625, "user": "svc", "ip": "185.220.101.7"})
        elif i % 5 == 1:
            events.append({"time": stamp, "host": host, "source": "Security",
                           "event_id": 4624, "user": f"user{i % 200}", "ip": "10.0.0.5"})
        elif i % 5 == 2:
            events.append({"time": stamp, "host": host, "source": "Sysmon", "event_id": 1,
                           "user": f"user{i % 200}", "image": "git.exe", "cmdline": "git status"})
        elif i % 5 == 3:
            events.append({"time": stamp, "host": host, "source": "Sysmon", "event_id": 3,
                           "user": f"user{i % 200}", "dest_ip": "142.250.187.4", "dest_port": 443})
        else:
            events.append({"time": stamp, "host": host, "source": "Sysmon", "event_id": 1,
                           "user": f"user{i % 200}", "image": "chrome.exe",
                           "cmdline": "chrome.exe --type=renderer"})
    return events


def run(sizes=DEFAULT_SIZES) -> None:
    print("=" * 72)
    print(f"{'EVENTS':>8}  {'INGEST':>9}  {'DETECT':>9}  {'CORRELATE':>10}  {'TOTAL':>9}  {'SIGNALS':>8}")
    print("=" * 72)

    for n in sizes:
        raw = synth_events(n)

        t0 = time.perf_counter()
        ingest_events(raw)
        t1 = time.perf_counter()
        signals = run_all_detectors()
        t2 = time.perf_counter()
        correlate(signals)
        t3 = time.perf_counter()

        print(f"{n:>8}  {t1-t0:>8.2f}s  {t2-t1:>8.2f}s  {t3-t2:>9.2f}s  "
              f"{t3-t0:>8.2f}s  {len(signals):>8}")

    print("=" * 72)
    print("Detection is the stage to watch: it runs every rule over the whole table.")
    ingest_file()  # leave the demo data in place


if __name__ == "__main__":
    sizes = tuple(int(a) for a in sys.argv[1:]) or DEFAULT_SIZES
    run(sizes)

"""
tests/test_robustness.py — regression tests for input handling and grounding.

These encode failures found during a code review. Each test documents a real defect:
malformed or hostile input crashes the pipeline, and the grounding validator accepts
reports it should reject.

They are expected to FAIL until the corresponding fix lands. That is the point — a
red test is the proof that the fix is real, and the proof that it stays fixed.
"""

import pytest

from ingest.ingest import ingest_events, ingest_file
from detect.correlate import build_incidents
from validate.grounding import validate_report


@pytest.fixture(autouse=True, scope="session")
def restore_demo_data():
    """Tests overwrite the shared database; put the demo data back afterwards."""
    yield
    ingest_file()


def _event(**overrides) -> dict:
    """A valid failed-logon event, with fields overridable per test."""
    base = {
        "time": "2026-07-03T10:00:00",
        "host": "HOST01",
        "source": "Security",
        "event_id": 4625,
        "user": "svc",
        "ip": "185.220.101.7",
    }
    return {**base, **overrides}


def _incident(techniques=("T1110",)) -> dict:
    """A minimal incident whose detected techniques the report is validated against."""
    return {
        "host": "HOST01",
        "start": "2026-07-03T10:00:00",
        "end": "2026-07-03T10:00:00",
        "techniques": list(techniques),
        "severity": "high",
        "signals": [],
        "event_ids": [],
    }


# --------------------------------------------------------------------------- #
# Input handling — the pipeline must not crash on real-world or malformed logs
# --------------------------------------------------------------------------- #
def test_mixed_timezone_timestamps_do_not_crash():
    """Real EVTX emits tz-aware times ('...Z'); sample JSON is naive. Mixing them
    in one file must not raise (it currently does: can't subtract offset-naive
    and offset-aware datetimes)."""
    ingest_events([
        _event(time="2026-07-03T10:00:00Z"),
        _event(time="2026-07-03T10:00:01"),
        _event(time="2026-07-03T10:00:02"),
    ])
    build_incidents()


def test_event_without_timestamp_is_rejected_cleanly():
    """A log line with no timestamp should produce a clear error (or be skipped),
    not a TypeError from deep inside datetime parsing."""
    with pytest.raises(ValueError):
        ingest_events([{"host": "HOST01", "event_id": 4625, "user": "svc"}] * 3)
        build_incidents()


def test_non_list_json_is_rejected():
    """The web UI accepts arbitrary uploaded JSON. A dict (rather than a list of
    events) must be rejected with a clear error, not an AttributeError."""
    with pytest.raises(ValueError):
        ingest_events({"events": [{"host": "HOST01"}]})


# --------------------------------------------------------------------------- #
# Grounding — the "hallucination shield" must actually reject bad reports
# --------------------------------------------------------------------------- #
def test_wrong_tactic_is_flagged():
    """The model may cite a real technique under the wrong tactic (observed:
    T1003.008 reported as 'Privilege Escalation' instead of 'Credential Access').
    The validator must not award a perfect score to a factually wrong report."""
    report = {
        "attack_chain": [{
            "technique": "T1110",
            "tactic": "Exfiltration",          # wrong: T1110 is Credential Access
            "explanation": "User baked a cake.",
        }],
        "severity": "low",
    }
    result = validate_report(report, _incident(["T1110"]))
    assert not result["grounded"], "report with a wrong ATT&CK tactic must not be grounded"


def test_empty_report_is_not_grounded():
    """A report that explains nothing must not be labelled trustworthy — currently
    it returns grounded=True with trust_score=0.0, which is self-contradictory."""
    result = validate_report({"attack_chain": [], "severity": "low"}, _incident(["T1110"]))
    assert not result["grounded"], "an empty attack_chain must not count as grounded"


def test_grounded_and_trust_score_never_contradict():
    """grounded is a gate, trust_score is a measure. A grounded report cannot have
    a zero trust score."""
    result = validate_report({"attack_chain": [], "severity": "low"}, _incident(["T1110"]))
    assert not (result["grounded"] and result["trust_score"] == 0.0)

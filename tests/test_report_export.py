"""
tests/test_report_export.py — an exported report must stay traceable and honest.

A finding that cannot leave the tool is of little use, but an export that drops the
evidence trail — or repeats the model's severity instead of the detectors' — would
carry the wrong conclusion into a ticket where nobody can check it.
"""

from ui.report import to_markdown

INCIDENT = {
    "host": "web-server-01",
    "start": "2026-07-03T20:05:22+00:00",
    "end": "2026-07-03T20:15:33+00:00",
    "techniques": ["T1059.004", "T1003.008"],
    "severity": "high",
    "signals": [],
    "event_ids": [2, 5],
    "campaign_id": 1,
    "related_hosts": ["db-server-01"],
}

REPORT = {
    "summary": "Reverse shell followed by credential file access.",
    "timeline": ["20:05 - reverse shell (id 2)"],
    "attack_chain": [
        {"technique": "T1059.004", "tactic": "Execution", "explanation": "bash over /dev/tcp"},
    ],
    "severity": "medium",          # the model disagrees with the detectors
    "recommended_actions": ["Isolate web-server-01"],
}

VALIDATION = {
    "grounded": False,
    "trust_score": 0.5,
    "warnings": ["SEVERITY DOWNGRADE: model rated this 'medium' but detections say 'high'."],
}


def test_export_keeps_the_detector_severity():
    """The model rated this 'medium'. An exported report must not carry that as the
    verdict — it is the number a reader will act on."""
    md = to_markdown(INCIDENT, REPORT, VALIDATION)
    assert "[HIGH]" in md
    assert "the detector rating stands" in md


def test_export_carries_the_evidence_trail():
    """Event ids are what let a reader verify a claim instead of believing it."""
    md = to_markdown(INCIDENT, REPORT, VALIDATION)
    assert "[2, 5]" in md
    assert "T1059.004" in md and "T1003.008" in md


def test_export_states_validation_outcome():
    md = to_markdown(INCIDENT, REPORT, VALIDATION)
    assert "NOT validated" in md
    assert "SEVERITY DOWNGRADE" in md


def test_export_notes_the_campaign():
    md = to_markdown(INCIDENT, REPORT, VALIDATION)
    assert "Campaign #1" in md and "db-server-01" in md


def test_export_survives_a_sparse_report():
    """Small models omit fields; the export must not raise on the way to a ticket."""
    md = to_markdown(INCIDENT, {"summary": "x"}, {"grounded": True, "trust_score": 1.0,
                                                  "warnings": []})
    assert "# Incident" in md and "validated against evidence" in md

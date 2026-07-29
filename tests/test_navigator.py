"""
tests/test_navigator.py — the coverage map must not flatter the tool.

A published capability map is a claim about what this system can catch. If the declared
coverage drifts from what the detectors actually emit, the picture becomes a
misleading one — which is worse than publishing nothing. These tests tie the claim to
the rules.
"""

import json

import pytest

from common.attack import TECHNIQUES
from detect.detectors import COVERED_TECHNIQUES
from ingest.ingest import ingest_events, ingest_file
from detect.correlate import build_incidents
from ui.navigator import detected_layer, coverage_layer, to_json

from tests.test_detectors import CASES  # the tested truth about what each rule reports


@pytest.fixture(autouse=True, scope="module")
def restore_demo_data():
    yield
    ingest_file()


def test_declared_coverage_matches_what_detectors_emit():
    """COVERED_TECHNIQUES is published as a capability map, so it must equal the set
    the rules are actually tested to report — no aspirational entries, no omissions."""
    tested = {technique for _, _, technique in CASES}
    assert COVERED_TECHNIQUES == tested, (
        f"declared but untested: {sorted(COVERED_TECHNIQUES - tested)}; "
        f"detected but undeclared: {sorted(tested - COVERED_TECHNIQUES)}"
    )


def test_coverage_layer_marks_gaps_red_and_says_so():
    layer = coverage_layer()
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == set(TECHNIQUES), "every catalogued technique must appear"

    gaps = [tid for tid, t in by_id.items() if "GAP" in t["comment"]]
    assert set(gaps) == set(TECHNIQUES) - COVERED_TECHNIQUES
    assert gaps, "a coverage map with no gaps would be a claim worth doubting"
    assert by_id[gaps[0]]["color"] != by_id[sorted(COVERED_TECHNIQUES)[0]]["color"]


def test_detected_layer_reflects_the_analysed_logs():
    ingest_events([{
        "time": f"2026-07-03T10:00:{i:02d}", "host": "HOST01", "source": "Security",
        "event_id": 4625, "user": "svc", "ip": "185.220.101.7",
    } for i in range(3)])

    layer = detected_layer(build_incidents())
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert "T1110" in by_id
    assert by_id["T1110"]["score"] >= 1
    assert "HOST01" in by_id["T1110"]["comment"]


def test_layers_are_valid_json_with_the_fields_navigator_needs():
    for layer in (coverage_layer(), detected_layer([])):
        parsed = json.loads(to_json(layer))
        for field in ("name", "versions", "domain", "techniques"):
            assert field in parsed, f"Navigator requires '{field}'"
        assert parsed["domain"] == "enterprise-attack"
        assert {"attack", "navigator", "layer"} <= set(parsed["versions"])


def test_sub_technique_ids_are_preserved():
    """Navigator addresses sub-techniques as 'T1059.001'; truncating to the parent
    would silently claim broader coverage than exists."""
    ids = {t["techniqueID"] for t in coverage_layer()["techniques"]}
    assert "T1059.001" in ids and "T1003.008" in ids

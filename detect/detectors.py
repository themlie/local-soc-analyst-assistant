"""
detect/detectors.py — Detection engineering layer.

Each function is a "detector": it encodes how a specific attack behavior looks in
the data as a rule, and returns matching events as a "signal". Every signal is
tagged with a MITRE ATT&CK technique.

A SIGNAL has this shape (later layers expect this uniform structure):
    {
      "rule": str,             # detector name
      "technique": str,        # ATT&CK ID (e.g. "T1110")
      "technique_name": str,
      "severity": "low|medium|high",
      "host": str,
      "user": str,
      "time": str,             # earliest event time of the signal (for correlation)
      "event_ids": list[int],  # ids of the events that produced this signal (for grounding)
      "description": str,
    }

Note: simple keyword rules can be weak against evasion; that's why several indicators
are combined. Resilience to evasion is measured with eval/golden.json.
"""

import common.console  # noqa: F401
from ipaddress import ip_address
from common.db import get_connection
from common.timeutil import parse_time as _parse_time
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, KERBEROS_FAILURE_THRESHOLD
from collections import defaultdict
from detect.registry import register_detector


def _is_external(ip: str) -> bool:
    """Is the IP not private, i.e. external?"""
    try:
        return not ip_address(ip).is_private
    except ValueError:
        return False


def _signal(rule, technique, name, severity, row, description) -> dict:
    """Short helper for single-event signals."""
    return {
        "rule": rule,
        "technique": technique,
        "technique_name": name,
        "severity": severity,
        "host": row["host"],
        "user": row["user"],
        "time": row["time"],
        "event_ids": [row["id"]],
        "description": description,
    }


def _process_rows(conn):
    """Return process-creation events (Sysmon EID 1) that carry a command line."""
    return conn.execute(
        "SELECT id, time, host, user, cmdline FROM events "
        "WHERE event_id = 1 AND cmdline IS NOT NULL ORDER BY time"
    ).fetchall()


# --------------------------------------------------------------------------- #
# Detector 1: Brute Force (T1110)
# --------------------------------------------------------------------------- #
@register_detector
def detect_brute_force(conn) -> list[dict]:
    """Many 4625 failures from the same host+user+IP in a short window = brute force."""
    rows = conn.execute(
        "SELECT id, time, host, user, src_ip FROM events "
        "WHERE event_id = 4625 ORDER BY time"
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["host"], r["user"], r["src_ip"])].append(r)

    signals = []
    for (host, user, src_ip), events in groups.items():
        for i in range(len(events)):
            window = [e for e in events[i:]
                      if _parse_time(e["time"]) - _parse_time(events[i]["time"]) <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                signals.append({
                    "rule": "brute_force_logon",
                    "technique": "T1110",
                    "technique_name": "Brute Force",
                    "severity": "high",
                    "host": host,
                    "user": user,
                    "time": window[0]["time"],
                    "event_ids": [e["id"] for e in window],
                    "description": (
                        f"{len(window)} failed logons (EID 4625) within "
                        f"{int(BRUTE_FORCE_WINDOW.total_seconds()//60)} min — "
                        f"{user}@{host}, source IP {src_ip}"
                    ),
                })
                break
    return signals


# --------------------------------------------------------------------------- #
# Detector 2: Suspicious PowerShell Execution (T1059.001)
# --------------------------------------------------------------------------- #
# Evasion variants: -enc / -e / -ec, encodedcommand, hidden window,
# FromBase64String, IEX / Invoke-Expression for in-memory execution.
_PS_INDICATORS = (
    " -enc", "-encodedcommand", " -e ", " -ec ", "-w hidden", "-windowstyle hidden",
    "frombase64string", "iex", "invoke-expression",
)


@register_detector
def detect_encoded_powershell(conn) -> list[dict]:
    """Obfuscated / in-memory PowerShell execution = suspicious Execution."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if "powershell" in cmd and any(ind in cmd for ind in _PS_INDICATORS):
            signals.append(_signal(
                "encoded_powershell", "T1059.001", "PowerShell", "high", r,
                f"Obfuscated/suspicious PowerShell execution — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# Detector 3: Ingress Tool Transfer (T1105)
# --------------------------------------------------------------------------- #
_DOWNLOAD_INDICATORS = (
    "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "iwr ",
    "certutil", "bitsadmin", "urlcache", "wget http", "curl http",
)


@register_detector
def detect_ingress_tool_transfer(conn) -> list[dict]:
    """DownloadString/certutil/bitsadmin etc. = external download (Ingress Tool Transfer)."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if any(ind in cmd for ind in _DOWNLOAD_INDICATORS):
            signals.append(_signal(
                "ingress_tool_transfer", "T1105", "Ingress Tool Transfer", "high", r,
                f"External download command — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# Detector 4: Defense Evasion / AMSI Bypass (T1562.001)
# --------------------------------------------------------------------------- #
_DEFENSE_EVASION_INDICATORS = (
    "amsi", "set-mppreference", "add-mppreference", "-exclusionpath",
    "disablerealtimemonitoring",
)


@register_detector
def detect_defense_evasion(conn) -> list[dict]:
    """AMSI bypass or changing Defender settings = defense evasion."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if any(ind in cmd for ind in _DEFENSE_EVASION_INDICATORS):
            signals.append(_signal(
                "defense_evasion", "T1562.001", "Impair Defenses", "high", r,
                f"Attempt to bypass/disable a security tool — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# Detector 5: Suspicious Outbound Connection / possible C2 (T1071)
# --------------------------------------------------------------------------- #
@register_detector
def detect_suspicious_network(conn) -> list[dict]:
    """Connection to an external IP on a non-standard port (not 80/443) = possible C2."""
    rows = conn.execute(
        "SELECT id, time, host, user, dst_ip, dst_port FROM events "
        "WHERE event_id = 3 AND dst_ip IS NOT NULL ORDER BY time"
    ).fetchall()

    signals = []
    for r in rows:
        if _is_external(r["dst_ip"]) and r["dst_port"] not in (80, 443):
            signals.append({
                "rule": "suspicious_outbound",
                "technique": "T1071",
                "technique_name": "Application Layer Protocol (C2)",
                "severity": "medium",
                "host": r["host"],
                "user": r["user"],
                "time": r["time"],
                "event_ids": [r["id"]],
                "description": (
                    f"Unusual connection to external IP — {r['dst_ip']}:{r['dst_port']} "
                    f"({r['user']}@{r['host']})"
                ),
            })
    return signals


# --------------------------------------------------------------------------- #
# Detector 6: Scheduled Task Persistence via Sysmon command line (T1053.005)
# --------------------------------------------------------------------------- #
@register_detector
def detect_scheduled_task(conn) -> list[dict]:
    """schtasks /create creating a new scheduled task = possible persistence."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if "schtasks" in cmd and "/create" in cmd:
            signals.append(_signal(
                "scheduled_task_persistence", "T1053.005", "Scheduled Task", "high", r,
                f"Scheduled task created (persistence) — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# REAL-DATA detectors (based on Windows Security event IDs)
# Synthetic data relied on Sysmon command lines; in real EVTX the same techniques
# appear under different event IDs. These detectors close that gap.
# --------------------------------------------------------------------------- #
@register_detector
def detect_scheduled_task_4698(conn) -> list[dict]:
    """Security EID 4698 = scheduled task created (real-log equivalent)."""
    rows = conn.execute(
        "SELECT id, time, host, user, cmdline FROM events WHERE event_id = 4698"
    ).fetchall()
    return [_signal(
        "scheduled_task_4698", "T1053.005", "Scheduled Task", "high", r,
        f"Scheduled task created (EID 4698) — {r['user']}@{r['host']}",
    ) for r in rows]


@register_detector
def detect_kerberos_spray(conn) -> list[dict]:
    """Many 4771 (Kerberos pre-authentication failures) = password spray."""
    rows = conn.execute(
        "SELECT id, time, host, user FROM events WHERE event_id = 4771 ORDER BY time"
    ).fetchall()
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r)

    signals = []
    for host, events in by_host.items():
        if len(events) >= KERBEROS_FAILURE_THRESHOLD:
            signals.append({
                "rule": "kerberos_password_spray",
                "technique": "T1110",
                "technique_name": "Brute Force",
                "severity": "high",
                "host": host,
                "user": events[0]["user"],
                "time": events[0]["time"],
                "event_ids": [e["id"] for e in events],
                "description": f"{len(events)} Kerberos pre-auth failures (EID 4771) — {host} (password spray)",
            })
    return signals


@register_detector
def detect_log_cleared(conn) -> list[dict]:
    """Security EID 1102 = event log cleared = indicator removal."""
    rows = conn.execute(
        "SELECT id, time, host, user FROM events WHERE event_id = 1102"
    ).fetchall()
    return [_signal(
        "log_cleared", "T1070.001", "Clear Windows Event Logs", "high", r,
        f"Security event log cleared (EID 1102) — {r['host']}",
    ) for r in rows]


# --------------------------------------------------------------------------- #
# LINUX / UNIX behavioral detectors (based on process command lines)
# These catch common Linux post-exploitation TTPs that don't map to Windows
# event IDs — reverse shells, credential file access, netcat exfiltration.
# --------------------------------------------------------------------------- #
_UNIX_SHELL_ABUSE = ("/dev/tcp/", "/dev/udp/", "bash -i", "sh -i", "nc -e", "ncat -e", "mkfifo")


@register_detector
def detect_unix_shell_abuse(conn) -> list[dict]:
    """Reverse shells (bash -i, /dev/tcp) or execution of a dropped payload = Unix Shell abuse."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        reverse = any(k in cmd for k in _UNIX_SHELL_ABUSE)
        dropped = "chmod +x" in cmd and ("/tmp/" in cmd or "/dev/shm/" in cmd)
        if reverse or dropped:
            what = "reverse shell over the network" if reverse else "execution of a dropped payload from /tmp"
            signals.append(_signal(
                "unix_shell_abuse", "T1059.004", "Unix Shell", "high", r,
                f"Unix shell abuse — {what} ({r['user']}@{r['host']})",
            ))
    return signals


@register_detector
def detect_credential_dumping(conn) -> list[dict]:
    """Reading /etc/shadow or /etc/passwd = OS credential dumping (Linux)."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if "/etc/shadow" in cmd or "/etc/passwd" in cmd:
            signals.append(_signal(
                "credential_dump", "T1003.008", "OS Credential Dumping", "high", r,
                f"Access to credential file (/etc/shadow or /etc/passwd) — {r['user']}@{r['host']}",
            ))
    return signals


@register_detector
def detect_exfiltration(conn) -> list[dict]:
    """Piping data out via netcat/curl to a remote host = exfiltration over alternative protocol."""
    signals = []
    for r in _process_rows(conn):
        cmd = (r["cmdline"] or "").lower()
        if any(k in cmd for k in ("| nc ", "|nc ", "| ncat", "| curl", "curl -t")):
            signals.append(_signal(
                "exfil_alt_protocol", "T1048", "Exfiltration Over Alternative Protocol", "high", r,
                f"Possible data exfiltration over netcat/curl — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# WEB / APPLICATION-LAYER detectors (WAF/IDS-style logs)
# These key off category / message / tool / url rather than Windows event IDs,
# so the same pipeline also handles web-attack telemetry.
# --------------------------------------------------------------------------- #
def _web_rows(conn):
    """Events that carry web/application-layer context."""
    return conn.execute(
        "SELECT id, time, host, user, src_ip, category, message, tool, url "
        "FROM events "
        "WHERE category IS NOT NULL OR message IS NOT NULL OR tool IS NOT NULL "
        "ORDER BY time"
    ).fetchall()


def _web_text(r) -> str:
    """Combined lowercased text of a web event's descriptive fields."""
    return " ".join(x for x in (r["category"], r["message"], r["tool"], r["url"]) if x).lower()


@register_detector
def detect_web_recon(conn) -> list[dict]:
    """Port/vulnerability scanning against a web app = Active Scanning."""
    signals = []
    for r in _web_rows(conn):
        t = _web_text(r)
        if any(k in t for k in ("reconnaissance", "nmap", "masscan", "port scan",
                                "connection attempts", "scanning", "scan")):
            signals.append(_signal(
                "web_reconnaissance", "T1595", "Active Scanning", "medium", r,
                f"Web scanning/recon from {r['src_ip']} — {r['message'] or r['category']}",
            ))
    return signals


@register_detector
def detect_web_exploit(conn) -> list[dict]:
    """SQLi / auth bypass / insecure access control = Exploit Public-Facing Application."""
    signals = []
    for r in _web_rows(conn):
        t = _web_text(r)
        if any(k in t for k in ("sql injection", "sqlmap", "web_attack", "access_control",
                                "idor", "authentication_bypass", "jwt", "bypass", "burpsuite")):
            signals.append(_signal(
                "web_exploit", "T1190", "Exploit Public-Facing Application", "high", r,
                f"Web application exploit attempt — {r['message'] or r['category']} "
                f"(from {r['src_ip']})",
            ))
    return signals


@register_detector
def detect_payload_upload(conn) -> list[dict]:
    """Uploading an exploit/payload (e.g. Metasploit/Meterpreter) = Ingress Tool Transfer."""
    signals = []
    for r in _web_rows(conn):
        t = _web_text(r)
        if any(k in t for k in ("exploitation", "metasploit", "meterpreter", "payload")):
            signals.append(_signal(
                "payload_upload", "T1105", "Ingress Tool Transfer", "high", r,
                f"Malicious payload/exploit delivery — {r['message'] or r['category']} "
                f"(from {r['src_ip']})",
            ))
    return signals


# --------------------------------------------------------------------------- #
# ADVERSARIAL-INPUT detector: prompt injection aimed at the LLM analyst
# This system feeds log content to a language model, which makes the log itself an
# attack surface: whoever controls a command line or a URL can plant text designed to
# manipulate the analysis. Escaping it in the prompt is the defence; flagging it here
# turns the attempt into evidence, because a log that argues with its reader is
# itself a strong indicator of compromise.
# --------------------------------------------------------------------------- #
_INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "ignore the above", "disregard the above",
    "system override", "new instructions", "you are now", "as an ai",
    "this is a false positive", "no action required", "mark as benign",
)


@register_detector
def detect_prompt_injection(conn) -> list[dict]:
    """Log content crafted to manipulate an LLM analyst = adversarial evasion."""
    rows = conn.execute(
        "SELECT id, time, host, user, cmdline, message, url FROM events "
        "WHERE cmdline IS NOT NULL OR message IS NOT NULL OR url IS NOT NULL"
    ).fetchall()

    signals = []
    for r in rows:
        blob = " ".join(x for x in (r["cmdline"], r["message"], r["url"]) if x).lower()
        hit = next((m for m in _INJECTION_MARKERS if m in blob), None)
        if hit:
            signals.append(_signal(
                "llm_prompt_injection", "T1027", "Obfuscated Files or Information",
                "high", r,
                f"Log content appears crafted to manipulate an LLM analyst "
                f"(prompt injection, matched \"{hit}\") — {r['user']}@{r['host']}",
            ))
    return signals


# --------------------------------------------------------------------------- #
# Runner that executes all detectors
# --------------------------------------------------------------------------- #
from detect.registry import DetectorRegistry

def run_all_detectors() -> list[dict]:
    """Run all detectors and return all signals sorted by time."""
    conn = get_connection()
    signals = []
    for detector in DetectorRegistry.get_all():
        signals.extend(detector(conn))
    conn.close()
    signals.sort(key=lambda s: s["time"])
    return signals


if __name__ == "__main__":
    sigs = run_all_detectors()
    print(f"{len(sigs)} signals found:\n")
    for s in sigs:
        print(f"  {s['time']} | [{s['technique']} {s['technique_name']}] ({s['severity']})")
        print(f"    {s['description']}")
        print(f"    event ids: {s['event_ids']}\n")

"""
common/attack.py — Local MITRE ATT&CK knowledge base.

This file serves two purposes:
  1) CONTEXT: gives the LLM a description of each technique (e.g. "what is T1110?")
     so it can reason more accurately.
  2) GROUNDING: when the LLM claims a technique ID, we check it against this catalog
     to confirm it is a REAL ATT&CK technique. If the model invents a "T9999" we
     catch it. This is part of the hallucination shield.

Note: real ATT&CK has 600+ techniques; we keep the core subset the project needs.
It can be extended later with the official ATT&CK JSON.
"""

# id -> technique info
TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "An attacker trying to crack passwords by trial and error; "
                       "shows up as many failed authentication attempts.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
        "description": "Logging in as a legitimate user using compromised valid "
                       "account credentials.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Using PowerShell to run commands and scripts; especially "
                       "suspicious when obfuscated (-enc/encoded) or run with a hidden window.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Hiding commands or files with base64/encryption to evade detection.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Hiding command-and-control (C2) traffic inside normal application "
                       "protocols; connections to unusual destination IPs/ports.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Downloading a tool or second-stage payload from an external source "
                       "to the target system.",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence / Execution",
        "description": "Creating a Windows Scheduled Task for persistence or execution.",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Disabling or bypassing security tools (AV, AMSI, logging).",
    },
    "T1546": {
        "name": "Event Triggered Execution",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Setting up a persistence mechanism that runs code in response to "
                       "an event (WMI subscription, logon, service).",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Clearing Windows event logs to erase traces "
                       "(clearing the Security log produces event 1102).",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Probing a target's infrastructure — port scans, vulnerability "
                       "scanning (e.g. Nmap, masscan) — to find weaknesses before attacking.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploiting a weakness in an internet-facing application (SQL "
                       "injection, authentication bypass, insecure access control) to gain access.",
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": "Abusing a Unix shell to run commands — e.g. reverse shells "
                       "(bash -i, /dev/tcp) or executing a dropped payload from a temp directory.",
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "description": "Reading /etc/shadow or /etc/passwd on Linux to steal password "
                       "hashes for offline cracking.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Sending stolen data out over a non-standard channel such as "
                       "netcat or raw sockets, bypassing normal monitored paths.",
    },
}


def is_valid_technique(technique_id: str) -> bool:
    """Is the given ID a real ATT&CK technique? (Used by the validation layer.)"""
    return technique_id in TECHNIQUES


def get_technique(technique_id: str) -> dict | None:
    """Return technique info, or None if unknown."""
    return TECHNIQUES.get(technique_id)


def describe(technique_id: str) -> str:
    """Produce a one-line description for the LLM context."""
    t = TECHNIQUES.get(technique_id)
    if not t:
        return f"{technique_id}: (unknown technique)"
    return f"{technique_id} ({t['name']}, {t['tactic']}): {t['description']}"

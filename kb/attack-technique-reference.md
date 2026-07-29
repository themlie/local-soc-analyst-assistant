# MITRE ATT&CK Technique Reference

Short descriptions of the techniques this system detects, with the tactic each belongs
to. Tactic names follow the ATT&CK Enterprise matrix.

## Credential Access

**T1110 — Brute Force.** Guessing passwords by repeated attempts. Shows up as many
failed authentications, or as password spraying, where few passwords are tried against
many accounts to stay under lockout thresholds.

**T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow.** Reading the Linux
password hash files to crack them offline.

## Execution

**T1059.001 — PowerShell.** Running commands through PowerShell, especially obfuscated
or encoded, or executed in memory to leave nothing on disk.

**T1059.004 — Unix Shell.** Abusing a Unix shell, typically a reverse shell over
`/dev/tcp` or execution of a payload dropped in a temporary directory.

## Persistence

**T1053.005 — Scheduled Task.** Creating a scheduled task so code runs again after a
reboot or at a chosen trigger.

**T1546 — Event Triggered Execution.** Persistence bound to an event, such as a WMI
subscription. This system does not yet detect it.

## Defense Evasion

**T1027 — Obfuscated Files or Information.** Hiding intent through encoding or
encryption. Also covers log content crafted to manipulate an automated analyst.

**T1070.001 — Clear Windows Event Logs.** Clearing the Security log to remove evidence;
produces event 1102.

**T1562.001 — Impair Defenses.** Disabling or bypassing security tooling, such as AMSI
bypass or changing Defender exclusions.

## Command and Control

**T1071 — Application Layer Protocol.** Hiding command-and-control traffic in ordinary
application protocols, or connecting to unusual destination ports.

**T1105 — Ingress Tool Transfer.** Downloading a tool or second-stage payload onto the
target.

## Reconnaissance and Initial Access

**T1595 — Active Scanning.** Probing infrastructure for weaknesses, such as port or
vulnerability scanning.

**T1190 — Exploit Public-Facing Application.** Exploiting an internet-facing
application, including SQL injection and authentication bypass.

## Exfiltration

**T1048 — Exfiltration Over Alternative Protocol.** Sending stolen data out over a
channel that is not normally monitored, such as netcat.

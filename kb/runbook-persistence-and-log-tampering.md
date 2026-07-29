# Runbook: Persistence and Log Tampering (T1053, T1070, T1562)

## Detection criteria

Scheduled task persistence is flagged from two sources: a `schtasks /create` command
line in process telemetry, and Windows Security event 4698, which records task
creation directly and is the more reliable of the two because it does not depend on
process command-line logging being enabled.

Log tampering is flagged on Windows Security event 1102, which is written when the
Security log is cleared. Defence tampering covers attempts to disable or bypass
security tooling, including AMSI bypass patterns and changes to Defender exclusions
or real-time monitoring.

## Immediate response

Event 1102 deserves particular attention. Clearing the Security log is almost never a
routine administrative action, and it usually means the attacker has already achieved
what they came for and is now removing evidence. Treat it as a late-stage indicator
and widen the investigation window backwards, not forwards.

For scheduled tasks, retrieve the task definition before deleting it. The action it
runs, the trigger, and the account it runs as together reveal both the payload and the
level of access the attacker holds.

## Containment

Delete the malicious task, then check for sibling persistence. Attackers rarely rely
on a single mechanism: check run keys, services, WMI event subscriptions and startup
folders on the same host before declaring persistence removed.

Where security tooling was disabled, re-enable it and verify from the management
console rather than from the host itself, since a compromised host may report a
healthy state that is not real.

## Known gap

This system does not currently detect WMI event-subscription persistence (T1546). If
scheduled-task persistence is found and no payload explains how it was installed,
check WMI subscriptions manually with `Get-WMIObject -Namespace root\\Subscription`.
The absence of an alert is not evidence of absence.

## Recovery and follow-up

Confirm the task is gone after a reboot. Some persistence mechanisms recreate tasks on
startup, and a task that returns after a reboot indicates a second, undetected
mechanism is still active.

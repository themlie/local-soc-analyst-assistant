# Runbook: Brute Force and Password Spray (T1110)

## Detection criteria

An alert is raised when a single account records three or more failed logons
(Windows Security event 4625) from the same source address within five minutes, or
when two or more Kerberos pre-authentication failures (event 4771) occur on a domain
controller. Password spraying differs from classic brute force: it tries one or two
passwords against many accounts, so the per-account failure count stays low. Judge
spraying by the number of distinct accounts targeted, not by failures per account.

## Immediate response

Confirm whether any attempt succeeded. A failed-logon burst followed by event 4624
from the same source address is a successful compromise and must be escalated
immediately under the critical path in the escalation policy.

If no logon succeeded, disable the targeted account only when the account is
privileged or the source address is external. Disabling ordinary user accounts during
a spray causes a self-inflicted denial of service across the estate, which is often
the attacker's secondary goal.

Block the source address at the perimeter when it is external. Internal source
addresses must not be blocked without checking whether the host is a shared service:
a misconfigured scheduled task with stale credentials produces an identical pattern
and is by far the more common cause.

## Containment

Force a password reset for any account whose logon succeeded from the suspicious
source. Revoke active Kerberos tickets for that account, because a password reset
alone leaves existing tickets valid until they expire.

Review whether the same source address appears in incidents on other hosts. Lateral
movement frequently follows a successful credential attack, and the pivot address is
the strongest link between otherwise separate incidents.

## Recovery and follow-up

Re-enable disabled accounts only after the password reset is confirmed and the owner
has been contacted through a channel other than the potentially compromised account.

Record the source address, the targeted accounts and the time window in the incident
record. If the attempt came from an internal host, open a separate investigation into
that host: it is a victim before it is an attacker.

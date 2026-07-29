# Runbook: Credential Access and Exfiltration (T1003, T1048)

## Detection criteria

Credential access on Linux is flagged when a process reads `/etc/shadow` or
`/etc/passwd`. Reading `/etc/passwd` alone is weak evidence — it is world-readable and
many tools touch it — while any read of `/etc/shadow` by a process other than a known
authentication component is a strong signal.

Exfiltration is flagged when command output is piped to a network utility, such as
`| nc`, `| ncat`, or a `curl` upload to an external address. The severity of an
exfiltration alert is set by what was piped, not by the tool used.

## Immediate response

Treat any successful read of `/etc/shadow` as a full credential compromise for that
host. Every local account password must be considered known to the attacker, including
service accounts, and shared passwords mean every host using them is affected.

Where data was piped to an external address, capture the destination address and port
immediately and check the network logs for the volume transferred. Volume is what
distinguishes a probe from an actual data loss, and it determines whether the incident
triggers a breach notification obligation.

## Containment

Isolate the host from the network before resetting anything. Resetting passwords while
the attacker retains a live session simply hands them the new credentials.

Reset every local account on the affected host, then rotate any shared or service
account whose password is also used elsewhere. Rotate credentials that appear in
scripts or scheduled tasks on that host, since those are commonly reused across the
estate.

## Recovery and follow-up

Rebuild the host. A host whose credential store was read cannot be trusted after a
password reset alone, because the attacker may have established persistence.

Escalate to the data protection contact whenever exfiltration is confirmed, following
the critical path in the escalation policy. This escalation is not optional and does
not wait for the technical investigation to finish.

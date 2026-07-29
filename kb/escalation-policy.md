# Escalation Policy

## Severity levels

**Critical.** Confirmed compromise of a domain controller or authentication server,
confirmed data exfiltration, or ransomware behaviour. Escalate immediately to the
incident manager by phone, and to the data protection contact within one hour if
personal data may be involved.

**High.** Successful unauthorised logon, reverse shell, credential file access, or
persistence installed on any host. Escalate to the on-call analyst within thirty
minutes. If the affected host is internet-facing, treat it as critical instead.

**Medium.** Failed attack attempts that show intent, such as a blocked exploitation
attempt or an unusual outbound connection with no confirmed payload. Handle within the
working day.

**Low.** Reconnaissance and scanning with no follow-on activity. Record and review
weekly for patterns; a single scan is rarely worth an analyst's attention, but a
recurring source is.

## Who decides severity

Severity is set by the detection rules, not by an analyst's impression and not by any
automated summary. An analyst may raise a severity, and must document the reason. An
analyst may lower a severity only after the incident is closed and reviewed, never
during the response.

Automated tooling, including any language-model assistant, must not lower a severity.
Its assessment is advisory. If a summary disagrees with the detection rating, the
detection rating stands and the disagreement is itself worth recording.

## Escalation contacts

The on-call analyst is reachable through the rota channel. The incident manager is
reached by phone for critical incidents; do not rely on email for a critical
escalation. The data protection contact is engaged for any confirmed or suspected loss
of personal data.

## Communication rules

Never discuss an active incident over the compromised system's own channels. If the
mail platform is implicated, move to the out-of-band channel.

Record every action with a timestamp as you take it. Reconstructing a timeline
afterwards from memory is the most common source of error in incident reports.

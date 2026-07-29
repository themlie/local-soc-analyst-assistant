# Runbook: Suspicious PowerShell and Shell Execution (T1059)

## Detection criteria

Alerts cover two families. On Windows, obfuscated PowerShell is flagged when a
process command line contains encoded execution (`-enc`, `-EncodedCommand`), a hidden
window, `FromBase64String`, or in-memory execution through `IEX` / `Invoke-Expression`.
On Linux, shell abuse is flagged on reverse-shell patterns (`bash -i`, `/dev/tcp/`,
`nc -e`, `mkfifo`) and on execution of a payload dropped into a temporary directory
(`chmod +x` on a path under `/tmp` or `/dev/shm`).

Encoding alone is not proof of malice. Several management tools legitimately pass
encoded commands. Treat encoding as one indicator and weigh it with the parent
process: `powershell.exe` spawned by `winword.exe` or `outlook.exe` is far more
suspicious than the same command from a management agent.

## Immediate response

Decode the command before acting. Base64 payloads usually reveal a download URL or a
second-stage script, and that content determines whether this is a download cradle, a
reverse shell, or a false positive.

Isolate the host from the network if the command establishes an outbound connection.
Do not power the host off: memory-resident payloads are lost on shutdown, and in-memory
execution is precisely the technique that leaves nothing on disk to recover afterwards.

## Containment

Capture the parent process chain and the full command line before terminating
anything. Terminating the process first destroys the evidence needed to explain how
execution started.

Search other hosts for the same command line or the same remote address. A download
cradle rarely runs once.

## Recovery and follow-up

Rebuild the host if a reverse shell was established and the session was interactive.
Interactive access must be assumed to have led to credential theft from that host.

Where the payload was retrieved from an external address, add that address to the
blocklist and record it as an indicator in the incident.

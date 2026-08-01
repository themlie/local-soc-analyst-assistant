# Architecture

Two pipelines share one offline runtime. Detection answers *what happened*; retrieval
answers *what to do about it*.

## Detection pipeline

```
Raw logs (JSON or Windows .evtx)
   │
   ▼
[ingest]    normalize field names from aliases, canonicalize timestamps to UTC,
            validate the batch, store in SQLite
   │
   ▼
[detect]    rule-based detectors flag suspicious events as ATT&CK-tagged signals
   │
   ▼
[correlate] group signals by host + time window into incidents, then link incidents
            that share a pivot address or a non-generic account into one campaign
   │
   ▼
[reason]    build an evidence package and generate an analysis with the local LLM
   │
   ▼
[validate]  check every claim against the detections (the hallucination shield)
   │
   ▼
[ui/main]   present a readable incident report
```

## Retrieval pipeline (RAG)

```
kb/*.md
   │
   ▼
[rag/index]  split into passages → embed each one → store vectors in SQLite
   │
   ▼
[rag/search] embed the question → cosine similarity → top-K passages
   │           (nothing above the similarity floor → return nothing)
   ▼
[rag/answer] answer from those passages alone, citing the document —
             or say "the knowledge base does not cover this"
```

The two meet in the incident report: runbook passages are retrieved for the *detected*
techniques, so remediation comes from documented procedure rather than the model's
recall.

## File guide

| File | Purpose |
|------|---------|
| `config.py` | Central configuration: models, thresholds, paths |
| `common/db.py` | SQLite connections; per-session isolation for the web interface |
| `common/attack.py` | Local MITRE ATT&CK catalogue (LLM context + validation source) |
| `common/llm.py` | Foundry Local chat + embedding wrapper, serialized model access |
| `common/timeutil.py` | Normalizes every log timestamp to timezone-aware UTC |
| `common/console.py` | Forces terminal output to UTF-8 |
| `common/logger.py` | Centralized logging to `data/soc_assistant.log` |
| `ingest/ingest.py` | Raw log → unified event → SQLite, with schema validation |
| `ingest/win_evtx.py` | Parses real Windows EVTX into the same schema |
| `detect/registry.py` | Pluggable detector registry (`@register_detector`) |
| `detect/detectors.py` | 16 rules across Windows, Linux and web sources |
| `detect/correlate.py` | Per-host incidents, then cross-host campaign linking |
| `reason/context.py` | Builds the evidence package; the untrusted-input boundary |
| `reason/analyst.py` | Produces a structured analysis with the local LLM |
| `validate/grounding.py` | Validates the model's claims against the detections |
| `kb/` | Knowledge base: runbooks, escalation policy, ATT&CK reference |
| `rag/index.py` | Chunks documents, embeds passages, stores them in SQLite |
| `rag/search.py` | Embeds a question, retrieves the closest passages |
| `rag/answer.py` | Answers with citations, refuses when uncovered, flags invented sources |
| `ui/app.py` | Streamlit interface |
| `ui/report.py` | Terminal report and Markdown export |
| `ui/navigator.py` | ATT&CK Navigator layer export (detections and coverage) |
| `main.py` | Orchestrator for the full pipeline |
| `eval/` | Evaluation and benchmarking — see [evaluation.md](evaluation.md) |

## Detection rules

16 detectors, each mapped to an ATT&CK technique:

- **Windows** — brute force (4625), Kerberos password spray (4771), scheduled task
  (Sysmon command line and Security 4698), log cleared (1102), obfuscated PowerShell,
  defence tampering, suspicious outbound connections
- **Linux/Unix** — reverse shells (`/dev/tcp`, `bash -i`), payload execution from a
  temp directory, `/etc/shadow` access, netcat exfiltration
- **Web/WAF** — active scanning, exploitation of a public-facing application, payload
  delivery
- **Adversarial** — log content crafted to manipulate an LLM analyst (prompt injection)

Adding a rule means writing a function with `@register_detector`; nothing else changes.
A test fails the build if a detector is added without a case covering it.

## Concurrency

Incidents are dispatched together but `LLM_CONCURRENCY` (default 1) decides how many may
hold the model at once. Foundry Local serves a single model instance on the CPU, so
parallel requests do not finish sooner — they contend, and the runtime starts cancelling
them. Access to the model is serialized in `common/llm.py` so this holds for every
caller, including the web interface.

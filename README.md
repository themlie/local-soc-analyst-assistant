# Local SOC Analyst Assistant (Air-Gapped)

An AI-powered SOC (Security Operations Center) analyst assistant that analyzes security
logs **fully offline**. It ingests raw Windows/Sysmon logs, flags suspicious activity
with rule-based detectors, correlates them into an attack chain, and uses a **local LLM
(Microsoft Foundry Local)** to produce a timeline, **MITRE ATT&CK** mapping, and severity
scoring. A validation layer grounds the model's output against real log evidence to
prevent hallucinations.

**Data never leaves the machine** — designed for security telemetry that cannot be sent
to the cloud.

**Offline scope (precise):** Inference, embeddings, detection and storage are fully local — no network calls at analysis time. *Bootstrap is not offline:* the first model download and `eval/real_eval.py`'s sample fetch require internet. On an air-gapped host, pre-stage the model cache and the EVTX samples. Streamlit telemetry is disabled via `.streamlit/config.toml`.

> Built as a one-month learning project around Microsoft Foundry Local. It runs on CPU,
> with no cloud account and no GPU required.

**Positioning:** This is a *detection engineering + LLM-assisted triage* system, not a document-RAG application. Detection is deterministic and rule-based by design; the local LLM explains and correlates findings but never decides whether something is malicious.

## Why this matters

Real security data (EDR/SIEM logs) usually cannot be sent to a third-party cloud for
privacy and compliance reasons. Foundry Local runs the LLM **on-device**, so this
assistant can reason over sensitive logs with zero network calls. This project sits at
the intersection of **GenAI and security operations** — turning raw, noisy logs into a
grounded, ATT&CK-mapped incident report.

## Architecture

```
Raw logs
   │
   ▼
[ingest]    → normalize logs into a unified schema, store in SQLite
   │
   ▼
[detect]    → rule-based detectors flag suspicious events as ATT&CK-tagged signals
   │
   ▼
[correlate] → group signals by host + time window into a single incident
   │
   ▼
[reason]    → build an evidence package + generate analysis with the local LLM
   │
   ▼
[validate]  → tie the LLM's claims back to real evidence (hallucination shield)
   │
   ▼
[ui/main]   → present the result as a readable incident report
```

## File guide

| File | Purpose |
|------|---------|
| `config.py` | Central configuration: model, thresholds, paths |
| `common/db.py` | SQLite connection (single source) |
| `common/attack.py` | Local MITRE ATT&CK knowledge base (context + validation source) |
| `common/llm.py` | Foundry Local chat + embedding wrapper |
| `common/console.py` | Forces terminal output to UTF-8 |
| `common/logger.py` | Centralized telemetry and error logging |
| `ingest/ingest.py` | Raw log → unified event → SQLite |
| `ingest/win_evtx.py` | Parses real Windows EVTX logs into the schema |
| `detect/registry.py` | Pluggable detector registry (`@register_detector`) |
| `detect/detectors.py` | Rule-based detectors across Windows, Linux and web sources (brute force, PowerShell, C2, scheduled task, reverse shell, credential dumping, exfiltration, SQLi/exploit, ...) |
| `detect/correlate.py` | Groups signals into incidents |
| `reason/context.py` | Builds the evidence package for the LLM |
| `reason/analyst.py` | Produces a structured analysis with the local LLM |
| `validate/grounding.py` | Hallucination shield: validates claims against evidence |
| `ui/report.py` | Prints the result as a readable report |
| `ui/app.py` | Streamlit web interface (clickable demo) |
| `main.py` | Orchestrator that runs the full pipeline |
| `eval/golden.json` | Hand-labeled test scenarios (ground truth) |
| `eval/evaluate.py` | Measures detection accuracy with precision/recall/F1 |
| `eval/grounding_eval.py` | Measures the LLM's hallucination/grounding quality |
| `eval/real_eval.py` | Measures recall on real labeled EVTX samples |

## Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
winget install Microsoft.FoundryLocal   # local model runtime
```

## Usage

```powershell
python main.py                       # default fast model (qwen2.5-1.5b)
python main.py --model phi-4-mini    # higher quality (large first-time download)
python main.py --file mylogs.json    # analyze an arbitrary JSON log file
python main.py --evtx "data/real/kerberos_pwd_spray_4771.evtx"   # analyze real EVTX
```

### Multi-source input

The ingest layer resolves field names from a list of aliases (e.g. `timestamp`/`time`,
`client_ip`/`ip`, `event_type`/`event_id`), so it accepts logs from different sources.
Detectors cover **Windows host** telemetry (Security/Sysmon events), **Linux/Unix**
behavior (reverse shells, `/etc/shadow` access, netcat exfiltration), and **web/WAF**
attacks (scanning, SQL injection, exploitation) — each mapped to the right ATT&CK technique.

## Evaluation

```powershell
python -m eval.evaluate              # detection metrics (fast, no LLM)
python -m eval.grounding_eval --limit 3   # LLM grounding metrics
python -m eval.real_eval             # recall on real EVTX samples
```

The detection evaluation is deterministic (needs no LLM), so it's fast and repeatable —
ideal for regression tracking as the code evolves.

## Results

| Evaluation | Result |
|---|---|
| Synthetic data | Precision **100%**, Recall **92.9%**, F1 **96.3%** |
| Real data (EVTX-ATTACK-SAMPLES) | Recall **75%** (3/4 techniques) |
| LLM grounding | 100% grounded, 0 hallucinations |

The synthetic-vs-real gap is intentional and honest: real-world telemetry uses different
event schemas (e.g. scheduled task = Security 4698, password spray = Kerberos 4771), and
simple rules can't catch every technique. The remaining misses are documented as known
gaps — a roadmap for future detectors, not hidden failures.

## Real data (EVTX)

Beyond synthetic JSON, the system also analyzes **real Windows EVTX** logs from
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(real attack logs labeled by ATT&CK). `eval/real_eval.py` downloads the required samples
automatically on first run.

## Experiments (not part of the pipeline)

```powershell
python -m experiments.attack_semantic_search
```

An approach that was evaluated and deliberately not adopted: embedding ATT&CK
descriptions locally and ranking them against a free-text query by cosine similarity.
Dense retrieval adds little over a 15-technique catalog, so the analysis pipeline does
not use it — the file is kept only to document the experiment.

## Enterprise-Grade Features

This project was recently refactored to include production-ready architecture:
- **Asynchronous Execution (`asyncio`):** Incident processing now runs concurrently. If there are multiple security incidents, LLM analysis tasks are dispatched in parallel, preventing I/O bottlenecks.
- **Pluggable Detectors:** A new `DetectorRegistry` allows adding new detection rules simply by using the `@register_detector` decorator. Core execution logic never needs to be modified when adding new rules.
- **Centralized Telemetry:** All system outputs and errors are now routed through Python's standard `logging` module and saved to `data/soc_assistant.log` (complete with stack traces) for enterprise auditability.

## Tech stack

Python (`asyncio`) · Microsoft Foundry Local · on-device LLM & embeddings · SQLite · MITRE ATT&CK ·
rule-based detection · evidence-package construction · grounding/validation ·
Streamlit · EVTX parsing

## Known gaps / future work

- No detector yet for WMI event-subscription persistence (T1546) or in-memory PowerShell
  whose payload isn't in the process command line — surfaced honestly by the evaluation.
- Multi-host attack correlation, more real-world detectors, and a larger labeled eval set
  are natural next steps.


# Local SOC Analyst Assistant (Air-Gapped)

[![CI](https://github.com/themlie/local-soc-analyst-assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/themlie/local-soc-analyst-assistant/actions/workflows/ci.yml)

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
[correlate] → group signals by host + time window into incidents, then link
              incidents that share a pivot address or account into one campaign
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
| `detect/correlate.py` | Groups signals into per-host incidents, then links incidents across hosts into campaigns |
| `common/timeutil.py` | Normalizes every log timestamp to timezone-aware UTC |
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
pip install -r requirements.txt          # to run it
pip install -r requirements-dev.txt      # to run the tests as well
winget install Microsoft.FoundryLocal    # local model runtime
```

`requirements.txt` declares only the three packages the project imports directly; pip
resolves the rest. Pins are exact, because an unreviewed dependency upgrade is still an
unreviewed change.

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
python -m pytest tests/ -q           # regression tests (fast, no LLM)
python -m eval.evaluate              # detection metrics (fast, no LLM)
python -m eval.grounding_eval --limit 3   # LLM grounding metrics
python -m eval.real_eval             # recall on real EVTX samples
```

The detection evaluation is deterministic (needs no LLM), so it's fast and repeatable —
which is what lets it act as a regression gate rather than a report:

```powershell
python -m eval.evaluate --min-precision 0.95 --min-recall 0.90   # exits 1 on regression
```

CI runs the tests and this gate on every push across Python 3.11–3.13. It installs only
`pytest`: the ingest, detection, correlation and validation layers are pure standard
library, so pulling in the on-device model runtime would cost minutes without covering
an extra line. Anything that needs a model is measured locally with
`eval/grounding_eval.py`.

The suite covers every registered detector (one firing case each), a benign corpus that
must produce **zero** alerts, cross-host campaign linking including four over-linking
guards, prompt-injection containment, and timestamp/schema robustness. A meta-test fails
the build if a detector is added without a case, so coverage cannot quietly rot.

## Results

| Evaluation | Result |
|---|---|
| Synthetic data | Precision **100%**, Recall **92.9%**, F1 **96.3%** |
| Real data (EVTX-ATTACK-SAMPLES) | Recall **75%** (3/4 techniques) |
| Regression tests | 15/15 passing |

**Read the synthetic numbers with suspicion.** Those scenarios were written alongside
the detection rules, so 100% precision measures internal consistency, not real-world
performance — a rule and its test sharing an author share their blind spots too. The
honest external number is the real-data recall (75%), measured on a deliberately small
sample (n=4) of labelled EVTX captures. Real telemetry uses different event schemas
(scheduled task = Security 4698, password spray = Kerberos 4771), and simple rules
cannot catch every technique; the misses are documented as known gaps rather than
tuned away.

**The LLM is not trusted, and it earns that distrust.** Running the local model over
the sample incidents, the validation layer routinely catches it filing a real
technique under an invented tactic (`UNIX_SHells`, `command_and_script_interpreter`),
leaving detected techniques unexplained, and rating an incident lower than the
detectors did. None of that reaches the analyst unchallenged — which is the point of
having a validation layer rather than a claim of zero hallucinations.

## Performance

```powershell
python -m eval.benchmark            # per-stage timings at several volumes
```

Deterministic stages only, on a 16 GB CPU-only laptop. The LLM stage is excluded
because it is bounded by the model runtime, not by this code (see *Known gaps*).

| Events | Ingest | Detect | Correlate | Total |
|---|---|---|---|---|
| 1,000 | 0.07s | 0.02s | <0.01s | **0.09s** |
| 10,000 | 0.44s | 0.27s | <0.01s | **0.71s** |
| 50,000 | 2.01s | 1.25s | <0.01s | **3.26s** |

Two results worth recording, both of which contradicted an assumption:

- **Brute-force detection was quadratic.** The naive "for every start, rescan what
  follows" only terminates early when the threshold is met — so the worst case is an
  ordinary one: an account failing auth all day without ever tripping it. Measured at
  4,000 attempts: **10.8s, and doubling the input quadrupled the time.** A two-pointer
  sliding window with lazily parsed timestamps brings that to **0.03s**.
- **Adding indexes made it slower.** Indexing `event_id` and `(host, time)` was tried
  and reverted: 50k events went from 3.26s to 3.35s while ingest paid to build them.
  Detectors filter on common values (`event_id = 1` matches ~40% of rows), and a scan
  beats an index lookup per row once a query matches much of the table. The reasoning
  is recorded in `ingest/ingest.py` so it does not get "fixed" back.

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
- Small local models follow the output schema unreliably. The validation layer catches
  the errors, but report quality depends on the model: `qwen2.5-0.5b` is fast and
  unusable here (ignores the schema), `qwen2.5-1.5b` is the working default.
- The runtime cancels requests that take too long on CPU, so generation is capped and
  the prompt asks for brevity. A faster machine would allow richer reports.
- A larger labelled evaluation set, more real-world detectors, and analyst feedback
  (marking false positives) are the natural next steps.


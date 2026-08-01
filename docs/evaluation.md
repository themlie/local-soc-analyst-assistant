# Evaluation

Three things are measured separately, because they fail differently: the detection
rules, the model's faithfulness, and the retrieval layer.

```powershell
python -m pytest tests/ -q                # 62 regression tests (fast, no model needed)
python -m eval.evaluate                   # detection metrics (deterministic, no LLM)
python -m eval.real_eval                  # recall on real labelled EVTX samples
python -m eval.grounding_eval --limit 3   # how faithful the model is (slow, needs LLM)
python -m eval.benchmark                  # per-stage timings — see performance.md
```

## Results

| Evaluation | Result |
|---|---|
| Synthetic scenarios | Precision **100%**, Recall **92.9%**, F1 **96.3%** |
| Real data (EVTX-ATTACK-SAMPLES) | Recall **75%** (3/4 techniques, n=4) |
| Regression tests | **62/62** passing on Python 3.11–3.13 |

### Read the synthetic numbers with suspicion

Those scenarios were written alongside the rules they test, so 100% precision measures
internal consistency, not real-world performance — a rule and its test sharing an author
share their blind spots too. The honest external number is the real-data recall, measured
on a deliberately small sample of labelled EVTX captures from
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(downloaded automatically on first run).

Real telemetry uses different event schemas — a scheduled task is Security 4698, a
password spray is Kerberos 4771 — and simple rules cannot catch every technique. The
misses are documented as known gaps rather than tuned away.

### The LLM is not trusted, and it earns that distrust

Running the local model over the sample incidents, the validation layer routinely catches
it filing a real technique under an invented tactic (`UNIX_SHells`,
`command_and_script_interpreter`), leaving detected techniques unexplained, and rating an
incident lower than the detectors did. It has also cited a source document that does not
exist. None of that reaches an analyst unchallenged — which is the point of having a
validation layer rather than a claim of zero hallucinations.

## What the test suite covers

- **Every registered detector** — one firing case each, plus a meta-test that fails the
  build when a detector is added without one, so coverage cannot quietly rot.
- **A benign corpus that must produce zero alerts.** An alert an analyst has to dismiss
  costs more than it is worth. Writing these found a real defect: keyword rules matched
  substrings, so `/api/invoices/scandal-report` alerted as a port scan and
  `"JSON payload"` as a Metasploit delivery. Web rules now match on word boundaries.
- **Campaign linking**, including four guards against over-linking — generic accounts,
  shared infrastructure addresses, and distant activity must not merge hosts.
- **Prompt-injection containment** — crafted log text must not escape its line, and the
  attempt itself must be detected.
- **Session isolation**, including a concurrent case and a path-traversal case.
- **Retrieval** — chunking stays within budget and inside headings; a question the
  knowledge base does not cover is refused without calling the model; invented citations
  are detected.
- **Timestamp and schema robustness** — mixed timezones, missing timestamps, non-list
  JSON.

## Continuous integration

CI runs the tests and a detection-accuracy gate on every push, across Python 3.11–3.13
on Linux — which also proves the code carries no hidden Windows assumptions.

```powershell
python -m eval.evaluate --min-precision 0.95 --min-recall 0.90   # exits 1 on regression
```

Thresholds turn the evaluation into a gate rather than a report: the build fails when a
change quietly makes detection worse. Floors sit just under the current numbers so
ordinary noise does not fail the build.

CI installs only `pytest` and `numpy`. The ingest, detection, correlation, validation and
chunking layers are pure standard library, and model imports are lazy, so pulling in the
on-device runtime would cost minutes without covering an extra line. Anything that needs
a model is measured locally with `eval.grounding_eval`.

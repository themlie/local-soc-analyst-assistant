# Performance

```powershell
python -m eval.benchmark            # per-stage timings at several volumes
```

Deterministic stages only, on a 16 GB CPU-only laptop. The LLM stage is excluded because
it is bounded by the model runtime rather than by this code.

| Events | Ingest | Detect | Correlate | Total |
|---|---|---|---|---|
| 1,000 | 0.07s | 0.02s | <0.01s | **0.09s** |
| 10,000 | 0.44s | 0.27s | <0.01s | **0.71s** |
| 50,000 | 2.01s | 1.25s | <0.01s | **3.26s** |

Two results are worth recording, because both contradicted an assumption.

## Brute-force detection was quadratic

The obvious implementation — for every starting attempt, rescan everything after it —
only terminates early when the threshold is met. So its worst case is an ordinary
situation, not an exotic one: an account failing authentication all day without ever
tripping the threshold means the rescan never stops early.

Measured at 4,000 attempts: **10.8 seconds, and doubling the input quadrupled the time.**
A two-pointer sliding window with lazily parsed timestamps brings that to **0.03s**.

Laziness matters. Parsing every timestamp in the group upfront fixed the rare case and
taxed the common one, where a real burst trips the threshold within a few events.

## Adding indexes made it slower

Indexing `event_id` and `(host, time)` was tried and reverted. 50k events went from
3.26s to 3.35s, and ingest paid to build the indexes on top.

The reason is not subtle once measured: detectors filter on common values — `event_id = 1`
matches roughly 40% of rows — and a sequential scan beats an index lookup per row once a
query matches much of the table. The reasoning is recorded in `ingest/ingest.py` so the
"missing" index does not get helpfully added back.

Revisit only if the table reaches millions of rows, or if detectors start filtering on
rare values.

## The model, not the code, is the bottleneck

Generating one incident report takes roughly 45–60 seconds on this hardware, and the
local runtime cancels a request that takes too long — surfacing as
`Operation was cancelled`. Three mitigations are in place: generation length is capped,
the prompt asks for brevity, and model access is serialized so requests do not contend.

Measurement ruled out the obvious suspects. Concurrency was not the cause (serializing
did not fix it), nor context size (the smallest incident failed too), nor `json_mode`.
A short prompt asking for a long answer fails, and a long prompt asking for a short one
succeeds — the budget is on generation time. Available memory turned out to matter most:
with a few gigabytes free the model finishes comfortably; under pressure it does not
finish at all.

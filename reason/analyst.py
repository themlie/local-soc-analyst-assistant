"""
reason/analyst.py — Reasoning layer: INCIDENT -> on-device LLM -> structured REPORT.

Here we give the Foundry Local on-device LLM the role of a "senior SOC analyst".
Reading the evidence package built by context.py, the model produces:
  - a summary of the incident,
  - a timeline,
  - the attack chain (with ATT&CK techniques),
  - a severity rating, and
  - recommended actions
as JSON.

The most important design decision is in the system prompt: we tell the model to rely
ONLY on the given evidence and to invent nothing. (If it does, the next layer,
`validate`, will catch it.)
"""

import common.console  # noqa: F401
from common.llm import complete, parse_json
from reason.context import build_context

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
You will be given raw logs, triggered detection rules, and relevant ATT&CK techniques
for a security incident. Your job is to analyze this evidence and produce a structured
incident report.

STRICT RULES:
- Rely ONLY on the events and evidence you are given. Do NOT invent any event, IP,
  user, process, or ATT&CK technique that was not provided.
- Ground every finding on the relevant event ids.
- If evidence is insufficient, say "insufficient evidence"; do not speculate.
- Only use the ATT&CK technique IDs given to you as reference.

Respond with ONLY the following JSON schema, and no other text:
{
  "summary": "a 1-2 sentence summary of the incident",
  "timeline": ["HH:MM - what happened (related event id)", "..."],
  "attack_chain": [
    {"technique": "T....", "tactic": "...", "explanation": "what happened at this step"}
  ],
  "severity": "low | medium | high | critical",
  "recommended_actions": ["recommended action 1", "recommended action 2"]
}
"""


def analyze_incident(incident: dict, alias: str | None = None, retries: int = 1) -> dict:
    """Analyze an incident with the on-device LLM and return a report dict.

    The local model runtime occasionally cancels the first request; retry once so a
    transient failure doesn't lose the incident.
    """
    context = build_context(incident)
    kwargs = {"json_mode": True}
    if alias:
        kwargs["alias"] = alias

    last_exc = None
    for _ in range(retries + 1):
        try:
            raw = complete(SYSTEM_PROMPT, context, **kwargs)
            return parse_json(raw)
        except Exception as exc:
            last_exc = exc
    raise last_exc


if __name__ == "__main__":
    # Quick end-to-end try: build incidents from ingested data, analyze the first.
    from detect.correlate import build_incidents

    incidents = build_incidents()
    if not incidents:
        print("No incidents found. Run 'python -m ingest.ingest' first.")
    else:
        print(f"{len(incidents)} incident(s) found. Analyzing the first (loading model)...\n")
        report = analyze_incident(incidents[0])
        import json
        print(json.dumps(report, ensure_ascii=False, indent=2))

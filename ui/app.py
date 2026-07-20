"""
ui/app.py — Streamlit web interface (clickable demo).

A visual interface instead of the terminal: pick logs -> analyze -> see incident
reports, the ATT&CK chain, and the validation result as colored cards.

Run with:
    streamlit run ui/app.py
"""

import json
import sys
from pathlib import Path

# When the Streamlit script runs directly, add the project root to the import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from ingest.ingest import ingest_events
from detect.correlate import build_incidents
from reason.analyst import analyze_incident
from validate.grounding import validate_report
from common.db import get_connection
from config import LOG_PATH, CHAT_MODEL

st.set_page_config(page_title="Local SOC Analyst Assistant", page_icon="🛡️", layout="wide")

_SEV_COLOR = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}

# --- Sidebar (settings) ---
st.sidebar.title("🛡️ SOC Assistant")
st.sidebar.caption("Fully offline · on-device LLM · data never leaves the machine")
model = st.sidebar.text_input("Model (Foundry Local alias)", value=CHAT_MODEL)

st.sidebar.markdown("---")
st.sidebar.subheader("Log source")
uploaded = st.sidebar.file_uploader("Upload a JSON log file", type=["json"])
run_btn = st.sidebar.button("🔎 Analyze", type="primary")


def load_logs() -> list[dict]:
    """Return the raw log list from the uploaded file, or the sample file."""
    if uploaded is not None:
        return json.loads(uploaded.getvalue().decode("utf-8"))
    return json.loads(LOG_PATH.read_text(encoding="utf-8"))


# --- Main header ---
st.title("Local SOC Analyst Assistant")
st.markdown(
    "Analyzes raw security logs with an **offline** LLM; links suspicious events into "
    "an attack chain and produces a **MITRE ATT&CK** mapping. Every result is "
    "**validated** against real log evidence (hallucination shield)."
)

if run_btn:
    logs = load_logs()
    n = ingest_events(logs)
    st.success(f"Processed {n} events.")

    # Raw event table
    with st.expander("📋 Processed raw events", expanded=False):
        conn = get_connection()
        rows = conn.execute(
            "SELECT id, time, host, event_id, user, src_ip, category, tool, url, message, cmdline "
            "FROM events ORDER BY time"
        ).fetchall()
        conn.close()
        # Drop columns that are entirely empty so the table stays readable
        data = [dict(r) for r in rows]
        if data:
            non_empty = [c for c in data[0] if any(row.get(c) is not None for row in data)]
            data = [{c: row[c] for c in non_empty} for row in data]
        st.dataframe(data, use_container_width=True)

    incidents = build_incidents()
    if not incidents:
        st.info("No suspicious activity found. Logs look clean. ✅")
    else:
        st.subheader(f"{len(incidents)} incident(s) detected")
        for idx, incident in enumerate(incidents, 1):
            sev = incident["severity"]
            with st.spinner(f"Analyzing incident #{idx} ({incident['host']})... "
                            f"(model may be loading)"):
                report = analyze_incident(incident, alias=model)
                validation = validate_report(report, incident)

            icon = _SEV_COLOR.get(str(report.get("severity", sev)).lower(), "⚪")
            st.markdown(f"### {icon} Incident #{idx} — {incident['host']}")
            c1, c2 = st.columns([3, 1])

            with c1:
                st.markdown(f"**Summary:** {report.get('summary', '-')}")

                st.markdown("**Timeline:**")
                for item in report.get("timeline", []) or []:
                    if isinstance(item, dict):
                        st.markdown(f"- `{item.get('time','')}` {item.get('description','')}")
                    else:
                        st.markdown(f"- {item}")

                st.markdown("**Attack chain (ATT&CK):**")
                for step in report.get("attack_chain", []) or []:
                    if isinstance(step, dict):
                        st.markdown(f"- **{step.get('technique','')}** "
                                    f"({step.get('tactic','')}): {step.get('explanation','')}")
                    else:
                        st.markdown(f"- {step}")

                st.markdown("**Recommended actions:**")
                for act in report.get("recommended_actions", []) or []:
                    st.markdown(f"- {act}")

            with c2:
                st.metric("Severity", str(report.get("severity", sev)).upper())
                st.metric("Trust score", validation["trust_score"])
                if validation["grounded"]:
                    st.success("✅ Validated\nAll claims backed by evidence")
                else:
                    st.error("⚠️ Caution\nUnsupported claim present")
                if validation["warnings"]:
                    with st.expander("Validation warnings"):
                        for w in validation["warnings"]:
                            st.caption(f"• {w}")
            st.markdown("---")
else:
    st.info("Pick a log source in the sidebar and press **Analyze**.")

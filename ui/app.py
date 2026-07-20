"""
ui/app.py — Streamlit web interface (clickable demo).
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

st.set_page_config(page_title="SOC Analyst AI", layout="wide", initial_sidebar_state="collapsed")

# Custom CSS for UI/UX improvements (focusing on cards, buttons, and readable inputs)
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif !important;
        font-size: 1.05rem !important;
    }
    
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif !important;
        font-weight: 800 !important;
    }
    
    /* Make the top padding smaller and add horizontal breathing room */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        padding-left: 5rem !important;
        padding-right: 5rem !important;
        max-width: 1400px !important;
        margin: 0 auto;
    }
    
    /* Premium Button Styling */
    .stButton > button {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
        color: white !important;
        border-radius: 8px;
        border: none;
        padding: 0.6rem 2rem;
        font-weight: 600;
        font-size: 1.1rem !important;
        box-shadow: 0 4px 14px 0 rgba(59,130,246,0.39);
        transition: all 0.2s ease-in-out;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(59,130,246,0.23);
    }
    
    /* Make metrics pop */
    div[data-testid="stMetricValue"] {
        font-size: 2.8rem !important;
        font-weight: 800;
        color: #8b5cf6;
    }
    
    /* Incident Cards */
    div.incident-card {
        background-color: #18181b;
        border: 1px solid #27272a;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
    }
    
    /* Fix file uploader and input readability */
    .stTextInput input, .stFileUploader, .stFileUploader section {
        background-color: #1f1f23 !important;
        color: #f4f4f5 !important;
        border-radius: 8px !important;
        font-size: 1.1rem !important;
    }
    </style>
""", unsafe_allow_html=True)

_SEV_COLOR = {"low": "[LOW]", "medium": "[MEDIUM]", "high": "[HIGH]", "critical": "[CRITICAL]"}

# --- Main Header ---
col1, col2 = st.columns([3, 1])
with col1:
    st.title("SOC Analyst Assistant")
    st.markdown("Yapay Zeka Destekli Otonom Siber Güvenlik Merkezi")
with col2:
    st.info("Durum: Çevrimdışı (Air-Gapped)\n\nVeriler buluta çıkmaz.")

st.divider()

# --- Top Controls (Moved from Sidebar for better UX) ---
st.subheader("1. Veri Kaynağını Seçin")
col_upload, col_model, col_btn = st.columns([2, 1, 1])

with col_upload:
    uploaded = st.file_uploader("JSON Log Dosyası Yükle (Veya varsayılan test verisi için boş bırakın)", type=["json"])

with col_model:
    model = st.text_input("Yapay Zeka Modeli", value=CHAT_MODEL, help="Kullanılacak Foundry Local modeli")

def load_logs() -> list[dict]:
    if uploaded is not None:
        return json.loads(uploaded.getvalue().decode("utf-8"))
    return json.loads(LOG_PATH.read_text(encoding="utf-8"))

with col_btn:
    st.write("") # Spacing
    st.write("")
    run_btn = st.button("Analizi Başlat", type="primary", use_container_width=True)

st.divider()

if run_btn:
    with st.spinner("Loglar işleniyor ve veritabanına yazılıyor..."):
        logs = load_logs()
        n = ingest_events(logs)
    
    st.success(f"{n} adet olay (event) başarıyla veritabanına işlendi.")
    
    tab_incidents, tab_raw = st.tabs(["Tespit Edilen Vakalar (Incidents)", "Ham Loglar (Raw Data)"])

    with tab_incidents:
        incidents = build_incidents()
        if not incidents:
            st.success("Harika! Sistemde şüpheli hiçbir hareket bulunamadı. Loglar temiz.")
        else:
            st.warning(f"Sistemde {len(incidents)} adet şüpheli vaka tespit edildi! Yapay zeka analizi başlıyor...")
            
            for idx, incident in enumerate(incidents, 1):
                sev = incident["severity"]
                
                with st.spinner(f"Vaka #{idx} ({incident['host']}) yapay zeka tarafından analiz ediliyor (Model yükleniyor olabilir)..."):
                    report = analyze_incident(incident, alias=model)
                    validation = validate_report(report, incident)
                
                # Render Incident Card
                st.markdown(f'<div class="incident-card">', unsafe_allow_html=True)
                icon = _SEV_COLOR.get(str(report.get("severity", sev)).lower(), "")
                st.subheader(f"{icon} Vaka #{idx} — Hedef: {incident['host']}")
                
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.markdown(f"**Özet:** {report.get('summary', '-')}")
                    
                    st.markdown("**Zaman Çizelgesi (Timeline):**")
                    for item in report.get("timeline", []) or []:
                        if isinstance(item, dict):
                            st.markdown(f"- `{item.get('time','')}` {item.get('description','')}")
                        else:
                            st.markdown(f"- {item}")
                            
                    st.markdown("**Saldırı Zinciri (MITRE ATT&CK):**")
                    for step in report.get("attack_chain", []) or []:
                        if isinstance(step, dict):
                            st.markdown(f"- **{step.get('technique','')}** ({step.get('tactic','')}): {step.get('explanation','')}")
                        else:
                            st.markdown(f"- {step}")
                            
                    st.markdown("**Önerilen Aksiyonlar:**")
                    for act in report.get("recommended_actions", []) or []:
                        st.markdown(f"- {act}")

                with c2:
                    st.metric("Risk Seviyesi", str(report.get("severity", sev)).upper())
                    st.metric("Yapay Zeka Güven Skoru", f"{validation['trust_score'] * 100:.0f}%")
                    
                    if validation["grounded"]:
                        st.success("Doğrulandı (Kanıtlara Dayalı)")
                    else:
                        st.error("Dikkat (Kanıtsız İddialar Var)")
                        
                    if validation["warnings"]:
                        with st.expander("Gözlemler / Uyarılar"):
                            for w in validation["warnings"]:
                                st.caption(f"• {w}")
                                
                st.markdown('</div>', unsafe_allow_html=True)

    with tab_raw:
        st.write("Veritabanına işlenmiş olan ham log verileri:")
        conn = get_connection()
        rows = conn.execute(
            "SELECT id, time, host, event_id, user, src_ip, category, tool, url, message, cmdline "
            "FROM events ORDER BY time"
        ).fetchall()
        conn.close()
        
        data = [dict(r) for r in rows]
        if data:
            non_empty = [c for c in data[0] if any(row.get(c) is not None for row in data)]
            data = [{c: row[c] for c in non_empty} for row in data]
        st.dataframe(data, use_container_width=True)
else:
    st.info("Lütfen yukarıdan log dosyanızı seçin (veya boş bırakın) ve 'Analizi Başlat' butonuna tıklayın.")

"""
ui/app.py — Streamlit web interface (clickable demo).
"""

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# When the Streamlit script runs directly, add the project root to the import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from ingest.ingest import ingest_events
from detect.correlate import build_incidents
from reason.analyst import analyze_incident
from reason.context import build_context
from validate.grounding import validate_report
from common.db import get_connection, use_session, purge_stale_sessions
from ui.report import to_markdown
from ui.navigator import detected_layer, coverage_layer, to_json
from rag.answer import answer_question, runbook_for_incident
from rag.index import index_stats
from config import LOG_PATH, DEMO_LOG_PATH, CHAT_MODEL

st.set_page_config(page_title="SOC Analyst AI", layout="wide", initial_sidebar_state="collapsed")

# Give this browser session its own database before anything reads or writes one.
# Ingest rebuilds the events table, so without this a second analyst uploading logs
# would wipe the first one's evidence — and then read results built from it.
# Streamlit reruns this script on every interaction, so the id is kept in session
# state and the binding is re-applied each run (it is thread-local, and reruns may
# land on a different worker thread).
if "session_id" not in st.session_state:
    import uuid
    st.session_state.session_id = uuid.uuid4().hex
    purge_stale_sessions()  # uploaded logs are sensitive; don't keep them forever
use_session(st.session_state.session_id)

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
    
    /* Center the file uploader text/label */
    div[data-testid="stFileUploader"] label {
        text-align: center !important;
        display: block !important;
        width: 100% !important;
    }
    </style>
""", unsafe_allow_html=True)

_SEV_COLOR = {"low": "[LOW]", "medium": "[MEDIUM]", "high": "[HIGH]", "critical": "[CRITICAL]"}


def run_with_live_view(fn, *args, **kwargs):
    """Run a model call in a worker thread while the main thread shows what it is doing.

    Calling the model directly would block this script, and nothing could be drawn
    until it returned — which is why the first ~30 seconds used to look like a freeze:
    the model reads the evidence before emitting a single token, so no streaming
    callback fires during it. Running the call in a worker lets this thread keep
    painting: an elapsed-time counter proves it is alive during that silent phase, and
    the generated text is shown as it arrives during the rest.

    The worker re-binds the session database, because that binding is thread-local and
    a worker without it would read the shared default instead of this user's uploads.
    """
    session_id = st.session_state.get("session_id")
    stream = {"text": ""}

    def on_chunk(text_so_far: str) -> None:
        stream["text"] = text_so_far          # worker thread: never touch Streamlit here

    def work():
        use_session(session_id)
        return fn(*args, on_chunk=on_chunk, **kwargs)

    box = st.empty()
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(work)
        while not future.done():
            _paint_live(box, stream["text"], time.monotonic() - started)
            time.sleep(0.25)
        _paint_live(box, stream["text"], time.monotonic() - started)
        result = future.result()             # re-raises worker exceptions to the caller
    box.empty()
    return result


def _paint_live(box, text: str, elapsed: float) -> None:
    """Draw the current phase, prominently enough to read from across a room."""
    with box.container():
        if not text:
            st.markdown(f"## ⏳ Model kanıtı okuyor…  `{elapsed:0.0f} sn`")
            st.info(
                "Model önce tüm kanıt paketini işliyor. Bu aşamada **çıktı üretilmez** — "
                "ekranda metin görünmemesi normaldir. CPU'da yaklaşık 30 saniye sürer, "
                "model ilk kez yükleniyorsa daha uzun."
            )
        else:
            st.markdown(f"## ✍️ Model yazıyor…  `{elapsed:0.0f} sn` · `{len(text)} karakter`")
            st.caption("Modelin ürettiği ham çıktı (canlı):")
            st.code(text[-1500:], language="json")

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
    model = st.selectbox(
        "Yapay Zeka Modeli",
        options=["qwen2.5-1.5b", "phi-4-mini", "llama-3-8b"],
        index=0,
        help="Kullanılacak yerel Foundry Local modelini seçin (İlk çalıştırmada otomatik indirilir)"
    )

_DATASETS = {
    "Hızlı örnek — 1 vaka (~1 dk)": LOG_PATH,
    "Tam senaryo — 2 vaka, kampanya + prompt injection (~2 dk)": DEMO_LOG_PATH,
}

with col_upload:
    dataset = st.radio(
        "Dosya yüklemezsen hangi örnek kullanılsın?",
        options=list(_DATASETS),
        index=1,
        horizontal=False,
        help="Her vakanın analizi CPU'da yaklaşık bir dakika sürer.",
    )


def load_logs() -> list[dict]:
    if uploaded is not None:
        return json.loads(uploaded.getvalue().decode("utf-8"))
    return json.loads(_DATASETS[dataset].read_text(encoding="utf-8"))

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
            
            if "phi" in model.lower() or "llama" in model.lower():
                st.info("⏳ **Bilgi:** Seçtiğiniz model yüksek kapasitelidir. Analizin tamamlanması **2-3 dakika** sürebilir. İşlemin iptal olmaması için lütfen rapor ekrana gelene kadar sayfada hiçbir yere tıklamadan bekleyin.")
            
            for idx, incident in enumerate(incidents, 1):
                sev = incident["severity"]
                
                try:
                    st.markdown(f"**Vaka #{idx}/{len(incidents)} — {incident['host']}**")
                    # Same evidence text for analysis and validation, so grounding
                    # checks what the model actually saw.
                    context = build_context(incident)
                    report = run_with_live_view(analyze_incident, incident,
                                                alias=model, context=context)
                    validation = validate_report(report, incident, context=context)
                except Exception as e:
                    if "cancelled" in str(e).lower():
                        st.error("⚠️ HATA: Sistem Belleği (RAM) Yetersiz veya İşlem İptal Edildi!")
                        st.warning("Seçtiğiniz yapay zeka modeli (örn. phi-4-mini) bilgisayarınızın donanım kapasitesini (RAM/İşlemci) aştığı için sistem çökmemek adına işlemi otomatik olarak durdurdu.")
                        st.info("💡 Çözüm: Lütfen yukarıdaki menüden daha hafif ve hızlı olan 'qwen2.5-1.5b' modelini seçerek analizi tekrar başlatın.")
                    else:
                        st.error(f"Yapay zeka analizi başarısız oldu: {str(e)}")
                        st.info("İpucu: Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.")
                    continue
                
                # Render Incident Card
                st.markdown(f'<div class="incident-card">', unsafe_allow_html=True)
                # Severity comes from the deterministic detectors, not the model —
                # crafted log text must not be able to talk an incident down to "low".
                icon = _SEV_COLOR.get(str(sev).lower(), "")
                st.subheader(f"{icon} Vaka #{idx} — Hedef: {incident['host']}")
                if incident.get("campaign_id"):
                    _related = ", ".join(incident.get("related_hosts", []))
                    st.warning(
                        f"🔗 **Kampanya #{incident['campaign_id']}** — bu vaka şu sunucularla "
                        f"aynı saldırı zincirine bağlı: **{_related}** (ortak pivot IP/hesap). "
                        f"Yanal hareket (lateral movement) şüphesi."
                    )
                
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
                            
                    st.markdown("**Önerilen Aksiyonlar (model önerisi):**")
                    for act in report.get("recommended_actions", []) or []:
                        st.markdown(f"- {act}")

                    # Retrieved from the team's runbooks using the DETECTED techniques,
                    # so the procedure an analyst follows is the documented one rather
                    # than whatever the model recalls.
                    try:
                        _runbook = runbook_for_incident(incident)
                    except Exception:
                        _runbook = []
                    if _runbook:
                        st.markdown("**Runbook prosedürü (bilgi tabanından getirildi):**")
                        for p in _runbook:
                            with st.expander(f"📘 {p['source']} — {p['heading']}  ·  benzerlik {p['similarity']}"):
                                st.write(p["content"])

                with c2:
                    st.metric("Risk Seviyesi", str(sev).upper())
                    _model_sev = str(report.get("severity", "")).strip().lower()
                    if _model_sev and _model_sev != str(sev).lower():
                        st.caption(f"Model '{_model_sev}' önerdi; dedektör değeri geçerlidir.")
                    st.metric("Yapay Zeka Güven Skoru", f"{validation['trust_score'] * 100:.0f}%")
                    
                    if validation["grounded"]:
                        st.success("Doğrulandı (Kanıtlara Dayalı)")
                    else:
                        st.error("Dikkat (Kanıtsız İddialar Var)")
                        
                    if validation["warnings"]:
                        with st.expander("Gözlemler / Uyarılar"):
                            for w in validation["warnings"]:
                                st.caption(f"• {w}")

                    # A finding is only useful if it can leave the tool — pasted into a
                    # ticket or attached to a handover. Event ids travel with it, so the
                    # recipient can trace every claim back to a log line.
                    st.download_button(
                        "Raporu indir (Markdown)",
                        data=to_markdown(incident, report, validation).encode("utf-8"),
                        file_name=f"incident-{idx}-{incident['host']}.md",
                        mime="text/markdown",
                        key=f"md-{idx}",
                        use_container_width=True,
                    )
                    st.download_button(
                        "Kanıt paketi (JSON)",
                        data=json.dumps(
                            {"incident": {k: v for k, v in incident.items() if k != "signals"},
                             "signals": incident["signals"],
                             "report": report,
                             "validation": validation},
                            ensure_ascii=False, indent=2, default=str).encode("utf-8"),
                        file_name=f"incident-{idx}-{incident['host']}.json",
                        mime="application/json",
                        key=f"json-{idx}",
                        use_container_width=True,
                    )

                st.markdown('</div>', unsafe_allow_html=True)

            # ATT&CK Navigator layers for the whole analysis. The coverage map is the
            # more useful of the two: it shows what these rules cannot catch as well as
            # what they can, in the notation a SOC already reads.
            st.divider()
            st.markdown("**MITRE ATT&CK Navigator katmanları**")
            st.caption(
                "İndirdiğin dosyayı https://mitre-attack.github.io/attack-navigator/ "
                "adresinde 'Open Existing Layer → Upload from local' ile aç."
            )
            nav1, nav2 = st.columns(2)
            with nav1:
                st.download_button(
                    "Bu analizde tespit edilenler",
                    data=to_json(detected_layer(incidents)).encode("utf-8"),
                    file_name="navigator-detections.json",
                    mime="application/json", key="nav-detected",
                    use_container_width=True,
                )
            with nav2:
                st.download_button(
                    "Tespit kapsamı (boşluklar dahil)",
                    data=to_json(coverage_layer()).encode("utf-8"),
                    file_name="navigator-coverage.json",
                    mime="application/json", key="nav-coverage",
                    use_container_width=True,
                )

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


# --------------------------------------------------------------------------- #
# Knowledge base Q&A (RAG)
#
# The other half of an analyst's job. Log analysis answers "what happened"; this
# answers "what do I do about it" from the team's own runbooks — retrieved, not
# recalled, so every answer carries the document it came from.
# --------------------------------------------------------------------------- #
st.divider()
st.subheader("2. Bilgi Tabanına Soru Sor")

_stats = index_stats()
if not _stats["total"]:
    st.warning(
        "Bilgi tabanı henüz indekslenmemiş. Terminalde `python -m rag.index` çalıştır "
        "(runbook'ları chunk'lara böler, embedding'lerini üretir ve SQLite'a yazar)."
    )
else:
    st.caption(
        f"{_stats['total']} passage · {len(_stats['by_source'])} doküman · "
        f"kaynak: {', '.join(_stats['by_source'])}"
    )

    question = st.text_input(
        "Sorunuz",
        placeholder="Örn: Security event log temizlenmişse ne yapmalıyım?",
        key="kb_question",
    )
    ask = st.button("Sor", type="secondary", key="kb_ask")

    if ask and question.strip():
        result = run_with_live_view(answer_question, question, alias=model)

        if not result["passages"]:
            # Retrieval found nothing above the similarity floor, so the model was
            # never asked. Saying "I don't know" is the correct answer here.
            st.info(f"**{result['answer']}**\n\nBu soru runbook'larda geçmiyor.")
        else:
            if result["answered"]:
                st.markdown(f"**Cevap:** {result['answer']}")
                # A fabricated filename looks verifiable and is not, so it is named
                # rather than quietly displayed alongside the real sources.
                if result.get("invented_citations"):
                    st.warning(
                        "⚠️ Model var olmayan bir kaynak gösterdi: "
                        + ", ".join(f"`{c}`" for c in result["invented_citations"])
                        + ". Aşağıdaki gerçek pasajlar geçerlidir."
                    )
            else:
                st.warning(result["answer"])

            st.markdown("**Kaynaklar** (cevabın dayandığı pasajlar):")
            for p in result["passages"]:
                with st.expander(f"{p['source']} — {p['heading']}  ·  benzerlik {p['similarity']}"):
                    st.write(p["content"])

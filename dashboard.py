import json
import streamlit as st
import plotly.graph_objects as go
import requests
import os
from datetime import datetime
import time
import random

# ── Config ───────────────────────────────────────────────────────────────
API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="CYBERSEC // THREAT CORE",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Cyberpunk Neon Dark Theme + Hacker Vibe ──────────────────────────────
st.markdown("""
<style>
    /* Global Reset & Cyberpunk Base */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Roboto+Mono:wght@300;400;700&display=swap');

    :root {
        --bg: #0d1117;
        --panel: #161b22;
        --neon-cyan: #00f0ff;
        --neon-magenta: #ff00aa;
        --neon-green: #00ff9f;
        --neon-red: #ff2a6d;
        --text: #e0f7ff;
        --text-dim: #8da0aa;
        --border: #30363d;
        --glow: 0 0 10px rgba(0, 240, 255, 0.5);
    }

    body, .stApp {
        background: var(--bg);
        color: var(--text);
        font-family: 'Roboto Mono', monospace;
    }

    h1, h2, h3, h4 {
        font-family: 'Orbitron', sans-serif;
        color: var(--neon-cyan);
        text-shadow: var(--glow);
        letter-spacing: 1.5px;
    }

    .stButton > button {
        background: transparent;
        border: 2px solid var(--neon-cyan);
        color: var(--neon-cyan);
        border-radius: 0;
        font-weight: bold;
        transition: all 0.3s;
        box-shadow: var(--glow);
    }
    .stButton > button:hover {
        background: var(--neon-cyan);
        color: #000;
        box-shadow: 0 0 20px var(--neon-cyan);
    }
    .stButton > button[kind="primary"] {
        background: var(--neon-magenta);
        border-color: var(--neon-magenta);
        color: white;
    }

    /* Metric Cards - Glass + Neon */
    .metric-card {
        background: rgba(22, 27, 34, 0.65);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: inset 0 0 15px rgba(0, 240, 255, 0.08);
        transition: transform 0.3s, box-shadow 0.4s;
    }
    .metric-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 10px 25px rgba(0, 240, 255, 0.25);
    }

    /* Severity borders + pulse */
    .critical { border-left: 5px solid var(--neon-red); animation: pulse-red 2s infinite; }
    .high     { border-left: 5px solid #ffaa00; animation: pulse-orange 2.5s infinite; }
    .medium   { border-left: 5px solid var(--neon-cyan); }
    .low      { border-left: 5px solid var(--neon-green); }

    @keyframes pulse-red   { 0%,100% {box-shadow: 0 0 8px var(--neon-red);} 50% {box-shadow: 0 0 20px var(--neon-red);} }
    @keyframes pulse-orange{ 0%,100% {box-shadow: 0 0 8px #ffaa00;} 50% {box-shadow: 0 0 18px #ffaa00;} }

    /* Terminal title typing effect */
    .typewriter {
        overflow: hidden;
        border-right: 0.15em solid var(--neon-cyan);
        white-space: nowrap;
        margin: 0;
        letter-spacing: 2px;
        animation: typing 3.5s steps(40, end) forwards, blink-caret 0.75s step-end infinite;
    }
    @keyframes typing {
        from { width: 0 }
        to   { width: 100% }
    }
    @keyframes blink-caret {
        from, to { border-color: transparent }
        50%      { border-color: var(--neon-cyan); }
    }

    /* Subtle scanline overlay */
    .scanline::after {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        background: linear-gradient(to bottom, transparent 50%, rgba(0,255,150,0.03) 50%);
        background-size: 100% 4px;
        pointer-events: none;
        animation: scan 8s linear infinite;
        z-index: 9999;
        opacity: 0.4;
    }
    @keyframes scan {
        0%   { transform: translateY(-100%); }
        100% { transform: translateY(100%); }
    }

    hr {
        border-color: var(--neon-cyan);
        opacity: 0.3;
    }

    .stExpander, .stTabs [data-baseweb="tab-panel"] {
        background: rgba(22,27,34,0.5);
        border: 1px solid var(--border);
    }
</style>
""", unsafe_allow_html=True)

# Fake glitch / matrix rain background (very light)
st.markdown('<div class="scanline"></div>', unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-shield-green.png", width=80)
    st.markdown("<h2 class='typewriter'>THREAT CORE</h2>", unsafe_allow_html=True)
    st.markdown("<small>NEURAL THREAT DETECTION v0.9</small>", unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio(
        "SYSTEM NAVIGATION",
        ["LOG ANALYZER", "IOC SCANNER", "REPORT ARCHIVE", "CORE STATUS"],
        label_visibility="collapsed"
    )
    st.markdown("---")
    st.caption("Powered by **AutoGen + Groq**")
    st.caption("NEON BUILT BY RITHIK 🌀")

# ── Helpers ──────────────────────────────────────────────────────────────
def severity_emoji(level: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢"
    }.get(level.lower(), "⚪")

def call_api(endpoint: str, method: str = "GET", payload: dict = None, timeout=300):
    try:
        url = f"{API_URL}{endpoint}"
        if method.upper() == "POST":
            resp = requests.post(url, json=payload, timeout=timeout)
        else:
            resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        st.error(f"→ API CONNECTION ERROR: {e}")
        return None

# ── Typing effect helper for important messages ─────────────────────────
def typewriter_text(text: str, speed=0.03):
    placeholder = st.empty()
    typed = ""
    for char in text:
        typed += char
        placeholder.markdown(f"<h3 style='color:var(--neon-green);'>{typed}</h3>", unsafe_allow_html=True)
        time.sleep(speed)
    return placeholder

# ── Main Pages ───────────────────────────────────────────────────────────
if page == "LOG ANALYZER":
    st.markdown("<h1 class='typewriter'>LOG ANALYZER // PIPELINE ACTIVE</h1>", unsafe_allow_html=True)
    st.markdown("Upload or paste raw security logs → **6-agent swarm** processes in ~60s")

    tab1, tab2 = st.tabs(["FILE UPLOAD", "PASTE RAW JSON"])

    with tab1:
        file = st.file_uploader("DROP JSON LOG BATCH", type=["json"])
        if file:
            try:
                logs = json.load(file)
                st.success(f"→ Loaded {len(logs)} entries")
                if st.button("EXECUTE ANALYSIS", type="primary"):
                    with st.spinner("Running neural swarm pipeline..."):
                        result = call_api("/analyze", "POST", {"logs": logs, "source": "neon_dashboard"})
                        if result:
                            st.session_state["analysis"] = result
            except Exception as e:
                st.error(f"→ JSON parse failed: {e}")

    with tab2:
        sample = call_api("/sample-logs") or {"logs": []}
        default = json.dumps(sample.get("logs", []), indent=2)
        raw = st.text_area("PASTE LOG STREAM", default, height=320)
        if st.button("EXECUTE ANALYSIS", type="primary", key="paste"):
            try:
                logs = json.loads(raw)
                with st.spinner("Neural agents analyzing..."):
                    result = call_api("/analyze", "POST", {"logs": logs, "source": "neon_paste"})
                    if result:
                        st.session_state["analysis"] = result
            except json.JSONDecodeError:
                st.error("→ Invalid JSON stream")

    # ── Results ──────────────────────────────────────────────────────────
    if "analysis" in st.session_state:
        res = st.session_state["analysis"]
        summ = res.get("summary", {})

        st.markdown("---")
        st.subheader("THREAT ASSESSMENT CORE")

        cols = st.columns(4)
        with cols[0]: st.markdown(f"<div class='metric-card'><strong>INCIDENT</strong><br>{res.get('incident_id','—')}</div>", unsafe_allow_html=True)
        with cols[1]:
            sev = summ.get("severity_level", "unknown")
            st.markdown(f"<div class='metric-card {sev}'><strong>SEVERITY</strong><br>{severity_emoji(sev)} {sev.upper()}</div>", unsafe_allow_html=True)
        with cols[2]: st.metric("SCORE", f"{summ.get('severity_score', '—')} / 10")
        with cols[3]: st.metric("CONTAINMENT", summ.get("containment_status", "—").upper())

        cols2 = st.columns(4)
        with cols2[0]: st.metric("THREAT TYPE", summ.get("threat_type", "—"))
        with cols2[1]: st.metric("ATTACK PHASE", summ.get("attack_stage", "—").upper())
        with cols2[2]:
            confirmed = "✅ CONFIRMED" if summ.get("threat_confirmed") else "❌ NOT DETECTED"
            st.metric("CONFIRMED", confirmed)
        with cols2[3]:
            esc = "🚨 ESCALATE" if summ.get("escalation_required") else "✓ MONITOR"
            st.metric("ACTION", esc)

        # Visuals
        st.markdown("---")
        c1, c2 = st.columns(2)

        with c1:
            st.subheader("THREAT GAUGE")
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=summ.get("severity_score", 0),
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "THREAT LEVEL"},
                delta={'reference': 5},
                gauge={
                    'axis': {'range': [0, 10]},
                    'bar': {'color': "cyan"},
                    'steps': [
                        {'range': [0, 3], 'color': "rgba(0,255,159,0.2)"},
                        {'range': [3, 6], 'color': "rgba(255,170,0,0.3)"},
                        {'range': [6, 10],'color': "rgba(255,42,109,0.4)"}
                    ],
                    'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': summ.get("severity_score",0)}
                }
            ))
            fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="cyan")
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.subheader("CIA TRIAD IMPACT")
            impact = res.get("full_results", {}).get("classification", {}).get("impact_assessment", {})
            vals = [ {"none":0,"low":3,"medium":6,"high":9}.get(impact.get(k,"none"),0) for k in ["confidentiality","integrity","availability"] ]
            fig2 = go.Figure(go.Bar(
                x=["CONF", "INT", "AVAIL"],
                y=vals,
                marker_color=[var(--neon-magenta), var(--neon-cyan), var(--neon-green)],
                text=vals,
                textposition="auto"
            ))
            fig2.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("---")
        st.subheader("EXECUTIVE INCIDENT REPORT")
        report = res.get("full_results", {}).get("report", {}).get("incident_report", {})
        st.markdown(f"**SUMMARY:** {report.get('executive_summary','—')}")
        st.markdown(f"**LESSONS:** {report.get('lessons_learned','—')}")

        with st.expander("FULL JSON DUMP"):
            st.json(res)

        st.download_button(
            "⬇ EXPORT INCIDENT REPORT",
            json.dumps(res, indent=2),
            file_name=f"INCIDENT-{res.get('incident_id','UNKNOWN')}.json",
            mime="application/json"
        )

elif page == "IOC SCANNER":
    st.markdown("<h1 class='typewriter'>IOC SCANNER // REPUTATION CHECK</h1>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["IP ADDRESS", "FILE HASH"])

    with tab1:
        ip = st.text_input("TARGET IP", placeholder="185.220.101.45")
        if st.button("SCAN IP", type="primary"):
            if ip:
                with st.spinner("Querying threat intel feeds..."):
                    r = call_api("/check/ip", "POST", {"ip": ip})
                    if r:
                        v = r.get("verdict", "unknown")
                        if v == "malicious":
                            st.error(f"🚨 MALICIOUS IOC DETECTED — {ip}")
                        else:
                            st.success(f"✓ CLEAN — {ip}")
                        st.json(r)

    with tab2:
        h = st.text_input("TARGET HASH (MD5/SHA256)", placeholder="d41d8cd98f00b204e9800998ecf8427e")
        if st.button("SCAN HASH", type="primary"):
            if h:
                with st.spinner("VirusTotal + threat intel..."):
                    r = call_api("/check/hash", "POST", {"file_hash": h})
                    if r:
                        v = r.get("verdict", "unknown")
                        if v == "malicious":
                            st.error(f"🚨 MALICIOUS FILE DETECTED")
                        else:
                            st.success(f"✓ CLEAN HASH")
                        st.json(r)

elif page == "REPORT ARCHIVE":
    st.markdown("<h1 class='typewriter'>REPORT ARCHIVE // PREVIOUS INCIDENTS</h1>", unsafe_allow_html=True)
    data = call_api("/reports") or {}
    reports = data.get("reports", [])
    if reports:
        choice = st.selectbox("SELECT INCIDENT", reports)
        if st.button("LOAD REPORT"):
            rid = choice.replace(".json", "")
            rep = call_api(f"/reports/{rid}")
            if rep:
                inc = rep.get("incident_report", {})
                st.subheader(inc.get("title", "INCIDENT REPORT"))
                cols = st.columns(3)
                cols[0].metric("ID", inc.get("incident_id"))
                cols[1].metric("CLASS", inc.get("classification"))
                cols[2].metric("STATUS", inc.get("status"))
                st.markdown(inc.get("executive_summary", "—"))
                with st.expander("RAW"):
                    st.json(rep)
    else:
        st.info("No incidents archived yet. Run analysis first.")

elif page == "CORE STATUS":
    st.markdown("<h1 class='typewriter'>CORE STATUS // SYSTEM HEALTH</h1>", unsafe_allow_html=True)
    health = call_api("/health")
    if health:
        st.success("CORE ONLINE")
        cols = st.columns(3)
        cols[0].metric("STATUS", health.get("status"))
        cols[1].metric("SERVICE", health.get("service"))
        cols[2].metric("VERSION", health.get("version"))
    else:
        st.error("CORE OFFLINE — start api.py")

    st.markdown("---")
    st.subheader("EXPOSED ENDPOINTS")
    for method, path, desc in [
        ("POST", "/analyze", "Execute full threat pipeline"),
        ("POST", "/check/ip", "IP reputation lookup"),
        ("POST", "/check/hash", "Hash intel check"),
        ("GET", "/reports", "List archived incidents"),
        ("GET", "/health", "System heartbeat"),
    ]:
        colr = "🟢" if method == "GET" else "🔵"
        st.markdown(f"{colr} **{method}** `{path}` — {desc}")

st.markdown("<small style='color:#444; text-align:center; display:block;'>NEON THREAT DETECTION — 2026</small>", unsafe_allow_html=True)
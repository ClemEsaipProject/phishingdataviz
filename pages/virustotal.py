import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from functions import scan_url_virustotal, get_url_report_virustotal
from database import save_scan

DARK = "plotly_dark"

CSS = """
<style>
.kpi-card {
    background: #1a1d2e;
    border: 1px solid #2a2d3e;
    border-radius: 12px;
    padding: 18px 20px;
    text-align: center;
}
.kpi-label { color: #8b95a5; font-size: 13px; margin-bottom: 6px; }
.kpi-value { color: #00d4ff; font-size: 28px; font-weight: 700; }
.kpi-value.danger { color: #ff4b4b; }
.kpi-value.warn   { color: #ffa500; }
.kpi-value.ok     { color: #00cc88; }
</style>
"""


def kpi(label, value, status=""):
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value {status}">{value}</div>
    </div>"""


def donut_chart(stats: dict) -> go.Figure:
    labels = ["Malicious", "Suspicious", "Harmless", "Undetected", "Timeout"]
    colors = ["#ff4b4b", "#ffa500", "#00cc88", "#8b95a5", "#4a4e69"]
    values = [stats.get(k.lower(), 0) for k in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#0e1117", width=2)),
        textinfo="percent+label",
        textfont=dict(color="#e0e0e0")
    ))
    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        title=dict(text="Distribution des resultats",
                   font=dict(color="#e0e0e0"), x=0.5),
        legend=dict(font=dict(color="#e0e0e0")),
        margin=dict(t=60, b=20, l=20, r=20),
        height=380
    )
    return fig


def top_engines_chart(scans: dict, n: int = 15) -> go.Figure:
    detected = [
        {"engine": k, "category": v.get("category", "unknown")}
        for k, v in scans.items()
        if v.get("category") in ("malicious", "suspicious")
    ][:n]

    if not detected:
        return None

    df        = pd.DataFrame(detected)
    color_map = {"malicious": "#ff4b4b", "suspicious": "#ffa500"}
    colors    = [color_map.get(c, "#8b95a5") for c in df["category"]]

    fig = go.Figure(go.Bar(
        x=df["engine"],
        y=[1] * len(df),
        marker_color=colors,
        text=df["category"],
        textposition="auto"
    ))
    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        plot_bgcolor="#1a1d2e",
        title=dict(text="Moteurs de detection",
                   font=dict(color="#e0e0e0"), x=0.5),
        xaxis=dict(tickfont=dict(color="#e0e0e0"), gridcolor="#2a2d3e"),
        yaxis=dict(visible=False),
        showlegend=False,
        margin=dict(t=60, b=80, l=20, r=20),
        height=350
    )
    return fig


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("VirusTotal Scanner")
    st.caption("Analyse multi-moteurs via VirusTotal API v3")

    with st.form("vt_form"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            url_input = st.text_input(
                "URL cible", placeholder="https://example.com"
            )
        with col_btn:
            st.write("")
            submitted = st.form_submit_button("Scanner", use_container_width=True)

    if not submitted or not url_input:
        return

    with st.spinner("Soumission a VirusTotal..."):
        vt_scan = scan_url_virustotal(url_input)

    if "error" in vt_scan:
        st.error(f"Connexion echouee : {vt_scan['error']}")
        return                                              # <- indente dans le if

    if not vt_scan.get("analysis_id"):
        st.error("Echec de la soumission. Verifie ta cle API VirusTotal.")
        return

    with st.spinner("Recuperation du rapport en cours..."):
        vt_report = get_url_report_virustotal(vt_scan)

    if not vt_report or "data" not in vt_report:
        st.error("Rapport indisponible. Relance le scan dans quelques secondes.")
        return

    attrs = vt_report["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats",   {})
    scans = attrs.get("last_analysis_results", {})

    total      = sum(stats.values())
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)

    threat_level   = "danger" if malicious > 5 else ("warn" if malicious > 0 else "ok")
    detection_rate = f"{round((malicious / total) * 100, 1)}%" if total else "N/A"

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, val, status in [
        (c1, "Moteurs scannant",  total,          ""),
        (c2, "Malveillants",      malicious,       threat_level),
        (c3, "Suspects",          suspicious,      "warn" if suspicious else "ok"),
        (c4, "Inoffensifs",       harmless,        "ok"),
        (c5, "Taux de detection", detection_rate,  threat_level),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    left, right = st.columns([1, 1])

    with left:
        st.plotly_chart(donut_chart(stats), width="stretch", key="vt_donut")

    with right:
        fig_engines = top_engines_chart(scans)
        if fig_engines:
            st.plotly_chart(fig_engines, width="stretch", key="vt_engines")
        else:
            st.success("Aucun moteur n'a detecte de menace sur cette URL.")

    save_scan(url_input, "VirusTotal", {
        "risk_score":   malicious * 10,
        "phishing":     malicious > 0,
        "malware":      malicious > 5,
        "suspicious":   suspicious > 0,
        "dns_valid":    True,
        "country_code": ""
    })


render()

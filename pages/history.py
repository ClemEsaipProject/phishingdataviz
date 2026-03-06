import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from database import get_all_scans, get_stats, clear_all

DARK = "plotly_dark"

CSS = """
<style>
.kpi-card {
    background: #1a1d2e;
    border: 1px solid #2a2d3e;
    border-radius: 12px;
    padding: 18px 20px;
    text-align: center;
    margin-bottom: 8px;
}
.kpi-label { color: #8b95a5; font-size: 13px; margin-bottom: 6px; }
.kpi-value { color: #00d4ff; font-size: 28px; font-weight: 700; }
.kpi-value.danger { color: #ff4b4b; }
.kpi-value.warn   { color: #ffa500; }
.kpi-value.ok     { color: #00cc88; }
</style>
"""


def kpi(label: str, value, status: str = "") -> str:
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value {status}">{value}</div>
    </div>"""


def risk_timeline(df: pd.DataFrame) -> go.Figure:
    df_sorted = df.sort_values("timestamp")
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=df_sorted["timestamp"],
        y=df_sorted["risk_score"],
        mode="lines+markers",
        name="Risk Score",
        line=dict(color="#00d4ff", width=2),
        marker=dict(
            color=[
                "#ff4b4b" if s >= 90 else ("#ffa500" if s >= 75 else "#00cc88")
                for s in df_sorted["risk_score"]
            ],
            size=8
        ),
        fill="tozeroy",
        fillcolor="rgba(0, 212, 255, 0.08)"
    ))

    fig.add_hline(
        y=75,
        line=dict(color="#ffa500", dash="dash", width=1),
        annotation_text="Seuil suspect (75)",
        annotation_font_color="#ffa500"
    )
    fig.add_hline(
        y=90,
        line=dict(color="#ff4b4b", dash="dash", width=1),
        annotation_text="Risque eleve (90)",
        annotation_font_color="#ff4b4b"
    )

    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        plot_bgcolor="#1a1d2e",
        title=dict(text="Evolution du Risk Score", font=dict(color="#e0e0e0"), x=0.5),
        xaxis=dict(title="Date", tickfont=dict(color="#8b95a5"),
                   gridcolor="#2a2d3e"),
        yaxis=dict(title="Risk Score", range=[0, 105],
                   tickfont=dict(color="#8b95a5"), gridcolor="#2a2d3e"),
        margin=dict(t=60, b=40, l=40, r=40),
        height=360
    )
    return fig


def threat_distribution(df: pd.DataFrame) -> go.Figure:
    any_threat = df[["phishing", "malware", "suspicious"]].any(axis=1)
    counts = {
        "Phishing":   int(df["phishing"].sum()),
        "Malware":    int(df["malware"].sum()),
        "Suspicious": int(df["suspicious"].sum()),
        "Clean":      int((~any_threat).sum()),
    }
    colors = ["#ff4b4b", "#ffa500", "#ffcc00", "#00cc88"]

    fig = go.Figure(go.Bar(
        x=list(counts.keys()),
        y=list(counts.values()),
        marker_color=colors,
        text=list(counts.values()),
        textposition="auto",
        textfont=dict(color="#e0e0e0")
    ))
    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        plot_bgcolor="#1a1d2e",
        title=dict(text="Distribution des menaces", font=dict(color="#e0e0e0"), x=0.5),
        xaxis=dict(tickfont=dict(color="#e0e0e0")),
        yaxis=dict(tickfont=dict(color="#8b95a5"), gridcolor="#2a2d3e"),
        margin=dict(t=60, b=40, l=40, r=40),
        height=340
    )
    return fig


import pycountry

def alpha2_to_alpha3(code: str) -> str:
    try:
        return pycountry.countries.get(alpha_2=code.upper()).alpha_3
    except Exception:
        return None


def country_map(df: pd.DataFrame) -> go.Figure:
    counts = (
        df[df["country"].str.len() == 2]["country"]
        .value_counts()
        .reset_index()
    )
    counts.columns = ["country_2", "count"]
    counts["country_3"] = counts["country_2"].apply(alpha2_to_alpha3)
    counts = counts.dropna(subset=["country_3"])

    if counts.empty:
        return None

    fig = px.choropleth(
        counts,
        locations="country_3",
        locationmode="ISO-3",
        color="count",
        color_continuous_scale=[[0, "#1a1d2e"], [1, "#ff4b4b"]],
        title="Origines geographiques des URLs scannees",
        hover_name="country_2",
        hover_data={"count": True, "country_3": False}
    )
    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        geo=dict(
            bgcolor="#0e1117",
            showframe=False,
            showcoastlines=True,
            coastlinecolor="#2a2d3e",
            landcolor="#1a1d2e",
            showland=True,
            showocean=True,
            oceancolor="#0e1117"
        ),
        title=dict(font=dict(color="#e0e0e0"), x=0.5),
        coloraxis_colorbar=dict(tickfont=dict(color="#e0e0e0")),
        margin=dict(t=60, b=20, l=0, r=0),
        height=380
    )
    return fig



def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("Historique des scans")

    scans = get_all_scans()

    if not scans:
        st.info(
            "Aucun scan enregistre pour le moment. "
            "Lance un scan depuis URL Scanner ou VirusTotal."
        )
        return

    stats = get_stats()
    df    = pd.DataFrame(scans)

    df["phishing"]   = df["phishing"].astype(int)
    df["malware"]    = df["malware"].astype(int)
    df["suspicious"] = df["suspicious"].astype(int)
    df["country"]    = df["country"].fillna("")

    avg_risk = round(stats["avg_risk"] or 0, 1)

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, val, status in [
        (c1, "Total scans",  stats["total"],         ""),
        (c2, "Risk moyen",   avg_risk,
         "danger" if avg_risk >= 75 else ("warn" if avg_risk >= 50 else "ok")),
        (c3, "Phishing",     stats["total_phishing"],
         "danger" if stats["total_phishing"] else "ok"),
        (c4, "Malware",      stats["total_malware"],
         "danger" if stats["total_malware"]  else "ok"),
        (c5, "Risque eleve", stats["high_risk"],
         "warn" if stats["high_risk"] else "ok"),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    left, right = st.columns([2, 1])
    with left:
        st.plotly_chart(
            risk_timeline(df),
            use_container_width=True,
            key="hist_timeline"
        )
    with right:
        st.plotly_chart(
            threat_distribution(df),
            use_container_width=True,
            key="hist_distribution"
        )

    if df["country"].str.len().gt(0).any():
        fig_map = country_map(df)
    if fig_map:
        st.plotly_chart(fig_map, use_container_width=True, key="hist_map")


    st.divider()
    st.markdown("#### Tous les scans")

    source_filter = st.selectbox(
        "Filtrer par source",
        ["Tous", "IPQualityScore", "VirusTotal"]
    )

    filtered = (
        df if source_filter == "Tous"
        else df[df["source"] == source_filter]
    )

    display_cols = [
        "timestamp", "url", "source",
        "risk_score", "phishing", "malware", "suspicious", "country"
    ]

    st.dataframe(
        filtered[display_cols].rename(columns={
            "timestamp":  "Date",
            "url":        "URL",
            "source":     "Source",
            "risk_score": "Risk Score",
            "phishing":   "Phishing",
            "malware":    "Malware",
            "suspicious": "Suspect",
            "country":    "Pays"
        }),
        use_container_width=True,
        hide_index=True,
        key="hist_table"
    )

    csv = filtered[display_cols].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Exporter CSV",
        data=csv,
        file_name="phishing_scans_history.csv",
        mime="text/csv",
        key="hist_export"
    )

    st.divider()
    with st.expander("Zone dangereuse"):
        st.warning("Cette action supprime definitivement tous les scans enregistres.")
        if st.button("Vider tout l'historique", type="primary", key="hist_clear"):
            clear_all()
            st.rerun()


render()

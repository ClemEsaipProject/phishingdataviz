import streamlit as st
import plotly.graph_objects as go
import pydeck as pdk
import pandas as pd
from functions import get_data, build_iq_url, get_coordinates, base_url, country_code_url

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

def kpi(label: str, value, status: str = ""):
    css_class = f"kpi-value {status}"
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="{css_class}">{value}</div>
    </div>"""


def radar_chart(data: dict) -> go.Figure:
    risk       = data.get("risk_score", 0) / 100
    spam       = 1.0 if data.get("spamming")   else 0.0
    malware    = 1.0 if data.get("malware")     else 0.0
    phishing   = 1.0 if data.get("phishing")    else 0.0
    suspicious = 1.0 if data.get("suspicious")  else 0.0
    dns_fail   = 0.0 if data.get("dns_valid")   else 1.0

    categories = ["Risk Score", "Spam", "Malware",
                  "Phishing", "Suspicious", "DNS Fail"]
    values = [risk, spam, malware, phishing, suspicious, dns_fail]
    values += [values[0]]
    categories += [categories[0]]

    fig = go.Figure(go.Scatterpolar(
        r=values,
        theta=categories,
        fill="toself",
        line=dict(color="#00d4ff", width=2),
        fillcolor="rgba(0, 212, 255, 0.15)"
    ))
    fig.update_layout(
        template=DARK,
        polar=dict(
            bgcolor="#1a1d2e",
            radialaxis=dict(visible=True, range=[0, 1],
                            tickfont=dict(color="#8b95a5"),
                            gridcolor="#2a2d3e"),
            angularaxis=dict(tickfont=dict(color="#e0e0e0"),
                             gridcolor="#2a2d3e")
        ),
        paper_bgcolor="#0e1117",
        title=dict(text="Threat Radar", font=dict(color="#e0e0e0"), x=0.5),
        margin=dict(t=60, b=20, l=20, r=20),
        height=380
    )
    return fig


def map_chart(latitude: float, longitude: float) -> pdk.Deck:
    df = pd.DataFrame([{"lat": latitude, "lon": longitude}])
    layer = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position="[lon, lat]",
        get_color="[0, 212, 255, 180]",
        get_radius=80000,
    )
    view = pdk.ViewState(latitude=latitude, longitude=longitude, zoom=4, pitch=30)
    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=pdk.map_styles.DARK,
        height=400
)



def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("URL Scanner")
    st.caption("Analyse via IPQualityScore")

    with st.form("url_form"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            url_input = st.text_input("URL cible", placeholder="https://example.com")
        with col_btn:
            st.write("")
            submitted = st.form_submit_button("Scanner", use_container_width=True)

    if not submitted or not url_input:
        return

    with st.spinner("Analyse en cours..."):
        data = get_data(build_iq_url(base_url, url_input))

    if "error" in data:
        st.error(data["error"])
        return

    risk       = data.get("risk_score",  0)
    dns_valid  = data.get("dns_valid",   False)
    spam       = data.get("spamming",    False)
    malware    = data.get("malware",     False)
    phishing   = data.get("phishing",    False)
    suspicious = data.get("suspicious",  False)
    domain_rank = data.get("domain_rank", "N/A")
    country    = data.get("country_code", "N/A")
    category   = data.get("category",    "N/A")

    risk_status  = "danger" if risk >= 90 else ("warn" if risk >= 75 else "ok")
    dns_status   = "ok" if dns_valid else "danger"
    flag_status  = lambda v: "danger" if v else "ok"

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    kpis = [
        (c1, "Risk Score",   risk,                       risk_status),
        (c2, "DNS Valid",    "Oui" if dns_valid else "Non", dns_status),
        (c3, "Phishing",     "Oui" if phishing  else "Non", flag_status(phishing)),
        (c4, "Malware",      "Oui" if malware   else "Non", flag_status(malware)),
        (c5, "Suspicious",   "Oui" if suspicious else "Non", flag_status(suspicious)),
        (c6, "Domain Rank",  domain_rank,                ""),
    ]
    for col, label, value, status in kpis:
        with col:
            st.markdown(kpi(label, value, status), unsafe_allow_html=True)

    st.divider()

    left, right = st.columns([1, 1])

    with left:
        st.plotly_chart(radar_chart(data), use_container_width=True)

        st.markdown(
            f"**Categorie :** {category} &nbsp;|&nbsp; **Pays :** {country} &nbsp;|&nbsp; "
            f"**Spam :** {'Oui' if spam else 'Non'}"
        )

    with right:
        lat, lon = get_coordinates(country)
        if lat and lon:
            st.pydeck_chart(map_chart(lat, lon),height=400)
        else:
            st.info("Geolocalisation indisponible pour ce pays.")


render()

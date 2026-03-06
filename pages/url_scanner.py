import streamlit as st
import plotly.graph_objects as go
import pydeck as pdk
import pandas as pd
from functions import (
    get_data,
    build_iq_url,
    get_coordinates,
    base_url,
    detect_typosquatting,
    lexical_analysis
)
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


def radar_chart(data: dict) -> go.Figure:
    risk       = data.get("risk_score", 0) / 100
    spam       = 1.0 if data.get("spamming")   else 0.0
    malware    = 1.0 if data.get("malware")     else 0.0
    phishing   = 1.0 if data.get("phishing")    else 0.0
    suspicious = 1.0 if data.get("suspicious")  else 0.0
    dns_fail   = 0.0 if data.get("dns_valid")   else 1.0

    categories = ["Risk Score", "Spam", "Malware",
                  "Phishing", "Suspicious", "DNS Fail"]
    values     = [risk, spam, malware, phishing, suspicious, dns_fail]
    categories += [categories[0]]
    values     += [values[0]]

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


def lexical_chart(lex: dict) -> go.Figure:
    features = {
        "Longueur URL":   min(lex["url_length"] / 150, 1.0),
        "IP dans URL":    1.0 if lex["has_ip"]               else 0.0,
        "Pas HTTPS":      0.0 if lex["has_https"]             else 1.0,
        "Caractere @":    1.0 if lex["has_at"]                else 0.0,
        "Sous-domaines":  min(lex["subdomains"] / 4,          1.0),
        "Mots suspects":  min(len(lex["keywords_hit"]) / 4,   1.0),
        "Chars speciaux": min(lex["special_chars"] / 6,       1.0),
    }
    cats = list(features.keys()) + [list(features.keys())[0]]
    vals = list(features.values()) + [list(features.values())[0]]

    fig = go.Figure(go.Scatterpolar(
        r=vals,
        theta=cats,
        fill="toself",
        line=dict(color="#ffa500", width=2),
        fillcolor="rgba(255, 165, 0, 0.15)"
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
        title=dict(text="Analyse lexicale", font=dict(color="#e0e0e0"), x=0.5),
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
        get_color="[0, 212, 255, 200]",
        get_radius=120000,
        pickable=True
    )
    view = pdk.ViewState(
        latitude=latitude,
        longitude=longitude,
        zoom=4,
        pitch=30
    )
    return pdk.Deck(
        layers=[layer],
        initial_view_state=view,
        map_style=pdk.map_styles.DARK,
        tooltip={"text": "Localisation detectee"}
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

    with st.spinner("Analyse IPQualityScore en cours..."):
        data = get_data(build_iq_url(base_url, url_input))

    if "error" in data:
        st.error(data["error"])
        return

    risk        = data.get("risk_score",  0)
    dns_valid   = data.get("dns_valid",   False)
    spam        = data.get("spamming",    False)
    malware     = data.get("malware",     False)
    phishing    = data.get("phishing",    False)
    suspicious  = data.get("suspicious",  False)
    domain_rank = data.get("domain_rank", "N/A")
    country     = data.get("country_code","N/A")
    category    = data.get("category",    "N/A")

    risk_status = "danger" if risk >= 90 else ("warn" if risk >= 75 else "ok")
    dns_status  = "ok" if dns_valid else "danger"
    flag_status = lambda v: "danger" if v else "ok"

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    for col, label, value, status in [
        (c1, "Risk Score",  risk,                            risk_status),
        (c2, "DNS Valid",   "Oui" if dns_valid  else "Non",  dns_status),
        (c3, "Phishing",    "Oui" if phishing   else "Non",  flag_status(phishing)),
        (c4, "Malware",     "Oui" if malware    else "Non",  flag_status(malware)),
        (c5, "Suspicious",  "Oui" if suspicious else "Non",  flag_status(suspicious)),
        (c6, "Domain Rank", domain_rank,                     ""),
    ]:
        with col:
            st.markdown(kpi(label, value, status), unsafe_allow_html=True)

    st.divider()

    lex   = lexical_analysis(url_input)
    typos = detect_typosquatting(url_input)

    tab1, tab2, tab3 = st.tabs(["Threat Radar", "Analyse Lexicale", "Typosquatting"])

    with tab1:
        left, right = st.columns([1, 1])
        with left:
            st.plotly_chart(
                radar_chart(data),
                use_container_width=True,
                key="url_radar_threat"
            )
            st.markdown(
                f"**Categorie :** {category} &nbsp;|&nbsp; "
                f"**Pays :** {country} &nbsp;|&nbsp; "
                f"**Spam :** {'Oui' if spam else 'Non'}"
            )
        with right:
            lat, lon = get_coordinates(country)
            if lat and lon:
                st.pydeck_chart(
                    map_chart(lat, lon),
                    height=400,
                    key="url_map"
                )
            else:
                st.info("Geolocalisation indisponible pour ce pays.")

    with tab2:
        l2, r2 = st.columns([1, 1])
        with l2:
            st.plotly_chart(
                lexical_chart(lex),
                use_container_width=True,
                key="url_radar_lexical"
            )
        with r2:
            st.markdown("#### Score lexical")
            lex_status = (
                "danger" if lex["score"] >= 60
                else ("warn" if lex["score"] >= 35 else "ok")
            )
            st.markdown(
                kpi("Score lexical local", lex["score"], lex_status),
                unsafe_allow_html=True
            )
            st.divider()
            features_display = {
                "Longueur URL":           f"{lex['url_length']} caracteres",
                "HTTPS":                  "Oui" if lex["has_https"]  else "Non",
                "IP dans URL":            "Oui" if lex["has_ip"]     else "Non",
                "Caractere @":            "Oui" if lex["has_at"]     else "Non",
                "Sous-domaines":          lex["subdomains"],
                "Caracteres speciaux":    lex["special_chars"],
                "Mots suspects detectes": ", ".join(lex["keywords_hit"]) or "Aucun",
            }
            for k, v in features_display.items():
                st.markdown(f"**{k} :** `{v}`")

    with tab3:
        if not typos:
            st.success("Aucune correspondance de typosquatting detectee.")
        else:
            st.warning(f"{len(typos)} marque(s) potentiellement usurpee(s) detectee(s)")
            for t in typos:
                color = "red" if t["risk"] == "Eleve" else "orange"
                st.markdown(
                    f"- Domaine **`{t['detected']}`** ressemble a "
                    f"**`{t['brand']}`** "
                    f"(distance Levenshtein : `{t['distance']}` — "
                    f":{color}[Risque {t['risk']}])"
                )

    save_scan(url_input, "IPQualityScore", data)


render()

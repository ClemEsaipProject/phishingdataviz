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
    lexical_analysis,
    detect_reserved_namespace,
    detect_homoglyphs,
    is_shorturl,
    resolve_shorturl,
    get_domain_age,
    get_whois,
)
from database import save_scan
from scorer import compute_global_score

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

    # ── Résolution URL court (Tier 1) ──────────────────────────────────────
    url_to_scan = url_input
    short_info  = None
    if is_shorturl(url_input):
        with st.spinner("Résolution du lien court…"):
            short_info = resolve_shorturl(url_input)
        if short_info.get("changed"):
            url_to_scan = short_info["final"]
            st.info(
                f"🔗 **Lien court résolu** : `{url_input}` "
                f"→ `{url_to_scan}` ({short_info['hops']} saut(s))"
            )

    with st.spinner("Analyse IPQualityScore en cours..."):
        data = get_data(build_iq_url(base_url, url_to_scan))

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

    lex        = lexical_analysis(url_to_scan)
    typos      = detect_typosquatting(url_to_scan)
    namespace  = detect_reserved_namespace(url_to_scan)
    homoglyphs = detect_homoglyphs(url_to_scan)

    # Âge du domaine via WHOIS (Tier 1)
    age_days: int | None = None
    with st.spinner("Lookup WHOIS (âge du domaine)…"):
        whois_data = get_whois(url_to_scan)
        if "error" not in whois_data:
            age_days = get_domain_age(whois_data)

    score = compute_global_score(
        data, lex["score"], typos,
        namespace=namespace,
        domain_age=age_days,
        homoglyphs=homoglyphs,
    )

    score_color = {"danger": "#ff4b4b", "warn": "#ffa500", "ok": "#00cc88"}[score["level"]]
    age_label = (
        f"{age_days}j" if age_days is not None
        else "inconnu"
    )
    breakdown = (
        f"IQ&nbsp;{score['iq_component']} · "
        f"Lexical&nbsp;{score['lex_component']} · "
        f"Typo&nbsp;{score['typo_component']} · "
        f"NS&nbsp;{score['ns_component']} · "
        f"Âge&nbsp;{age_label} · "
        f"IDN&nbsp;{score['homo_component']}"
        + (f" · VT&nbsp;{score['vt_component']}" if score["has_vt"] else "")
    )
    st.markdown(
        f"""
        <div style="background:#1a1d2e;border:2px solid {score_color};border-radius:14px;
                    padding:18px 24px;margin:14px 0;display:flex;
                    align-items:center;justify-content:space-between;">
            <div>
                <div style="color:#8b95a5;font-size:13px;margin-bottom:4px;">
                    Score Global Fusionné
                </div>
                <div style="color:{score_color};font-size:42px;font-weight:800;
                            line-height:1;">
                    {score['global_score']}<span style="font-size:20px;color:#8b95a5;">/100</span>
                </div>
                <div style="color:#8b95a5;font-size:12px;margin-top:6px;">{breakdown}</div>
            </div>
            <div style="color:{score_color};font-size:26px;font-weight:700;
                        letter-spacing:1px;">
                {score['label'].upper()}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    ns_tab_label   = "🔴 Namespace" if namespace["risk"] == "danger" \
        else ("🟡 Namespace" if namespace["risk"] == "warn" else "Namespace")
    homo_tab_label = "🔴 IDN/Homoglyphes" if homoglyphs.get("flagged") else "IDN/Homoglyphes"

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Threat Radar", "Analyse Lexicale", "Typosquatting",
         ns_tab_label, homo_tab_label]
    )

    with tab1:
        left, right = st.columns([1, 1])
        with left:
            st.plotly_chart(
                radar_chart(data),
                width="stretch",
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
                width="stretch",
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

    with tab4:
        st.markdown("#### Détection de namespace réservé")
        st.caption(
            "Contre-mesure contre les campagnes exploitant des TLDs réservés "
            "(RFC 2606, .arpa, extensions de fichiers, TLDs privés d'entreprise)."
        )
        if not namespace["flagged"]:
            st.success(
                f"TLD **`.{namespace['tld']}`** — aucun namespace réservé détecté."
            )
        else:
            risk_fn = st.error if namespace["risk"] == "danger" else st.warning
            risk_fn(
                f"**TLD `.{namespace['tld']}`** — {namespace['category_label']}\n\n"
                f"{namespace['explanation']}"
            )
            c1, c2 = st.columns(2)
            with c1:
                risk_status = "danger" if namespace["risk"] == "danger" else "warn"
                st.markdown(
                    kpi("Niveau de risque", namespace["risk"].upper(), risk_status),
                    unsafe_allow_html=True,
                )
            with c2:
                st.markdown(
                    kpi("Catégorie", namespace["category_label"], risk_status),
                    unsafe_allow_html=True,
                )
            st.divider()
            st.markdown("##### Pourquoi ce TLD est-il suspect ?")
            st.markdown(namespace["explanation"])
            st.markdown(
                "> **Références :** RFC 2606 (IETF), RFC 3172 (.arpa), "
                "recherches Bleeping Computer / Kaspersky 2024-2025 sur "
                "les campagnes de phishing exploitant l'espace de noms réservé."
            )

    with tab5:
        st.markdown("#### Détection Homoglyphes / IDN / Leetspeak")
        st.caption(
            "Identifie les domaines utilisant des caractères Unicode confusables (Cyrillique, Grec), "
            "l'encodage Punycode (xn--) ou des substitutions de chiffres (0→o, 1→l…) "
            "pour usurper des marques connues."
        )
        if not homoglyphs.get("flagged"):
            st.success("Aucun homoglyph, IDN ou leetspeak suspect détecté.")
            st.markdown(
                f"Hostname analysé : `{homoglyphs.get('hostname', url_to_scan)}`"
            )
        else:
            method_labels = {
                "punycode":          "Encodage Punycode (IDN — xn--)",
                "punycode_malformed": "Punycode malformé",
                "unicode_direct":    "Unicode direct dans le domaine",
                "leetspeak":         "Substitution leetspeak (chiffres)",
            }
            method = homoglyphs.get("method", "inconnu")
            st.error(
                f"**Attaque par homoglyph détectée** — "
                f"{method_labels.get(method, method)}"
            )
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(
                    kpi("Méthode", method_labels.get(method, method), "danger"),
                    unsafe_allow_html=True,
                )
            with c2:
                brand = homoglyphs.get("matched_brand", "—")
                st.markdown(
                    kpi("Marque ciblée", brand.upper() if brand != "—" else brand, "danger"),
                    unsafe_allow_html=True,
                )
            st.divider()
            st.markdown("##### Détails")
            if homoglyphs.get("decoded"):
                st.markdown(f"**Décodé (Punycode) :** `{homoglyphs['decoded']}`")
            if homoglyphs.get("normalized"):
                st.markdown(f"**Normalisé (confusables → ASCII) :** `{homoglyphs['normalized']}`")
            st.markdown(f"**Hostname original :** `{homoglyphs.get('hostname', '')}`")
            if homoglyphs.get("matched_brand"):
                st.markdown(
                    f"> **Ce domaine imite visuellement `{homoglyphs['matched_brand']}`** "
                    f"grâce à des caractères d'apparence identique mais encodés différemment. "
                    f"C'est une technique de phishing avancée (attaque homographique)."
                )

    # ── Âge du domaine (Tier 1) ────────────────────────────────────────────
    if age_days is not None or "error" in whois_data:
        with st.expander("Âge du domaine (WHOIS)", expanded=age_days is not None and age_days < 180):
            if age_days is not None:
                age_status = (
                    "danger" if age_days < 30
                    else ("warn" if age_days < 180 else "ok")
                )
                age_human = (
                    f"{age_days} jours"  if age_days < 365
                    else f"{age_days // 365} an(s) {age_days % 365} j"
                )
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(
                        kpi("Âge du domaine", age_human, age_status),
                        unsafe_allow_html=True,
                    )
                with c2:
                    reg = whois_data.get("registrar", "N/A")
                    st.markdown(kpi("Registrar", reg[:30] if reg != "N/A" else reg, ""),
                                unsafe_allow_html=True)
                if age_days < 30:
                    st.error("Domaine très récent (< 30 jours) — signal fort de phishing.")
                elif age_days < 180:
                    st.warning("Domaine récent (< 6 mois) — signal modéré.")
                else:
                    st.success("Domaine établi (> 6 mois) — signal neutre.")
            else:
                st.warning(f"WHOIS indisponible : {whois_data.get('error', 'inconnu')}")

    save_scan(url_to_scan, "IPQualityScore", data)


render()

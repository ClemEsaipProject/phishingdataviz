import streamlit as st
from functions import get_whois

CSS = """
<style>
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    margin: 2px;
}
.badge-done   { background: #1a2e1a; color: #00cc88; border: 1px solid #00cc88; }
.badge-source { background: #1a1d2e; color: #00d4ff; border: 1px solid #00d4ff; }
</style>
"""

SPRINTS = [
    ("Sprint 1", ["Historique des scans", "Base de données SQLite", "Graphiques timeline"]),
    ("Sprint 2", ["Typosquatting (Levenshtein)", "Analyse lexicale (7 facteurs)", "SSL Certificate Checker"]),
    ("Sprint 3", ["Redirect Chain Explorer", "Détection downgrade HTTPS", "Géolocalisation cartographique"]),
    ("Sprint 4", ["Bulk Scanner CSV", "Scan de masse avec progression", "Export résultats CSV"]),
    ("Sprint 5", ["Score Global Fusionné", "Pondération multi-sources", "Surcharge menaces confirmées"]),
    ("Sprint 6", ["WHOIS Lookup", "About final", "README mis à jour"]),
]


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("À propos & WHOIS Lookup")
    st.caption("PhishingDataViz — URL & Email Threat Intelligence Dashboard")

    # ── WHOIS Lookup ──────────────────────────────────────────────────────────
    st.markdown("### WHOIS Lookup")
    st.markdown(
        "Interroge les serveurs WHOIS autoritatifs pour obtenir les informations "
        "d'enregistrement d'un domaine."
    )

    with st.form("whois_form"):
        col_in, col_btn = st.columns([4, 1])
        with col_in:
            whois_input = st.text_input(
                "URL ou domaine", placeholder="https://example.com"
            )
        with col_btn:
            st.write("")
            submitted = st.form_submit_button("Rechercher", use_container_width=True)

    if submitted and whois_input:
        url = whois_input if whois_input.startswith("http") else f"https://{whois_input}"
        with st.spinner("Interrogation WHOIS en cours…"):
            result = get_whois(url)

        if "error" in result:
            st.error(f"WHOIS indisponible : {result['error']}")
        else:
            fields = {
                "Domaine":             result.get("domain",             "—"),
                "Registrar":           result.get("registrar",          "—"),
                "Date de création":    result.get("creation_date",      "—"),
                "Date d'expiration":   result.get("expiration_date",    "—"),
                "Dernière mise à jour":result.get("updated_date",       "—"),
                "Organisation":        result.get("registrant_org",     "—"),
                "Pays du titulaire":   result.get("registrant_country", "—"),
                "Serveur WHOIS":       result.get("whois_server",       "—"),
            }

            col1, col2 = st.columns(2)
            items = list(fields.items())
            for i, (k, v) in enumerate(items):
                with (col1 if i % 2 == 0 else col2):
                    st.markdown(f"**{k} :** `{v}`")

            ns = result.get("name_servers")
            if ns:
                st.markdown(f"**Serveurs de noms :** `{' · '.join(ns)}`")

            statuses = result.get("status")
            if statuses:
                st.markdown(f"**Statut :** `{' · '.join(statuses)}`")

    st.divider()

    # ── Interprétation des scores ──────────────────────────────────────────────
    st.markdown("### Interprétation des scores")

    col_a, col_b = st.columns(2)
    with col_a:
        st.error("**≥ 75 / 100** — Malveillant  \nPhishing, malware ou menace confirmée.")
        st.warning("**40 – 74** — Suspect  \nComportements associés à des liens abusifs.")
    with col_b:
        st.info("**< 40** — Propre  \nAucune anomalie significative détectée.")
        st.success("`suspicious: true` — Domaine potentiellement abusif (score non critique).")

    st.markdown("#### Score Global Fusionné (Sprint 5)")
    st.markdown("""
| Signal | Poids (sans VT) | Poids (avec VT) |
|---|---|---|
| IPQualityScore risk_score | 55 % | 40 % |
| Analyse lexicale | 30 % | 20 % |
| VirusTotal détections | — | 25 % |
| Typosquatting | 15 % | 15 % |

> Surcharge forcée : phishing ou malware confirmé → score plancher à **75**.
    """)

    st.divider()

    # ── Sources de données ─────────────────────────────────────────────────────
    st.markdown("### Sources de données")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**IPQualityScore**")
        st.markdown(
            "DNS, spam, malware, phishing, géolocalisation, réputation email. "
            "Score de risque 0–100 basé sur des listes noires et du machine learning."
        )
    with c2:
        st.markdown("**VirusTotal**")
        st.markdown(
            "Agrégation de 70+ moteurs antivirus et scanners web (API v3). "
            "Fournit des statistiques par catégorie : malicious, suspicious, harmless, undetected."
        )
    with c3:
        st.markdown("**WHOIS (RFC 3912)**")
        st.markdown(
            "Interrogation directe des serveurs WHOIS via socket TCP port 43. "
            "Résolution TLD → serveur autoritatif via whois.iana.org."
        )

    st.divider()

    # ── Fonctionnalités par sprint ─────────────────────────────────────────────
    st.markdown("### Fonctionnalités par sprint")

    for sprint_name, features in SPRINTS:
        with st.expander(sprint_name):
            for f in features:
                st.markdown(
                    f'<span class="badge badge-done">✓ {f}</span>',
                    unsafe_allow_html=True,
                )

    st.divider()
    st.caption("Projet académique — Data Mining & Cybersecurity · 2025")


render()

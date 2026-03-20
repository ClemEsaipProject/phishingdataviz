import time
import streamlit as st
import pandas as pd
from functions import get_data, build_iq_url, base_url
from database import save_scan

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


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("Bulk URL Scanner")
    st.caption("Analyse de masse via IPQualityScore")

    with st.expander("Format CSV attendu", expanded=False):
        st.markdown(
            "Le fichier doit contenir une colonne **`url`**. "
            "Les autres colonnes sont ignorées."
        )
        st.code("url\nhttps://example.com\nhttps://suspicious-site.xyz", language="text")

    uploaded = st.file_uploader("Importer un fichier CSV", type=["csv"])

    if not uploaded:
        return

    try:
        df_input = pd.read_csv(uploaded)
    except Exception as e:
        st.error(f"Erreur lecture CSV : {e}")
        return

    if "url" not in df_input.columns:
        st.error("Colonne `url` introuvable dans le CSV.")
        return

    urls = df_input["url"].dropna().str.strip().unique().tolist()
    st.info(f"{len(urls)} URL(s) détectée(s).")

    save_to_db = st.checkbox("Sauvegarder dans l'historique", value=True)

    if not st.button("Lancer le scan", type="primary"):
        return

    results = []
    progress    = st.progress(0)
    status_text = st.empty()

    for i, url in enumerate(urls):
        status_text.text(f"Scan {i + 1}/{len(urls)} : {url[:70]}...")
        data = get_data(build_iq_url(base_url, url))

        if "error" in data:
            results.append({
                "url":          url,
                "risk_score":   None,
                "phishing":     None,
                "malware":      None,
                "suspicious":   None,
                "dns_valid":    None,
                "country_code": None,
                "error":        data["error"],
            })
        else:
            results.append({
                "url":          url,
                "risk_score":   data.get("risk_score",  0),
                "phishing":     data.get("phishing",    False),
                "malware":      data.get("malware",     False),
                "suspicious":   data.get("suspicious",  False),
                "dns_valid":    data.get("dns_valid",   False),
                "country_code": data.get("country_code", ""),
                "error":        None,
            })
            if save_to_db:
                save_scan(url, "BulkScan", data)

        progress.progress((i + 1) / len(urls))
        time.sleep(0.3)  # respect rate limits

    status_text.empty()
    progress.empty()

    result_df   = pd.DataFrame(results)
    ok          = result_df[result_df["error"].isna()]
    n_phishing  = int(ok["phishing"].sum())  if not ok.empty else 0
    n_malware   = int(ok["malware"].sum())   if not ok.empty else 0
    n_errors    = int(result_df["error"].notna().sum())
    avg_risk    = round(ok["risk_score"].mean(), 1) if not ok.empty else 0

    st.divider()

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, val, status in [
        (c1, "Total scannés",  len(urls),    ""),
        (c2, "Risk moyen",     avg_risk,
         "danger" if avg_risk >= 75 else ("warn" if avg_risk >= 40 else "ok")),
        (c3, "Phishing",       n_phishing,   "danger" if n_phishing else "ok"),
        (c4, "Malware",        n_malware,    "danger" if n_malware  else "ok"),
        (c5, "Erreurs",        n_errors,     "warn"   if n_errors   else "ok"),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    st.markdown("#### Résultats détaillés")

    display = result_df.rename(columns={
        "url":          "URL",
        "risk_score":   "Risk Score",
        "phishing":     "Phishing",
        "malware":      "Malware",
        "suspicious":   "Suspect",
        "dns_valid":    "DNS OK",
        "country_code": "Pays",
        "error":        "Erreur",
    })

    st.dataframe(display, width="stretch", hide_index=True)

    csv_out = result_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Télécharger les résultats (CSV)",
        data=csv_out,
        file_name="bulk_scan_results.csv",
        mime="text/csv",
    )


render()

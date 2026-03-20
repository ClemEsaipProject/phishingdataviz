import streamlit as st
import plotly.graph_objects as go
from functions import get_data, build_iq_url, base_email, check_email_auth

DARK = "plotly_dark"

CSS = """
<style>
.kpi-card {
    background: #1a1d2e; border: 1px solid #2a2d3e;
    border-radius: 12px; padding: 18px 20px; text-align: center;
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


def fraud_gauge(score: int) -> go.Figure:
    color = "#ff4b4b" if score >= 75 else ("#ffa500" if score >= 50 else "#00cc88")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge=dict(
            axis=dict(range=[0, 100], tickfont=dict(color="#8b95a5")),
            bar=dict(color=color),
            bgcolor="#1a1d2e",
            steps=[
                dict(range=[0, 50],  color="#1a2e1a"),
                dict(range=[50, 75], color="#2e2a1a"),
                dict(range=[75, 100], color="#2e1a1a"),
            ],
            threshold=dict(
                line=dict(color=color, width=3),
                thickness=0.8,
                value=score
            )
        ),
        title=dict(text="Fraud Score", font=dict(color="#e0e0e0"))
    ))
    fig.update_layout(
        template=DARK,
        paper_bgcolor="#0e1117",
        height=300,
        margin=dict(t=60, b=20, l=40, r=40)
    )
    return fig


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("Email Scanner")
    st.caption("Analyse de reputation email via IPQualityScore")

    with st.form("email_form"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            email_input = st.text_input("Adresse email", placeholder="user@example.com")
        with col_btn:
            st.write("")
            submitted = st.form_submit_button("Analyser", use_container_width=True)

    if not submitted or not email_input:
        return

    with st.spinner("Analyse en cours..."):
        data = get_data(build_iq_url(base_email, email_input))

    if "error" in data:
        st.error(data["error"])
        return

    fraud_score  = data.get("fraud_score",    0)
    deliverable  = data.get("deliverability", "N/A")
    spam_trap    = data.get("spam_trap_score", "N/A")
    disposable   = data.get("disposable",     False)
    leaked       = data.get("leaked",         False)
    domain_age   = data.get("domain_age",     {}).get("human", "N/A")
    domain       = data.get("sanitized_email", email_input).split("@")[-1]

    fs_status    = "danger" if fraud_score >= 75 else ("warn" if fraud_score >= 50 else "ok")
    disp_status  = "danger" if disposable else "ok"
    leak_status  = "danger" if leaked    else "ok"

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, val, status in [
        (c1, "Fraud Score",   fraud_score,                    fs_status),
        (c2, "Deliverable",   deliverable,                    ""),
        (c3, "Disposable",    "Oui" if disposable else "Non", disp_status),
        (c4, "Leaked",        "Oui" if leaked     else "Non", leak_status),
        (c5, "Domain Age",    domain_age,                     ""),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    left, right = st.columns([1, 1])
    with left:
        st.plotly_chart(fraud_gauge(fraud_score), width="stretch")
    with right:
        st.markdown("#### Details du domaine")
        st.markdown(f"**Domaine :** `{domain}`")
        st.markdown(f"**Spam Trap Score :** `{spam_trap}`")
        st.markdown(f"**Statut :** {'Risque eleve' if fraud_score >= 75 else 'Acceptable'}")

    # ── SPF / DKIM / DMARC (Tier 1) ────────────────────────────────────────
    st.divider()
    st.markdown("#### Authentification email (SPF · DKIM · DMARC)")
    st.caption("Vérifie les enregistrements DNS d'authentification du domaine expéditeur.")

    with st.spinner("Vérification SPF / DKIM / DMARC…"):
        auth = check_email_auth(domain)

    if "error" in auth:
        st.warning(auth["error"])
    else:
        score_auth = auth["auth_score"]
        risk_auth  = auth["risk"]
        auth_status = "ok" if risk_auth == "ok" else ("warn" if risk_auth == "warn" else "danger")

        ca1, ca2, ca3, ca4 = st.columns(4)
        with ca1:
            st.markdown(
                kpi("Score auth", f"{score_auth}/3", auth_status),
                unsafe_allow_html=True,
            )

        # SPF
        spf_val = auth.get("spf", "absent")
        spf_ok  = spf_val not in ("absent", None)
        with ca2:
            st.markdown(
                kpi("SPF", "✓ Présent" if spf_ok else "✗ Absent",
                    "ok" if spf_ok else "danger"),
                unsafe_allow_html=True,
            )

        # DMARC
        dmarc_val = auth.get("dmarc", "absent")
        dmarc_ok  = dmarc_val not in ("absent", None)
        with ca3:
            st.markdown(
                kpi("DMARC", "✓ Présent" if dmarc_ok else "✗ Absent",
                    "ok" if dmarc_ok else "danger"),
                unsafe_allow_html=True,
            )

        # DKIM
        dkim_val = auth.get("dkim", "absent")
        dkim_ok  = dkim_val != "absent"
        with ca4:
            st.markdown(
                kpi("DKIM", "✓ Présent" if dkim_ok else "✗ Absent",
                    "ok" if dkim_ok else "warn"),
                unsafe_allow_html=True,
            )

        if risk_auth == "danger":
            st.error(
                "**Aucun mécanisme d'authentification détecté.** "
                "Ce domaine est vulnérable à l'usurpation d'identité (spoofing)."
            )
        elif risk_auth == "warn":
            st.warning("Authentification partielle — certains mécanismes sont manquants.")
        else:
            st.success("SPF, DKIM et DMARC sont configurés — authentification complète.")

        with st.expander("Détails des enregistrements DNS"):
            st.markdown(f"**SPF :** `{spf_val}`")
            st.markdown(f"**DMARC :** `{dmarc_val}`")
            st.markdown(f"**DKIM :** `{dkim_val}`")


render()

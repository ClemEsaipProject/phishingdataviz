import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from functions import check_ssl, get_redirect_chain

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


def ssl_gauge(days_left: int) -> go.Figure:
    max_days  = 365
    clamped   = max(min(days_left, max_days), 0)
    color     = "#ff4b4b" if days_left < 15 \
        else ("#ffa500" if days_left < 60 else "#00cc88")

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=clamped,
        number=dict(suffix=" jours", font=dict(color=color, size=28)),
        gauge=dict(
            axis=dict(range=[0, max_days],
                      tickfont=dict(color="#8b95a5")),
            bar=dict(color=color),
            bgcolor="#1a1d2e",
            steps=[
                dict(range=[0,  15],  color="#2e1a1a"),
                dict(range=[15, 60],  color="#2e2a1a"),
                dict(range=[60, 365], color="#1a2e1a"),
            ],
            threshold=dict(
                line=dict(color=color, width=3),
                thickness=0.8, value=clamped
            )
        ),
        title=dict(text="Jours avant expiration",
                   font=dict(color="#e0e0e0"))
    ))
    fig.update_layout(
        paper_bgcolor="#0e1117",
        height=300,
        margin=dict(t=60, b=20, l=40, r=40)
    )
    return fig


def redirect_chain_chart(chain: list[dict]) -> go.Figure:
    risk_colors = {
        "ok":     "#00cc88",
        "warn":   "#ffa500",
        "danger": "#ff4b4b"
    }

    nodes_x, nodes_y, node_texts, node_colors = [], [], [], []
    edge_x,  edge_y  = [], []

    for i, hop in enumerate(chain):
        nodes_x.append(i)
        nodes_y.append(0)
        label   = (
            f"Hop {hop['hop']}<br>"
            f"{hop['domain']}<br>"
            f"HTTP {hop['status']}"
        )
        if hop["anomaly"]:
            label += f"<br><b>{hop['anomaly']}</b>"
        node_texts.append(label)
        node_colors.append(risk_colors.get(hop["risk"], "#8b95a5"))

        if i > 0:
            edge_x += [i - 1, i, None]
            edge_y += [0, 0, None]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(color="#2a2d3e", width=2),
        hoverinfo="none"
    ))

    fig.add_trace(go.Scatter(
        x=nodes_x, y=nodes_y,
        mode="markers+text",
        marker=dict(size=30, color=node_colors,
                    line=dict(color="#0e1117", width=2)),
        text=[str(h["hop"]) for h in chain],
        textfont=dict(color="#0e1117", size=12),
        textposition="middle center",
        hovertext=node_texts,
        hoverinfo="text"
    ))

    fig.update_layout(
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
        title=dict(text="Chaine de redirections",
                   font=dict(color="#e0e0e0"), x=0.5),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        showlegend=False,
        margin=dict(t=60, b=20, l=20, r=20),
        height=280
    )
    return fig


def render_ssl(url_input: str):
    with st.spinner("Analyse du certificat SSL..."):
        ssl_data = check_ssl(url_input)

    if not ssl_data.get("valid"):
        st.error(f"SSL invalide : {ssl_data.get('error', 'Erreur inconnue')}")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(kpi("Certificat", "Invalide", "danger"),
                        unsafe_allow_html=True)
        return

    days      = ssl_data["days_left"]
    day_status = ("danger" if days < 15
                  else ("warn" if days < 60 else "ok"))
    ss_status  = "danger" if ssl_data["self_signed"] else "ok"
    exp_status = "danger" if ssl_data["expired"]     else "ok"

    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, status in [
        (c1, "Statut",          "Valide",                           "ok"),
        (c2, "Expire dans",     f"{days}j",                         day_status),
        (c3, "Auto-signe",      "Oui" if ssl_data["self_signed"]
                                else "Non",                          ss_status),
        (c4, "Expire",          "Oui" if ssl_data["expired"]
                                else "Non",                          exp_status),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    left, right = st.columns([1, 1])

    with left:
        st.plotly_chart(ssl_gauge(days), width="stretch", key="ssl_gauge")

    with right:
        st.markdown("#### Details du certificat")
        details = {
            "Hostname":        ssl_data["hostname"],
            "Subject CN":      ssl_data["subject_cn"],
            "Emetteur":        ssl_data["issuer_org"],
            "Emetteur CN":     ssl_data["issuer_cn"],
            "Date emission":   ssl_data["issued_on"],
            "Date expiration": ssl_data["expires_on"],
        }
        for k, v in details.items():
            st.markdown(f"**{k} :** `{v}`")

        if ssl_data["san"]:
            st.markdown(f"**SAN :** `{', '.join(ssl_data['san'])}`")


def render_redirect(url_input: str):
    with st.spinner("Suivi des redirections..."):
        chain = get_redirect_chain(url_input)

    if not chain:
        st.info("Aucune redirection detectee.")
        return

    dangers = [h for h in chain if h["risk"] == "danger"]
    warns   = [h for h in chain if h["risk"] == "warn"]

    c1, c2, c3 = st.columns(3)
    for col, label, val, status in [
        (c1, "Nombre de sauts",   len(chain),    "warn" if len(chain) > 3 else "ok"),
        (c2, "Anomalies critiques", len(dangers), "danger" if dangers else "ok"),
        (c3, "Avertissements",    len(warns),     "warn"   if warns   else "ok"),
    ]:
        with col:
            st.markdown(kpi(label, val, status), unsafe_allow_html=True)

    st.divider()

    if len(chain) > 1:
        st.plotly_chart(
            redirect_chain_chart(chain),
            width="stretch",
            key="redirect_chain"
        )

    st.markdown("#### Detail des sauts")
    for hop in chain:
        risk_icon = (
            ":red_circle:"    if hop["risk"] == "danger"
            else (":orange_circle:" if hop["risk"] == "warn"
                  else ":green_circle:")
        )
        with st.expander(
            f"{risk_icon} Hop {hop['hop']} - {hop['domain']} "
            f"(HTTP {hop['status']})"
        ):
            st.markdown(f"**URL :** `{hop['url']}`")
            st.markdown(f"**HTTPS :** {'Oui' if hop['is_https'] else 'Non'}")
            if hop["anomaly"]:
                st.warning(f"Anomalie : {hop['anomaly']}")
            else:
                st.success("Aucune anomalie detectee")


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("Analyse Avancee")
    st.caption("Certificat SSL et chaine de redirections")

    with st.form("advanced_form"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            url_input = st.text_input(
                "URL cible", placeholder="https://example.com"
            )
        with col_btn:
            st.write("")
            submitted = st.form_submit_button(
                "Analyser", use_container_width=True
            )

    if not submitted or not url_input:
        return

    if not url_input.startswith("http"):
        st.warning("L'URL doit commencer par http:// ou https://")
        return

    tab_ssl, tab_redirect = st.tabs(["Certificat SSL", "Chaine de redirections"])

    with tab_ssl:
        render_ssl(url_input)

    with tab_redirect:
        render_redirect(url_input)


render()

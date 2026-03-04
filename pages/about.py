import streamlit as st

def render():
    st.title("A propos")
    st.caption("PhishingDataViz - URL & Email Threat Intelligence Dashboard")

    st.divider()

    st.markdown("#### Interpretation des scores de risque")

    col1, col2 = st.columns(2)
    with col1:
        st.error("Score >= 100 + phishing/malware : activite malveillante confirmee (24-48h)")
        st.warning("Score >= 90 : risque eleve, forte confiance en la malveillance")
    with col2:
        st.warning("Score >= 75 : suspect, modeles associes a des liens malveillants")
        st.info("suspicious: true : domaine potentiellement abusif")

    st.divider()
    st.markdown("#### Sources de donnees")
    st.markdown("""
- **IPQualityScore** : DNS, spam, malware, phishing, geolocation, email reputation
- **VirusTotal** : agregation de 70+ moteurs antivirus et scanners web (API v3)
    """)
    st.divider()
    st.caption("Projet academique - Data Mining & Cybersecurity")


render()

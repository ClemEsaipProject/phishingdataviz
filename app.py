import streamlit as st

st.set_page_config(
    page_title="PhishingDataViz",
    page_icon=":material/security:",
    layout="wide",
    initial_sidebar_state="expanded"
)

pg = st.navigation({
    "Scanner": [
        st.Page("pages/url_scanner.py",   title="URL Scanner",   icon=":material/link:"),
        st.Page("pages/email_scanner.py", title="Email Scanner", icon=":material/email:"),
        st.Page("pages/virustotal.py",    title="VirusTotal",    icon=":material/shield:"),
        st.Page("pages/advanced_scan.py", title="Analyse Avancee",  icon=":material/security:")
    ],
     "Analyse": [
        st.Page("pages/history.py", title="Historique", icon=":material/history:"),
    ],
    "Info": [
        st.Page("pages/about.py", title="About", icon=":material/info:"),
    ]
})

pg.run()

"""
pages/phishguard.py — PhishGuard Control Panel

Permet de démarrer / arrêter le serveur Flask (api.py) directement
depuis l'interface Streamlit, sans passer par un terminal.
Les logs du serveur sont affichés en temps réel avec coloration intelligente.
"""

import os
import queue
import sys
import socket
import threading
import subprocess
from datetime import datetime
from pathlib import Path

import streamlit as st

# ── Constantes ────────────────────────────────────────────────────────────────
API_PORT  = 5050
API_SCRIPT = str(Path(__file__).parent.parent / "api.py")
MAX_LOGS  = 300   # buffer glissant
_log_queue: queue.Queue = queue.Queue()   # thread-safe : reader thread → Streamlit thread
_server_process: subprocess.Popen | None = None  # référence module-level (survit aux rechargements de session)

CSS = """
<style>
.kpi-card {
    background: #1a1d2e; border: 1px solid #2a2d3e;
    border-radius: 12px; padding: 18px 20px; text-align: center;
}
.kpi-label { color: #8b95a5; font-size: 13px; margin-bottom: 6px; }
.kpi-value { color: #00d4ff; font-size: 28px; font-weight: 700; }
.kpi-value.ok     { color: #00cc88; }
.kpi-value.danger { color: #ff4b4b; }

.log-line        { font-family: monospace; font-size: 12px;
                   padding: 1px 0; line-height: 1.5; }
.log-info        { color: #00d4ff; }
.log-warning     { color: #ffa500; }
.log-error       { color: #ff4b4b; font-weight: bold; }
.log-success     { color: #00cc88; }
.log-default     { color: #c0c8d8; }

.log-box {
    background: #0a0c12;
    border: 1px solid #2a2d3e;
    border-radius: 8px;
    padding: 12px 16px;
    height: 420px;
    overflow-y: auto;
    font-family: monospace;
}
</style>
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_server_running() -> bool:
    """Vérifie si le port 5050 répond."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", API_PORT)) == 0


def _init_state():
    if "api_process" not in st.session_state:
        st.session_state.api_process = None
    if "api_logs" not in st.session_state:
        st.session_state.api_logs = []
    if "api_requests" not in st.session_state:
        st.session_state.api_requests = 0


def _push_log(line: str):
    """Ajoute une ligne au buffer en conservant MAX_LOGS lignes max."""
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.api_logs.append(f"[{ts}]  {line}")
    if len(st.session_state.api_logs) > MAX_LOGS:
        st.session_state.api_logs = st.session_state.api_logs[-MAX_LOGS:]
    # Compteur de requêtes (lignes contenant "Analyze request")
    if "Analyze request" in line or "analyze" in line.lower():
        st.session_state.api_requests += 1


def _reader_thread(process):
    """Thread daemon : lit stdout et enfile les lignes dans _log_queue (thread-safe)."""
    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if line:
            _log_queue.put(line)
    _log_queue.put("— Processus terminé —")


def start_server():
    global _server_process
    if is_server_running():
        _push_log("INFO  Serveur déjà actif sur le port 5050.")
        return

    _push_log("INFO  Démarrage de PhishGuard API…")
    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            [sys.executable, "-u", API_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(Path(API_SCRIPT).parent),
            env=env,
            bufsize=1,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        _server_process = proc
        st.session_state.api_process = proc
        t = threading.Thread(target=_reader_thread, args=(proc,), daemon=True)
        t.start()
        _push_log(f"INFO  PID {proc.pid} — en attente de connexions sur :5050")
    except Exception as e:
        _push_log(f"ERROR {e}")


def stop_server():
    global _server_process
    # Fallback sur la variable module-level si la session a été rechargée
    proc = st.session_state.get("api_process") or _server_process
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
        _push_log("INFO  Serveur arrêté proprement.")
    st.session_state.api_process = None
    _server_process = None


def _filter_logs(logs: list[str], filter_level: str) -> list[str]:
    if filter_level == "Erreurs":
        return [l for l in logs if any(k in l.lower() for k in ("error", "warn", "exception"))]
    if filter_level == "Requêtes":
        return [l for l in logs if any(k in l.lower() for k in ("analyze", "get", "post", "result"))]
    return logs


# ── Fragment auto-refresh (toutes les 2 s) ────────────────────────────────────

@st.fragment(run_every=2)
def _live_panel():
    # Draine la queue dans session_state (exécuté sur le thread Streamlit)
    while not _log_queue.empty():
        _push_log(_log_queue.get_nowait())

    running = is_server_running()

    # KPIs
    c1, c2, c3 = st.columns(3)
    with c1:
        status_val = "EN LIGNE" if running else "HORS LIGNE"
        status_cls = "ok" if running else "danger"
        st.markdown(
            f'<div class="kpi-card">'
            f'<div class="kpi-label">Statut API</div>'
            f'<div class="kpi-value {status_cls}">{status_val}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="kpi-card">'
            f'<div class="kpi-label">Port</div>'
            f'<div class="kpi-value">{API_PORT}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with c3:
        req_count = st.session_state.get("api_requests", 0)
        st.markdown(
            f'<div class="kpi-card">'
            f'<div class="kpi-label">Requêtes analysées</div>'
            f'<div class="kpi-value">{req_count}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # Contrôles + filtre log sur la même ligne
    col_start, col_stop, col_clear, col_filter = st.columns([1, 1, 1, 2])

    with col_start:
        if st.button("▶ Démarrer", disabled=running,
                     use_container_width=True, type="primary"):
            start_server()

    with col_stop:
        if st.button("⏹ Arrêter", disabled=not running,
                     use_container_width=True):
            stop_server()

    with col_clear:
        if st.button("🗑 Vider logs", use_container_width=True):
            st.session_state.api_logs = []
            st.session_state.api_requests = 0

    with col_filter:
        filter_level = st.selectbox(
            "Filtre",
            ["Tout", "Erreurs", "Requêtes"],
            label_visibility="collapsed",
        )

    # Fenêtre de logs
    logs = st.session_state.get("api_logs", [])
    filtered = _filter_logs(logs, filter_level)
    with st.container(height=420, border=False):
        if filtered:
            st.code("\n".join(filtered[-150:]), language=None)
        else:
            st.caption("Aucune entrée.")


# ── Rendu principal ───────────────────────────────────────────────────────────

def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("PhishGuard — Serveur API")
    st.caption(
        "Contrôle du backend Flask utilisé par l'extension navigateur. "
        "Démarrez le serveur avant d'activer l'extension."
    )

    _init_state()

    with st.expander("Installation de l'extension Chrome", expanded=False):
        st.markdown("""
1. Ouvrir `chrome://extensions`
2. Activer le **mode développeur** (en haut à droite)
3. Cliquer **"Charger l'extension non empaquetée"**
4. Sélectionner le dossier `extension/`
5. Démarrer le serveur ci-dessous puis recharger la page à analyser
        """)

    _live_panel()


render()

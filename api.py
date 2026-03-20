"""
api.py - PhishGuard Flask API

Backend local pour l'extension navigateur PhishGuard.
Expose /api/analyze (POST) et /api/health (GET).

Lancement :
    python api.py
    # ou
    flask --app api run --port 5050
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from functions import (
    lexical_analysis,
    detect_typosquatting,
    detect_reserved_namespace,
    get_data,
    build_iq_url,
    base_url,
)
from scorer import compute_global_score
from logger import get_logger

log = get_logger("phishguard-api")

app = Flask(__name__)

# Autorise les appels depuis les extensions Chrome et Firefox
CORS(app, resources={r"/api/*": {"origins": [
    "chrome-extension://*",
    "moz-extension://*",
    "http://localhost:*",
    "http://127.0.0.1:*",
]}})

# Mapping score → niveau (aligné avec scorer.py)
_THRESHOLDS = [(75, "CRITICAL"), (50, "HIGH"), (30, "MEDIUM"), (10, "LOW")]


def _score_to_level(score: int) -> str:
    return next((lvl for thr, lvl in _THRESHOLDS if score >= thr), "SAFE")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "PhishGuard API v1"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True)
    if not body or not body.get("url"):
        return jsonify({"error": "URL manquante"}), 400

    url = body["url"].strip()
    log.info(f"Analyze request : {url[:80]}")

    # ── Couche 1 : analyse locale (aucun appel API, quota 0) ──────────────────
    lex       = lexical_analysis(url)
    typos     = detect_typosquatting(url)
    namespace = detect_reserved_namespace(url)

    _empty_iq = {"risk_score": 0, "phishing": False, "malware": False}
    local     = compute_global_score(_empty_iq, lex["score"], typos, namespace=namespace)

    # Collecte des flags lisibles pour le tooltip
    flags: list[str] = []
    if namespace["flagged"]:
        flags.append(f"Namespace réservé : .{namespace['tld']} ({namespace['category_label']})")
    for t in typos:
        flags.append(f"Typosquatting : {t['detected']} ~ {t['brand']} (dist. {t['distance']})")
    if lex["has_ip"]:
        flags.append("IP directe dans l'URL")
    if not lex["has_https"]:
        flags.append("Pas de HTTPS")
    if lex["keywords_hit"]:
        flags.append(f"Mots suspects : {', '.join(lex['keywords_hit'])}")

    # ── Couche 2 : appel IPQualityScore si score local >= 30 ──────────────────
    # Stratégie quota-aware : on ne consomme l'API que si la couche locale
    # a déjà détecté un signal suspect.
    iq_data = _empty_iq
    if local["global_score"] >= 30:
        iq_raw = get_data(build_iq_url(base_url, url))
        if "error" not in iq_raw:
            iq_data = iq_raw
            if iq_data.get("phishing"):
                flags.append("Phishing confirmé — IPQualityScore")
            if iq_data.get("malware"):
                flags.append("Malware confirmé — IPQualityScore")

    # ── Score final fusionné ──────────────────────────────────────────────────
    final = compute_global_score(iq_data, lex["score"], typos, namespace=namespace)
    level = _score_to_level(final["global_score"])

    log.info(f"Result : {url[:60]} → {level} ({final['global_score']}/100)")

    return jsonify({
        "url":        url,
        "risk_score": final["global_score"],
        "risk_level": level,
        "flags":      flags,
        "details": {
            "iq":        final["iq_component"],
            "lexical":   final["lex_component"],
            "typo":      final["typo_component"],
            "namespace": final["ns_component"],
        },
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  PhishGuard API — http://127.0.0.1:5050")
    print("  /api/health  · /api/analyze")
    print("=" * 50)
    app.run(host="127.0.0.1", port=5050, debug=False)

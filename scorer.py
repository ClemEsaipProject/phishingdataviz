"""
scorer.py - Score Global fusionné (Sprint 5 + countermeasure namespace)

Signaux combinés :
  - IPQualityScore risk_score
  - Analyse lexicale
  - Typosquatting (Levenshtein)
  - VirusTotal détections (optionnel)
  - Reserved Namespace (bonus malus, surcharge forcée si danger)
"""

# Bonus de score selon le risque du namespace détecté
_NAMESPACE_BONUS = {"danger": 40, "warn": 20, "ok": 0}


def compute_global_score(
    iq_data:    dict,
    lex_score:  int,
    typos:      list,
    vt_stats:   dict | None = None,
    namespace:  dict | None = None,
) -> dict:
    """
    Calcule un score global fusionné.

    Pondérations sans VT : IQ 55%, Lexical 30%, Typo 15%
    Pondérations avec VT : IQ 40%, Lexical 20%, VT 25%, Typo 15%

    Surcharge forcée :
      - phishing ou malware confirmé         → score >= 75
      - namespace réservé catégorie danger   → score >= 80
      - namespace réservé catégorie warn     → score >= 50
    """
    iq_score = iq_data.get("risk_score", 0)
    phishing = iq_data.get("phishing",   False)
    malware  = iq_data.get("malware",    False)

    # Typosquatting : 25 pts par correspondance, plafonné à 50
    typo_pts = min(len(typos) * 25, 50)

    # Namespace réservé : malus additionnel brut avant pondération
    ns_risk  = namespace.get("risk", "ok") if namespace and namespace.get("flagged") else "ok"
    ns_bonus = _NAMESPACE_BONUS[ns_risk]

    if vt_stats:
        total_vt   = sum(vt_stats.values())
        malicious  = vt_stats.get("malicious",  0)
        suspicious = vt_stats.get("suspicious", 0)
        vt_pts = (malicious + suspicious * 0.5) / total_vt * 100 if total_vt > 0 else 0

        raw = (
            iq_score  * 0.38
            + lex_score * 0.19
            + vt_pts    * 0.23
            + typo_pts  * 0.12
            + ns_bonus  * 0.08
        )
    else:
        vt_pts = None
        raw = (
            iq_score  * 0.50
            + lex_score * 0.27
            + typo_pts  * 0.13
            + ns_bonus  * 0.10
        )

    score = min(round(raw), 100)

    # Planchers forcés
    if phishing or malware:
        score = max(score, 75)
    if ns_risk == "danger":
        score = max(score, 80)
    elif ns_risk == "warn":
        score = max(score, 50)

    level = "danger" if score >= 75 else ("warn" if score >= 40 else "ok")
    label = "Malveillant" if score >= 75 else ("Suspect" if score >= 40 else "Propre")

    return {
        "global_score":    score,
        "iq_component":    round(iq_score),
        "lex_component":   round(lex_score),
        "vt_component":    round(vt_pts) if vt_pts is not None else None,
        "typo_component":  round(typo_pts),
        "ns_component":    ns_bonus,
        "ns_risk":         ns_risk,
        "has_vt":          vt_stats is not None,
        "level":           level,
        "label":           label,
    }

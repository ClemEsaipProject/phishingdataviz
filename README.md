# PhishingDataViz

Dashboard de threat intelligence pour l'analyse d'URLs et d'emails, développé avec Streamlit.
Projet académique — Data Mining & Cybersecurity.

## Fonctionnalités

| Page | Description |
| --- | --- |
| **URL Scanner** | Analyse via IPQualityScore + Score Global Fusionné + radar de menaces |
| **Email Scanner** | Réputation email, score de fraude, indicateurs spam |
| **VirusTotal** | Résultats agrégés de 70+ moteurs AV (API v3) |
| **Analyse Avancée** | Certificat SSL, chaîne de redirections |
| **Bulk Scanner** | Scan de masse depuis un fichier CSV, export des résultats |
| **Historique** | Timeline des scans, distribution des menaces, carte géographique |
| **About & WHOIS** | Lookup WHOIS, guide d'interprétation, sources de données |

### Score Global Fusionné

Combinaison pondérée de 4 signaux :

- **IPQualityScore** risk_score — 55 % (sans VT) / 40 % (avec VT)
- **Analyse lexicale** — 30 % / 20 %
- **VirusTotal** détections — — / 25 %
- **Typosquatting** Levenshtein — 15 % / 15 %

Surcharge forcée : phishing ou malware confirmé → score plancher à 75.

### Détection de menaces

- Typosquatting : distance de Levenshtein contre 25 marques connues
- Analyse lexicale : 7 facteurs (IP dans l'URL, HTTPS, `@`, sous-domaines, mots suspects, caractères spéciaux, redirections internes)
- SSL : validité, expiration, auto-signé, SAN
- Redirect chain : détection downgrade HTTPS → HTTP et changements de domaine
- WHOIS : résolution TLD via IANA, informations registrar et dates

## Installation

```bash
git clone <repo-url>
cd phishingdataviz
pip install -r requirements.txt
```

Créer un fichier `.env` à la racine :

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key
```

## Lancement

```bash
streamlit run app.py
```

Application disponible sur `http://localhost:8501`.

## Tests

```bash
pytest                          # tous les tests
pytest -v                       # verbose
pytest tests/test_functions.py  # fichier spécifique
pytest -k "TestCheckSSL"        # classe spécifique
```

## Format CSV pour le Bulk Scanner

Le fichier doit contenir une colonne `url` :

```csv
url
https://example.com
https://suspicious-site.xyz
```

## Architecture

```text
app.py              # point d'entrée, navigation multi-pages
functions.py        # moteur : IPQualityScore, VirusTotal, typosquatting,
                    #          analyse lexicale, SSL, redirections, WHOIS
scorer.py           # Score Global Fusionné (Sprint 5)
database.py         # persistance SQLite (scans.db)
logger.py           # logs rotatifs (logs/phishingdataviz.log)
pages/              # pages Streamlit
tests/              # suite pytest
```

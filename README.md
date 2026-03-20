# PhishingDataViz — URL & Email Threat Intelligence Dashboard

> Projet académique · Data Mining & Cybersecurity · 2025
> Développé avec Python 3.12 · Streamlit · Flask · SQLite

---

## Table des matières

1. [Présentation](#1-présentation)
2. [Architecture système](#2-architecture-système)
3. [Modules d'analyse](#3-modules-danalyse)
4. [Score Global Fusionné](#4-score-global-fusionné)
5. [PhishGuard — Extension navigateur](#5-phishguard--extension-navigateur)
6. [Installation](#6-installation)
7. [Lancement](#7-lancement)
8. [Tests](#8-tests)
9. [Structure du projet](#9-structure-du-projet)
10. [Sprints](#10-sprints)
11. [Références](#11-références)

---

## 1. Présentation

PhishingDataViz est une plateforme d'analyse de menaces web combinant plusieurs couches de détection pour évaluer le niveau de risque d'URLs et d'adresses email. Le projet intègre des API de threat intelligence externes (IPQualityScore, VirusTotal) avec des méthodes d'analyse locale (heuristique lexicale, distance de Levenshtein, inspection TLS, détection de namespace réservé) pour produire un **Score Global Fusionné** représentant la dangerosité d'une ressource.

Le projet se prolonge en une **extension navigateur active** (PhishGuard) capable de colorier en temps réel les liens suspects sur n'importe quelle page web, email Gmail ou Outlook Web, sans interaction utilisateur.

### Cas d'usage couverts

- Analyse individuelle d'URL ou d'email
- Scan de masse depuis un fichier CSV
- Analyse avancée : certificat SSL, chaîne de redirections HTTP
- Lookup WHOIS via socket TCP (sans dépendance externe)
- Détection de la variante phishing exploitant les espaces de noms réservés (`.arpa`, RFC 2606, extensions de fichiers, namespace collision AD)
- Coloration contextuelle des liens dans le navigateur (extension Chrome/Firefox)

---

## 2. Architecture système

```text
┌──────────────────────────────────────────────────────────────┐
│                 NAVIGATEUR / GMAIL / OUTLOOK                 │
│                                                              │
│   content.js ──── scanne tous les <a>                        │
│        │                                                     │
│        │  chrome.runtime.sendMessage                         │
│        ▼                                                     │
│   background.js (Service Worker MV3)                         │
│        │                                                     │
│        │  fetch POST /api/analyze                            │
└────────┼─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│   Flask API  :5050      │  api.py
│   /api/analyze  (POST)  │
│   /api/health   (GET)   │
└────────────┬────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
functions.py       scorer.py
  · IQ API         · Score Global
  · VT API           Fusionné
  · Lexical
  · Typosquatting        ▼
  · Namespace      database.py
  · SSL / WHOIS    · SQLite
  · Redirections   · Historique
```

```text
┌──────────────────────────────────────────────────────────────┐
│                 DASHBOARD STREAMLIT  :8501                   │
│                                                              │
│  URL Scanner · Email Scanner · VirusTotal · Analyse Avancée  │
│  Bulk Scanner · Historique · About & WHOIS                   │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Modules d'analyse

### 3.1 IPQualityScore (API externe)

Fournit un score de risque 0–100 avec les indicateurs : `phishing`, `malware`, `spamming`, `suspicious`, `dns_valid`, `domain_rank`, `country_code`. Utilisé dans URL Scanner, Email Scanner et Bulk Scanner.

### 3.2 VirusTotal (API v3)

Agrégation des résultats de 70+ moteurs antivirus. Le polling implémente un mécanisme de retry (8 tentatives, intervalle 5 s) avec une session TLS unique par requête.

### 3.3 Analyse lexicale

Scoring heuristique local en 7 facteurs, sans appel API :

| Facteur | Points max |
| --- | --- |
| IP directe dans le hostname | 30 |
| Caractère `@` dans l'URL | 20 |
| Absence de HTTPS | 15 |
| Longueur de l'URL | 15 |
| Nombre de sous-domaines | 10 |
| Mots-clés suspects (18 termes) | 20 |
| Caractères spéciaux (`-`, `_`, `~`, `%`) | 10 |

### 3.4 Typosquatting (Levenshtein)

Distance de Levenshtein (bibliothèque `jellyfish`) entre le domaine cible et 25 marques de référence. Distance 1 → risque élevé, distance 2 → risque moyen.

### 3.5 Certificat SSL

Connexion socket directe sur le port 443 (`ssl.create_default_context`). Vérifie la validité, l'expiration, l'auto-signature et extrait les SAN. Supporte IPv4 et IPv6 via `socket.getaddrinfo`.

### 3.6 Chaîne de redirections

Suivi hop-by-hop des redirections HTTP (301/302/303/307/308) avec détection de :

- Downgrade `HTTPS → HTTP`
- Changement de domaine inter-sauts
- Boucles de redirection

### 3.7 WHOIS (socket TCP raw)

Résolution en deux passes : IANA (`whois.iana.org:43`) pour obtenir le serveur autoritatif du TLD, puis requête sur ce serveur. Extraction des champs `registrar`, `creation_date`, `expiration_date`, `name_servers`, `status` par analyse ligne-à-ligne. Aucune dépendance externe.

### 3.8 Reserved Namespace Detection

Contre-mesure contre les campagnes de phishing exploitant les espaces de noms réservés (2024–2025). Quatre catégories de TLDs à risque :

| Catégorie | Exemples | Risque |
| --- | --- | --- |
| Infrastructure DNS | `.arpa` | CRITICAL |
| RFC 2606 (IETF) | `.test` `.example` `.invalid` `.localhost` | CRITICAL |
| Extension de fichier | `.zip` `.mov` `.exe` `.bat` | CRITICAL |
| Namespace privé (collision AD) | `.corp` `.internal` `.home` `.lan` | HIGH |

---

## 4. Score Global Fusionné

Le score global combine les signaux de manière pondérée selon la disponibilité des données VirusTotal :

### Sans données VirusTotal

| Signal | Poids |
| --- | --- |
| IPQualityScore `risk_score` | 50 % |
| Analyse lexicale | 27 % |
| Typosquatting | 13 % |
| Reserved Namespace | 10 % |

### Avec données VirusTotal

| Signal | Poids |
| --- | --- |
| IPQualityScore `risk_score` | 38 % |
| VirusTotal (malicious + suspicious × 0.5) | 23 % |
| Analyse lexicale | 19 % |
| Typosquatting | 12 % |
| Reserved Namespace | 8 % |

### Planchers forcés

| Condition | Score minimum |
| --- | --- |
| `phishing = true` ou `malware = true` (IQ) | 75 |
| TLD réservé catégorie `danger` | 80 |
| TLD réservé catégorie `warn` | 50 |

### Niveaux de risque

| Score | Niveau | Couleur |
| --- | --- | --- |
| ≥ 75 | Malveillant | Rouge |
| 40 – 74 | Suspect | Orange |
| < 40 | Propre | Vert |

---

## 5. PhishGuard — Extension navigateur

### Principe

L'extension injecte un content script sur chaque page visitée. Ce script extrait les URLs de tous les éléments `<a>`, les envoie à l'API Flask locale et applique un style visuel selon le niveau de risque retourné.

### Stratégie quota-aware

L'API backend opère en deux passes pour minimiser la consommation de quotas externes :

1. **Passe locale** (0 appel API) : lexicale + namespace + typosquatting → score immédiat
2. **Passe externe** (IQ API) : déclenchée uniquement si le score local ≥ 30

Sur une page contenant 50 liens, seuls les 3 à 5 qui déclenchent un signal local consomment un appel API.

### Niveaux de coloration

| Niveau | Seuil | Style |
| --- | --- | --- |
| CRITICAL | ≥ 75 | Rouge vif · gras · notification système |
| HIGH | ≥ 50 | Orange · gras |
| MEDIUM | ≥ 30 | Jaune · badge inline |
| LOW | ≥ 10 | Bleu clair · badge inline |
| SAFE | < 10 | Lien bleu par défaut (aucune modification) |

### Compatibilité

| Plateforme | Sélecteur CSS ciblé |
| --- | --- |
| Pages web standard | `a[href]` |
| Gmail | `.a3s.aiL a`, `.ii.gt a` |
| Outlook Web | `.ReadMsgBody a`, `.ExternalClass a` |

Le `MutationObserver` (debounce 600 ms) assure le re-scan automatique sur les SPA et les clients mail qui injectent leur contenu dynamiquement.

---

## 6. Installation

### Prérequis

- Python 3.12+
- pip
- Navigateur Chrome ou Firefox (pour l'extension)

### Dépendances Python

```bash
git clone <repo-url>
cd phishingdataviz
pip install -r requirements.txt
```

### Variables d'environnement

Créer un fichier `.env` à la racine :

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key
```

### Extension navigateur (Chrome)

1. Ouvrir `chrome://extensions`
2. Activer le **mode développeur**
3. Cliquer sur **"Charger l'extension non empaquetée"**
4. Sélectionner le dossier `extension/`

---

## 7. Lancement

### Dashboard Streamlit

```bash
streamlit run app.py
# → http://localhost:8501
```

### API Flask (pour l'extension)

```bash
python api.py
# → http://127.0.0.1:5050
```

Les deux processus sont indépendants et peuvent tourner simultanément.

### Format CSV pour le Bulk Scanner

```csv
url
https://example.com
https://suspicious-site.xyz
```

---

## 8. Tests

```bash
pytest                           # suite complète
pytest -v                        # verbose
pytest tests/test_functions.py   # module ciblé
pytest -k "TestCheckSSL"         # classe ou fonction ciblée
```

La suite couvre : fonctions d'analyse (`test_functions.py`), opérations base de données (`test_database.py`), SSL et redirections (`test_sprint3.py`).

---

## 9. Structure du projet

```text
phishingdataviz/
│
├── app.py                  # Point d'entrée Streamlit (navigation multi-pages)
├── api.py                  # Backend Flask pour l'extension PhishGuard (:5050)
├── functions.py            # Moteur d'analyse : IQ, VT, lexical, typosquatting,
│                           #   SSL, redirections, WHOIS, namespace réservé
├── scorer.py               # Score Global Fusionné (pondération multi-signaux)
├── database.py             # Persistance SQLite — historique des scans
├── logger.py               # Logs rotatifs (logs/phishingdataviz.log)
│
├── pages/
│   ├── url_scanner.py      # Scanner URL + Score Global + onglet Namespace
│   ├── email_scanner.py    # Réputation email
│   ├── virustotal.py       # Agrégation VirusTotal
│   ├── advanced_scan.py    # SSL + chaîne de redirections
│   ├── bulk_scan.py        # Scan de masse CSV
│   ├── history.py          # Historique, timeline, carte
│   └── about.py            # WHOIS lookup + documentation
│
├── extension/
│   ├── manifest.json       # Manifest V3 Chrome/Firefox
│   ├── content.js          # Scanner DOM + coloration contextuelle
│   ├── background.js       # Service Worker + notifications
│   ├── popup.html          # Interface popup
│   ├── popup.js            # Stats page courante + health check
│   └── icons/icon32.png
│
├── tests/
│   ├── conftest.py
│   ├── fixtures.py
│   ├── test_functions.py
│   ├── test_database.py
│   └── test_sprint3.py
│
├── .streamlit/config.toml  # Thème sombre, couleur primaire #00d4ff
├── requirements.txt
└── .env                    # Clés API (non versionné)
```

---

## 10. Sprints

| Sprint | Fonctionnalité | Fichiers principaux |
| --- | --- | --- |
| 1 | Historique des scans · SQLite · timeline | `database.py` · `pages/history.py` |
| 2 | Typosquatting · Analyse lexicale · SSL | `functions.py` |
| 3 | Redirect chain · Géolocalisation · SSL avancé | `functions.py` · `pages/advanced_scan.py` |
| 4 | Bulk Scanner CSV · export résultats | `pages/bulk_scan.py` |
| 5 | Score Global Fusionné | `scorer.py` · `pages/url_scanner.py` |
| 6 | WHOIS lookup · About final · README | `functions.py` · `pages/about.py` |
| 7 | Reserved Namespace Detection · PhishGuard | `functions.py` · `api.py` · `extension/` |

---

## 11. Références

- **RFC 2606** — Reserved Top Level DNS Names. IETF, 1999. [https://datatracker.ietf.org/doc/html/rfc2606](https://datatracker.ietf.org/doc/html/rfc2606)
- **RFC 3172** — Management Guidelines & Operational Requirements for the Address and Routing Parameter Area Domain. IETF, 2001. [https://datatracker.ietf.org/doc/html/rfc3172](https://datatracker.ietf.org/doc/html/rfc3172)
- **ICANN** — New gTLD Program — Reserved Names. [https://www.icann.org/resources/pages/reserved-2013-05-03-en](https://www.icann.org/resources/pages/reserved-2013-05-03-en)
- **Bleeping Computer** — Hackers abuse .arpa DNS and IPv6 to evade phishing defenses, 2025.
- **Kaspersky** — Security risks of the .zip and .mov domains, 2023.
- **Chrome Extensions** — Content Scripts. Chrome Developers. [https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)
- **IPQualityScore** — URL Reputation API. [https://www.ipqualityscore.com/documentation/url-reputation/overview](https://www.ipqualityscore.com/documentation/url-reputation/overview)
- **VirusTotal** — API v3 Reference. [https://docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview)
- **jellyfish** — Python library for doing approximate and phonetic matching of strings. [https://github.com/jamesturk/jellyfish](https://github.com/jamesturk/jellyfish)

---

Projet académique — Data Mining & Cybersecurity · 2025

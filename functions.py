import os
import re
import ssl as ssl_lib
import time
import base64
import jellyfish
import requests
import socket
from urllib.parse import urlparse, quote
from geopy.geocoders import Nominatim
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from dotenv import load_dotenv
from logger import get_logger
import virustotal_python

load_dotenv()
log = get_logger("functions")

KEY_VT = os.getenv("VIRUSTOTAL_API_KEY")
KEY_IQ = os.getenv("IPQUALITYSCORE_API_KEY")

base_url         = f"https://www.ipqualityscore.com/api/json/url/{KEY_IQ}/"
base_email       = f"https://www.ipqualityscore.com/api/json/email/{KEY_IQ}/"
country_code_url = "https://www.ipqualityscore.com/api/json/country/list"
geolocator       = Nominatim(user_agent="phishingdataviz")
VT_BASE          = "https://www.virustotal.com/api/v3"
VT_HEADERS       = {"x-apikey": KEY_VT}


# =============================================================
# TLS Adapter
# =============================================================

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.set_ciphers("DEFAULT")
        ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


def vt_session() -> requests.Session:
    s = requests.Session()
    s.mount("https://", TLSAdapter())
    return s


# =============================================================
# IPQualityScore
# =============================================================

def build_iq_url(base: str, target: str) -> str:
    encoded = quote(target, safe="")
    url = base + encoded
    log.debug(f"IQ URL construit : {url}")
    return url


def _redact_url(url: str) -> str:
    """Masque la clé API dans l'URL avant de loguer."""
    if KEY_IQ and KEY_IQ in url:
        return url.replace(KEY_IQ, "***")
    return url


def get_data(url: str) -> dict:
    log.info(f"GET {_redact_url(url)}")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            log.warning(f"404 sur {url}")
            return {"error": "404 - endpoint introuvable"}
        if resp.status_code == 401:
            log.error("401 - cle API invalide")
            return {"error": "401 - cle API invalide"}
        resp.raise_for_status()
        data = resp.json()
        log.debug(f"Reponse recue : {list(data.keys())}")
        return data
    except requests.exceptions.SSLError as e:
        log.error(f"SSL Error sur {url} : {e}")
        return {"error": f"SSL : {str(e)[:100]}"}
    except requests.exceptions.Timeout:
        log.error(f"Timeout sur {url}")
        return {"error": "Timeout - le serveur ne repond pas"}
    except requests.exceptions.RequestException as e:
        log.error(f"Erreur reseau : {e}")
        return {"error": str(e)[:120]}


def get_coordinates(country_code: str):
    if not country_code or len(country_code) < 2:
        return None, None
    try:
        location = geolocator.geocode(country_code)
        if location:
            log.debug(
                f"Coordonnees pour {country_code} : "
                f"{location.latitude}, {location.longitude}"
            )
            return location.latitude, location.longitude
    except Exception as e:
        log.warning(f"Geocoding echoue pour {country_code} : {e}")
    return None, None


# =============================================================
# VirusTotal API v3
# =============================================================

def scan_url_virustotal(url: str) -> dict:
    log.info(f"VT scan soumis : {url}")
    try:
        with virustotal_python.Virustotal(KEY_VT) as vtotal:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            aid  = resp.data.get("id")
            log.info(f"VT analysis_id obtenu : {aid}")
            return {"analysis_id": aid, "url": url}
    except Exception as e:
        log.error(f"VT scan error : {e}")
        return {"error": str(e)[:120]}


def get_url_report_virustotal(
    scan_result: dict,
    max_retries: int = 8,
    interval:    int = 5
) -> dict:
    url      = scan_result.get("url", "")
    url_id   = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    log.info(f"VT polling pour : {url}")

    try:
        with virustotal_python.Virustotal(KEY_VT) as vtotal:
            for attempt in range(1, max_retries + 1):
                try:
                    resp  = vtotal.request(f"urls/{url_id}")
                    stats = resp.data.get("attributes", {}).get("last_analysis_stats")
                    if stats is not None:
                        log.info(f"VT rapport recu apres {attempt} tentative(s)")
                        return {"data": resp.data}
                    log.debug(f"VT tentative {attempt}/{max_retries} - en attente...")
                    time.sleep(interval)
                except Exception as e:
                    log.error(f"VT polling erreur tentative {attempt} : {e}")
                    if attempt == max_retries:
                        return {"error": str(e)[:120]}
                    time.sleep(interval)
    except Exception as e:
        log.error(f"VT session erreur : {e}")
        return {"error": str(e)[:120]}

    log.warning("VT rapport indisponible apres max retries")
    return {}


# =============================================================
# Reserved Namespace Detection (variante phishing RFC 2606 / .arpa / TLD-ext)
# =============================================================

# TLDs classés par catégorie de risque.
# Sources : RFC 2606, RFC 3172, ICANN, recherches Bleeping Computer / Kaspersky 2024-2025.
_RESERVED_TLD_MAP: dict[str, tuple[str, str, str]] = {
    # Infrastructure DNS — jamais légitime comme site web
    "arpa":      ("infrastructure", "danger",
                  ".arpa est réservé à l'infrastructure DNS inverse (RFC 3172). "
                  "Son usage comme site web est un indicateur fort de phishing évasif."),
    # RFC 2606 — garantis non-résolvables / réservés aux tests
    "test":      ("rfc2606", "danger",
                  ".test est réservé aux environnements de test (RFC 2606). "
                  "Toute résolution publique est anormale."),
    "example":   ("rfc2606", "danger",
                  ".example est réservé à la documentation (RFC 2606)."),
    "invalid":   ("rfc2606", "danger",
                  ".invalid est garanti non-résolvable par le RFC 2606."),
    "localhost": ("rfc2606", "danger",
                  ".localhost est réservé à la boucle locale (RFC 2606)."),
    # TLDs « extension de fichier » — confusion intentionnelle
    "zip":       ("file_extension", "danger",
                  ".zip imite une extension d'archive. Technique active : l'URL ressemble "
                  "à un fichier que l'utilisateur croit ouvrir localement."),
    "mov":       ("file_extension", "danger",
                  ".mov imite une extension vidéo Apple/QuickTime."),
    "exe":       ("file_extension", "danger",
                  ".exe imite une extension d'exécutable Windows."),
    "bat":       ("file_extension", "danger",
                  ".bat imite une extension de script batch Windows."),
    "cmd":       ("file_extension", "danger",
                  ".cmd imite une extension de script Windows."),
    "iso":       ("file_extension", "warn",
                  ".iso imite une extension d'image disque."),
    # TLDs privés d'entreprise qui « fuient » vers le DNS public (namespace collision)
    "corp":      ("private_leak", "warn",
                  ".corp est largement utilisé en interne par les entreprises. "
                  "Sa résolution publique indique une collision de namespace Active Directory."),
    "home":      ("private_leak", "warn",
                  ".home est un TLD de réseau local non officiel utilisé par certains routeurs."),
    "mail":      ("private_leak", "warn",
                  ".mail est un TLD d'intranet non officiel — peut détourner des flux email."),
    "workgroup": ("private_leak", "warn",
                  ".workgroup est le TLD implicite des groupes de travail Windows."),
    "internal":  ("private_leak", "warn",
                  ".internal est désormais réservé par l'ICANN pour les réseaux privés (2024). "
                  "Sa présence en accès public est une anomalie."),
    "lan":       ("private_leak", "warn",
                  ".lan est couramment utilisé dans les réseaux locaux domestiques."),
    "intranet":  ("private_leak", "warn",
                  ".intranet est un TLD d'intranet privé non officiel."),
    "private":   ("private_leak", "warn",
                  ".private est utilisé dans certains réseaux internes d'entreprise."),
}

_CATEGORY_LABELS = {
    "infrastructure":  "Infrastructure DNS réservée",
    "rfc2606":         "TLD réservé RFC 2606",
    "file_extension":  "TLD imitant une extension de fichier",
    "private_leak":    "Collision de namespace privé",
}


def detect_reserved_namespace(url: str) -> dict:
    """
    Détecte l'utilisation d'un TLD réservé ou à risque élevé
    exploité dans les nouvelles campagnes de phishing (2024-2025).

    Retourne un dict avec :
      - flagged      : bool
      - tld          : str
      - category     : str  (infrastructure | rfc2606 | file_extension | private_leak | none)
      - category_label : str
      - risk         : str  (danger | warn | ok)
      - explanation  : str
    """
    try:
        netloc   = urlparse(url).netloc.lower()
        hostname = netloc.split(":")[0]          # retire le port éventuel
        tld      = hostname.rstrip(".").rsplit(".", 1)[-1]
    except Exception:
        return {"flagged": False, "tld": "", "category": "none",
                "category_label": "", "risk": "ok", "explanation": ""}

    if tld in _RESERVED_TLD_MAP:
        category, risk, explanation = _RESERVED_TLD_MAP[tld]
        log.warning(f"Reserved namespace détecté : .{tld} ({category}) pour {url}")
        return {
            "flagged":        True,
            "tld":            tld,
            "category":       category,
            "category_label": _CATEGORY_LABELS[category],
            "risk":           risk,
            "explanation":    explanation,
        }

    return {
        "flagged":        False,
        "tld":            tld,
        "category":       "none",
        "category_label": "",
        "risk":           "ok",
        "explanation":    "",
    }


# =============================================================
# Typosquatting
# =============================================================

BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "spotify", "youtube", "whatsapp", "telegram", "binance", "coinbase",
    "orange", "sfr", "laposte", "impots", "ameli", "caf", "pole-emploi"
]


def detect_typosquatting(url: str) -> list[dict]:
    try:
        domain = (
            urlparse(url).netloc
            .replace("www.", "")
            .split(".")[0]
            .lower()
        )
    except Exception:
        return []

    results = []
    for brand in BRANDS:
        dist = jellyfish.levenshtein_distance(domain, brand)
        if 0 < dist <= 2:
            results.append({
                "brand":    brand,
                "detected": domain,
                "distance": dist,
                "risk":     "Eleve" if dist == 1 else "Moyen"
            })
    return sorted(results, key=lambda x: x["distance"])


# =============================================================
# Analyse lexicale locale
# =============================================================

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "update", "account",
    "banking", "confirm", "password", "credential", "wallet",
    "urgent", "suspended", "alert", "click", "free", "prize", "winner"
]


def lexical_analysis(url: str) -> dict:
    parsed   = urlparse(url)
    hostname = parsed.netloc.lower()
    full     = url.lower()

    has_ip        = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", hostname))
    subdomains    = max(len(hostname.split(".")) - 2, 0)
    url_length    = len(url)
    has_at        = "@" in url
    has_https     = url.startswith("https")
    special_chars = len(re.findall(r"[-_~%]", url))
    keywords_hit  = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    redirects_in  = url.count("http", 1) > 0

    def weight(value, threshold, max_pts):
        return min(value / threshold, 1.0) * max_pts

    score = 0
    score += 30 if has_ip                     else 0
    score += 20 if has_at                     else 0
    score += 15 if not has_https              else 0
    score += weight(url_length,           100, 15)
    score += weight(max(subdomains - 1, 0),  3, 10)
    score += weight(len(keywords_hit),        3, 20)
    score += weight(special_chars,            5, 10)
    score += 20 if redirects_in               else 0

    return {
        "score":         min(round(score), 100),
        "url_length":    url_length,
        "has_ip":        has_ip,
        "has_https":     has_https,
        "has_at":        has_at,
        "subdomains":    subdomains,
        "special_chars": special_chars,
        "keywords_hit":  keywords_hit,
        "redirects_in":  redirects_in
    }
# =============================================================
# Sprint 3a - SSL Certificate Checker
# =============================================================

def check_ssl(url: str) -> dict:
    try:
        hostname = urlparse(url).netloc.replace("www.", "").split(":")[0]
        if not hostname:
            return {"valid": False, "error": "Hostname invalide"}

        ctx = ssl_lib.create_default_context()
        addr_info = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        af, socktype, proto, _, sockaddr = addr_info[0]
        conn = ctx.wrap_socket(socket.socket(af, socktype, proto), server_hostname=hostname)
        conn.settimeout(8)
        conn.connect(sockaddr)
        cert      = conn.getpeercert()
        conn.close()

        not_after  = cert.get("notAfter",  "")
        not_before = cert.get("notBefore", "")

        from datetime import datetime, timezone
        expiry    = datetime.strptime(not_after,  "%b %d %H:%M:%S %Y %Z")
        issued    = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.now(timezone.utc).replace(tzinfo=None)).days

        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))

        san = [
            v for _, v in cert.get("subjectAltName", [])
        ]

        return {
            "valid":        True,
            "hostname":     hostname,
            "issuer_org":   issuer.get("organizationName",  "N/A"),
            "issuer_cn":    issuer.get("commonName",        "N/A"),
            "subject_cn":   subject.get("commonName",       "N/A"),
            "issued_on":    issued.strftime("%Y-%m-%d"),
            "expires_on":   expiry.strftime("%Y-%m-%d"),
            "days_left":    days_left,
            "expired":      days_left < 0,
            "self_signed":  issuer.get("commonName") == subject.get("commonName"),
            "san":          san[:5]
        }

    except ssl_lib.SSLCertVerificationError as e:
        log.warning(f"SSL cert invalide pour {url} : {e}")
        return {"valid": False, "error": f"Certificat invalide : {str(e)[:100]}"}
    except (socket.timeout, socket.gaierror) as e:
        log.warning(f"SSL connexion echouee pour {url} : {e}")
        return {"valid": False, "error": f"Connexion impossible : {str(e)[:100]}"}
    except Exception as e:
        log.warning(f"SSL check erreur inattendue pour {url} : {e}")
        return {"valid": False, "error": str(e)[:120]}


# =============================================================
# Sprint 3b - Redirect Chain Explorer
# =============================================================

def get_redirect_chain(url: str, max_hops: int = 10) -> list[dict]:
    chain   = []
    session = requests.Session()
    session.max_redirects = max_hops
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        )
    }

    current = url
    visited = set()

    for hop in range(max_hops):
        if current in visited:
            chain.append({
                "hop":       hop + 1,
                "url":       current,
                "status":    0,
                "is_https":  current.startswith("https"),
                "domain":    urlparse(current).netloc,
                "anomaly":   "Boucle de redirection detectee",
                "risk":      "danger"
            })
            break

        visited.add(current)

        try:
            resp = session.get(
                current,
                headers=headers,
                allow_redirects=False,
                timeout=8
            )

            domain   = urlparse(current).netloc
            is_https = current.startswith("https")

            anomaly = None
            risk    = "ok"

            if resp.status_code in (301, 302, 303, 307, 308):
                next_url    = resp.headers.get("Location", "")
                next_domain = urlparse(next_url).netloc
                next_https  = next_url.startswith("https")

                if not next_https and is_https:
                    anomaly = "Downgrade HTTPS -> HTTP"
                    risk    = "danger"
                elif next_domain and next_domain != domain:
                    anomaly = f"Changement de domaine -> {next_domain}"
                    risk    = "warn"

                chain.append({
                    "hop":       hop + 1,
                    "url":       current,
                    "status":    resp.status_code,
                    "is_https":  is_https,
                    "domain":    domain,
                    "anomaly":   anomaly,
                    "risk":      risk
                })

                current = next_url if next_url.startswith("http") \
                    else f"{urlparse(current).scheme}://{domain}{next_url}"

            else:
                chain.append({
                    "hop":       hop + 1,
                    "url":       current,
                    "status":    resp.status_code,
                    "is_https":  is_https,
                    "domain":    domain,
                    "anomaly":   None,
                    "risk":      "ok" if resp.status_code == 200 else "warn"
                })
                break

        except requests.exceptions.SSLError:
            chain.append({
                "hop":      hop + 1,
                "url":      current,
                "status":   0,
                "is_https": current.startswith("https"),
                "domain":   urlparse(current).netloc,
                "anomaly":  "Erreur SSL",
                "risk":     "danger"
            })
            break
        except requests.exceptions.RequestException as e:
            chain.append({
                "hop":      hop + 1,
                "url":      current,
                "status":   0,
                "is_https": current.startswith("https"),
                "domain":   urlparse(current).netloc,
                "anomaly":  f"Erreur reseau : {str(e)[:60]}",
                "risk":     "danger"
            })
            break

    log.info(f"Redirect chain : {len(chain)} hop(s) pour {url}")
    return chain


# =============================================================
# Sprint 6 - WHOIS Lookup (raw socket, sans dépendance externe)
# =============================================================

def _whois_query(server: str, query: str) -> str:
    """Envoie une requête WHOIS brute sur le port 43."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((server, 43))
    s.send(f"{query}\r\n".encode())
    chunks = []
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _parse_whois(raw: str, domain: str) -> dict:
    """Extrait les champs clés d'une réponse WHOIS brute."""
    result: dict = {"domain": domain}

    field_map = {
        "registrar":          ["registrar:", "registrar name:"],
        "creation_date":      ["creation date:", "created:", "domain registered:"],
        "expiration_date":    ["expiry date:", "registrar registration expiration date:",
                               "expiration date:", "paid-till:"],
        "updated_date":       ["updated date:", "last updated:", "last-updated:"],
        "registrant_org":     ["registrant organization:", "registrant org:"],
        "registrant_country": ["registrant country:", "registrant state/province:"],
        "status":             ["domain status:"],
        "name_servers":       ["name server:", "nserver:"],
    }

    ns_list:     list[str] = []
    status_list: list[str] = []

    for line in raw.splitlines():
        lower = line.lower().strip()
        for field, prefixes in field_map.items():
            for prefix in prefixes:
                if lower.startswith(prefix):
                    value = line.split(":", 1)[1].strip() if ":" in line else ""
                    if field == "name_servers":
                        if value:
                            ns_list.append(value.lower())
                    elif field == "status":
                        if value:
                            status_list.append(value.split()[0])
                    elif field not in result and value:
                        result[field] = value
                    break

    if ns_list:
        result["name_servers"] = list(dict.fromkeys(ns_list))[:4]
    if status_list:
        result["status"] = list(dict.fromkeys(status_list))[:3]

    return result


def get_whois(url: str) -> dict:
    """
    Retourne les informations WHOIS pour le domaine de l'URL.

    Effectue d'abord une requête sur whois.iana.org pour obtenir
    le serveur WHOIS autoritatif du TLD, puis interroge ce serveur.
    """
    try:
        hostname = urlparse(url).netloc.replace("www.", "").split(":")[0]
        if not hostname:
            return {"error": "Hostname invalide"}

        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        tld    = parts[-1].lower()

        log.info(f"WHOIS lookup : {domain}")

        # Étape 1 : serveur WHOIS du TLD via IANA
        try:
            iana_raw = _whois_query("whois.iana.org", tld)
        except Exception as e:
            log.warning(f"IANA WHOIS echoue : {e}")
            return {"error": f"IANA injoignable : {str(e)[:80]}"}

        whois_server = None
        for line in iana_raw.splitlines():
            if line.lower().startswith("whois:"):
                whois_server = line.split(":", 1)[1].strip()
                break

        if not whois_server:
            return {"error": f"Serveur WHOIS introuvable pour .{tld}"}

        # Étape 2 : requête sur le serveur du TLD
        try:
            raw = _whois_query(whois_server, domain)
        except Exception as e:
            log.warning(f"WHOIS {whois_server} echoue : {e}")
            return {"error": f"Serveur WHOIS injoignable : {str(e)[:80]}"}

        result = _parse_whois(raw, domain)
        result["whois_server"] = whois_server
        log.info(f"WHOIS recu pour {domain} via {whois_server}")
        return result

    except Exception as e:
        log.error(f"WHOIS erreur inattendue pour {url} : {e}")
        return {"error": str(e)[:120]}


# =============================================================
# Tier 1 — Homoglyph / IDN / Punycode Detection
# =============================================================

# Confusables : caractère Unicode → équivalent ASCII visuel
_CONFUSABLES: dict[str, str] = {
    # Cyrillique
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0455": "s", "\u04cf": "l",
    # Grec
    "\u03bf": "o", "\u03c1": "p", "\u03b5": "e", "\u03b1": "a",
    # Leetspeak (chiffres substitués aux lettres)
    "0": "o", "1": "l", "3": "e", "5": "s",
}


def _normalize_confusables(text: str) -> str:
    """Remplace les confusables par leurs équivalents ASCII."""
    return "".join(_CONFUSABLES.get(c, c) for c in text)


def detect_homoglyphs(url: str) -> dict:
    """
    Détecte les attaques par homoglyphes, IDN (Punycode) et leetspeak.

    Retourne {flagged, method, matched_brand?, decoded?, normalized?}.
    """
    try:
        hostname = urlparse(url).netloc.replace("www.", "").split(":")[0].lower()
        if not hostname:
            return {"flagged": False}

        result: dict = {"flagged": False, "hostname": hostname}

        # ── Cas 1 : Punycode / xn-- (IDN) ─────────────────────────────────
        if "xn--" in hostname:
            try:
                decoded = hostname.encode("ascii").decode("idna")
                result.update({"method": "punycode", "decoded": decoded})
                domain_part = decoded.split(".")[0]
                norm = _normalize_confusables(domain_part)
                for brand in BRANDS:
                    if jellyfish.levenshtein_distance(norm, brand) <= 1:
                        result.update({"flagged": True, "matched_brand": brand,
                                       "normalized": norm})
                        return result
                # Punycode sans match exact → suspect quand même
                result["flagged"] = True
            except Exception:
                result.update({"flagged": True, "method": "punycode_malformed"})
            return result

        # ── Cas 2 : Unicode direct dans le domaine ─────────────────────────
        if not hostname.isascii():
            result["method"] = "unicode_direct"
            domain_part = hostname.split(".")[0]
            norm = _normalize_confusables(domain_part)
            result["normalized"] = norm
            for brand in BRANDS:
                if jellyfish.levenshtein_distance(norm, brand) <= 1:
                    result.update({"flagged": True, "matched_brand": brand})
                    return result
            result["flagged"] = True
            return result

        # ── Cas 3 : Leetspeak ASCII (0→o, 1→l, 3→e, 5→s) ─────────────────
        domain_part = hostname.split(".")[0]
        if any(c in domain_part for c in "0135"):
            norm = _normalize_confusables(domain_part)
            if norm != domain_part:
                result.update({"method": "leetspeak", "normalized": norm})
                for brand in BRANDS:
                    if jellyfish.levenshtein_distance(norm, brand) <= 1:
                        result.update({"flagged": True, "matched_brand": brand})
                        return result

        return result

    except Exception as e:
        log.warning(f"detect_homoglyphs error: {e}")
        return {"flagged": False}


# =============================================================
# Tier 1 — Domain Age (via données WHOIS)
# =============================================================

_DATE_FORMATS_AGE = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d/%m/%Y",
    "%Y.%m.%d",
    "%Y%m%d",
]


def get_domain_age(whois_data: dict) -> int | None:
    """
    Calcule l'âge du domaine en jours à partir de creation_date WHOIS.
    Retourne None si la date est absente ou non parseable.
    """
    from datetime import datetime as _dt

    raw = whois_data.get("creation_date")
    if not raw:
        return None

    raw_clean = re.sub(r"\.\d+Z?$", "", raw.strip())

    for fmt in _DATE_FORMATS_AGE:
        try:
            creation = _dt.strptime(raw_clean, fmt)
            return max((_dt.now() - creation).days, 0)
        except ValueError:
            continue

    # Fallback : extraire YYYY-MM-DD par regex
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        try:
            creation = _dt(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return max((_dt.now() - creation).days, 0)
        except Exception:
            pass

    log.warning(f"get_domain_age: format de date non reconnu '{raw}'")
    return None


# =============================================================
# Tier 1 — URL Shortener Resolution
# =============================================================

SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "tiny.cc", "qr.ae",
    "goo.gl", "lnkd.in", "wp.me", "youtu.be", "dlvr.it",
    "mcaf.ee", "soo.gd", "snip.ly", "bl.ink", "clk.sh",
})


def is_shorturl(url: str) -> bool:
    """Retourne True si l'URL provient d'un raccourcisseur connu."""
    try:
        host = urlparse(url).netloc.replace("www.", "").lower()
        return host in SHORTENERS
    except Exception:
        return False


def resolve_shorturl(url: str) -> dict:
    """
    Suit les redirections HTTP pour obtenir la destination finale.
    Retourne {original, final, hops, changed, error?}.
    """
    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=8,
            headers={"User-Agent": "Mozilla/5.0 PhishGuard/1.0"},
        )
        final = resp.url
        hops  = len(resp.history)
        log.info(f"resolve_shorturl: {url} → {final} ({hops} hop(s))")
        return {"original": url, "final": final, "hops": hops, "changed": final != url}
    except Exception as e:
        log.warning(f"resolve_shorturl error pour {url}: {e}")
        return {"original": url, "final": url, "hops": 0, "changed": False,
                "error": str(e)[:80]}


# =============================================================
# Tier 1 — SPF / DKIM / DMARC (Email Authentication)
# =============================================================

def check_email_auth(domain: str) -> dict:
    """
    Vérifie les enregistrements SPF, DMARC et DKIM d'un domaine.
    Nécessite dnspython. Retourne {spf, dmarc, dkim, auth_score, risk}.
    """
    try:
        import dns.resolver as _dns  # type: ignore
    except ImportError:
        return {
            "error": "dnspython non installé — pip install dnspython",
            "auth_score": 0,
            "risk": "unknown",
        }

    result: dict = {"domain": domain, "spf": None, "dmarc": None, "dkim": None}

    # ── SPF ──────────────────────────────────────────────────────────────────
    try:
        for r in _dns.resolve(domain, "TXT"):
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["spf"] = txt[:140]
                break
        if result["spf"] is None:
            result["spf"] = "absent"
    except Exception:
        result["spf"] = "absent"

    # ── DMARC ─────────────────────────────────────────────────────────────────
    try:
        for r in _dns.resolve(f"_dmarc.{domain}", "TXT"):
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                result["dmarc"] = txt[:160]
                break
        if result["dmarc"] is None:
            result["dmarc"] = "absent"
    except Exception:
        result["dmarc"] = "absent"

    # ── DKIM (sélecteurs courants) ─────────────────────────────────────────────
    result["dkim"] = "absent"
    for sel in ("default", "google", "selector1", "selector2", "mail", "dkim", "k1"):
        try:
            for r in _dns.resolve(f"{sel}._domainkey.{domain}", "TXT"):
                txt = r.to_text().strip('"')
                if "v=DKIM1" in txt or "k=rsa" in txt or "k=ed25519" in txt:
                    result["dkim"] = f"présent (sélecteur : {sel})"
                    break
            if result["dkim"] != "absent":
                break
        except Exception:
            continue

    # ── Score global d'authentification (0-3) ─────────────────────────────────
    auth_score = sum([
        result["spf"]   not in ("absent", None),
        result["dmarc"] not in ("absent", None),
        result["dkim"]  != "absent",
    ])
    result["auth_score"] = auth_score
    result["risk"] = "danger" if auth_score == 0 else ("warn" if auth_score <= 1 else "ok")
    log.info(f"check_email_auth({domain}): score={auth_score}/3")
    return result

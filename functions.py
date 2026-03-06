import os
import re
import ssl
import time
import base64
import jellyfish
import requests
import socket
import ssl as ssl_lib
import matplotlib.pyplot as plt
import pandas as pd
from urllib.parse import urlparse, urlencode, quote
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
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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


def get_data(url: str) -> dict:
    log.info(f"GET {url}")
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

import virustotal_python

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

    for attempt in range(1, max_retries + 1):
        try:
            with virustotal_python.Virustotal(KEY_VT) as vtotal:
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

    log.warning("VT rapport indisponible apres max retries")
    return {}


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

        ctx  = ssl_lib.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname
        )
        conn.settimeout(8)
        conn.connect((hostname, 443))
        cert      = conn.getpeercert()
        conn.close()

        not_after  = cert.get("notAfter",  "")
        not_before = cert.get("notBefore", "")

        from datetime import datetime
        expiry    = datetime.strptime(not_after,  "%b %d %H:%M:%S %Y %Z")
        issued    = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days

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
                timeout=8,
                verify=False
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

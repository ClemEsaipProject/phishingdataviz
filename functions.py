import os
import time
import base64
import requests
import matplotlib.pyplot as plt
import pandas as pd
from geopy.geocoders import Nominatim
from dotenv import load_dotenv

load_dotenv()
from urllib.parse import quote


KEY_VT = os.getenv("VIRUSTOTAL_API_KEY")
KEY_IQ = os.getenv("IPQUALITYSCORE_API_KEY")

base_url   = f"https://www.ipqualityscore.com/api/json/url/{KEY_IQ}/"
base_email = f"https://www.ipqualityscore.com/api/json/email/{KEY_IQ}/"
country_code_url = "https://www.ipqualityscore.com/api/json/country/list"

geolocator = Nominatim(user_agent="phishingdataviz")

VT_BASE    = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": KEY_VT}



def build_iq_url(base: str, target: str) -> str:
    return base + quote(target, safe="")


def get_data(url: str) -> dict:
    resp = requests.get(url, timeout=10)
    if resp.status_code == 404:
        return {"error": "404 - endpoint introuvable ou URL mal formee"}
    if resp.status_code == 401:
        return {"error": "401 - cle API invalide ou expiree"}
    resp.raise_for_status()
    return resp.json()



def get_coordinates(country_code: str):
    location = geolocator.geocode(country_code)
    if location:
        return location.latitude, location.longitude
    return None, None


def scan_url_virustotal(url: str) -> dict:
    """Soumet une URL a VirusTotal API v3. Retourne l'analysis_id et l'URL."""
    response = requests.post(
        f"{VT_BASE}/urls",
        headers=VT_HEADERS,
        data={"url": url},
        timeout=10
    )
    response.raise_for_status()
    data = response.json()
    return {
        "analysis_id": data.get("data", {}).get("id"),
        "url": url
    }


def get_url_report_virustotal(scan_result: dict) -> dict:
    """
    Recupere le rapport d'analyse VirusTotal API v3.
    Attend 15s pour laisser le temps a l'analyse de se terminer.
    """
    url    = scan_result.get("url", "")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    time.sleep(15)

    response = requests.get(
        f"{VT_BASE}/urls/{url_id}",
        headers=VT_HEADERS,
        timeout=10
    )
    response.raise_for_status()
    return response.json()


def plot_virustotal_data(vt_report: dict):
    """
    Genere un pie chart a partir du rapport VirusTotal API v3.
    Retourne une Figure matplotlib (plus le module plt entier).
    """
    stats = (
        vt_report
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    categories = {
        "Malicious":  ("red",    stats.get("malicious",  0)),
        "Suspicious": ("orange", stats.get("suspicious", 0)),
        "Undetected": ("gray",   stats.get("undetected", 0)),
        "Harmless":   ("green",  stats.get("harmless",   0)),
    }

    filtered = {k: v for k, (_, v) in categories.items() if v > 0}
    colors   = [categories[k][0] for k in filtered]

    if not filtered:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, "Aucune donnee disponible", ha="center", va="center")
        return fig

    explode = [0.1 if k == "Malicious" else 0 for k in filtered]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(
        filtered.values(),
        explode=explode,
        labels=filtered.keys(),
        colors=colors,
        autopct="%1.1f%%",
        shadow=True,
        startangle=140
    )
    ax.axis("equal")
    ax.set_title("VirusTotal Scan Results")
    return fig

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import base64
import pytest
import requests as req
from fixtures import VT_SCAN_RESPONSE, VT_REPORT_RESPONSE, IQ_RESPONSE
import functions


# =============================================================
# build_iq_url
# =============================================================

class TestBuildIqUrl:
    def test_encodes_https_scheme(self):
        result = functions.build_iq_url("https://api.test/", "https://evil.com/path")
        assert "https%3A%2F%2F" in result

    def test_encodes_at_symbol(self):
        result = functions.build_iq_url("https://api.test/", "http://user@evil.com")
        assert "%40" in result

    def test_base_preserved(self):
        result = functions.build_iq_url("https://api.test/", "https://target.com")
        assert result.startswith("https://api.test/")

    def test_empty_target(self):
        result = functions.build_iq_url("https://api.test/", "")
        assert result == "https://api.test/"


# =============================================================
# get_data
# =============================================================

class TestGetData:
    def test_returns_json_on_200(self, requests_mock):
        requests_mock.get("https://api.test/url", json=IQ_RESPONSE)
        result = functions.get_data("https://api.test/url")
        assert result["risk_score"] == 85
        assert result["phishing"]   is True

    def test_returns_error_dict_on_404(self, requests_mock):
        requests_mock.get("https://api.test/url", status_code=404)
        result = functions.get_data("https://api.test/url")
        assert "error" in result
        assert "404"   in result["error"]

    def test_returns_error_dict_on_401(self, requests_mock):
        requests_mock.get("https://api.test/url", status_code=401)
        result = functions.get_data("https://api.test/url")
        assert "error" in result
        assert "401"   in result["error"]

    def test_returns_error_on_timeout(self, requests_mock):
        requests_mock.get("https://api.test/url", exc=req.exceptions.Timeout)
        result = functions.get_data("https://api.test/url")
        assert "error"   in result
        assert "Timeout" in result["error"]

    def test_returns_error_on_ssl(self, requests_mock):
        requests_mock.get(
            "https://api.test/url",
            exc=req.exceptions.SSLError("ssl fail")
        )
        result = functions.get_data("https://api.test/url")
        assert "error" in result
        assert "SSL"   in result["error"]


# =============================================================
# scan_url_virustotal
# =============================================================

class TestScanUrlVirustotal:
    def test_returns_analysis_id(self, requests_mock):
        requests_mock.post(
            "https://www.virustotal.com/api/v3/urls",
            json=VT_SCAN_RESPONSE
        )
        result = functions.scan_url_virustotal("https://evil.com")
        assert result["analysis_id"] == "dTJMTi02MDIwNmQzM2Y0NDFiMTk="
        assert result["url"]         == "https://evil.com"

    def test_returns_url_in_result(self, requests_mock):
        requests_mock.post(
            "https://www.virustotal.com/api/v3/urls",
            json=VT_SCAN_RESPONSE
        )
        result = functions.scan_url_virustotal("https://test.com")
        assert result["url"] == "https://test.com"

    def test_returns_error_on_http_error(self, requests_mock):
        requests_mock.post(
            "https://www.virustotal.com/api/v3/urls",
            status_code=400
        )
        result = functions.scan_url_virustotal("https://evil.com")
        assert "error" in result

    def test_returns_error_on_ssl(self, requests_mock):
        requests_mock.post(
            "https://www.virustotal.com/api/v3/urls",
            exc=req.exceptions.SSLError("eof")
        )
        result = functions.scan_url_virustotal("https://evil.com")
        assert "error" in result
        assert "SSL"   in result["error"]


# =============================================================
# get_url_report_virustotal
# =============================================================

class TestGetUrlReport:
    def _url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def test_returns_report_immediately(self, requests_mock):
        url = "https://evil.com"
        requests_mock.get(
            f"https://www.virustotal.com/api/v3/urls/{self._url_id(url)}",
            json=VT_REPORT_RESPONSE
        )
        result = functions.get_url_report_virustotal(
            {"url": url}, max_retries=3, interval=0
        )
        stats = result["data"]["attributes"]["last_analysis_stats"]
        assert stats["malicious"] == 5
        assert stats["harmless"]  == 60

    def test_returns_empty_after_max_retries(self, requests_mock):
        url = "https://evil.com"
        requests_mock.get(
            f"https://www.virustotal.com/api/v3/urls/{self._url_id(url)}",
            json={"data": {"attributes": {}}}
        )
        result = functions.get_url_report_virustotal(
            {"url": url}, max_retries=2, interval=0
        )
        assert result == {}

    def test_returns_error_on_network_failure(self, requests_mock):
        url = "https://evil.com"
        requests_mock.get(
            f"https://www.virustotal.com/api/v3/urls/{self._url_id(url)}",
            exc=req.exceptions.ConnectionError("refused")
        )
        result = functions.get_url_report_virustotal(
            {"url": url}, max_retries=2, interval=0
        )
        assert "error" in result


# =============================================================
# detect_typosquatting
# =============================================================

class TestDetectTyposquatting:
    def test_detects_paypal_typo(self):
        hits   = functions.detect_typosquatting("https://paypa1.com/login")
        brands = [h["brand"] for h in hits]
        assert "paypal" in brands

    def test_detects_amazon_typo(self):
        hits   = functions.detect_typosquatting("https://arnazon.com")
        brands = [h["brand"] for h in hits]
        assert "amazon" in brands

    def test_no_hit_on_exact_brand(self):
        hits = functions.detect_typosquatting("https://google.com")
        assert hits == []

    def test_no_hit_on_unrelated_domain(self):
        hits = functions.detect_typosquatting("https://xkcd.com")
        assert hits == []

    def test_distance_1_is_eleve(self):
        hits = functions.detect_typosquatting("https://paypa1.com")
        hit  = next((h for h in hits if h["brand"] == "paypal"), None)
        assert hit is not None
        assert hit["risk"]     == "Eleve"
        assert hit["distance"] == 1

    def test_distance_2_is_moyen(self):
        hits = functions.detect_typosquatting("https://p4yp4l.com")
        hit  = next((h for h in hits if h["brand"] == "paypal"), None)
        assert hit is not None
        assert hit["distance"] == 2
        assert hit["risk"]     == "Moyen"

    def test_sorted_by_distance(self):
        hits = functions.detect_typosquatting("https://paypa1.com")
        if len(hits) > 1:
            distances = [h["distance"] for h in hits]
            assert distances == sorted(distances)


# =============================================================
# lexical_analysis
# =============================================================

class TestLexicalAnalysis:
    def test_high_score_on_suspicious_url(self):
        url    = "http://192.168.1.1/login/secure/verify?user=admin@paypal.com"
        result = functions.lexical_analysis(url)
        assert result["score"]     >= 60
        assert result["has_ip"]    is True
        assert result["has_https"] is False
        assert result["has_at"]    is True
        assert "login"  in result["keywords_hit"]
        assert "secure" in result["keywords_hit"]

    def test_low_score_on_clean_url(self):
        result = functions.lexical_analysis("https://www.github.com")
        assert result["score"]     < 20
        assert result["has_https"] is True
        assert result["has_ip"]    is False
        assert result["has_at"]    is False

    def test_url_length_counted(self):
        url    = "https://example.com/" + "a" * 81   # 101 chars
        result = functions.lexical_analysis(url)
        assert result["url_length"] >= 100


    def test_http_penalised(self):
        r_http  = functions.lexical_analysis("http://example.com")
        r_https = functions.lexical_analysis("https://example.com")
        assert r_http["score"] > r_https["score"]

    def test_at_symbol_detected(self):
        result = functions.lexical_analysis("https://legit.com@evil.com")
        assert result["has_at"] is True

    def test_subdomains_counted(self):
        result = functions.lexical_analysis("https://a.b.c.evil.com/path")
        assert result["subdomains"] >= 2

    def test_keywords_none_on_clean(self):
        result = functions.lexical_analysis("https://www.wikipedia.org")
        assert result["keywords_hit"] == []

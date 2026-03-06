import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import socket
import ssl as ssl_lib
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import functions


# =============================================================
# check_ssl
# =============================================================

def make_mock_cert(days_offset: int = 90, self_signed: bool = False):
    future  = datetime.utcnow() + timedelta(days=days_offset)
    past    = datetime.utcnow() - timedelta(days=30)
    issuer  = "TestCA" if not self_signed else "example.com"
    return {
        "subject":        ((("commonName", "example.com"),),),
        "issuer":         ((("commonName",        issuer),),
                           (("organizationName",  "TestCA Inc."),)),
        "notAfter":       future.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore":      past.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }


class TestCheckSSL:
    def test_returns_valid_on_good_cert(self):
        mock_cert = make_mock_cert(days_offset=90)
        with patch("ssl.create_default_context") as mock_ctx:
            mock_conn = MagicMock()
            mock_conn.getpeercert.return_value = mock_cert
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            result = functions.check_ssl("https://example.com")
        assert result["valid"]      is True
        assert result["days_left"]  > 0
        assert result["expired"]    is False

    def test_detects_expired_cert(self):
        mock_cert = make_mock_cert(days_offset=-5)
        with patch("ssl.create_default_context") as mock_ctx:
            mock_conn = MagicMock()
            mock_conn.getpeercert.return_value = mock_cert
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            result = functions.check_ssl("https://example.com")
        assert result["expired"] is True

    def test_detects_self_signed(self):
        mock_cert = make_mock_cert(days_offset=90, self_signed=True)
        with patch("ssl.create_default_context") as mock_ctx:
            mock_conn = MagicMock()
            mock_conn.getpeercert.return_value = mock_cert
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            result = functions.check_ssl("https://example.com")
        assert result["self_signed"] is True

    def test_returns_error_on_ssl_failure(self):
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = \
                ssl_lib.SSLCertVerificationError("cert verify failed")
            result = functions.check_ssl("https://example.com")
        assert result["valid"] is False
        assert "error"         in result

    def test_returns_error_on_timeout(self):
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = \
                socket.timeout("timed out")
            result = functions.check_ssl("https://example.com")
        assert result["valid"] is False

    def test_invalid_hostname(self):
        result = functions.check_ssl("not_a_url")
        assert result["valid"] is False


# =============================================================
# get_redirect_chain
# =============================================================

class TestRedirectChain:
    def _make_response(self, status: int, location: str = None):
        mock_resp = MagicMock()
        mock_resp.status_code  = status
        mock_resp.is_redirect  = status in (301, 302, 303, 307, 308)
        mock_resp.headers      = {"Location": location} if location else {}
        return mock_resp

    def test_no_redirect_returns_single_hop(self, requests_mock):
        requests_mock.get("https://example.com", status_code=200)
        chain = functions.get_redirect_chain("https://example.com")
        assert len(chain)          == 1
        assert chain[0]["status"]  == 200
        assert chain[0]["hop"]     == 1
        assert chain[0]["risk"]    == "ok"

    def test_single_redirect_followed(self, requests_mock):
        requests_mock.get(
            "https://example.com",
            status_code=301,
            headers={"Location": "https://www.example.com"}
        )
        requests_mock.get("https://www.example.com", status_code=200)
        chain = functions.get_redirect_chain("https://example.com")
        assert len(chain) == 2
        assert chain[0]["status"] == 301
        assert chain[1]["status"] == 200

    def test_detects_https_to_http_downgrade(self, requests_mock):
        requests_mock.get(
            "https://secure.com",
            status_code=301,
            headers={"Location": "http://insecure.com"}
        )
        requests_mock.get("http://insecure.com", status_code=200)
        chain = functions.get_redirect_chain("https://secure.com")
        hop1  = chain[0]
        assert hop1["risk"]    == "danger"
        assert "Downgrade"     in hop1["anomaly"]

    def test_detects_domain_change(self, requests_mock):
        requests_mock.get(
            "https://legit.com",
            status_code=302,
            headers={"Location": "https://other-domain.com"}
        )
        requests_mock.get("https://other-domain.com", status_code=200)
        chain = functions.get_redirect_chain("https://legit.com")
        hop1  = chain[0]
        assert hop1["risk"] == "warn"
        assert "domaine"    in hop1["anomaly"].lower()

    def test_ssl_error_stops_chain(self, requests_mock):
        import requests as req
        requests_mock.get(
            "https://bad-ssl.com",
            exc=req.exceptions.SSLError("ssl error")
        )
        chain = functions.get_redirect_chain("https://bad-ssl.com")
        assert chain[0]["risk"]    == "danger"
        assert "SSL"               in chain[0]["anomaly"]

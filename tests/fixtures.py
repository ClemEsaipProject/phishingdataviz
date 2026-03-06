VT_SCAN_RESPONSE = {
    "data": {"id": "dTJMTi02MDIwNmQzM2Y0NDFiMTk="}
}

VT_REPORT_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious":  5,
                "suspicious": 2,
                "harmless":   60,
                "undetected": 10,
                "timeout":    0
            },
            "last_analysis_results": {
                "Google Safebrowsing": {"category": "malicious", "detected": True},
                "Kaspersky":           {"category": "malicious", "detected": True},
                "Bitdefender":         {"category": "harmless",  "detected": False},
            }
        }
    }
}

IQ_RESPONSE = {
    "success":      True,
    "risk_score":   85,
    "dns_valid":    True,
    "phishing":     True,
    "malware":      False,
    "suspicious":   True,
    "spamming":     False,
    "country_code": "FR",
    "domain_rank":  0,
    "category":     "Phishing"
}

IQ_RESPONSE_CLEAN = {
    "success":      True,
    "risk_score":   10,
    "dns_valid":    True,
    "phishing":     False,
    "malware":      False,
    "suspicious":   False,
    "spamming":     False,
    "country_code": "US",
    "domain_rank":  500,
    "category":     "Technology"
}

DB_SAMPLE = {
    "risk_score":   90,
    "phishing":     True,
    "malware":      False,
    "suspicious":   True,
    "dns_valid":    True,
    "country_code": "FR"
}

DB_SAMPLE_CLEAN = {
    "risk_score":   10,
    "phishing":     False,
    "malware":      False,
    "suspicious":   False,
    "dns_valid":    True,
    "country_code": "US"
}

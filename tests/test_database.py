import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fixtures import DB_SAMPLE, DB_SAMPLE_CLEAN
from database import (
    init_db, save_scan, get_all_scans,
    get_stats, delete_scan, clear_all
)


class TestDatabase:
    def test_save_and_retrieve(self, tmp_db):
        save_scan("https://evil.com", "IPQualityScore", DB_SAMPLE)
        rows = get_all_scans()
        assert len(rows)           == 1
        assert rows[0]["url"]      == "https://evil.com"
        assert rows[0]["risk_score"] == 90
        assert rows[0]["phishing"] == 1
        assert rows[0]["source"]   == "IPQualityScore"

    def test_multiple_saves(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "VirusTotal",     DB_SAMPLE_CLEAN)
        rows = get_all_scans()
        assert len(rows) == 2

    def test_ordered_by_timestamp_desc(self, tmp_db):
        save_scan("https://first.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://second.com", "IPQualityScore", DB_SAMPLE_CLEAN)
        rows = get_all_scans()
        assert rows[0]["url"] == "https://second.com"

    def test_stats_total(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "IPQualityScore", DB_SAMPLE_CLEAN)
        stats = get_stats()
        assert stats["total"] == 2

    def test_stats_avg_risk(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "IPQualityScore", DB_SAMPLE_CLEAN)
        stats = get_stats()
        assert stats["avg_risk"] == 50.0

    def test_stats_phishing_count(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "IPQualityScore", DB_SAMPLE_CLEAN)
        stats = get_stats()
        assert stats["total_phishing"] == 1

    def test_stats_malware_count(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        stats = get_stats()
        assert stats["total_malware"] == 0

    def test_stats_high_risk(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "IPQualityScore", DB_SAMPLE_CLEAN)
        stats = get_stats()
        assert stats["high_risk"] == 1

    def test_delete_scan(self, tmp_db):
        save_scan("https://evil.com", "IPQualityScore", DB_SAMPLE)
        rows = get_all_scans()
        delete_scan(rows[0]["id"])
        assert get_all_scans() == []

    def test_clear_all(self, tmp_db):
        save_scan("https://evil.com",  "IPQualityScore", DB_SAMPLE)
        save_scan("https://clean.com", "VirusTotal",     DB_SAMPLE_CLEAN)
        clear_all()
        assert get_all_scans() == []

    def test_empty_db_returns_empty_list(self, tmp_db):
        assert get_all_scans() == []

    def test_stats_on_empty_db(self, tmp_db):
        stats = get_stats()
        assert stats["total"] == 0

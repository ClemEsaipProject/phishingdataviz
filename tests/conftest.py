import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    db_path = str(tmp_path / "test_scans.db")
    monkeypatch.setattr("database.DB_PATH", db_path)
    return db_path

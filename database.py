import sqlite3
import json
from datetime import datetime

DB_PATH = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            source      TEXT    NOT NULL,
            risk_score  INTEGER DEFAULT 0,
            phishing    INTEGER DEFAULT 0,
            malware     INTEGER DEFAULT 0,
            suspicious  INTEGER DEFAULT 0,
            dns_valid   INTEGER DEFAULT 1,
            country     TEXT    DEFAULT '',
            timestamp   TEXT    NOT NULL,
            raw         TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(url: str, source: str, data: dict):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO scans
           (url, source, risk_score, phishing, malware,
            suspicious, dns_valid, country, timestamp, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            url,
            source,
            data.get("risk_score",  0),
            int(data.get("phishing",   False)),
            int(data.get("malware",    False)),
            int(data.get("suspicious", False)),
            int(data.get("dns_valid",  True)),
            data.get("country_code", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            json.dumps(data)
        )
    )
    conn.commit()
    conn.close()


def get_all_scans() -> list[dict]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC"  # id autoincrement, toujours fiable
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # manquait ici
    cur = conn.execute("""
        SELECT
            COUNT(*)                        AS total,
            AVG(risk_score)                 AS avg_risk,
            SUM(phishing)                   AS total_phishing,
            SUM(malware)                    AS total_malware,
            SUM(CASE WHEN risk_score >= 75
                THEN 1 ELSE 0 END)          AS high_risk
        FROM scans
    """)
    row = cur.fetchone()
    conn.close()

    if row is None or row["total"] == 0:    # protection table vide
        return {
            "total":          0,
            "avg_risk":       0.0,
            "total_phishing": 0,
            "total_malware":  0,
            "high_risk":      0
        }

    return dict(row)



def delete_scan(scan_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


def clear_all():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

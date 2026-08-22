import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scamlens.db")


def get_connection():
    """Open a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scan_history table if it doesn't already exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            content_snippet TEXT,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            signal_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def log_scan(scan_type, content_snippet, score, risk_level, signal_count):
    """
    Save one scan result into the database.

    scan_type: "message" or "url"
    content_snippet: a short (truncated) preview of what was scanned — never store full
                      sensitive content long-term in a real production system.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Only keep a short snippet, not the full message, to avoid storing
    # sensitive personal data (OTPs, card numbers, etc.) unnecessarily.
    safe_snippet = (content_snippet or "")[:120]

    cursor.execute("""
        INSERT INTO scan_history
            (scan_type, content_snippet, score, risk_level, signal_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_type,
        safe_snippet,
        score,
        risk_level,
        signal_count,
        datetime.now(timezone.utc).isoformat()
    ))

    conn.commit()
    conn.close()


def get_stats():
    """Return overall usage stats for the dashboard / homepage."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(*) AS high_risk FROM scan_history WHERE risk_level = 'High Risk'"
    )
    high_risk = cursor.fetchone()["high_risk"]

    conn.close()

    return {
        "total_scans": total,
        "high_risk_scans": high_risk
    }


def get_recent_scans(limit=20):
    """Return the most recent scans (for an admin/history view)."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, scan_type, content_snippet, score, risk_level, signal_count, created_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return rows
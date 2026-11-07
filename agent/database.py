"""Sentinel Agent - SQLite database for caching VT results and scan history."""
import sqlite3
from datetime import datetime, timedelta
from config import DB_PATH


class SentinelDatabase:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            file_hash TEXT PRIMARY KEY,
            file_path TEXT,
            file_name TEXT,
            file_size INTEGER,
            sha256 TEXT, md5 TEXT, sha1 TEXT,
            positives INTEGER, total INTEGER,
            malicious INTEGER, suspicious INTEGER, undetected INTEGER,
            status TEXT,
            threat_level TEXT,
            scan_date TEXT,
            source TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            file_path TEXT, file_name TEXT, file_hash TEXT,
            status TEXT, threat_level TEXT,
            positives INTEGER, total INTEGER,
            scanned_at TEXT, action TEXT
        );
        CREATE TABLE IF NOT EXISTS quarantine_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            original_path TEXT, quarantine_path TEXT,
            file_hash TEXT, reason TEXT, quarantined_at TEXT
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            file_hash TEXT PRIMARY KEY,
            file_path TEXT, added_at TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_config (
            key TEXT PRIMARY KEY, value TEXT, updated_at TEXT
        );
        """)
        conn.commit()
        conn.close()

    # ---- cache ----
    def get_cached_result(self, file_hash):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scan_cache WHERE file_hash = ?", (file_hash,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        scan_date = datetime.fromisoformat(row["scan_date"])
        if datetime.now() - scan_date > timedelta(hours=__import__("config").HASH_CACHE_TTL_HOURS):
            return None
        return dict(row)

    def save_result(self, result):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO scan_cache
        (file_hash, file_path, file_name, file_size, sha256, md5, sha1,
         positives, total, malicious, suspicious, undetected, status,
         threat_level, scan_date, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["hash"], result.get("file_path"), result.get("file_name"),
            result.get("file_size"), result.get("sha256"), result.get("md5"),
            result.get("sha1"), result.get("positives"), result.get("total"),
            result.get("malicious"), result.get("suspicious"),
            result.get("undetected"), result.get("status"),
            result.get("threat_level"), result.get("scan_date"),
            result.get("source", "virustotal"),
        ))
        conn.commit()
        conn.close()

    # ---- history ----
    def add_history(self, entry):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO scan_history
        (agent_id, file_path, file_name, file_hash, status, threat_level,
         positives, total, scanned_at, action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.get("agent_id"), entry.get("file_path"), entry.get("file_name"),
            entry.get("hash"), entry.get("status"), entry.get("threat_level"),
            entry.get("positives"), entry.get("total"),
            entry.get("scanned_at"), entry.get("action", "none"),
        ))
        conn.commit()
        conn.close()

    def get_history(self, limit=100):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    # ---- quarantine log ----
    def add_quarantine(self, entry):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO quarantine_log
        (agent_id, original_path, quarantine_path, file_hash, reason, quarantined_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            entry.get("agent_id"), entry.get("original_path"),
            entry.get("quarantine_path"), entry.get("hash"),
            entry.get("reason"), entry.get("quarantined_at"),
        ))
        conn.commit()
        conn.close()

    # ---- whitelist ----
    def is_whitelisted(self, file_hash):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM whitelist WHERE file_hash = ?", (file_hash,))
        row = cur.fetchone()
        conn.close()
        return row is not None

    def add_to_whitelist(self, file_hash, file_path):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO whitelist (file_hash, file_path, added_at)
        VALUES (?, ?, ?)
        """, (file_hash, file_path, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    # ---- agent config ----
    def get_config(self, key):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM agent_config WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row["value"] if row else None

    def set_config(self, key, value):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO agent_config (key, value, updated_at)
        VALUES (?, ?, ?)
        """, (key, value, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_stats(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT status, COUNT(*) as c FROM scan_cache GROUP BY status")
        by_status = {r["status"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) as c FROM scan_cache")
        total = cur.fetchone()["c"]
        conn.close()
        return {"total": total, "by_status": by_status}

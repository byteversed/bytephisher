"""Security regression suite — every finding from the adversarial audit.

Each test pins a bug that was found live and then fixed, so it can never come
back silently. Written from the attacker's point of view: the proxy, the static
server, the dashboard, the store and the CLI are all treated as hostile input
sinks.

Run:  ./.venv/bin/python -m pytest tests/test_security.py -v
"""
import http.client
import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import urllib.parse
import urllib.request

import pytest
from conftest import free_port

from core import capture as cap
from core import classify
from core import server as srv
from core.proxy import CAPTURE_PATH, HOOK_PATH, Phishlet, ProxyEngine, serve_proxy

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# =========================================================== SSRF / proxy ====
class InternalService:
    """A loopback service that must NEVER be reachable through the proxy."""

    hits = 0

    def __enter__(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                InternalService.hits += 1
                b = b"INTERNAL-SECRET-DATA"
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.port = free_port()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.15)
        return self

    def __exit__(self, *e):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


class ProxyServer:
    def __init__(self, db, upstream="127.0.0.1:9"):
        self.port = free_port()
        eng = ProxyEngine(Phishlet(name="sec", upstream=upstream, scheme="http",
                                   verify_tls=False),
                          db=db, geo_provider="off")
        self.engine = eng
        self.httpd = serve_proxy(eng, self.port, campaign="sec")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)

    def raw(self, request_bytes, read=400):
        if isinstance(request_bytes, str):
            request_bytes = request_bytes.encode()
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(request_bytes)
        data = b""
        try:
            data = s.recv(read)
        except Exception:
            pass
        s.close()
        return data.decode("utf-8", "replace")

    def get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path, headers=headers or {})
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        pairs = r.getheaders()
        conn.close()
        return r.status, body, pairs

    def stop(self):
        self.httpd.shutdown()


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_sec_"), "s.db"))
    yield d
    d.close()


class TestSSRF:
    """The proxy must never act as a forward proxy or reach internal services."""

    def test_absolute_form_uri_does_not_reach_an_internal_service(self, db):
        with InternalService() as internal:
            p = ProxyServer(db)
            try:
                resp = p.raw(f"GET http://127.0.0.1:{internal.port}/secret HTTP/1.1\r\n"
                             f"Host: x\r\n\r\n")
                assert "INTERNAL-SECRET-DATA" not in resp
                # the path is kept, but it is fetched from OUR upstream only
                assert resp.startswith("HTTP/1.1 502") or "HTTP/1.1 5" in resp
            finally:
                p.stop()

    def test_absolute_form_uri_cannot_address_cloud_metadata(self, db):
        p = ProxyServer(db)
        try:
            resp = p.raw("GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n"
                         "Host: x\r\n\r\n", read=200)
            # it may fail to connect, but it must never return metadata content
            assert "meta-data" not in resp or "502" in resp
            assert "ami-id" not in resp and "iam/" not in resp
        finally:
            p.stop()

    def test_engine_refuses_a_foreign_absolute_url(self, db):
        eng = ProxyEngine(Phishlet(name="x", upstream="upstream.test", scheme="https"),
                          db=db, geo_provider="off")
        sess = eng.session(None, ip="1.2.3.4")
        with pytest.raises(ValueError):
            eng.fetch(sess, "GET", "http://evil.example.com/steal")

    def test_victim_cookies_are_not_sent_to_a_foreign_host(self, db):
        """The SSRF also leaked the victim's upstream jar; that must be gone."""
        InternalService.hits = 0
        with InternalService() as internal:
            p = ProxyServer(db)
            try:
                sess = p.engine.session(None, ip="9.9.9.9")
                sess.note_cookies(p.engine.phishlet, ["auth=SUPERSECRETTOKEN; Path=/"])
                assert "SUPERSECRETTOKEN" in sess.cookie_header()
                p.raw(f"GET http://127.0.0.1:{internal.port}/x HTTP/1.1\r\nHost: x\r\n\r\n")
                # the internal service was never contacted, so the victim's
                # cookie could not have been handed to it
                assert InternalService.hits == 0
            finally:
                p.stop()


@pytest.fixture()
def live_proxy(db):
    """Proxy in front of a real local upstream (a dead upstream returns 502 and
    never reaches the response-header path)."""
    class Up(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = b"<html><head></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sess=X; Path=/; Secure; HttpOnly")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    port = free_port()
    up = socketserver.ThreadingTCPServer(("127.0.0.1", port), Up)
    up.daemon_threads = True
    threading.Thread(target=up.serve_forever, daemon=True).start()
    time.sleep(0.2)
    p = ProxyServer(db, upstream=f"127.0.0.1:{port}")
    yield p
    p.stop()
    up.shutdown()


class TestProxySessionHardening:
    def test_short_sid_is_rejected(self, db):
        p = ProxyServer(db)
        try:
            status, _, pairs = p.get(f"{HOOK_PATH}?s=aaaaaa")
            cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
            assert cookies
            sid = cookies[0].split("=")[1].split(";")[0]
            assert len(sid) >= 32                      # server-generated, not "aaaaaa"
        finally:
            p.stop()

    def test_wellformed_sid_is_accepted(self, db):
        p = ProxyServer(db)
        try:
            good = "a" * 32
            _, _, pairs = p.get(f"{HOOK_PATH}?s={good}")
            cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
            assert any(f"__bhs={good}" in c for c in cookies)
        finally:
            p.stop()

    def test_capture_payload_sid_must_be_wellformed(self, db):
        p = ProxyServer(db)
        try:
            bad = json.dumps({"sid": "../../etc/passwd",
                              "fields": {"username": "a@b.c", "password": "p"},
                              "fingerprint": {"ua": "x"}}).encode()
            conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
            conn.request("POST", CAPTURE_PATH, body=bad,
                         headers={"Content-Type": "application/json"})
            r = conn.getresponse()
            body = json.loads(r.read())
            conn.close()
            assert r.status == 200
            assert body["session"] != "../../etc/passwd"
            assert db.intel_for_session("../../etc/passwd") == {}
        finally:
            p.stop()

    def test_session_cookie_is_httponly(self, live_proxy):
        p = live_proxy
        try:
            _, _, pairs = p.get("/")
            cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
            bhs = [c for c in cookies if c.startswith("__bhs=")]
            assert bhs and "HttpOnly" in bhs[0]
        finally:
            p.stop()

    def test_session_cookie_is_secure_when_the_victim_is_on_https(self, live_proxy):
        p = live_proxy
        try:
            _, _, pairs = p.get("/", headers={"X-Forwarded-Proto": "https"})
            cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
            bhs = [c for c in cookies if c.startswith("__bhs=")]
            assert bhs and "Secure" in bhs[0]
        finally:
            p.stop()

    def test_upstream_secure_flag_kept_over_https_stripped_over_http(self, db):
        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                b = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "sess=X; Path=/; Secure; HttpOnly")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        port = free_port()
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), Upstream)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        p = ProxyServer(db, upstream=f"127.0.0.1:{port}")
        try:
            _, _, plain = p.get("/")
            _, _, tls = p.get("/", headers={"X-Forwarded-Proto": "https"})
            sess_plain = [v for k, v in plain if k.lower() == "set-cookie" and v.startswith("sess=")]
            sess_tls = [v for k, v in tls if k.lower() == "set-cookie" and v.startswith("sess=")]
            assert sess_plain and "; Secure" not in sess_plain[0]
            assert sess_tls and "; Secure" in sess_tls[0]
            assert all("Domain=" not in v for v in sess_plain + sess_tls)
        finally:
            p.stop()
            httpd.shutdown()


class TestResourceLimits:
    def test_proxy_rejects_an_oversized_body(self, db):
        p = ProxyServer(db)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
            conn.putrequest("POST", "/login")
            conn.putheader("Content-Length", str(5 * 1024 * 1024))
            conn.endheaders()
            try:
                conn.send(b"x" * 1024)
            except Exception:
                pass
            r = conn.getresponse()
            assert r.status == 413
            conn.close()
        finally:
            p.stop()

    def test_session_map_is_bounded(self, db):
        from core.proxy import MAX_SESSIONS
        eng = ProxyEngine(Phishlet(name="x", upstream="u.test"), db=db, geo_provider="off")
        for i in range(MAX_SESSIONS + 200):
            eng.session(f"{i:032x}", ip="1.1.1.1")
        assert len(eng.sessions) <= MAX_SESSIONS + 1

    def test_recording_is_capped(self, db):
        p = ProxyServer(db)
        try:
            sess = p.engine.session(None, ip="1.1.1.1")
            for _ in range(40):
                p.engine.capture(sess, {"fields": {"username": "a@b.c", "password": "p"},
                                        "events": [{"t": i} for i in range(500)]},
                                 ip="1.1.1.1")
            assert len(sess.recording) <= 5000
        finally:
            p.stop()


# ===================================================== dashboard / output ====
class TestDashboardEscaping:
    def test_row_values_are_escaped_before_insertadjacenthtml(self):
        src = open(os.path.join(HERE, "dashboard", "__init__.py")).read()
        assert "insertAdjacentHTML" in src
        # every interpolated value in rowHtml must go through esc()
        row = src.split("function rowHtml")[1].split("function setStats")[0]
        for var in ("c.campaign", "c.ip", "c.device", "c.city"):
            assert f"esc({var}" in row, var
        assert "esc(k)" in row and "esc(v)" in row
        # no raw interpolation of an attacker-controlled value survives
        for bad in ("${c.campaign}", "${c.ip}", "${c.device}"):
            assert bad not in row, bad

    def test_terminal_output_is_sanitised(self):
        import dashboard
        cell = dashboard._safe_cell("\x1b[2J[red]spoof[/red] evil")
        assert "\x1b" not in cell
        # every opening bracket is escaped (rich markup neutralised)
        assert cell.count("[") == cell.count("\\[") == 2, cell
        assert "red" in cell and "spoof" in cell   # content still readable

    def test_control_characters_are_stripped(self):
        import dashboard
        assert "\x07" not in dashboard._safe_cell("a\x07b")
        assert "\x00" not in dashboard._safe_cell("a\x00b")


class TestCSVExport:
    def test_formula_injection_is_neutralised(self, db):
        db.record("/", "1.1.1.1", "", "", "", "ua", "android",
                  {"email": '=HYPERLINK("http://evil","x")', "password": "p"}, True)
        db.record("/", "1.1.1.2", "", "", "", "ua", "android",
                  {"email": "+1+1", "password": "p"}, True)
        db.record("/", "1.1.1.3", "", "", "", "ua", "android",
                  {"email": "@SUM(A1)", "password": "p"}, True)
        out = os.path.join(tempfile.mkdtemp(), "c.csv")
        db.export_csv(out)
        text = open(out).read()
        for payload in ("'=HYPERLINK", "'+1+1", "'@SUM"):
            assert payload in text, payload
        # no cell may start with a formula character
        for line in text.splitlines()[1:]:
            for cell in line.split(","):
                assert cell[:1] not in ("=", "+", "@"), line


class TestImportSite:
    def test_file_scheme_is_refused(self):
        from tools import import_site
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/y"):
            with pytest.raises(ValueError):
                import_site.fetch(url)


# ================================================ server-side classification =
class TestCredentialDetection:
    def test_shipping_field_is_not_a_password(self):
        assert classify.is_credential_pair({"email": "a@b.c",
                                            "shipping": "123 Main St"}) is False
        assert classify.is_credential_pair({"email": "a@b.c",
                                            "shipping_address": "x"}) is False

    def test_real_pairs_are_detected(self):
        for fields in ({"email": "a@b.c", "password": "x"},
                       {"login_id": "u", "passwd": "x"},
                       {"user": "u", "user_pin": "1234"},
                       {"username": "u", "passphrase": "x"},
                       {"account": "u", "pwd": "x"}):
            assert classify.is_credential_pair(fields) is True, fields

    def test_identity_alone_is_not_a_pair(self):
        assert classify.is_credential_pair({"email": "a@b.c"}) is False
        assert classify.is_credential_pair({"password": "x"}) is False
        assert classify.is_credential_pair({}) is False

    def test_otp_submission_is_not_a_pair(self):
        assert classify.is_credential_pair({"otp": "123456"}) is False
        assert classify.looks_like_otp({"otp": "123456"}) is True
        assert classify.looks_like_otp({"password": "x", "otp": "1"}) is False

    def test_server_and_proxy_agree(self, db):
        eng = ProxyEngine(Phishlet(name="x", upstream="u.test"), db=db, geo_provider="off")
        samples = [{"email": "a@b.c", "password": "x"},
                   {"email": "a@b.c", "shipping": "123 Main St"},
                   {"login_id": "u", "passwd": "x"},
                   {"otp": "123456"}]
        for f in samples:
            assert srv._is_creds(f) == eng._looks_like_credentials(f), f


class TestBlankAndDuplicateFields:
    def test_blank_urlencoded_value_is_kept(self):
        f = srv._extract_fields(b"email=&password=secret123",
                                "application/x-www-form-urlencoded")
        assert f.get("email") == "" and f.get("password") == "secret123"

    def test_blank_identity_still_counts_as_a_pair_field(self):
        # the field exists (blank), so the submission is a credential pair shape
        f = srv._extract_fields(b"email=&password=x",
                                "application/x-www-form-urlencoded")
        assert classify.is_credential_pair(f) is True

    def test_json_and_multipart_blanks(self):
        j = srv._extract_fields(json.dumps({"email": "", "password": "x"}).encode(),
                                "application/json")
        assert j.get("email") == "" and j.get("password") == "x"


class TestGatingHardening:
    def test_post_counts_against_the_hit_cap(self):
        from core.gate import Gate
        g = Gate(max_hits_per_ip=2)
        # simulate what the handler does now on every POST
        hits = 0
        for _ in range(5):
            allowed = g.hits("9.9.9.9") < g.max_hits
            g.note_hit("9.9.9.9")
            hits += 1 if allowed else 0
        assert hits == 2

    def test_post_requests_are_capped_over_http(self):
        from core.gate import Gate
        dbfile = os.path.join(tempfile.mkdtemp(), "gate.db")
        port = free_port()
        httpd, _ = srv.serve(os.path.join(HERE, "templates"),
                             os.path.join(HERE, "templates", "03_google"), port, dbfile,
                             geo_provider="off", gate=Gate(max_hits_per_ip=2),
                             campaign="cap")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            codes = []
            for _ in range(5):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("POST", "/", body=urllib.parse.urlencode(
                    {"email": "a@b.c", "password": "x"}),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                r = conn.getresponse()
                codes.append(r.status)
                r.read()
                conn.close()
            assert codes.count(200) <= 3, codes       # the cap bites on POST too
        finally:
            httpd.shutdown()

    def test_no_trust_headers_ignores_spoofed_xff(self):
        dbfile = os.path.join(tempfile.mkdtemp(), "gate2.db")
        port = free_port()
        from core.gate import Gate
        httpd, _ = srv.serve(os.path.join(HERE, "templates"),
                             os.path.join(HERE, "templates", "03_google"), port, dbfile,
                             geo_provider="off", gate=Gate(max_hits_per_ip=2),
                             campaign="cap2", trust_headers=False)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            codes = []
            for i in range(6):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/", headers={"X-Forwarded-For": f"10.0.0.{i}"})
                r = conn.getresponse()
                codes.append(r.status)
                r.read()
                conn.close()
            # rotating XFF must not defeat the cap when headers are untrusted
            assert codes.count(200) <= 3, codes
        finally:
            httpd.shutdown()


class TestTLSGuard:
    def test_tls_without_cert_refuses_to_start(self):
        with pytest.raises(ValueError):
            srv.serve(os.path.join(HERE, "templates"),
                      os.path.join(HERE, "templates", "03_google"),
                      free_port(), os.path.join(tempfile.mkdtemp(), "t.db"),
                      geo_provider="off", tls=True, cert_path=None)


class TestCampaignScopedStats:
    def test_visitors_are_scoped_to_the_campaign(self, db):
        db.record("/", "1.1.1.1", "", "", "", "ua", "android",
                  {"email": "a@b.c", "password": "p"}, True, campaign="alpha")
        db.record("/", "2.2.2.2", "", "", "", "ua", "android",
                  {"email": "c@d.e", "password": "p"}, True, campaign="beta")
        db.log_visit("3.3.3.3", "ua")
        db.log_visit("4.4.4.4", "ua")
        assert db.stats(campaign="alpha")["visitors"] == 1
        assert db.stats(campaign="beta")["visitors"] == 1
        assert db.stats()["visitors"] == 4          # global view: all distinct visitors

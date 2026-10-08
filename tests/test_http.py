"""BytePhisher HTTP-level tests — real server, real sockets, real SQLite.

Run:  ./.venv/bin/python -m pytest tests/test_http.py -v
"""
import contextlib
import http.client
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import FIXTURES, TEMPLATES, StubHTTP, free_port

from core import capture as cap
from core import server as srv

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration



# ------------------------------------------------------------- fixtures ------
class ServerFixture:
    def __init__(self, site="03_google", geo="off", redirect="", otp=False,
                 notifier=None, tls=False):
        # unique DB per fixture: deriving the path from the port collided when
        # the OS re-handed-out a port, leaking rows into the next test
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bp_http_"), "caps.db")
        self.port = free_port()
        self.site_dir = os.path.join(TEMPLATES, site)
        self.site_name = site.split("_", 1)[-1]
        self.httpd, _ = srv.serve(
            TEMPLATES, self.site_dir, self.port, self.db_path,
            geo_provider=geo, redirect_url=redirect, otp=otp,
            on_capture=notifier, site_name=self.site_name,
            tls=tls, cert_path=os.path.join(FIXTURES, "cert_cert.pem") if tls else None)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.db = cap.CaptureDB(self.db_path)
        time.sleep(0.25)

    @property
    def base(self):
        scheme = "https" if self.httpd.socket.__class__.__name__ == "SSLSocket" else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def opener(self, follow_redirects=True):
        if follow_redirects:
            return urllib.request.build_opener()
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        return urllib.request.build_opener(_NoRedirect)

    def get(self, path="/", headers=None, follow=True, timeout=10):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        return self.opener(follow).open(req, timeout=timeout)

    def post(self, path="/", data=None, ctype="application/x-www-form-urlencoded",
             headers=None, follow=True, raw=None, timeout=10):
        if raw is None:
            raw = urllib.parse.urlencode(data or {}).encode()
        h = {"Content-Type": ctype}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=raw, headers=h)
        try:
            return self.opener(follow).open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            return e

    def stop(self):
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
        with contextlib.suppress(Exception):
            self.db.close()


@pytest.fixture()
def srv_default():
    s = ServerFixture()
    yield s
    s.stop()


# =============================================================== GET =========
class TestGet:
    def test_login_page(self, srv_default):
        r = srv_default.get("/")
        body = r.read().decode()
        assert r.status == 200
        assert r.headers["Content-Type"].startswith("text/html")
        assert "Log in to Google" in body
        assert 'name="password"' in body and 'method="POST"' in body

    def test_catch_all_paths(self, srv_default):
        for p in ["/auth/login", "/session/new?next=%2F", "/index.html", "/a/b/c"]:
            assert srv_default.get(p).status == 200, p

    def test_health_endpoint(self, srv_default):
        r = srv_default.get("/health")
        assert r.status == 200 and r.read() == b"ok"

    def test_tracking_pixel(self, srv_default):
        before = srv_default.db.stats()["visitors"]
        r = srv_default.get("/px.gif")
        data = r.read()
        assert r.status == 200
        assert r.headers["Content-Type"] == "image/gif"
        assert data.startswith(b"GIF89a") and len(data) == len(srv.GIF_1PX)
        time.sleep(0.2)
        assert srv_default.db.stats()["visitors"] == before + 1

    def test_get_counts_a_visit(self, srv_default):
        before = srv_default.db.stats()["visitors"]
        srv_default.get("/")
        time.sleep(0.2)
        # exactly one new visitor: >= 1 hid a double-count regression
        assert srv_default.db.stats()["visitors"] == before + 1

    def test_repeated_get_is_one_visitor(self, srv_default):
        for _ in range(3):
            srv_default.get("/")
        time.sleep(0.3)
        assert srv_default.db.stats()["visitors"] == 1


# =============================================================== POST ========
class TestPost:
    def test_urlencoded_capture(self, srv_default):
        srv_default.post("/", {"email": "http@example.com", "password": "P@ss!",
                               "_tpl": "google"})
        time.sleep(0.2)
        rows = srv_default.db.all()
        assert len(rows) == 1
        assert rows[0]["fields"]["email"] == "http@example.com"
        assert rows[0]["is_cred"] is True

    def test_multipart_capture(self, srv_default):
        b = "----bps"
        raw = (f"--{b}\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\n"
               f"mp@example.com\r\n--{b}\r\nContent-Disposition: form-data; "
               f"name=\"password\"\r\n\r\nMPpass\r\n--{b}--\r\n").encode()
        srv_default.post("/", ctype=f"multipart/form-data; boundary={b}", raw=raw)
        time.sleep(0.2)
        assert srv_default.db.all()[0]["fields"]["email"] == "mp@example.com"

    def test_json_capture(self, srv_default):
        raw = json.dumps({"email": "json@example.com", "password": "jsonpw"}).encode()
        srv_default.post("/", ctype="application/json", raw=raw)
        time.sleep(0.2)
        assert srv_default.db.all()[0]["fields"]["email"] == "json@example.com"

    def test_unicode_capture(self, srv_default):
        srv_default.post("/", {"username": "सूरज", "password": "🔐päss"})
        time.sleep(0.2)
        f = srv_default.db.all()[0]["fields"]
        assert f["username"] == "सूरज" and f["password"] == "🔐päss"

    def test_honeypot_value_recorded(self, srv_default):
        srv_default.post("/", {"email": "bot@example.com", "password": "x",
                               "hp_email": "autofilled@example.com"})
        time.sleep(0.2)
        assert srv_default.db.all()[0]["fields"]["hp_email"] == "autofilled@example.com"

    def test_timing_field_recorded(self, srv_default):
        srv_default.post("/", {"email": "a@b.c", "password": "x", "_ts": "4123"})
        time.sleep(0.2)
        assert srv_default.db.all()[0]["fields"]["_ts"] == "4123"

    def test_empty_post_is_not_creds_and_does_not_crash(self, srv_default):
        r = srv_default.post("/", raw=b"", ctype="application/x-www-form-urlencoded")
        assert r.status == 200
        time.sleep(0.2)
        rows = srv_default.db.all()
        assert rows and rows[0]["is_cred"] is False

    def test_otp_only_post_is_not_creds(self, srv_default):
        srv_default.post("/otp", {f"otp_{i}": str(i) for i in range(1, 7)})
        time.sleep(0.2)
        assert srv_default.db.all()[0]["is_cred"] is False

    def test_large_body(self, srv_default):
        big = "B" * 100_000
        srv_default.post("/", {"email": "big@example.com", "password": big})
        time.sleep(0.3)
        assert len(srv_default.db.all()[0]["fields"]["password"]) == 100_000

    def test_thankyou_default_response(self, srv_default):
        body = srv_default.post("/", {"email": "a@b.c", "password": "x"}).read().decode()
        assert "Thank you" in body

    def test_referer_stored_as_source(self, srv_default):
        srv_default.post("/", {"email": "a@b.c", "password": "x"},
                         headers={"Referer": "https://mail.example.com/inbox"})
        time.sleep(0.2)
        assert srv_default.db.all()[0]["source_url"] == "https://mail.example.com/inbox"


# ======================================================= IP resolution =======
class TestClientIP:
    def _captured_ip(self, server, headers):
        server.post("/", {"email": "ip@example.com", "password": "x"}, headers=headers)
        time.sleep(0.2)
        return server.db.all()[0]["ip"]

    def test_cf_connecting_ip_wins(self, srv_default):
        ip = self._captured_ip(srv_default, {
            "CF-Connecting-IP": "203.0.113.9",
            "X-Forwarded-For": "198.51.100.7, 10.0.0.1"})
        assert ip == "203.0.113.9"

    def test_x_real_ip(self, srv_default):
        assert self._captured_ip(srv_default, {"X-Real-IP": "203.0.113.10"}) == "203.0.113.10"

    def test_xff_first_hop(self, srv_default):
        assert self._captured_ip(srv_default, {"X-Forwarded-For": "198.51.100.7, 10.0.0.1"}) == "198.51.100.7"

    def test_socket_fallback(self, srv_default):
        assert self._captured_ip(srv_default, {}) == "127.0.0.1"


# ======================================================== device over HTTP ===
class TestDeviceOverHTTP:
    @pytest.mark.parametrize("ua,expect", [
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "ios"),
        ("Mozilla/5.0 (Linux; Android 14; Pixel 8)", "android"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"),
    ])
    def test_ua_classified_on_real_request(self, srv_default, ua, expect):
        srv_default.post("/", {"email": "a@b.c", "password": "x"},
                         headers={"User-Agent": ua})
        time.sleep(0.2)
        assert srv_default.db.all()[0]["device"] == expect


# ========================================================== behaviour =======
class TestBehaviourModes:
    def test_redirect_mode(self):
        s = ServerFixture(redirect="https://example.com/landing")
        try:
            r = s.post("/", {"email": "a@b.c", "password": "x"}, follow=False)
            assert r.status == 302
            assert r.headers["Location"] == "https://example.com/landing"
            time.sleep(0.2)
            assert s.db.stats()["credentials"] == 1   # captured even with redirect
        finally:
            s.stop()

    def test_otp_flow(self):
        s = ServerFixture(otp=True)
        try:
            assert 'name="password"' in s.get("/").read().decode()
            assert 'name="otp_1"' not in s.get("/").read().decode()
            assert 'name="otp_1"' in s.get("/otp").read().decode()
            after_creds = s.post("/", {"email": "otp@example.com", "password": "x"}).read().decode()
            assert 'name="otp_1"' in after_creds and after_creds.count('name="otp_') == 6
            s.post("/otp", {f"otp_{i}": str(i) for i in range(1, 7)})
            time.sleep(0.3)
            rows = s.db.all()
            assert len(rows) == 2
            assert rows[1]["fields"]["email"] == "otp@example.com" and rows[1]["is_cred"]
            assert rows[0]["fields"]["otp_3"] == "3" and not rows[0]["is_cred"]
        finally:
            s.stop()

    def test_tls_mode(self):
        s = ServerFixture(tls=True)
        try:
            ctx = ssl._create_unverified_context()
            r = urllib.request.urlopen(s.base + "/", context=ctx, timeout=10)
            assert r.status == 200 and "Log in to Google" in r.read().decode()
        finally:
            s.stop()

    def test_notifier_fires_end_to_end(self):
        stub = StubHTTP()
        try:
            from core.alerts import make_notifier
            s = ServerFixture(notifier=make_notifier(webhook=stub.url, async_=False))
            try:
                s.post("/", {"email": "alert@example.com", "password": "S3cret!"},
                       headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
                time.sleep(0.3)
                assert len(stub.received) == 1
                payload = json.loads(stub.received[0]["body"])
                assert payload["capture"]["fields"]["email"] == "alert@example.com"
                assert payload["capture"]["device"] == "windows"
                assert payload["capture"]["template"] == "google"
            finally:
                s.stop()
        finally:
            stub.stop()

    def test_broken_notifier_does_not_break_capture(self):
        def boom(_c):
            raise RuntimeError("webhook exploded")
        s = ServerFixture(notifier=boom)
        try:
            r = s.post("/", {"email": "safe@example.com", "password": "x"})
            assert r.status == 200
            time.sleep(0.2)
            assert s.db.all()[0]["fields"]["email"] == "safe@example.com"
        finally:
            s.stop()


# ======================================================== concurrency ========
class TestConcurrency:
    def test_forty_parallel_submissions(self, srv_default):
        results = []
        def worker(i):
            try:
                c = http.client.HTTPConnection("127.0.0.1", srv_default.port, timeout=15)
                body = urllib.parse.urlencode({
                    "email": f"load{i}@example.com", "password": f"pw{i}",
                    "_tpl": "google"})
                c.request("POST", "/", body=body,
                          headers={"Content-Type": "application/x-www-form-urlencoded",
                                   "User-Agent": f"Agent/{i}"})
                results.append(c.getresponse().status)
                c.close()
            except Exception as e:
                results.append(f"ERR:{type(e).__name__}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        bad = [r for r in results if r != 200]
        assert not bad, f"{len(bad)} non-200 responses: {bad[:10]}"
        time.sleep(0.5)
        st = srv_default.db.stats()
        assert st["total_captures"] == 40
        assert st["credentials"] == 40
        assert st["visitors"] == 40          # 40 distinct UAs
        emails = {r["fields"]["email"] for r in srv_default.db.all(limit=100)}
        assert len(emails) == 40             # no lost or crossed writes

    def test_concurrent_mixed_reads_and_writes(self, srv_default):
        def poster(i):
            c = http.client.HTTPConnection("127.0.0.1", srv_default.port, timeout=15)
            body = urllib.parse.urlencode({"email": f"m{i}@x.com", "password": "p"})
            c.request("POST", "/", body=body,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            c.getresponse().read()
            c.close()

        def reader():
            for _ in range(10):
                srv_default.get("/")

        ts = [threading.Thread(target=poster, args=(i,)) for i in range(15)]
        ts += [threading.Thread(target=reader) for _ in range(3)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        time.sleep(0.4)
        assert srv_default.db.stats()["total_captures"] == 15


# ==================================================== malformed framing =======
class TestMalformedFraming:
    """Raw-socket cases.

    `int(Content-Length)` raised ValueError -> dropped connection + a traceback in the
    operator's log; a negative length reached read(-1) and held the worker; and a
    request carrying both Content-Length and Transfer-Encoding (or two lengths) let a
    client smuggle a second request past the first one's body.
    """

    def _raw(self, srv, request, read=8192, timeout=10):
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=timeout)
        try:
            s.sendall(request)
            try:
                return s.recv(read).decode("utf-8", "replace")
            except TimeoutError:
                return "<no answer: the server held the connection>"
        finally:
            s.close()

    def _head(self, r):
        return r.split("\r\n", 1)[0]

    def test_a_non_numeric_content_length_is_a_400(self, srv_default):
        r = self._raw(srv_default, b"POST / HTTP/1.1\r\nHost: x.test\r\n"
                                   b"Content-Length: abc\r\n\r\n")
        assert " 400 " in self._head(r), r[:120]

    def test_an_oversized_content_length_is_a_413(self, srv_default):
        r = self._raw(srv_default, b"POST / HTTP/1.1\r\nHost: x.test\r\n"
                                   b"Content-Length: 99999999\r\n\r\n")
        assert " 413 " in self._head(r), r[:120]

    def test_a_negative_content_length_is_answered_not_held(self, srv_default):
        r = self._raw(srv_default, b"POST / HTTP/1.1\r\nHost: x.test\r\n"
                                   b"Content-Length: -1\r\n\r\n")
        assert "<no answer" not in r, "read(-1) held the worker thread"

    def test_length_plus_transfer_encoding_is_refused(self, srv_default):
        r = self._raw(srv_default, b"POST / HTTP/1.1\r\nHost: x.test\r\n"
                                   b"Content-Length: 0\r\n"
                                   b"Transfer-Encoding: chunked\r\n\r\n")
        assert " 400 " in self._head(r), r[:120]

    def test_a_duplicated_content_length_is_refused(self, srv_default):
        r = self._raw(srv_default, b"POST / HTTP/1.1\r\nHost: x.test\r\n"
                                   b"Content-Length: 0\r\nContent-Length: 5\r\n\r\n")
        assert " 400 " in self._head(r), r[:120]

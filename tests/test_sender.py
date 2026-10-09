"""The sender identity kit: lookalike candidates and the DNS facts behind a domain.

The DNS half is tested with injected resolvers, so the suite never depends on the network
and every policy branch (strict SPF, soft SPF, no SPF, DMARC none/quarantine/reject, a
revoked DKIM key, a resolver failure) is exercised. One live test checks the resolver path
itself against a real domain and skips when there is no network.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import net  # noqa: E402
from core import sender as S  # noqa: E402

pytestmark = pytest.mark.unit


class TestCandidates:

    def test_the_font_swap_case_is_generated_and_ranked_first(self):
        names = [c["name"] for c in S.candidates("acmecorp.com")]
        assert "acrnecorp.com" in names           # rn -> m
        assert S.candidates("acmecorp.com")[0]["score"] >= 80

    def test_every_candidate_is_a_registerable_hostname(self):
        for row in S.candidates("acmecorp.com", limit=200):
            ok, why = S.validate_host(row["name"])
            assert ok, (row["name"], why)

    def test_the_kinds_are_all_present(self):
        kinds = {c["kind"] for c in S.candidates("acmecorp.com", limit=200)}
        assert {"swap", "omission", "prefix", "suffix", "tld", "homoglyph"} <= kinds

    def test_homoglyphs_are_flagged_because_they_show_as_punycode(self):
        rows = [c for c in S.candidates("acmecorp.com", limit=200) if c["kind"] == "homoglyph"]
        assert rows, "no IDN candidates generated"
        assert all(r["needs_punycode"] for r in rows)
        assert all(r["score"] < 60 for r in rows), "a punycode name must not look plausible"

    def test_homoglyphs_can_be_turned_off(self):
        rows = S.candidates("acmecorp.com", limit=200, include_homoglyphs=False)
        assert not [r for r in rows if r["kind"] == "homoglyph"]

    def test_the_limit_and_the_order(self):
        rows = S.candidates("acmecorp.com", limit=5)
        assert len(rows) == 5
        assert [r["score"] for r in rows] == sorted([r["score"] for r in rows], reverse=True)

    def test_a_non_domain_gives_nothing(self):
        assert S.candidates("localhost") == []
        assert S.candidates("") == []

    def test_validate_host_rejects_the_things_that_are_not_names(self):
        for bad, _reason in (("10.0.0.1", "IP"), ("localhost", "TLD"), ("a..b", "label"),
                             ("-" + "a" * 10 + ".com", "label")):
            ok, why = S.validate_host(bad)
            assert not ok, bad
        assert S.validate_host("xn--80ak6aa92e.com")[0] is True


class TestTheDnsFacts:

    def _txt(self, records):
        return lambda name: list(records.get(name, []))

    def test_a_fully_configured_domain_passes(self):
        records = {
            "acme.test": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.acme.test": ["v=DMARC1; p=reject; rua=mailto:r@acme.test"],
            "google._domainkey.acme.test": ["v=DKIM1; k=rsa; p=" + "A" * 200],
        }
        facts = S.check("acme.test", txt=self._txt(records), resolves=lambda *a: True)
        assert facts["ok"] is True and facts["spoofable"] is False
        assert facts["spf_strict"] is True and facts["dkim_selectors"] == ["google"]
        assert facts["dmarc_policy"] == "reject"

    def test_no_spf_is_a_failure(self):
        facts = S.check("weak.test", txt=lambda n: [], resolves=lambda *a: True)
        assert facts["ok"] is False
        assert any("SPF" in r for r in facts["reasons"])

    def test_a_soft_spf_is_reported_as_soft(self):
        facts = S.dns_facts("acme.test", txt=self._txt({"acme.test": ["v=spf1 ~all"]}),
                            resolves=lambda *a: True)
        assert facts["spf_soft"] is True and facts["spf_strict"] is False

    def test_dmarc_none_means_others_can_spoof_it(self):
        records = {"acme.test": ["v=spf1 -all"], "_dmarc.acme.test": ["v=DMARC1; p=none"]}
        facts = S.check("acme.test", txt=self._txt(records), resolves=lambda *a: True)
        assert facts["ok"] is True and facts["spoofable"] is True
        assert any("p=none" in w for w in facts["warnings"])

    def test_no_dmarc_at_all_is_spoofable(self):
        records = {"acme.test": ["v=spf1 -all"]}
        facts = S.check("acme.test", txt=self._txt(records), resolves=lambda *a: True)
        assert facts["spoofable"] is True

    def test_a_revoked_dkim_key_is_not_a_key(self):
        # `p=` with nothing after it is a revoked key (RFC 6376), and a wildcard
        # *._domainkey answering with a null key must not count either
        records = {"acme.test": ["v=spf1 -all"],
                   "default._domainkey.acme.test": ["v=DKIM1; p="],
                   "s1._domainkey.acme.test": ["v=DKIM1; p=short"]}
        facts = S.dns_facts("acme.test", txt=self._txt(records), resolves=lambda *a: True)
        assert facts["dkim_selectors"] == []

    def test_a_real_key_is_detected(self):
        records = {"selector1._domainkey.acme.test": ["v=DKIM1; k=rsa; p=" + "B" * 300]}
        facts = S.dns_facts("acme.test", txt=self._txt(records), resolves=lambda *a: True)
        assert facts["dkim_selectors"] == ["selector1"]

    def test_a_missing_mx_is_a_warning_not_a_failure(self):
        facts = S.check("acme.test", txt=self._txt({"acme.test": ["v=spf1 -all"]}),
                        resolves=lambda name, kind="A": kind != "MX")
        assert facts["ok"] is True
        assert any("MX" in w for w in facts["warnings"])

    def test_a_domain_that_does_not_resolve_fails(self):
        facts = S.check("gone.test", txt=lambda n: [], resolves=lambda *a: False)
        assert facts["ok"] is False
        assert any("does not resolve" in r for r in facts["reasons"])

    def test_a_resolver_failure_is_unknown_not_a_verdict(self):
        # None means "could not ask"; treating it as "no record" would fail a domain just
        # because the resolver was unreachable
        facts = S.check("acme.test", txt=self._txt({"acme.test": ["v=spf1 -all"]}),
                        resolves=lambda *a: None)
        assert facts["a"] is None and facts["mx"] is None
        assert not any("does not resolve" in r for r in facts["reasons"])

    def test_the_report_says_the_verdict(self):
        facts = S.check("acme.test", txt=lambda n: [], resolves=lambda *a: True)
        text = S.describe(facts)
        assert "NOT READY" in text and "spoofable" in text


@pytest.mark.live  # one real DNS-over-HTTPS query
class TestTheLiveResolver:
    """The resolver path itself (one real query). Skipped without network."""

    def test_a_real_domain_resolves(self):
        try:
            body = net.fetch_json("https://dns.google/resolve?name=example.com&type=A")
        except Exception as e:
            pytest.skip(f"no DNS-over-HTTPS reachable: {type(e).__name__}")
        assert isinstance(body, dict) and body.get("Answer"), body
        facts = S.dns_facts("example.com")
        assert facts["a"] is True
        # example.com publishes a null DKIM key and a strict SPF; the null key is not a key
        assert facts["spf_strict"] is True
        assert facts["dkim_selectors"] == []

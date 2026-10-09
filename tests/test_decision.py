"""The click-to-access decision matrix.

Every test drives decide() with a COMPLETE capability map of stubs, so the suite is
hermetic: it never depends on which leaf modules happen to exist on this machine, and a
module appearing later cannot silently change a verdict. The stubs are duck-typed - the
matrix only asks each capability for the one call it documents.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import decision as D  # noqa: E402

pytestmark = pytest.mark.unit


class Stub:
    """A present capability. `match`/`plan` are added by the subclasses that need them."""


class PackStub(Stub):
    def __init__(self, matches=None, boom=False):
        self.matches = matches if matches is not None else []
        self.boom = boom
        self.seen = None

    def match(self, facts):
        self.seen = facts
        if self.boom:
            raise RuntimeError("matcher exploded")
        return self.matches


def caps(**overrides):
    """A full capability map: every name is either a stub or explicitly None."""
    out = {name: Stub() for name in D.CAPABILITIES}
    for name, value in overrides.items():
        out[name] = value
    return out


def windows_facts(**overrides):
    facts = {"os": "Windows", "browser": "MSIE", "version": "11", "intranet": False}
    facts.update(overrides)
    return facts


class TestNormalise:

    def test_os_spellings_collapse_to_one_name(self):
        assert D.normalise_os("Windows NT 10.0") == "windows"
        assert D.normalise_os("Mac OS X") == "macos"
        assert D.normalise_os("Ubuntu") == "linux"
        assert D.normalise_os("iPhone") == "ios"
        assert D.normalise_os("") == "unknown"
        assert D.normalise_os("plan9") == "unknown"

    def test_browser_spellings_collapse_to_one_name(self):
        assert D.normalise_browser("MSIE 11.0") == "ie"
        assert D.normalise_browser("Chrome/91.0.4472.124") == "chrome"
        assert D.normalise_browser("Edg/120.0") == "edge"
        assert D.normalise_browser("") == "unknown"
        assert D.normalise_browser("lynx") == "unknown"

    def test_a_version_is_reduced_to_its_major(self):
        f = D.normalise({"browser": "Chrome", "version": "91.0.4472.124"})
        assert f["version"] == 91
        assert D.normalise({"browser": "Chrome", "version": "120"})["version"] == 120
        assert D.normalise({"browser": "Chrome"})["version"] is None
        assert D.normalise({"browser": "Chrome", "version": "unknown"})["version"] is None

    def test_string_flags_are_read_as_words_not_as_truthiness(self):
        """"no"/"false"/"0" must be False: a form that posts strings cannot read as yes."""
        f = D.normalise({"os": "windows", "smb_reachable": "no",
                         "http_ntlm_relay_ready": "false", "relay_target": "0",
                         "intranet": "yes"})
        assert f["smb_reachable"] is False
        assert f["http_ntlm_relay_ready"] is False
        assert f["relay_target"] is False
        assert f["intranet"] is True

    def test_ie_is_inferred_from_the_browser_on_windows(self):
        assert D.normalise({"os": "windows", "browser": "MSIE"})["is_ie"] is True
        assert D.normalise({"os": "windows", "browser": "Chrome"})["is_ie"] is False
        assert D.normalise({"os": "linux", "browser": "MSIE"})["is_ie"] is False

    def test_an_unknown_policy_is_kept_as_unknown_not_as_allowed(self):
        assert D.normalise({"os": "windows"})["macro_policy"] == "unknown"
        assert D.normalise({"os": "windows", "macro_policy": "allowed"})["macro_policy"] \
            == "allowed"
        assert D.normalise({"os": "windows", "macro_policy": "maybe"})["macro_policy"] \
            == "unknown"

    def test_services_may_arrive_as_a_comma_string(self):
        f = D.normalise({"os": "linux", "local_services": "docker,jenkins , "})
        assert f["local_services"] == ["docker", "jenkins"]
        assert D.normalise({"os": "linux"})["local_services"] == []

    def test_a_non_mapping_is_refused(self):
        with pytest.raises(ValueError):
            D.normalise(["windows"])
        with pytest.raises(ValueError):
            D.normalise(None)


class TestUserAgents:
    """A full user agent is the input this module actually receives from a campaign, and
    it carries several OS and browser tokens at once: the order of the checks decides."""

    CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    SAFARI_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/17.0 Safari/605.1.15")
    SAFARI_IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                     "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
                     "Safari/604.1")
    ANDROID_CHROME = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
    EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91")
    OPERA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0")
    IE11 = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
    FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

    def test_an_iphone_is_not_read_as_a_mac(self):
        assert D.normalise_os(self.SAFARI_IPHONE) == "ios"
        assert D.normalise_os(self.SAFARI_MAC) == "macos"

    def test_an_android_is_not_read_as_linux(self):
        assert D.normalise_os(self.ANDROID_CHROME) == "android"
        assert D.normalise_os(self.FIREFOX) == "linux"

    def test_the_specific_browser_wins_over_the_tokens_it_imitates(self):
        assert D.normalise_browser(self.EDGE) == "edge"
        assert D.normalise_browser(self.OPERA) == "opera"
        assert D.normalise_browser(self.CHROME_WIN) == "chrome"
        assert D.normalise_browser(self.SAFARI_MAC) == "safari"
        assert D.normalise_browser(self.IE11) == "ie"

    def test_facts_from_a_user_agent_carry_the_major_version(self):
        assert D.facts_from_ua(self.CHROME_WIN) == {"os": "windows", "browser": "chrome",
                                                    "version": 91, "is_ie": False}
        assert D.facts_from_ua(self.ANDROID_CHROME)["version"] == 120
        assert D.facts_from_ua(self.SAFARI_IPHONE)["version"] == 17
        assert D.facts_from_ua(self.IE11)["is_ie"] is True
        assert D.facts_from_ua("")["version"] is None

    def test_facts_from_a_user_agent_do_not_invent_lan_or_relay_facts(self):
        """The string says nothing about the LAN, the relay or a macro policy, and the
        matrix depends on those being absent rather than assumed."""
        facts = D.facts_from_ua(self.CHROME_WIN)
        assert "local_services" not in facts and "relay_target" not in facts
        assert "macro_policy" not in facts


class TestTheRelayPath:

    def test_a_windows_victim_with_a_relay_target_is_the_top_path(self):
        facts = windows_facts(http_ntlm_relay_ready=True, relay_target=True)
        result = D.decide(facts, caps=caps())
        assert result["best"] == "T2_ntlm_relay"
        assert result["payoff"] == "domain-access"
        top = result["paths"][0]
        assert top["path"] == "T2_ntlm_relay" and top["confidence"] == "CONFIRMED"
        assert top["ready"] is True and top["missing"] == []

    def test_without_a_relay_target_the_path_is_not_ready_and_says_why(self):
        facts = windows_facts(http_ntlm_relay_ready=True, relay_target=False)
        result = D.decide(facts, caps=caps())
        relay = next(p for p in result["paths"] if p["path"] == "T2_ntlm_relay")
        assert relay["ready"] is False and relay["confidence"] == "SUSPECTED"
        assert any("relay target" in m for m in relay["missing"])

    def test_a_non_windows_host_fails_the_relay_path_outright(self):
        result = D.decide({"os": "linux", "browser": "firefox"}, caps=caps())
        relay = next(p for p in result["paths"] if p["path"] == "T2_ntlm_relay")
        assert relay["confidence"] == "FAILED" and relay["ready"] is False

    def test_a_missing_trigger_module_is_named_not_hidden(self):
        result = D.decide(windows_facts(http_ntlm_relay_ready=True, relay_target=True),
                          caps=caps(mshtml=None))
        relay = next(p for p in result["paths"] if p["path"] == "T2_ntlm_relay")
        assert relay["confidence"] == "SUSPECTED"
        assert any("mshtml" in m for m in relay["missing"])


class TestTheIntranetPath:

    def test_a_seen_local_service_makes_it_ready(self):
        result = D.decide({"os": "windows", "local_services": ["docker", "jenkins"]},
                          caps=caps())
        intranet = next(p for p in result["paths"] if p["path"] == "T1_intranet")
        assert intranet["ready"] is True and intranet["confidence"] == "CONFIRMED"
        assert intranet["services"] == ["docker", "jenkins"]
        assert intranet["payoff"] == "host-access"

    def test_no_service_seen_is_waiting_on_the_lan_probe(self):
        result = D.decide({"os": "windows"}, caps=caps())
        intranet = next(p for p in result["paths"] if p["path"] == "T1_intranet")
        assert intranet["confidence"] == "SUSPECTED"
        assert any("LAN probe" in m for m in intranet["missing"])


class TestTheExploitPackPath:

    def test_a_matching_pack_entry_is_reported_with_its_name_and_cve(self):
        pack = PackStub(matches=[{"name": "demo-chain", "cve": "CVE-2099-0001",
                                  "verified": True}])
        result = D.decide({"os": "windows", "browser": "Chrome", "version": "91"},
                          caps=caps(exploitpack=pack))
        top = next(p for p in result["paths"] if p["path"] == "T3_exploitpack")
        assert top["ready"] is True and top["entry"] == "demo-chain"
        assert top["cve"] == "CVE-2099-0001" and top["confidence"] == "CONFIRMED"
        assert pack.seen == {"browser": "chrome", "version": 91, "os": "windows",
                             "ja3": "", "ja4h": ""}

    def test_an_unverified_payload_holds_the_path_at_suspected(self):
        pack = PackStub(matches=[{"name": "x", "cve": "CVE-1", "verified": False}])
        result = D.decide({"os": "windows", "browser": "Chrome", "version": "91"},
                          caps=caps(exploitpack=pack))
        top = next(p for p in result["paths"] if p["path"] == "T3_exploitpack")
        assert top["confidence"] == "SUSPECTED"
        assert any("verified on disk" in m for m in top["missing"])

    def test_no_match_rules_the_path_out_and_names_the_fingerprint(self):
        result = D.decide({"os": "windows", "browser": "Chrome", "version": "130"},
                          caps=caps(exploitpack=PackStub(matches=[])))
        top = next(p for p in result["paths"] if p["path"] == "T3_exploitpack")
        assert top["confidence"] == "FAILED"
        assert "chrome 130" in top["why"]

    def test_a_matcher_that_raises_becomes_a_reported_failure_not_a_crash(self):
        result = D.decide({"os": "windows", "browser": "Chrome", "version": "91"},
                          caps=caps(exploitpack=PackStub(boom=True)))
        top = next(p for p in result["paths"] if p["path"] == "T3_exploitpack")
        assert top["confidence"] == "FAILED" and "matcher exploded" in top["why"]


class TestTheMacroAndFilePaths:

    def test_macros_allowed_on_windows_is_ready(self):
        result = D.decide(windows_facts(macro_policy="allowed"), caps=caps())
        macro = next(p for p in result["paths"] if p["path"] == "T4_macro")
        assert macro["ready"] is True and macro["confidence"] == "CONFIRMED"

    def test_macros_blocked_rules_the_path_out(self):
        result = D.decide(windows_facts(macro_policy="blocked"), caps=caps())
        macro = next(p for p in result["paths"] if p["path"] == "T4_macro")
        assert macro["confidence"] == "FAILED"

    def test_an_unknown_macro_policy_waits_on_that_one_fact(self):
        result = D.decide(windows_facts(), caps=caps())
        macro = next(p for p in result["paths"] if p["path"] == "T4_macro")
        assert macro["confidence"] == "SUSPECTED"
        assert any("macro policy" in m for m in macro["missing"])

    def test_the_file_path_needs_smb_and_a_script_host_policy(self):
        result = D.decide(windows_facts(hta_policy="allowed", smb_reachable=False),
                          caps=caps())
        path = next(p for p in result["paths"] if p["path"] == "T5_file")
        assert path["confidence"] == "SUSPECTED"
        assert any("SMB reachability" in m for m in path["missing"])

    def test_the_macro_and_file_paths_fail_on_a_mac(self):
        result = D.decide({"os": "macos", "browser": "safari"}, caps=caps())
        for name in ("T4_macro", "T5_file"):
            path = next(p for p in result["paths"] if p["path"] == name)
            assert path["confidence"] == "FAILED", name


class TestTheDnsChannel:

    def test_dns_is_a_channel_and_ranks_after_the_access_paths(self):
        """All six ready: the channel must sort after the access paths, because an
        operator reading top-down must not meet 'exfil channel' before 'domain access'."""
        facts = windows_facts(http_ntlm_relay_ready=True, relay_target=True,
                              macro_policy="allowed", hta_policy="allowed",
                              smb_reachable=True, intranet=True, beacon_filtered=True)
        pack = PackStub(matches=[{"name": "p", "cve": "CVE-1", "verified": True}])
        result = D.decide(facts, caps=caps(exploitpack=pack))
        assert result["paths"][-1]["path"] == "C1_dns"
        assert result["paths"][-1]["payoff"] == "channel"
        assert result["best"] == "T2_ntlm_relay"
        assert all(p["ready"] for p in result["paths"])

    def test_without_a_filtered_beacon_it_waits_for_a_reason(self):
        result = D.decide({"os": "windows", "browser": "Chrome"}, caps=caps())
        dns = next(p for p in result["paths"] if p["path"] == "C1_dns")
        assert dns["confidence"] == "SUSPECTED"
        assert any("filtered" in m for m in dns["missing"])


class TestTheVerdictItself:

    def test_a_hopeless_victim_gets_a_plain_none_and_says_so(self):
        result = D.decide({"os": "linux", "browser": "firefox", "beacon_filtered": False},
                          caps=caps())
        assert result["best"] is None and result["payoff"] == "none"
        assert "nothing is ready" in result["summary"]
        assert all(not p["ready"] for p in result["paths"])

    def test_ready_paths_always_sort_before_the_rest(self):
        facts = windows_facts(http_ntlm_relay_ready=True, relay_target=True,
                              macro_policy="allowed", hta_policy="allowed",
                              smb_reachable=True, intranet=True)
        result = D.decide(facts, caps=caps())
        flags = [p["ready"] for p in result["paths"]]
        assert flags == sorted(flags, reverse=True), "a ready path was ranked under a dead one"

    def test_confidence_is_only_ever_one_of_three_labels(self):
        for facts in ({"os": "windows", "browser": "Chrome"},
                      {"os": "macos"}, {"os": "linux", "local_services": ["x"]}):
            result = D.decide(facts, caps=caps())
            for path in result["paths"]:
                assert path["confidence"] in ("CONFIRMED", "SUSPECTED", "FAILED")

    def test_every_path_is_decided_exactly_once(self):
        result = D.decide({"os": "windows", "browser": "Chrome"}, caps=caps())
        names = [p["path"] for p in result["paths"]]
        assert sorted(names) == sorted(D.PATHS)
        assert len(names) == len(set(names)), "a path was decided twice"

    def test_the_capability_map_is_resolved_without_raising(self):
        """A tree with no leaf modules must still produce a map of Nones, not a crash."""
        resolved = D.capabilities(overrides=dict.fromkeys(D.CAPABILITIES))
        assert set(resolved) == set(D.CAPABILITIES)
        assert all(v is None for v in resolved.values())

    def test_explain_prints_the_summary_and_every_path(self):
        result = D.decide(windows_facts(http_ntlm_relay_ready=True, relay_target=True),
                          caps=caps())
        text = D.explain(result)
        assert result["summary"] in text
        for path in result["paths"]:
            assert path["path"] in text
        with pytest.raises(ValueError):
            D.explain({"not": "a decision"})


class TestCrossModuleAgreement:
    """`decision` owns the whole path, `mshtml` owns the trigger. On the facts where the
    trigger fires but no relay target is known, the path is SUSPECTED - and the trigger must
    not report CONFIRMED for the same facts, which is how the two modules used to disagree."""

    def test_the_trigger_and_the_path_agree_when_no_target_is_known(self):
        from core import mshtml
        facts = {"os": "windows", "browser": "MSIE", "is_ie": True,
                 "http_ntlm_relay_ready": True, "relay_target": False}
        relay = next(p for p in D.decide(facts)["paths"] if p["path"] == "T2_ntlm_relay")
        trigger = next(r for r in mshtml.plan(facts) if r["kind"] == "mshtml-object")
        assert relay["confidence"] == "SUSPECTED"
        assert trigger["confidence"] == "SUSPECTED", (
            "the trigger claimed CONFIRMED while the path it feeds is SUSPECTED")

    def test_both_agree_the_path_is_ready_when_the_target_is_present(self):
        from core import mshtml
        facts = {"os": "windows", "browser": "MSIE", "is_ie": True,
                 "http_ntlm_relay_ready": True, "relay_target": True}
        relay = next(p for p in D.decide(facts)["paths"] if p["path"] == "T2_ntlm_relay")
        trigger = next(r for r in mshtml.plan(facts) if r["kind"] == "mshtml-object")
        assert relay["confidence"] == "CONFIRMED" == trigger["confidence"]

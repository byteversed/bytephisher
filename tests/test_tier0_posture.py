"""ConsentFix, passkeys and the tier-0 posture map.

The posture map is the interesting one: it decides, from the token's own rights, which
root-of-trust path an identity opens - and it says `not_reachable_from_a_session` for the
paths a token cannot give (a CA private key, a firmware implant, a route hijack) instead of
pretending otherwise.
"""
import base64
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import consentfix as CF  # noqa: E402
from core import oauth as O  # noqa: E402
from core import passkey as PK  # noqa: E402
from core import tier0  # noqa: E402

pytestmark = pytest.mark.unit

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def jwt(payload):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return seg({"alg": "RS256"}) + "." + seg(payload) + ".signature"


def tokens(**claims):
    claims.setdefault("exp", time.time() + 600)
    return {"access_token": jwt(claims), "refresh_token": "RT-1"}


class TestConsentFix:

    def test_a_code_means_a_silent_capture_worked(self):
        verdict, detail = CF.classify("code=CODE-1&state=s")
        assert verdict == "code" and "without asking" in detail

    def test_every_provider_answer_is_classified_with_a_next_step(self):
        for query, want in (("error=login_required", "login_required"),
                            ("error=interaction_required", "interaction_required"),
                            ("error=consent_required", "consent_required"),
                            ("error=access_denied", "access_denied")):
            verdict, detail = CF.classify(query)
            assert verdict == want and detail
            assert "next:" in CF.describe((verdict, detail))

    def test_a_provider_description_is_carried_through(self):
        verdict, detail = CF.classify("error=consent_required&error_description=admin%20only")
        assert verdict == "consent_required" and "admin only" in detail

    def test_an_empty_redirect_is_unknown_not_success(self):
        assert CF.classify("")[0] == "unknown"

    def test_the_silent_url_asks_for_no_prompt(self):
        spec = O.OauthSpec(provider="custom", client_id="c", tenant="http://127.0.0.1:9")
        flow = O.OauthFlow(spec, "sid-1")
        url = CF.silent_url(spec, flow.state, flow.challenge)
        assert "prompt=none" in url and "code_challenge=" in url

    def test_the_interactive_url_can_carry_a_login_hint(self):
        spec = O.OauthSpec(provider="custom", client_id="c", tenant="http://127.0.0.1:9")
        flow = O.OauthFlow(spec, "sid-1")
        url = CF.interactive_url(spec, flow.state, flow.challenge, login_hint="a@b.test")
        assert "login_hint=a%40b.test" in url and "prompt=none" not in url

    def test_the_plan_tries_silent_first_and_explains_every_outcome(self):
        spec = O.OauthSpec(provider="custom", client_id="c", tenant="http://127.0.0.1:9")
        flow = O.OauthFlow(spec, "sid-1")
        plan = CF.plan(spec, flow.state, flow.challenge)
        assert plan["order"] == ["silent", "interactive"]
        assert "prompt=none" in plan["silent"]
        assert set(plan["meanings"]) >= {"login_required", "consent_required",
                                         "interaction_required"}


class TestPasskey:

    def test_a_page_offering_webauthn_is_detected(self):
        report = PK.detect(page_text='<script>navigator.credentials.create({publicKey: {}})</script>')
        assert report["verdict"] == "offers" and report["evidence"]

    def test_the_collectors_own_module_counts_as_evidence(self):
        report = PK.detect(intel={"mods": {"webauthn": {"supported": True}}})
        assert report["verdict"] == "offers"

    def test_nothing_inspected_is_unknown_not_no(self):
        report = PK.detect()
        assert report["verdict"] == "unknown"
        assert "unknown, not 'no'" in PK.describe(report)

    def test_an_inspected_page_without_webauthn_is_no(self):
        assert PK.detect(page_text="<html><form></form></html>")["verdict"] == "no"

    def test_the_enrolment_plan_states_where_and_what_refuses_it(self):
        plan = PK.enrolment_plan(display_name="YubiKey 5")
        assert plan["display_name"] == "YubiKey 5"
        assert plan["steps"] and plan["refused_when"]
        assert any("attestation" in r for r in plan["refused_when"])

    def test_the_relay_is_declared_not_implemented(self):
        report = PK.relay_feasibility()
        assert report["implemented"] is False
        assert len(report["would_need"]) >= 3
        assert "CTAP2" in report["why_not"]


class TestTier0Posture:

    def test_a_global_admin_token_opens_the_federation_path(self):
        report = tier0.assess(tokens(wids=[GLOBAL_ADMIN], roles=["Directory.ReadWrite.All"]))
        row = {r["path"]: r for r in report["verdicts"]}["federation"]
        assert row["verdict"] in ("needs_a_call", "open")
        assert "Global Administrator" in row["rights_held"]
        assert "Directory.ReadWrite.All" in row["rights_held"]

    def test_a_plain_user_token_opens_nothing(self):
        report = tier0.assess(tokens(scp="Mail.Read User.Read"))
        for row in report["verdicts"]:
            if row["rights_needed"]:
                assert row["verdict"] == "no_rights_visible", row

    def test_the_paths_a_session_cannot_reach_say_so(self):
        report = tier0.assess(tokens(wids=[GLOBAL_ADMIN]))
        by_path = {r["path"]: r for r in report["verdicts"]}
        for path in ("endpoint_root", "infrastructure"):
            assert by_path[path]["verdict"] == "not_reachable_from_a_session"
            assert by_path[path]["rights_needed"] == []

    def test_a_confirmed_live_check_makes_it_open(self):
        report = tier0.assess(tokens(wids=[GLOBAL_ADMIN]), checks={"federation": "confirmed"})
        row = {r["path"]: r for r in report["verdicts"]}["federation"]
        assert row["verdict"] == "open"

    def test_a_refused_live_check_makes_it_blocked(self):
        report = tier0.assess(tokens(wids=[GLOBAL_ADMIN]), checks={"pki": "refused"})
        row = {r["path"]: r for r in report["verdicts"]}["pki"]
        assert row["verdict"] == "blocked"

    def test_the_report_is_ordered_by_what_is_actually_open(self):
        report = tier0.assess(tokens(wids=[GLOBAL_ADMIN]))
        verdicts = [r["verdict"] for r in report["verdicts"]]
        assert verdicts[0] in ("open", "needs_a_call")
        assert verdicts[-1] == "not_reachable_from_a_session"

    def test_the_report_carries_the_replayability_verdict(self):
        report = tier0.assess(tokens(deviceid="d", wids=[GLOBAL_ADMIN]))
        assert report["device_bound"] is True and report["replayability"] == "not_replayable"
        assert "device-bound" in tier0.describe(report)

    def test_rights_are_collected_from_every_claim_shape(self):
        rights = tier0.rights_of(tokens(scp="Mail.Read User.Read", roles=["X"],
                                        wids=[GLOBAL_ADMIN]))
        assert "Mail.Read" in rights and "X" in rights and "Global Administrator" in rights

    def test_the_description_lists_the_rights_that_matter(self):
        text = tier0.describe(tier0.assess(tokens(wids=[GLOBAL_ADMIN])))
        assert "federation" in text and "rights:" in text
        assert "not_reachable_from_a_session" in text

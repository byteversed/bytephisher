"""The token-theft tier: replayability, scope swap and the PRT/phantom-device chain.

Everything here is driven with injected transports, so no test touches a tenant. The point of
each assertion answers directly: which of these paths is open, and which is refused by a
control the operator cannot see from the outside.
"""
import base64
import json
import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import dbsc, foci, prt  # noqa: E402

pytestmark = pytest.mark.unit

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def jwt(payload):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return seg({"alg": "RS256", "typ": "JWT"}) + "." + seg(payload) + ".signature"


def tokens(**claims):
    claims.setdefault("exp", time.time() + 600)
    return {"access_token": jwt(claims), "refresh_token": "RT-1"}


class TestReplayability:

    def test_a_device_bound_token_is_not_replayable(self):
        report = dbsc.replayability(tokens(deviceid="dev-1"))
        assert report["verdict"] == "not_replayable" and report["device_bound"] is True
        assert any("device" in r for r in report["reasons"])

    def test_a_cae_capable_token_is_fragile_not_replayable(self):
        report = dbsc.replayability(tokens(xms_cc=["cp1"]))
        assert report["verdict"] == "fragile" and report["cae_capable"] is True
        assert any("revoke" in r for r in report["reasons"])

    def test_a_plain_refresh_token_is_replayable(self):
        report = dbsc.replayability(tokens())
        assert report["verdict"] == "replayable"
        assert report["device_bound"] is False and report["cae_capable"] is False

    def test_an_expired_access_token_without_a_refresh_token_is_dead(self):
        tok = {"access_token": jwt({"exp": time.time() - 10})}
        report = dbsc.replayability(tok)
        assert report["verdict"] == "not_replayable" and report["expired"] is True

    def test_no_tokens_is_unknown_not_replayable(self):
        report = dbsc.replayability({})
        assert report["verdict"] == "unknown"
        assert any("no token" in r for r in report["reasons"])

    def test_an_opaque_token_decodes_to_nothing(self):
        assert dbsc.decode_jwt("opaque-token-value") == {}
        assert dbsc.decode_jwt("") == {}
        assert dbsc.decode_jwt(None) == {}
        assert dbsc.replayability({"access_token": "opaque"})["verdict"] == "fragile"

    def test_the_claims_merge_the_id_token_and_the_access_token(self):
        tok = {"id_token": jwt({"preferred_username": "a@b.test"}),
               "access_token": jwt({"scp": "Mail.Read"})}
        claims = dbsc.claims_of(tok)
        assert claims["preferred_username"] == "a@b.test" and claims["scp"] == "Mail.Read"

    def test_the_report_carries_the_signals_it_used(self):
        report = dbsc.replayability(tokens(deviceid="d"), ja3="abc", ip="1.2.3.4",
                                    device_token="dt")
        assert report["ja3"] == "abc" and report["ip"] == "1.2.3.4"
        assert report["device_token"] == "dt" and report["claims_seen"]
        assert "replayability" in dbsc.describe(report)


class TestScopeSwap:

    def test_the_client_ids_are_real_uuids(self):
        for name, client in foci.CLIENTS.items():
            assert UUID.match(client), (name, client)

    def test_a_swap_sends_the_refresh_grant_with_the_new_client(self):
        seen = {}

        def post(url, data, timeout):
            seen.update(data)
            seen["url"] = url
            return {"access_token": "AT-2", "refresh_token": "RT-2",
                    "scope": "Mail.ReadWrite"}

        out = foci.swap("RT-1", foci.CLIENTS["office"], scope="Mail.ReadWrite",
                        post=post)
        assert seen["grant_type"] == "refresh_token"
        assert seen["refresh_token"] == "RT-1"
        assert seen["client_id"] == foci.CLIENTS["office"]
        assert seen["scope"] == "Mail.ReadWrite"
        assert out["access_token"] == "AT-2"

    def test_a_refusal_carries_the_tenants_own_words(self):
        def post(url, data, timeout):
            return {"error": "invalid_grant",
                    "error_description": "AADSTS50076: MFA is required"}

        with pytest.raises(foci.FociError) as ei:
            foci.swap("RT-1", foci.CLIENTS["office"], post=post)
        assert "MFA is required" in str(ei.value)

    def test_a_swap_without_a_token_or_client_is_refused(self):
        with pytest.raises(foci.FociError):
            foci.swap("", "client")
        with pytest.raises(foci.FociError):
            foci.swap("RT", "")

    def test_a_chain_walks_the_clients_and_keeps_what_it_gets(self):
        calls = []

        def post(url, data, timeout):
            calls.append(data["client_id"])
            if data["client_id"] == foci.CLIENTS["teams"]:
                return {"error": "invalid_grant",
                        "error_description": "admin consent required"}
            # deterministic per client, so the assertion says WHICH client's token survived
            tag = data["client_id"][:8]
            return {"access_token": f"AT-{tag}", "refresh_token": f"RT-{tag}",
                    "scope": "Mail.ReadWrite"}

        out, steps = foci.chain("RT-0", "azure-cli", ["office", "teams", "outlook-mobile"],
                                post=post)
        assert [s["ok"] for s in steps] == [True, True, False, True]
        assert steps[2]["error"].endswith("admin consent required")
        assert out["refresh_token"] == "RT-" + foci.CLIENTS["outlook-mobile"][:8], \
            "the walk must keep the newest successful token"
        assert "Mail.ReadWrite" in out["scope"]
        assert "scope swap" in foci.describe(steps)

    def test_a_chain_reports_every_step(self):
        seen = []
        foci.chain("RT", "office", ["teams"], post=lambda *a: {"error": "x",
                                                              "error_description": "no"},
                   on_step=seen.append)
        assert seen and seen[-1]["ok"] is False

    def test_the_plan_names_the_capability_each_scope_unlocks(self):
        plan = foci.plan()
        by_scope = {p["scope"]: p["capability"] for p in plan}
        assert "tenant-level" in by_scope["https://graph.microsoft.com/Directory.ReadWrite.All"]
        assert "mailbox" in by_scope["https://graph.microsoft.com/User.ReadWrite.All"]
        assert "files" in by_scope["https://graph.microsoft.com/Files.ReadWrite.All"]


class TestPrt:

    def _reg(self, **over):
        kwargs = {"display_name": "DESKTOP-1", "device_id": "dev-1",
                  "object_id": "obj-1", "transport_key": "key-1"}
        kwargs.update(over)
        return prt.DeviceRegistration(**kwargs)

    def test_a_prt_cookie_needs_a_registration_and_a_key(self):
        with pytest.raises(prt.PrtError):
            prt.prt_cookie(None)
        with pytest.raises(prt.PrtError):
            prt.prt_cookie(self._reg(transport_key=""))

    def test_the_cookie_has_three_segments_and_an_empty_signature(self):
        cookie = prt.prt_cookie(self._reg(), nonce="n-1")
        parts = cookie.split(".")
        assert len(parts) == 3 and parts[2] == "", "an unsigned cookie must not look signed"
        payload = json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4)))
        assert payload["device_id"] == "dev-1" and payload["nonce"] == "n-1"

    def test_registering_a_device_posts_the_expected_body(self):
        seen = {}

        def post(url, payload, timeout, access_token):
            seen.update(payload)
            seen["url"] = url
            seen["auth"] = access_token
            return {"id": "obj-9", "deviceId": "dev-9", "transportKey": "tk-9"}

        reg = prt.register_device("AT", display_name="LAPTOP-X", post=post)
        assert reg.device_id == "dev-9" and reg.transport_key == "tk-9"
        assert seen["displayName"] == "LAPTOP-X" and seen["trustType"] == "AzureAd"
        assert seen["accountEnabled"] is True
        assert seen["auth"] == "AT" and seen["url"].endswith("/devices")

    def test_a_registration_without_a_token_is_refused(self):
        with pytest.raises(prt.PrtError):
            prt.register_device("")

    def test_a_tenant_refusal_is_reported(self):
        def post(url, payload, timeout, access_token):
            return {"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges"}}

        with pytest.raises(prt.PrtError) as ei:
            prt.register_device("AT", post=post)
        assert "Insufficient privileges" in str(ei.value)

    def test_an_answer_without_a_device_id_is_refused(self):
        with pytest.raises(prt.PrtError):
            prt.register_device("AT", post=lambda *a: {"ok": True})

    def test_posture_is_blocked_by_a_compliant_device_requirement(self):
        report = prt.posture(tokens(deviceid="d"),
                             tenant_policy={"require_compliant_device": True})
        assert report["verdict"] == "blocked"
        assert any("COMPLIANT" in b for b in report["blockers"])
        assert "blocked" in prt.describe(report)

    def test_posture_reports_unknown_without_policy_or_claims(self):
        report = prt.posture({})
        assert report["verdict"] == "unknown"
        assert any("UNKNOWN" in f for f in report["findings"])

    def test_posture_carries_the_replayability_verdict(self):
        report = prt.posture(tokens(xms_cc=["cp1"]))
        assert report["cae_capable"] is True and report["replayability"] == "fragile"
        assert report["device_bound"] is False

    def test_hybrid_join_and_registration_restrictions_block_too(self):
        report = prt.posture({}, tenant_policy={"require_hybrid_join": True,
                                                "device_registration_restricted": True})
        assert report["verdict"] == "blocked" and len(report["blockers"]) == 2

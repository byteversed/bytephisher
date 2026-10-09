"""App-only persistence: the credential that has no user behind it.

Everything is driven against a fake tenant. The two things worth pinning: the permission ids
are FETCHED from the tenant (a guessed GUID either grants nothing or grants the wrong thing),
and the plan states plainly what this survives - because that list is the reason it sits above
AiTM and above the PRT.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import appconsent as AC  # noqa: E402

pytestmark = pytest.mark.unit

MAIL_READ_ID = "11111111-1111-1111-1111-111111111111"


def fake_tenant(calls=None):
    """A fake Graph: records the calls, answers like the real one."""
    def post(method, url, payload, timeout, token):
        if calls is not None:
            calls.append({"method": method, "url": url, "payload": payload, "token": token})
        if url.endswith("/addPassword"):
            return {"secretText": "SECRET-XYZ", "keyId": "key-1", "hint": "xyz"}
        if url.endswith("/oauth2PermissionGrants"):
            return {"id": "grant-1", **dict(payload or {})}
        if url.endswith("/applications"):
            return {"id": "obj-1", "appId": "client-1"}
        return {"id": "obj-1", "appId": "client-1"}
    return post


def fake_ids(url, timeout):
    assert " " not in url, "an OData filter with a raw space is an invalid URL"
    assert "%20" in url or "%20" in url.replace(" ", ""), url
    return {"value": [{"appRoles": [{"value": "Mail.Read", "id": MAIL_READ_ID}],
                       "oauth2PermissionScopes": [{"value": "User.Read", "id": "3333"}]}]}


class TestThePlan:

    def test_the_plan_names_the_five_calls(self):
        plan = AC.plan(app_name="connector")
        assert [s["step"] for s in plan["steps"]] == [1, 2, 3, 4, 5]
        assert "client_credentials" in plan["steps"][4]["call"]

    def test_the_plan_states_what_this_survives(self):
        plan = AC.plan()
        joined = " ".join(plan["survives"])
        assert "password reset" in joined and "MFA" in joined
        assert "DBSC" in joined and "session revocation" in joined

    def test_the_plan_names_the_four_audit_entries_and_the_remediation(self):
        plan = AC.plan()
        assert len(plan["visible"]) >= 3 and "audit log" in plan["visible"][0]
        assert "oauth2PermissionGrant" in plan["remediation"]

    def test_an_unknown_scope_name_is_flagged_not_silently_dropped(self):
        plan = AC.plan(scopes=["Mail.Read", "Something.New"])
        assert plan["unknown_scopes"] == ["Something.New"]

    def test_the_description_lists_the_steps_and_the_survives_list(self):
        text = AC.describe(AC.plan(app_name="connector", scopes=["Mail.Read"]))
        assert "connector" in text and "survives:" in text and "remediation:" in text


class TestTheChain:

    def test_registering_posts_a_display_name(self):
        calls = []
        out = AC.register_app("AT-1", "reporting-connector", post=fake_tenant(calls))
        assert out["appId"] == "client-1"
        assert calls[0]["method"] == "POST" and calls[0]["url"].endswith("/applications")
        assert calls[0]["payload"]["displayName"] == "reporting-connector"
        assert calls[0]["token"] == "AT-1"

    def test_permission_ids_come_from_the_tenant(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "obj-1"}

        AC.add_permissions("AT-1", "obj-1", app_roles=["Mail.Read"], post=post,
                           ids=AC.role_ids("AT-1", get=fake_ids))
        access = seen["payload"]["requiredResourceAccess"][0]["resourceAccess"]
        assert access == [{"id": MAIL_READ_ID, "type": "Role"}]

    def test_the_role_ids_reader_quotes_the_odata_filter(self):
        ids = AC.role_ids("AT-1", get=fake_ids)
        assert ids == {"Mail.Read": MAIL_READ_ID, "User.Read": "3333"}

    def test_a_permission_the_tenant_does_not_report_is_refused_not_guessed(self):
        with pytest.raises(AC.AppConsentError) as ei:
            AC.add_permissions("AT-1", "obj-1", app_roles=["Nope.Read"], post=fake_tenant(),
                               ids={"Mail.Read": MAIL_READ_ID})
        assert "nothing was guessed" in str(ei.value)

    def test_a_guid_is_accepted_as_is(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "obj-1"}

        AC.add_permissions("AT-1", "obj-1", app_roles=[MAIL_READ_ID], post=post, ids={})
        access = seen["payload"]["requiredResourceAccess"][0]["resourceAccess"]
        assert access == [{"id": MAIL_READ_ID, "type": "Role"}]

    def test_delegated_and_application_permissions_are_typed_differently(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "obj-1"}

        AC.add_permissions("AT-1", "obj-1", app_roles=[MAIL_READ_ID], delegated=[MAIL_READ_ID],
                           post=post, ids={})
        access = seen["payload"]["requiredResourceAccess"][0]["resourceAccess"]
        assert {row["type"] for row in access} == {"Role", "Scope"}

    def test_consent_is_all_principals_by_default(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "grant-1"}

        AC.grant_consent("AT-1", "client-1", scopes=["Mail.Read"], post=post)
        assert seen["payload"]["consentType"] == "AllPrincipals"
        assert seen["payload"]["scope"] == "Mail.Read"
        assert "principalId" not in seen["payload"]

    def test_a_user_scoped_consent_names_the_principal(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {"id": "grant-1"}

        AC.grant_consent("AT-1", "client-1", scopes=["Mail.Read"], principal_id="user-9",
                         post=post)
        assert seen["payload"]["consentType"] == "Principal"
        assert seen["payload"]["principalId"] == "user-9"

    def test_the_secret_comes_back_once_and_is_reported_by_hint(self):
        out = AC.add_password("AT-1", "obj-1", post=fake_tenant())
        assert out["secretText"] == "SECRET-XYZ" and out["hint"] == "xyz"

    def test_the_app_only_token_uses_the_client_credentials_grant(self):
        seen = {}

        def post(url, data, timeout):
            seen.update(data)
            seen["url"] = url
            return {"access_token": "APP-ONLY", "token_type": "Bearer"}

        out = AC.app_token("client-1", "SECRET", tenant="contoso.test", post=post)
        assert seen["grant_type"] == "client_credentials"
        assert seen["client_secret"] == "SECRET" and seen["client_id"] == "client-1"
        assert "contoso.test" in seen["url"]
        assert out["access_token"] == "APP-ONLY"

    def test_the_token_endpoint_refusal_is_reported(self):
        def post(url, data, timeout):
            return {"error": "invalid_client",
                    "error_description": "AADSTS7000215: Invalid client secret"}

        with pytest.raises(AC.AppConsentError) as ei:
            AC.app_token("c", "bad", post=post)
        assert "Invalid client secret" in str(ei.value)

    def test_revoke_removes_the_grant_then_the_app(self):
        calls = []
        AC.revoke("AT-1", app_object_id="obj-1", grant_id="grant-1",
                  post=fake_tenant(calls))
        assert [c["method"] for c in calls] == ["DELETE", "DELETE"]
        assert calls[0]["url"].endswith("/oauth2PermissionGrants/grant-1")
        assert calls[1]["url"].endswith("/applications/obj-1")

    def test_revoke_with_nothing_to_do_is_refused(self):
        with pytest.raises(AC.AppConsentError):
            AC.revoke("AT-1")


class TestTheGuards:

    @pytest.mark.parametrize("call", [
        lambda: AC.register_app("", "x"),
        lambda: AC.register_app("AT", ""),
        lambda: AC.add_permissions("", "obj"),
        lambda: AC.add_permissions("AT", ""),
        lambda: AC.add_permissions("AT", "obj"),
        lambda: AC.grant_consent("AT", ""),
        lambda: AC.add_password("", "obj"),
        lambda: AC.app_token("", "s"),
        lambda: AC.app_token("c", ""),
    ])
    def test_the_required_fields_are_enforced(self, call):
        with pytest.raises(AC.AppConsentError):
            call()

    def test_a_tenant_refusal_becomes_a_refusal_here(self):
        def post(method, url, payload, timeout, token):
            return {"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges to complete the operation."}}

        with pytest.raises(AC.AppConsentError) as ei:
            AC.register_app("AT", "x", post=post)
        assert "Insufficient privileges" in str(ei.value)

    def test_the_scope_table_explains_what_each_permission_buys(self):
        assert "every mailbox" in AC.SCOPES["Mail.Read"]
        assert "any directory role" in AC.SCOPES["RoleManagement.ReadWrite.Directory"]


class TestConsentPhishing:

    def test_the_url_points_at_the_real_provider_with_the_app_and_the_scopes(self):
        out = AC.consent_url("abc-123", "https://lure.test/cb", scopes=["Mail.Read"],
                             tenant="contoso.test", state="s-1")
        assert out["url"].startswith("https://login.microsoftonline.com/contoso.test/")
        assert "client_id=abc-123" in out["url"]
        assert "redirect_uri=https%3A%2F%2Flure.test%2Fcb" in out["url"]
        assert "response_type=code" in out["url"] and "state=s-1" in out["url"]
        assert out["scopes"] == ["Mail.Read"]

    def test_the_default_scopes_ask_for_offline_access(self):
        out = AC.consent_url("c", "https://x/cb")
        assert any("offline_access" in sc for sc in out["scopes"])

    def test_the_plan_states_that_no_administrator_is_needed(self):
        plan = AC.consent_plan(client_id="c", redirect_uri="https://x/cb")
        assert plan["needs_no_admin"] is True
        assert "admin consent" in " ".join(plan["stops_it"])
        assert any("password change" in item for item in plan["survives"])

    def test_the_plan_lists_five_steps_and_the_grants(self):
        plan = AC.consent_plan(client_id="c", redirect_uri="https://x/cb",
                               scopes=["Mail.Read"])
        assert [s["step"] for s in plan["steps"]] == [1, 2, 3, 4, 5]
        assert "every mailbox" in " ".join(plan["what_it_grants"])
        assert "consent-phishing plan" in AC.describe(plan)

    def test_a_url_without_a_client_or_a_redirect_is_refused(self):
        with pytest.raises(AC.AppConsentError):
            AC.consent_url("", "https://x/cb")
        with pytest.raises(AC.AppConsentError):
            AC.consent_url("c", "")

    def test_a_plan_without_a_client_still_describes_the_technique(self):
        plan = AC.consent_plan()
        assert plan["url"] == "" and plan["steps"]

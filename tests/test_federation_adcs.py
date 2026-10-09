"""The two tier-0 rungs that can be reached from a session: federation and AD CS.

The federation calls are the real Graph shapes, driven here against a fake tenant so no test
touches a real one. The AD CS probe reports only what an HTTP request can observe - and says
explicitly that template ACLs and subject flags are NOT visible from outside, because a probe
that implies it saw them is a probe that lies.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import adcs  # noqa: E402
from core import federation as F  # noqa: E402

pytestmark = pytest.mark.unit


class TestFederation:

    def test_the_plan_names_three_steps_and_what_each_needs(self):
        plan = F.plan("contoso.test")
        assert [s["step"] for s in plan["steps"]] == [1, 2, 3]
        assert "Domain.ReadWrite.All" in plan["steps"][0]["needs"]
        assert "DNS" in plan["steps"][1]["needs"]
        assert "federationConfiguration" in plan["steps"][2]["what"]
        assert "audit log" in plan["visible"]
        assert "federation plan for contoso.test" in F.describe(plan)

    def test_adding_a_domain_posts_the_id_to_the_domains_endpoint(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen.update({"method": method, "url": url, "payload": payload, "token": token})
            return {"id": "contoso.test"}

        out = F.add_domain("AT-1", "contoso.test", post=post)
        assert seen["method"] == "POST" and seen["url"].endswith("/v1.0/domains")
        assert seen["payload"] == {"id": "contoso.test"} and seen["token"] == "AT-1"
        assert out["id"] == "contoso.test"

    def test_setting_federation_sends_the_issuer_and_the_signing_certificate(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen.update({"method": method, "url": url, "payload": payload})
            return {"id": "contoso.test"}

        F.set_federation("AT-1", "contoso.test", "https://idp.test/saml", "MIIBcert",
                         post=post)
        conf = seen["payload"]["federationConfiguration"]
        assert seen["method"] == "PATCH" and seen["url"].endswith("/domains/contoso.test")
        assert conf["issuerUri"] == "https://idp.test/saml"
        assert conf["signingCertificate"] == "MIIBcert"
        assert conf["preferredAuthenticationProtocol"] == "saml"
        assert seen["payload"]["isVerified"] is True

    def test_a_federation_without_a_certificate_is_refused_before_the_call(self):
        with pytest.raises(F.FederationError) as ei:
            F.set_federation("AT-1", "contoso.test", "https://idp.test/saml", "")
        assert "signing certificate" in str(ei.value)
        with pytest.raises(F.FederationError):
            F.set_federation("AT-1", "contoso.test", "", "MIIBcert")
        with pytest.raises(F.FederationError):
            F.set_federation("", "contoso.test", "https://x", "MIIBcert")

    def test_a_tenant_refusal_is_reported_verbatim(self):
        def post(method, url, payload, timeout, token):
            return {"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges"}}

        with pytest.raises(F.FederationError) as ei:
            F.add_domain("AT-1", "contoso.test", post=post)
        assert "Insufficient privileges" in str(ei.value)

    def test_removing_federation_clears_the_configuration(self):
        seen = {}

        def post(method, url, payload, timeout, token):
            seen["payload"] = payload
            return {}

        F.remove_federation("AT-1", "contoso.test", post=post)
        assert seen["payload"] == {"federationConfiguration": []}

    def test_a_domain_is_required(self):
        with pytest.raises(F.FederationError):
            F.add_domain("AT-1", "")
        with pytest.raises(F.FederationError):
            F.add_domain("", "contoso.test")


class TestAdcs:


    def test_an_ntlm_offer_is_the_esc8_precondition(self):
        rep = adcs.probe("http://ca.test", fetch=lambda url, t: (
            401, {"WWW-Authenticate": "Negotiate, NTLM"}, ""))
        assert rep["ntlm_offered"] is True
        findings = {f["esc"]: f for f in adcs.esc_findings(rep)}
        assert findings["ESC8"]["verdict"] == "possible"

    def test_a_disclosed_template_list_is_parsed_and_flagged(self):
        def fetch(url, timeout):
            if "certfnsh" in url:
                return (200, {"WWW-Authenticate": "NTLM"},
                        '<select name="Template"><option value="User">User</option>'
                        '<option value="WebServer">Web</option></select>')
            return 401, {"WWW-Authenticate": "NTLM"}, ""

        rep = adcs.probe("http://ca.test", fetch=fetch)
        assert rep["anonymous_read"] is True
        assert "User" in rep["templates"] and "WebServer" in rep["templates"]
        verdicts = {f["esc"] for f in adcs.esc_findings(rep)}
        assert {"ESC8", "ESC1"} <= verdicts

    def test_the_template_parser_takes_the_option_values(self):
        names = adcs.parse_templates('<option value="A">a</option><option value="B">b</option>')
        assert names == ["A", "B"]
        assert adcs.parse_templates("") == []

    def test_a_hardened_endpoint_reports_nothing_observed(self):
        rep = adcs.probe("http://ca.test", fetch=lambda url, t: (404, {}, ""))
        findings = adcs.esc_findings(rep)
        assert any(f["verdict"] == "nothing-observed" for f in findings)

    def test_the_probe_always_states_what_it_cannot_see(self):
        rep = adcs.probe("http://ca.test", fetch=lambda url, t: (401, {}, ""))
        findings = adcs.esc_findings(rep)
        hidden = [f for f in findings if f["verdict"] == "not_visible_from_here"]
        assert hidden and "LDAP" in hidden[0]["why"]

    def test_an_unreachable_ca_is_reported_per_endpoint(self):
        def fetch(url, timeout):
            raise OSError("connection refused")

        rep = adcs.probe("http://ca.test", fetch=fetch)
        assert rep["endpoints"] and all(e.get("error") for e in rep["endpoints"])
        assert "ERR" in adcs.describe(rep)

    def test_a_probe_without_a_base_url_is_refused(self):
        with pytest.raises(adcs.AdcsError):
            adcs.probe("")

    def test_the_description_reports_the_endpoints_and_the_findings(self):
        rep = adcs.probe("http://ca.test", fetch=lambda url, t: (
            401, {"WWW-Authenticate": "NTLM"}, ""))
        text = adcs.describe(rep)
        assert "AD CS probe" in text and "[ESC8]" in text and "401" in text

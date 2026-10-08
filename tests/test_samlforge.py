"""Golden SAML: the assertion and the signature.

The signing key is the operator's (it lives on the IdP host), so the tests drive the signature
with an INJECTED signer and verify what can be verified without a key: the canonical form the
digest is taken over, the digest itself, the enveloped placement, and the refusal when no key
is supplied. The real RSA-SHA256 path is skipped when `cryptography` is not installed - stated,
not hidden.
"""
import base64
import hashlib
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import samlforge as SF  # noqa: E402

pytestmark = pytest.mark.unit


class TestTheAssertion:

    def test_the_assertion_carries_the_subject_the_audience_and_the_window(self):
        xml = SF.assertion("https://adfs.test/trust", "https://sp.test/saml", "admin@c.test",
                           not_before=0, not_after=3600)
        assert "admin@c.test" in xml and "https://sp.test/saml" in xml
        assert "<saml:Conditions" in xml and "AudienceRestriction" in xml
        assert 'ID="_' in xml and "Version=\"2.0\"" in xml

    def test_the_role_claim_is_where_the_privilege_comes_from(self):
        xml = SF.assertion("https://idp.test", "https://sp.test", "a@b.test",
                           attributes={SF.ROLE_CLAIMS[0]: ["Domain Admins"]})
        assert "Domain Admins" in xml and "AttributeStatement" in xml

    def test_a_multi_value_attribute_becomes_several_values(self):
        xml = SF.assertion("https://idp.test", "https://sp.test", "a@b.test",
                           attributes={"Group": ["A", "B"]})
        assert xml.count("<saml:AttributeValue ") == 2, "one element per value"

    def test_a_subject_with_markup_is_escaped(self):
        xml = SF.assertion("https://idp.test", "https://sp.test", 'a<b>&"c"')
        assert "a&lt;b&gt;&amp;&quot;c&quot;" in xml

    @pytest.mark.parametrize("kwargs", [
        {"issuer": "", "audience": "x", "subject": "y"},
        {"issuer": "x", "audience": "", "subject": "y"},
        {"issuer": "x", "audience": "y", "subject": ""},
    ])
    def test_the_three_required_fields_are_enforced(self, kwargs):
        with pytest.raises(SF.SamlForgeError):
            SF.assertion(**kwargs)

    def test_a_backwards_window_is_refused(self):
        with pytest.raises(SF.SamlForgeError):
            SF.assertion("https://i", "https://a", "s", not_before=100, not_after=50)

    def test_the_response_wraps_the_assertion_with_a_status(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        resp = SF.response(xml, "https://i.test", destination="https://a.test/saml")
        assert resp.startswith("<samlp:Response") and "<saml:Assertion" in resp
        assert "status:Success" in resp and 'Destination="https://a.test/saml"' in resp

    def test_a_failure_status_is_not_success(self):
        resp = SF.response("<saml:Assertion/>", "https://i", status="Requester")
        assert "status:Requester" in resp and "Success" not in resp


class TestCanonicalisation:

    def test_inter_tag_whitespace_is_removed(self):
        assert SF.c14n("<a>\n  <b/>\n</a>") == "<a><b/></a>"

    def test_attributes_are_sorted(self):
        assert SF.c14n('<a z="1" b="2"/>') == '<a b="2" z="1"/>'

    def test_a_tag_without_attributes_is_untouched(self):
        assert SF.c14n("<a><b>text</b></a>") == "<a><b>text</b></a>"


class TestTheSignature:

    def test_the_digest_is_taken_over_the_canonical_form(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        signed = SF.sign(xml, signer=lambda data: b"SIG")
        digest = re.search(r"<ds:DigestValue>([^<]+)</ds:DigestValue>", signed).group(1)
        expect = base64.b64encode(hashlib.sha256(SF.c14n(xml).encode()).digest()).decode()
        assert digest == expect

    def test_the_signature_is_enveloped_inside_the_assertion(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        signed = SF.sign(xml, signer=lambda data: b"SIG")
        assert signed.index("<ds:Signature") < signed.index("</saml:Assertion>")
        assert "</saml:Issuer><ds:Signature" in signed

    def test_the_signature_value_is_base64_of_what_the_signer_returned(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        signed = SF.sign(xml, signer=lambda data: b"FAKE-SIG")
        assert base64.b64encode(b"FAKE-SIG").decode() in signed

    def test_the_signer_receives_the_canonical_signed_info(self):
        seen = {}

        def signer(data):
            seen["text"] = data.decode()
            return b"SIG"

        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        SF.sign(xml, signer=signer)
        assert seen["text"].startswith("<ds:SignedInfo")
        assert "DigestMethod" in seen["text"] and "CanonicalizationMethod" in seen["text"]
        assert "\n" not in seen["text"], "the signer must get the canonical form"

    def test_the_reference_points_at_the_assertions_own_id(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        aid = re.search(r'ID="([^"]+)"', xml).group(1)
        assert f'URI="#{aid}"' in SF.sign(xml, signer=lambda d: b"SIG")

    def test_the_certificate_lands_in_the_key_info(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        assert "MIIBcert" in SF.sign(xml, signer=lambda d: b"SIG", cert_b64="MIIBcert")
        assert "MIIBcert" not in SF.sign(xml, signer=lambda d: b"SIG")

    def test_without_a_key_or_a_signer_it_refuses_instead_of_emitting_nothing(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        with pytest.raises(SF.SamlForgeError) as ei:
            SF.sign(xml)
        assert "token-signing key" in str(ei.value)

    def test_an_unsupported_digest_is_refused(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        with pytest.raises(SF.SamlForgeError):
            SF.sign(xml, signer=lambda d: b"SIG", digest="md5")

    def test_signing_nothing_is_refused(self):
        with pytest.raises(SF.SamlForgeError):
            SF.sign("", signer=lambda d: b"SIG")

    def test_sha1_is_available_for_older_relying_parties(self):
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        signed = SF.sign(xml, signer=lambda d: b"SIG", digest="sha1")
        assert "xmldsig#sha1" in signed and "xmlenc#sha256" not in signed

    @pytest.mark.skipif(
        __import__("importlib").util.find_spec("cryptography") is None,
        reason="the real RSA signer needs the optional cryptography package (not installed "
               "here): the injected-signer path above is what this environment verifies")
    def test_a_real_rsa_key_signs(self):            # pragma: no cover - env dependent
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        xml = SF.assertion("https://i.test", "https://a.test", "s@x")
        signed = SF.sign(xml, key_pem=pem)
        assert "<ds:SignatureValue>" in signed
        assert len(re.search(r"<ds:SignatureValue>([^<]+)", signed).group(1)) > 100


class TestThePlan:

    def test_the_plan_names_the_key_as_the_first_requirement(self):
        plan = SF.plan(issuer="https://adfs.test", audience="https://sp.test/saml")
        assert "signing" in plan["steps"][0]["what"]
        assert "IdP host" in plan["steps"][0]["needs"]
        assert "MFA" in plan["why_it_is_the_top"]

    def test_the_detection_that_works_is_stated(self):
        plan = SF.plan()
        assert any("IdP's own logs" in item for item in plan["visible"])
        assert "correlate" in plan["defender_priority"]

    def test_the_description_lists_the_steps_and_the_visibility(self):
        text = SF.describe(SF.plan(issuer="https://i", audience="https://a"))
        assert "golden SAML plan" in text and "visible:" in text and "why it is the top" in text

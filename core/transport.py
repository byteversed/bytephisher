"""Outbound HTTP for the proxy, with a real browser's TLS fingerprint.

Why this exists
---------------
A reverse proxy is only as convincing as the client that talks to the upstream.
`requests`/urllib send Python's ClientHello: one cipher list, one extension order,
no GREASE - a fingerprint Cloudflare, Akamai and PerimeterX have carried in their
rules for years. The victim's own browser sits behind us looking like Chrome while
our upstream leg looks like a script, which is exactly the mismatch that gets a
campaign challenged or blocked.

This module keeps one entry point (`request`) and two engines:

* **impersonating** - `curl_cffi`, which replays a captured Chrome/Firefox/Safari
  ClientHello (cipher order, extensions, curves, ALPN, HTTP/2 settings and header
  order). Selected with `--impersonate chrome`.
* **plain** - `requests` with the victim's cookie jar, the behaviour the proxy has
  always had. Used when impersonation is off or unavailable, so the fallback is
  never a hard dependency.

The cookie jar stays ours in both engines: the jar decides which cookies apply to
the target (domain/path/secure), and the Set-Cookie values come back to the caller
so the session can update the jar itself.
"""
import http.cookiejar
import urllib.parse
import urllib.request

__all__ = ["PROFILES", "available", "effective_profile", "profile_ok",
           "request", "Response", "set_cookies"]

# curl_cffi's browser profiles. Kept as a tuple so `--impersonate` can be
# validated up front instead of failing on the first upstream request.
PROFILES = ("chrome", "chrome99", "chrome100", "chrome101", "chrome104",
            "chrome107", "chrome110", "chrome116", "chrome119", "chrome120",
            "chrome123", "chrome124", "chrome131", "chrome133a", "chrome136",
            "edge99", "edge101", "firefox133", "firefox135", "safari153",
            "safari155", "safari170", "safari180", "safari184", "tor145")

DEFAULT_PROFILE = "chrome"


def _curl_cffi():
    """The curl_cffi requests module, or None when it is not installed."""
    try:
        from curl_cffi import requests as curl_requests
        return curl_requests
    except Exception:
        return None


def available():
    return _curl_cffi() is not None


def effective_profile(requested="", opt_out=False, have=None):
    """Which profile the upstream leg should use.

    A plain Python TLS client is the loudest signal on the wire (JA3/JA4, extension
    order, no ALPN shape a browser would send, no client hints), and the upstream leg
    is the one a bank or an anti-bot vendor actually sees. So the browser profile is
    the DEFAULT whenever curl_cffi is installed, and `--no-impersonate` is the
    explicit opt-out; an explicit `--impersonate PROFILE` always wins.
    """
    if opt_out:
        return ""
    requested = (requested or "").strip()
    if requested:
        return requested
    # NOTE: the parameter must not be named `available`, or it shadows the module
    # function of the same name and the call below raises TypeError
    installed = available() if have is None else have
    return "chrome" if installed else ""


def profile_ok(name):
    """Is `name` a profile this build can impersonate?"""
    name = (name or "").strip().lower()
    if not name:
        return True                     # empty = impersonation off
    mod = _curl_cffi()
    if mod is None:
        return False
    try:
        known = {str(b.value).lower() for b in mod.BrowserType}
    except Exception:
        known = set()
    return name in known or name in PROFILES


def cookie_header(jar, url):
    """The Cookie header a browser would send to `url` (RFC 6265 matching).

    Domain/path/secure matching is implemented here rather than delegated to
    `CookieJar.add_cookie_header` for two reasons: that call needs a request object
    with urllib's private attributes (a plain `Request` raises AttributeError, which
    silently yielded an EMPTY header - the upstream never saw the session cookie and
    every authenticated flow fell back to the login page), and its policy treats a
    dotless host such as `localhost` as `localhost.local`, dropping perfectly valid
    cookies for the intranet and loopback upstreams this tool proxies.
    """
    if not jar:
        return ""
    parts = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    host = (parts.hostname or "").lower().strip(".")
    if not host:
        return ""
    path = parts.path or "/"
    secure = parts.scheme == "https"
    out = []
    for c in jar:
        if getattr(c, "is_expired", None) and c.is_expired():
            continue
        dom = (c.domain or "").lstrip(".").lower()
        # RFC 6265 5.1.3: exact host, or a suffix that starts on a dot boundary.
        # A sibling host (api.acme.test vs app.acme.test) never matches.
        if dom and host != dom and not host.endswith("." + dom):
            continue
        if c.secure and not secure:
            continue
        cpath = c.path or "/"
        if not (path == cpath or
                (path.startswith(cpath) and (cpath.endswith("/") or
                                             path[len(cpath):len(cpath) + 1] == "/"))):
            continue
        out.append(f"{c.name}={c.value}")
    return "; ".join(out)

def set_cookies(resp):
    """Every Set-Cookie value on a response, as a list.

    Read from `pairs` first: it is the one place both engines preserve duplicates,
    and a page that sets several cookies must not lose all but the first.
    """
    pairs = getattr(resp, "pairs", None)
    if pairs:
        out = [str(v) for k, v in pairs if str(k).lower() == "set-cookie"]
        if out:
            return out
    headers = getattr(resp, "headers", None)
    raw = getattr(getattr(resp, "raw", None), "headers", None)
    for holder in (raw, headers):
        for getter in ("getlist", "get_list"):
            fn = getattr(holder, getter, None)
            if callable(fn):
                try:
                    vals = fn("Set-Cookie") or fn("set-cookie") or []
                    if vals:
                        return [str(v) for v in vals]
                except Exception:
                    pass
    try:
        one = headers.get("Set-Cookie") or headers.get("set-cookie")
        return [str(one)] if one else []
    except Exception:
        return []


class Response:
    """The small surface the proxy needs, from either engine.

    Deliberately not a `requests.Response` subclass: the proxy reads
    `status_code`, `headers`, `content`, `text`, `url` and the Set-Cookie list, and
    the impersonating engine cannot produce a requests.Response.
    """

    __slots__ = ("status_code", "headers", "content", "url", "impersonated",
                 "engine", "pairs")

    def __init__(self, status_code, headers, content, url="", impersonated="",
                 engine="", pairs=None):
        self.status_code = int(status_code or 0)
        self.headers = headers if headers is not None else _CI()
        self.content = content or b""
        self.url = url
        self.impersonated = impersonated
        self.engine = engine
        # duplicates matter: an upstream page can set several cookies and a dict
        # would silently drop all but one
        self.pairs = list(pairs) if pairs else list(self.headers.items())

    @property
    def raw(self):
        """A shim for the one thing old call sites used: raw.headers.getlist()."""
        outer = self

        class _RawHeaders:
            def getlist(self, name):
                low = str(name).lower()
                return [v for k, v in outer.pairs if k.lower() == low]

            def items(self):
                return list(outer.pairs)

        class _Raw:
            headers = _RawHeaders()

        return _Raw()

    @property
    def text(self):
        raw = self.content
        ctype = ""
        try:
            ctype = str(self.headers.get("Content-Type") or "")
        except Exception:
            ctype = ""
        charset = "utf-8"
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
        return raw.decode(charset, "replace")

    def header(self, name, default=""):
        try:
            return self.headers.get(name, default)
        except Exception:
            return default

    def __repr__(self):
        return (f"<Response {self.status_code} {len(self.content)}b "
                f"engine={self.engine or 'requests'}"
                f"{' impersonate=' + self.impersonated if self.impersonated else ''}>")


def request(method, url, headers=None, body=None, jar=None, timeout=30,
            verify=True, impersonate=""):
    """One upstream request.

    `jar` is an `http.cookiejar.CookieJar` (the victim's session). Its cookies are
    attached per its own scoping rules, and the response's Set-Cookie values are
    handed back through `set_cookies(resp)` for the caller to store.
    """
    headers = dict(headers or {})
    jar = jar if jar is not None else http.cookiejar.CookieJar()
    ck = cookie_header(jar, url)
    if ck:
        headers.setdefault("Cookie", ck)

    mod = _curl_cffi() if impersonate else None
    if mod is not None:
        profile = (impersonate or DEFAULT_PROFILE).strip().lower()
        if not profile_ok(profile):
            # an unknown profile must not silently downgrade the fingerprint
            raise ValueError(f"unknown impersonation profile: {profile}")
        session = mod.Session(impersonate=profile, verify=bool(verify),
                              timeout=timeout)
        r = session.request(method, url, headers=headers, data=body,
                            allow_redirects=False)
        return Response(r.status_code, _headers_dict(r.headers), r.content,
                        url=getattr(r, "url", url), impersonated=profile,
                        engine="curl_cffi", pairs=_pairs(r))

    import requests
    KNOWN = ("gzip", "deflate", "identity", "compress", "")
    client = requests.Session()
    client.cookies = jar
    enc = ""
    with client.request(method, url, headers=headers, data=body, stream=True,
                        allow_redirects=False, verify=bool(verify),
                        timeout=timeout) as r:
        enc = (r.headers.get("Content-Encoding") or "").strip().lower()
        if enc not in KNOWN:
            # requests returns an EMPTY body for an encoding it cannot decode, which
            # then mismatches the declared Content-Length and hangs the client
            content = r.raw.read(decode_content=False) or b""
        else:
            content = r.content
        status, hdrs, pairs = r.status_code, _headers_dict(r.headers), _pairs(r)
        final_url = getattr(r, "url", url)
    # the length we advertise must describe the bytes we actually hold
    fixed = []
    for k, v in pairs:
        if k.lower() == "content-length":
            fixed.append((k, str(len(content))))
        else:
            fixed.append((k, v))
    return Response(status, hdrs, content, url=final_url, engine="requests",
                    pairs=fixed or [("Content-Length", str(len(content)))])


class _CI(dict):
    """A case-insensitive header mapping.

    The proxy asks for `headers.get("Content-Type")`, iterates `.items()` and
    tests `"Set-Cookie" in headers`. `requests` returns a CaseInsensitiveDict, but
    the impersonating engine returns its own type, so both are normalised here -
    a case-sensitive dict silently missed every header lookup.
    """

    def __init__(self, data=None):
        super().__init__()
        for k, v in (data or {}).items():
            self[str(k)] = str(v)

    def _key(self, name):
        low = str(name).lower()
        for k in self.keys():
            if k.lower() == low:
                return k
        return None

    def __setitem__(self, k, v):
        old = self._key(k)
        super().__setitem__(old if old is not None else str(k), v)

    def __getitem__(self, k):
        key = self._key(k)
        if key is None:
            raise KeyError(k)
        return super().__getitem__(key)

    def __contains__(self, k):
        return self._key(k) is not None

    def get(self, k, default=None):
        key = self._key(k)
        return default if key is None else super().__getitem__(key)


def _pairs(resp):
    """Every header as (name, value), duplicates included, in wire order.

    `requests` keeps duplicates only in the raw http.client headers (its own dict
    collapses them), and curl_cffi keeps them in `multi_items()`. Reading the
    wrong one silently dropped every Set-Cookie but the first.
    """
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    # urllib3's HTTPHeaderDict joins duplicates on .items(), so enumerate the
    # unique names and ask for the values of each - that keeps every Set-Cookie
    if raw_headers is not None and hasattr(raw_headers, "keys"):
        for getter in ("getlist", "get_list"):
            fn = getattr(raw_headers, getter, None)
            if not callable(fn):
                continue
            try:
                out = []
                for k in raw_headers:
                    for v in fn(k) or []:
                        out.append((str(k), str(v)))
                if out:
                    return out
            except Exception:
                pass
    if raw_headers is not None and hasattr(raw_headers, "items"):
        try:
            return [(str(k), str(v)) for k, v in raw_headers.items()]
        except Exception:
            pass
    headers = getattr(resp, "headers", None)
    fn = getattr(headers, "multi_items", None)
    if callable(fn):
        try:
            return [(str(k), str(v)) for k, v in fn()]
        except Exception:
            pass
    if headers is not None and hasattr(headers, "items"):
        try:
            return [(str(k), str(v)) for k, v in headers.items()]
        except Exception:
            pass
    return []


def _headers_dict(headers):
    """Normalise either engine's headers into a case-insensitive mapping."""
    try:
        return _CI({str(k): str(v) for k, v in headers.items()})
    except Exception:
        return _CI()

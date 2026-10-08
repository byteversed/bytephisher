"""Per-campaign symbol names: the fixed strings a scanner can grep.

A fixed set of names is a signature: the session cookie was always `__bhs`, the intel cookie always
`__bhi`, and the injected tags always carried `data-capture` / `data-beacon` /
`data-intel`. Those are signatures - a defender (or a vendor's page-side script) can
look for them in a page, a cookie jar or a log, and one fingerprint covers every
campaign the tool has ever run.

`Symbols.fixed()` keeps the historical names (so existing tooling, tests and
runbooks keep working) and `Symbols.random()` derives a fresh set per campaign from
`secrets`, which is what `tools/campaign.sh` uses. Nothing else about the protocol
changes: the names are still written and read in exactly the same places.
"""
import re
import secrets

__all__ = ["Symbols", "SESSION_DEFAULT", "INTEL_DEFAULT", "ATTR_DEFAULTS"]

SESSION_DEFAULT = "__bhs"
INTEL_DEFAULT = "__bhi"
ATTR_DEFAULTS = {"capture": "data-capture", "beacon": "data-beacon",
                 "intel": "data-intel"}

# cookie names a browser will accept (a leading underscore run is fine: the historical
# names are `__bhs` / `__bhi`), and attribute names that survive HTML parsing
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{1,60}$")


class Symbols:
    """The names this campaign writes into a victim's browser and page."""

    __slots__ = ("session", "intel", "capture_attr", "beacon_attr", "intel_attr",
                 "random")

    def __init__(self, session=SESSION_DEFAULT, intel=INTEL_DEFAULT,
                 capture_attr=ATTR_DEFAULTS["capture"],
                 beacon_attr=ATTR_DEFAULTS["beacon"],
                 intel_attr=ATTR_DEFAULTS["intel"], random=False):
        for value in (session, intel, capture_attr, beacon_attr, intel_attr):
            if not _NAME_RE.match(str(value or "")):
                raise ValueError(f"unsafe symbol name: {value!r}")
        self.session = session
        self.intel = intel
        self.capture_attr = capture_attr
        self.beacon_attr = beacon_attr
        self.intel_attr = intel_attr
        self.random = bool(random)

    @classmethod
    def fixed(cls):
        """The historical names. Tooling and tests written against them keep working."""
        return cls()

    @classmethod
    def random_(cls, prefix="bh"):
        """A fresh set, so two campaigns do not share a fingerprint."""
        token = secrets.token_hex(4)
        stem = f"{prefix}_{token}"
        return cls(session=f"__{stem}s", intel=f"__{stem}i",
                   capture_attr=f"data-{stem}-c", beacon_attr=f"data-{stem}-b",
                   intel_attr=f"data-{stem}-i", random=True)

    @classmethod
    def from_mode(cls, mode):
        """`--symbols fixed|random` (anything falsy means fixed)."""
        mode = (mode or "fixed").strip().lower()
        if mode in ("random", "rand", "fresh"):
            return cls.random_()
        return cls.fixed()

    def to_dict(self):
        return {"session": self.session, "intel": self.intel,
                "capture_attr": self.capture_attr, "beacon_attr": self.beacon_attr,
                "intel_attr": self.intel_attr, "random": self.random}

    def __repr__(self):
        return (f"Symbols(session={self.session!r}, intel={self.intel!r}, "
                f"random={self.random})")

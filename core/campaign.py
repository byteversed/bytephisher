# ============================================================================
# FILE: core/campaign.py
# ============================================================================
"""Cohorts, A/B variants, and a target that always sees the same page.

Sending one lure to everyone and learning nothing from the result is the difference between a
send and a campaign. This module splits a list into cohorts, gives each cohort a variant, and
answers two questions: which page does THIS target get, and which variant is actually working.

The assignment is a hash of the target, not a counter, and that matters for one reason: a
target who reloads, or who opens the link on a second device, must see the same page. A
different page on the second visit is how a target notices, and it also destroys the A/B
result because the same person counted twice.

Nothing here sends anything: it decides, and it reports.
"""
import hashlib
import time

__all__ = ["Cohort", "Campaign", "VARIANTS", "variant_of", "summarise", "describe"]


class Cohort:
    """One arm of the test: a name, a weight, and the variant it serves."""

    __slots__ = ("name", "weight", "variant", "pretext", "locale", "notes")

    def __init__(self, name="", weight=1, variant="", pretext="", locale="en", notes=""):
        self.name = str(name or "")
        self.weight = max(0, int(weight or 0))
        self.variant = str(variant or "")
        self.pretext = str(pretext or "")
        self.locale = str(locale or "en")
        self.notes = str(notes or "")

    def to_dict(self):
        return {"name": self.name, "weight": self.weight, "variant": self.variant,
                "pretext": self.pretext, "locale": self.locale, "notes": self.notes}


# The dimensions worth testing, cheapest first. A variant is a value on one of these.
VARIANTS = {
    "lure_shape": ("link", "qr", "attachment", "calendar"),
    "pretext": ("invoice_hold", "it_password_expiry", "mfa_enrolment", "shared_document",
                "device_code_setup"),
    "ask": ("click_only", "credentials", "device_code", "consent"),
    "sender_tone": ("formal", "colleague", "system"),
}


class Campaign:
    """The cohort table, and the assignment of a target to one of them."""

    def __init__(self, cohorts=None, name="", salt=""):
        self.name = str(name or "")
        self.salt = str(salt or "")
        self.cohorts = [c if isinstance(c, Cohort) else Cohort(**c)
                        for c in (cohorts or [])]

    def __len__(self):
        return len(self.cohorts)

    def add(self, name, weight=1, variant="", pretext="", locale="en", notes=""):
        cohort = Cohort(name, weight, variant, pretext, locale, notes)
        self.cohorts.append(cohort)
        return cohort

    def total_weight(self):
        return sum(c.weight for c in self.cohorts) or 0

    def assign(self, target):
        """The cohort for one target: stable across visits, and proportional to the weights.

        A hash of the target (plus the campaign salt) is mapped onto the weight table, so a
        reload or a second device lands on the same arm while the arms stay proportional.
        """
        if not self.cohorts:
            return None
        total = self.total_weight()
        if total <= 0:
            return self.cohorts[0]
        key = f"{self.salt}:{str(target or '').strip().lower()}"
        bucket = int(hashlib.sha256(key.encode()).hexdigest()[:12], 16) % total
        upto = 0
        for cohort in self.cohorts:
            upto += cohort.weight
            if bucket < upto:
                return cohort
        return self.cohorts[-1]

    def split(self, targets):
        """Assign a whole list: {cohort_name: [targets]}."""
        out = {}
        for target in targets or []:
            cohort = self.assign(target)
            out.setdefault(cohort.name if cohort else "(none)", []).append(target)
        return out

    def to_dict(self):
        return {"name": self.name, "salt": self.salt,
                "cohorts": [c.to_dict() for c in self.cohorts], "created": time.time()}

    def describe(self):
        total = self.total_weight()
        lines = [f"campaign {self.name or '(unnamed)'}: {len(self.cohorts)} cohort(s), "
                 f"weight {total}"]
        for cohort in self.cohorts:
            share = (cohort.weight / total * 100) if total else 0
            lines.append(f"  {cohort.name:<16} {share:5.1f}%  variant={cohort.variant or '-'}"
                         f"  pretext={cohort.pretext or '-'}  locale={cohort.locale}")
        return "\n".join(lines)


def variant_of(target, dimension, cohorts=None, salt=""):
    """A value for one dimension, chosen stably for this target."""
    choices = VARIANTS.get(dimension)
    if not choices:
        raise KeyError(f"unknown dimension {dimension!r}; have: "
                       f"{', '.join(sorted(VARIANTS))}")
    if cohorts:
        cohort = Campaign(cohorts=cohorts, salt=salt).assign(target)
        if cohort is None:
            return ""
        return getattr(cohort, dimension, "") or cohort.variant
    key = f"{salt}:{dimension}:{str(target or '').strip().lower()}"
    return choices[int(hashlib.sha256(key.encode()).hexdigest()[:12], 16) % len(choices)]


def summarise(captures, key="variant"):
    """Per-variant totals from capture rows: which arm is actually working.

    `captures` is a list of dicts carrying the variant that was served (the tool records it on
    the session), so the answer comes from what happened rather than from a plan.
    """
    out = {}
    for row in captures or []:
        name = str((row or {}).get(key) or "(unlabelled)")
        bucket = out.setdefault(name, {"targets": 0, "clicks": 0, "credentials": 0})
        bucket["targets"] += 1
        if row.get("state") in ("clicked", "visited", "captured"):
            bucket["clicks"] += 1
        if row.get("credentials") or row.get("creds"):
            bucket["credentials"] += 1
    for bucket in out.values():
        bucket["click_rate"] = (round(bucket["clicks"] / bucket["targets"], 3)
                                if bucket["targets"] else 0.0)
        bucket["credential_rate"] = (round(bucket["credentials"] / bucket["targets"], 3)
                                     if bucket["targets"] else 0.0)
    return out


def describe(summary):
    lines = ["variant results:"]
    for name in sorted(summary or {}):
        row = summary[name]
        lines.append(f"  {name:<18} targets={row['targets']:<5} "
                     f"clicks={row['click_rate']:<6} creds={row['credential_rate']}")
    if not summary:
        lines.append("  no captures yet: an A/B result needs data, not a plan")
    return "\n".join(lines)

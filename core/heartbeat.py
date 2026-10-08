# ============================================================================
# FILE: core/heartbeat.py
# ============================================================================
"""The dead-man's switch, and the domain-age preflight.

Two things an operator needs before and during a campaign, and both are about the same fear:
finding out too late.

**The dead-man's switch.** A campaign that has stopped (the tunnel died, the process was
killed, the box was suspended) looks identical to a campaign nobody clicked - until the second
day. The heartbeat is written by the running server and checked from outside: if it is older
than the window, the operator is told, and can be told to stop the campaign automatically.

**The domain-age preflight.** A domain registered last week is the single most reliable
filter both major mail providers apply, and it is visible for free: RDAP answers with the
registration date, no API key and no account. Checking it costs one request and saves a wave.

Nothing here decides for the operator: it reports the age, the verdict and what each provider
does with it.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from core import net

__all__ = ["Heartbeat", "check", "rdap_lookup", "domain_age_verdict", "describe",
           "YOUNG_DOMAIN_DAYS", "ESTABLISHED_DAYS"]

# A domain younger than this is a filter tell for both major providers.
YOUNG_DOMAIN_DAYS = 30
# Older than this and the age is no longer the reason a message lands in spam.
ESTABLISHED_DAYS = 365
RDAP = "https://rdap.org/domain/"


class Heartbeat:
    """A heartbeat file: written by the campaign, read by anything that can see the disk."""

    def __init__(self, path="", window=600):
        self.path = str(path or "")
        self.window = int(window or 600)

    def beat(self, note="", now=None):
        """Write a heartbeat (atomic: a reader never sees half a file)."""
        if not self.path:
            raise ValueError("no heartbeat path")
        now = now if now is not None else time.time()
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"at": now, "pid": os.getpid(), "note": str(note or "")}, fh)
        os.replace(tmp, self.path)
        return now

    def read(self):
        """(at, note) or (0, '') when there is no heartbeat yet."""
        if not self.path or not os.path.isfile(self.path):
            return 0.0, ""
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return 0.0, ""
        return float(data.get("at") or 0), str(data.get("note") or "")

    def status(self, now=None):
        """ok / stale / missing, with the age and what to do about it."""
        now = now if now is not None else time.time()
        at, note = self.read()
        if not at:
            return {"state": "missing", "age": None, "window": self.window, "note": note,
                    "action": "no heartbeat has ever been written: is the campaign running?"}
        age = max(0.0, now - at)
        if age > self.window:
            return {"state": "stale", "age": age, "window": self.window, "note": note,
                    "action": f"no heartbeat for {int(age)}s (window {self.window}s): the "
                              "campaign has stopped - check the tunnel and the process"}
        return {"state": "ok", "age": age, "window": self.window, "note": note,
                "action": ""}


def check(path, window=600, now=None):
    """Convenience wrapper: the status of a heartbeat file."""
    return Heartbeat(path, window).status(now=now)


def rdap_lookup(domain, fetch=None, timeout=10):
    """Registration facts for a domain, over RDAP (free, no key).

    Returns {ok, created, age_days, registrar, error}. An unreadable answer is reported as an
    error, never as "old enough".
    """
    name = str(domain or "").strip().lower()
    if not name or "." not in name:
        return {"ok": False, "error": "not a domain name", "domain": name}
    url = RDAP + urllib.parse.quote(name, safe="")
    try:
        data = fetch(url, timeout) if fetch else _get_json(url, timeout)
    except Exception as e:
        return {"ok": False, "domain": name, "error": f"{type(e).__name__}: {e}"}
    if not isinstance(data, dict):
        return {"ok": False, "domain": name, "error": "unexpected RDAP answer"}
    created, registrar = "", ""
    for event in data.get("events") or []:
        if str(event.get("eventAction", "")).lower() == "registration":
            created = str(event.get("eventDate") or "")
    for entity in data.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            for vcard in entity.get("vcardArray", [None, []])[1]:
                if vcard and vcard[0] == "fn":
                    registrar = str(vcard[3])
    age = _age_days(created)
    return {"ok": True, "domain": name, "created": created, "age_days": age,
            "registrar": registrar, "status": data.get("status") or []}


def _age_days(created):
    if not created:
        return None
    text = created.replace("Z", "+00:00")
    try:
        from datetime import datetime, timezone
        when = datetime.fromisoformat(text)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - when).total_seconds() // 86400)
    except Exception:
        return None


def domain_age_verdict(age_days):
    """What the age means for deliverability, honestly and without a provider's internals."""
    if age_days is None:
        return {"verdict": "unknown", "why": "no registration date was returned"}
    if age_days < YOUNG_DOMAIN_DAYS:
        return {"verdict": "young",
                "why": f"{age_days} day(s) old: a recently registered domain is the filter "
                       "both major providers apply first, and it is not a reputation problem "
                       "you can warm your way out of"}
    if age_days < ESTABLISHED_DAYS:
        return {"verdict": "maturing",
                "why": f"{age_days} day(s) old: no longer new, still thin on history - "
                       "volume and link reputation decide it from here"}
    return {"verdict": "established",
            "why": f"{age_days} day(s) old: the age itself is no longer the reason a message "
                   "is filtered"}


def describe(report):
    if "state" in report:
        lines = [f"heartbeat: {report['state']}"
                 + (f" (age {int(report['age'])}s / window {report['window']}s)"
                    if report.get("age") is not None else "")]
        if report.get("action"):
            lines.append(f"  {report['action']}")
        return "\n".join(lines)
    head = f"domain age: {report.get('domain')}" if report.get("domain") else "domain age"
    lines = [f"{head} -> "
             f"{report.get('verdict') or ('error' if not report.get('ok') else 'unknown')}"]
    if report.get("created"):
        lines.append(f"  registered {report['created']}"
                     f" ({report.get('age_days')} day(s) ago)"
                     + (f", registrar {report['registrar']}" if report.get("registrar") else ""))
    if report.get("why"):
        lines.append(f"  {report['why']}")
    if report.get("error"):
        lines.append(f"  {report['error']}")
    return "\n".join(lines)


def _get_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"RDAP answered {e.code}") from e
    return json.loads(raw)

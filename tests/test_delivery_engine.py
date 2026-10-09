"""Delivery-engine hardening tests: the lure surface a victim actually receives.

Every test here pins a defect found by rendering the ENGINE, not the unit: real
template files from the repo's template set, hostile input driven at each public
function, and the escaping rules that keep a template from breaking its own inline
script. The fixes live in core/templates.py, core/lures.py, core/phishlet.py,
core/pwa.py, core/qr.py, core/campaign.py, core/inbox.py, core/redirectors.py,
core/clickfix.py, core/heartbeat.py, tools/gen_templates.py and tools/import_site.py.

No network: IMAP, RDAP and the redirect chain are driven through their injected
fetchers/clients. The one served test starts the real static server on a free port.
"""
import json
import os
import sys
import tempfile
import threading
import time
from html.parser import HTMLParser

import pytest
from conftest import TEMPLATES, free_port

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import campaign as C  # noqa: E402
from core import clickfix as CF  # noqa: E402
from core import heartbeat as HB  # noqa: E402
from core import inbox as IB  # noqa: E402
from core import lures as L  # noqa: E402
from core import phishlet as PH  # noqa: E402
from core import pwa as PWA  # noqa: E402
from core import qr as QR  # noqa: E402
from core import redirectors as R  # noqa: E402
from core import templates as TPL  # noqa: E402

# integration: serves pages over a real local socket
pytestmark = pytest.mark.integration


# --------------------------------------------------------------- html parsing --
class _Doc(HTMLParser):
    """A real parse: collect forms, input names and script sources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.inputs = []
        self.scripts = []
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append(a)
            self._in_form = True
        elif tag in ("input", "select", "textarea") and a.get("name"):
            self.inputs.append(a)
        elif tag == "script":
            self.scripts.append(a.get("src") or "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False

    @classmethod
    def parse(cls, html):
        d = cls()
        d.feed(html)
        d.close()
        return d


def _manifest():
    with open(os.path.join(TEMPLATES, "templates.json"), encoding="utf-8") as f:
        return json.load(f)


def _site_dir(entry):
    return TPL.resolve_dir(entry["dir"], TEMPLATES)


def _pick(*slugs):
    """Real manifest entries by slug (fails loudly if the template set changed)."""
    man = {t["slug"]: t for t in _manifest()}
    out = []
    for s in slugs:
        assert s in man, f"template {s!r} is not in the generated set"
        out.append(man[s])
    return out


# ===================================================== real templates end to end =
class TestRealTemplatesRenderCleanly:
    """template -> the HTML a victim receives: a valid page with the real fields."""

    def test_every_generated_template_renders_valid_html(self):
        """Parse every generated template; the form and fields must be real ones."""
        from tools import gen_templates
        slugs = {s[0] for s in gen_templates.SITES}
        entries = [t for t in _manifest() if t["slug"] in slugs]
        assert len(entries) >= 80, "the template set is unexpectedly small"
        for entry in entries:
            site = _site_dir(entry)
            html = TPL.render_site(site, "/", False)
            doc = _Doc.parse(html)                       # must not raise
            assert len(doc.forms) == 1, f'{entry["slug"]}: {len(doc.forms)} forms'
            form = doc.forms[0]
            assert form.get("method", "").upper() == "POST", entry["slug"]
            assert form.get("action") == "/", (entry["slug"], form.get("action"))
            names = {i["name"] for i in doc.inputs}
            with open(os.path.join(site, "fields.json"), encoding="utf-8") as f:
                fields = json.load(f)
            for want in fields["capture_fields"]:
                assert want in names, f'{entry["slug"]}: no input named {want!r}'
            assert "password" in names, entry["slug"]

    def test_a_split_and_a_dark_layout_still_parse(self):
        """The two non-card layouts wrap the form differently; both must stay valid."""
        # a bank (split hero) and a crypto brand (dark) exercise the layout branches
        for entry in _pick("hdfc", "binance"):
            html = TPL.render_site(_site_dir(entry), "/", False)
            doc = _Doc.parse(html)
            assert len(doc.forms) == 1 and doc.forms[0].get("action") == "/", entry["slug"]

    def test_the_otp_page_has_six_fields_for_every_template(self):
        from tools import gen_templates
        slugs = {s[0] for s in gen_templates.SITES}
        for entry in [t for t in _manifest() if t["slug"] in slugs]:
            html = TPL.render_site(_site_dir(entry), "/", True)
            doc = _Doc.parse(html)
            otp = [i for i in doc.inputs if i["name"].startswith("otp_")]
            assert len(otp) == 6, entry["slug"]

    def test_the_served_page_carries_the_collector_exactly_once(self):
        """The HTML a victim receives: valid, one form, one injected collector tag."""
        from core import server as srv
        entry = _pick("google")[0]
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_deliv_"), "d.db")
        port = free_port()
        httpd, _ = srv.serve(TEMPLATES, _site_dir(entry), port, db_path,
                             geo_provider="off", site_name="google", campaign="t")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/", headers={"Host": "127.0.0.1",
                                              "User-Agent": "Mozilla/5.0"})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            conn.close()
            assert r.status == 200
            doc = _Doc.parse(body)
            assert len(doc.forms) == 1 and doc.forms[0].get("action") == "/"
            assert {i["name"] for i in doc.inputs} >= {"email", "password"}
            assert body.count("intel.js") == 1, "the collector must be injected once"
        finally:
            httpd.shutdown()

    def test_a_lure_path_serves_the_same_template(self):
        """`/l/<token>` is a lure entry point and must still yield the real page."""
        from core import server as srv
        entry = _pick("google")[0]
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_lure_"), "d.db")
        port = free_port()
        httpd, _ = srv.serve(TEMPLATES, _site_dir(entry), port, db_path,
                             geo_provider="off", site_name="google", campaign="t")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/l/8f3k2m1", headers={"Host": "127.0.0.1",
                                                       "User-Agent": "Mozilla/5.0"})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            conn.close()
            assert r.status == 200
            assert len(_Doc.parse(body).forms) == 1
        finally:
            httpd.shutdown()


# ============================================================ hostile input ====
class TestTemplateHostileInput:
    def test_a_manifest_dir_with_a_separator_or_dotdot_is_refused(self):
        # a crafted manifest entry must not let render_site read outside the root
        assert TPL.resolve_dir("../../etc/passwd", "/srv/templates") == ""
        assert TPL.resolve_dir("a/../../b", "/srv/templates") == ""
        assert TPL.resolve_dir("..", "/srv/templates") == ""

    def test_a_normal_relative_dir_is_resolved_and_an_absolute_one_passes(self):
        assert TPL.resolve_dir("01_facebook", "/srv/templates") == "/srv/templates/01_facebook"
        assert TPL.resolve_dir("sub/dir", "/srv/templates") == "/srv/templates/sub/dir"
        assert TPL.resolve_dir("/abs/site", "/srv/templates") == "/abs/site"

    def test_an_empty_or_none_template_dir_is_a_clean_404_not_a_crash(self):
        assert "404" in TPL.render_site(None, "/", False)
        assert "404" in TPL.render_site("", "/", False)
        assert "404" in TPL.render_site(tempfile.mkdtemp(), "/", False)

    def test_an_empty_template_set_renders_a_404(self):
        empty = tempfile.mkdtemp()
        html = TPL.render_site(empty, "/", False)
        assert "no index.html" in html and "404" in html

    def test_a_broken_fields_json_does_not_break_rendering(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as f:
            f.write("<html><body>hi</body></html>")
        with open(os.path.join(d, "fields.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        assert TPL.render_site(d, "/", False) == "<html><body>hi</body></html>"

    def test_a_missing_placeholder_does_not_render_a_broken_page(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as f:
            f.write("<h1>{{ Doc_Name }}</h1><p>{{ Missing_Too }}</p>")
        out = TPL.render_site(d, "/", False)
        assert "{{" not in out and "}}" not in out

    def test_a_template_with_jinja_syntax_errors_does_not_leak_markers(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as f:
            f.write("<h1>{{ Doc_Name }} and {% if %} broken {{unclosed</h1>")
        out = TPL.render_site(d, "/", False)
        for marker in ("{{", "}}", "{%", "%}", "{#", "#}"):
            assert marker not in out, (marker, out)

    def test_a_unicode_brand_name_renders_without_error(self):
        from tools import gen_templates
        html, otp_html, fields = gen_templates.build_site(
            "u", "Ünïcödé Банк", "#123456", "#abcdef", "email", "код")
        assert "Ünïcödé" in html and "Банк" in otp_html
        assert fields["capture_fields"] == ["email", "password"]


# ============================================== inline-script / attribute escape =
class TestInlineScriptEscaping:
    """Any operator- or victim-supplied string that lands in a <script> or an
    attribute must be escaped, or the string breaks the page it is embedded in."""

    def test_a_pwa_service_worker_path_cannot_close_the_script_tag(self):
        page = PWA.inject("<html><head></head><body></body></html>",
                          sw_path="/a'</script><script>alert(1)</script>")
        assert "</script><script>alert(1)" not in page
        # the registration string is still a valid JS literal and the normal path is intact
        assert "serviceWorker.register('/sw.js')" in PWA.inject(
            "<html><head></head><body></body></html>")

    def test_a_pwa_manifest_path_is_attribute_escaped(self):
        page = PWA.inject("<html><head></head><body></body></html>",
                          manifest_path='/m" onload="x')
        doc = _Doc.parse(page)
        # the injected attribute did not become a real event handler
        assert 'onload' not in "".join(
            f'{k}={v}' for a in doc.forms for k, v in a.items())
        assert 'onload="x"' not in page
        assert "&quot;" in page

    def test_pwa_injection_is_still_idempotent(self):
        once = PWA.inject("<html><head></head><body></body></html>")
        assert PWA.inject(once) == once

    def test_a_clickfix_command_with_a_script_close_is_json_escaped(self):
        page = CF.build_page(command='powershell -c "</script><script>alert(1)</script>"')
        assert "</script><script>alert(1)" not in page
        assert "\\u003c" in page

    def test_a_clickfix_headline_and_brand_are_html_escaped(self):
        page = CF.build_page(command="cmd", headline="<img src=x onerror=alert(1)>",
                             brand="<script>alert(2)</script>")
        assert "<img src=x onerror" not in page
        assert "<script>alert(2)" not in page

    def test_a_qr_svg_colour_cannot_break_out_of_the_attribute(self):
        m = QR.encode("https://lure.test/x")
        svg = QR.svg(m, dark='" /><script>alert(1)</script>', light='" onload="x')
        assert "<script>" not in svg and 'onload="x"' not in svg
        import xml.etree.ElementTree as ET
        ET.fromstring(svg)                     # must still be well-formed XML

    def test_a_qr_payload_containing_a_script_close_encodes_fine(self):
        m = QR.encode("https://lure.test/?a=</script><script>alert(1)</script>")
        assert len(m) == len(m[0])
        assert "</script>" not in QR.svg(m)
        assert "</script>" not in QR.ascii_art(m)


# ==================================================================== lures ====
class TestLures:
    def test_extract_token_accepts_every_shape_and_rejects_garbage(self):
        assert L.extract_token("/l/8f3k2m1") == "8f3k2m1"
        assert L.extract_token("/", "?l=abcd1234") == "abcd1234"
        assert L.extract_token("/", "", "#l=zzzz9999") == "zzzz9999"
        # a lure id that does not exist / is malformed is not invented
        assert L.extract_token("/l/") == ""
        assert L.extract_token("/nothing/here") == ""
        assert L.extract_token("../../etc/passwd") == ""

    def test_a_lure_url_is_stable_and_fragment_lures_hide_the_token(self):
        lure = L.Lure(phishlet="p", token="tok12345")
        assert lure.url("https://x.test/") == "https://x.test/l/tok12345"
        frag = L.Lure(phishlet="p", kind="fragment", token="tok12345")
        assert frag.url("https://x.test") == "https://x.test/#l=tok12345"

    def test_a_one_time_lure_burns_and_an_unknown_kind_defaults_to_link(self):
        lure = L.Lure(kind="one-time", max_uses=1, uses=1)
        assert lure.burned is True
        assert L.Lure(kind="nonsense").kind == "link"

    def test_a_lure_with_no_token_still_gets_one(self):
        lure = L.Lure(phishlet="p")
        assert len(lure.token) >= 4 and lure.url("https://x.test").endswith(lure.token)


# ================================================================ phishlet =====
class TestPhishletRobustness:
    def test_child_params_with_quotes_backslashes_and_braces_do_not_corrupt_json(self):
        ph = PH.Phishlet(upstream="{tenant}.okta.com", params={"tenant": ""}, name="t")
        # a quote used to break the json.dumps/str.replace round-trip in child()
        child = ph.child("c", tenant='a"b')
        assert child.name == "c" and child.params["tenant"] == 'a"b'
        assert ph.child("c", tenant="a\\b").proxy_hosts[0].orig_host == "a\\b.okta.com"
        assert ph.child("c", tenant="a{b").name == "c"

    def test_a_bad_regex_is_a_non_match_not_a_crash(self):
        ph = PH.Phishlet(upstream="x.test", inject_paths=["[unclosed"])
        assert ph.wants_injection("/login") is False
        blocked = PH.Phishlet(upstream="x.test", block_paths=["[bad"], inject_paths=[".*"])
        assert blocked.wants_injection("/login") is True

    def test_a_bad_js_trigger_and_force_post_pattern_are_non_matches(self):
        ji = PH.JsInject(payload="x", trigger_paths=["[bad"])
        assert ji.applies("h", "/p", "text/html") is False
        fp = PH.ForcePost(path="/s", search=[{"key": "[bad"}])
        assert fp.applies("/s", "body") is False

    def test_a_bad_auth_url_regex_does_not_complete_the_session(self):
        ph = PH.Phishlet(upstream="x.test", auth_urls=["[unclosed"],
                         auth_tokens=[{"keys": ["sid"], "domain": "x.test"}])
        assert ph.session_complete([], "/anything") is False
        assert ph.session_complete(["sid"]) is True


# ============================================================== campaign =======
class TestCampaignCohorts:
    def _write_cohorts(self, rows):
        path = os.path.join(tempfile.mkdtemp(), "cohorts.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f)
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_an_empty_cohort_file_assigns_nothing(self):
        rows = self._write_cohorts([])
        camp = C.Campaign(cohorts=rows)
        assert camp.assign("a@x.test") is None
        # no cohorts: every target lands in the documented "(none)" bucket
        assert camp.split(["a@x.test"]) == {"(none)": ["a@x.test"]}
        assert "needs data" in C.describe(C.summarise([]))

    def test_rows_with_unknown_columns_are_kept_not_rejected(self):
        rows = self._write_cohorts([{"name": "control", "weight": 1, "variant": "link",
                                     "comment": "extra column"}])
        camp = C.Campaign(cohorts=rows)
        assert camp.assign("a@x.test").name == "control"
        # no pretext on the cohort: the dimension falls back to the cohort's variant
        assert C.variant_of("a@x.test", "pretext", cohorts=rows) == "link"

    def test_non_mapping_rows_are_dropped_cleanly(self):
        camp = C.Campaign(cohorts=["not-a-dict", 42, None])
        assert len(camp) == 0 and camp.assign("a@x.test") is None

    def test_a_valid_cohort_file_still_assigns_stably(self):
        rows = self._write_cohorts([
            {"name": "control", "weight": 1, "variant": "link", "pretext": "invoice_hold"},
            {"name": "qr", "weight": 1, "variant": "qr", "pretext": "mfa_enrolment"}])
        camp = C.Campaign(cohorts=rows, salt="s")
        assert camp.assign("a@x.test").name == camp.assign("a@x.test").name
        assert set(camp.split([f"t{i}@x.test" for i in range(20)])) <= {"control", "qr"}


# ================================================================= inbox =======
class TestInboxFailures:
    def test_a_select_that_raises_is_a_clean_inboxerror(self):
        class Bad:
            def select(self, folder):
                raise OSError("socket reset")

            def logout(self):
                pass

        with pytest.raises(IB.InboxError):
            IB.fetch(client=Bad())

    def test_a_search_that_raises_is_a_clean_inboxerror(self):
        class Bad:
            def select(self, folder):
                return "OK", [b"1"]

            def search(self, *a):
                raise OSError("boom")

            def logout(self):
                pass

        with pytest.raises(IB.InboxError):
            IB.fetch(client=Bad())

    def test_an_imaplib_error_type_is_wrapped_too(self):
        """imaplib raises its own error class, not an OSError; it must not leak."""
        import imaplib

        class Bad:
            def select(self, folder):
                raise imaplib.IMAP4.error("BAD no such mailbox")

            def logout(self):
                pass

        with pytest.raises(IB.InboxError) as ei:
            IB.fetch(client=Bad())
        assert "IMAP read failed" in str(ei.value)

    def test_both_connect_attempts_failing_is_a_clean_inboxerror(self, monkeypatch):
        def raiser(*a, **kw):
            raise OSError("connection refused")

        monkeypatch.setattr(IB.imaplib, "IMAP4_SSL", raiser)
        monkeypatch.setattr(IB.imaplib, "IMAP4", raiser)
        with pytest.raises(IB.InboxError) as ei:
            IB._connect("127.0.0.1", "u", "p", 1)
        assert "connect" in str(ei.value)

    def test_fetching_without_a_host_is_still_refused(self):
        with pytest.raises(IB.InboxError):
            IB.fetch()


# ============================================================= redirectors ====
class TestRedirectors:
    def test_a_chain_that_loops_is_reported_dead(self):
        report = R.verify_chain("https://a.test/x",
                                fetch=lambda url, t=10: (302, "https://a.test/x"))
        assert report["dead"] and "loops" in report["dead"][0]["why"]
        assert report["ok"] is False

    def test_a_hop_that_raises_is_a_clean_dead_hop(self):
        def boom(url, t=10):
            raise OSError("connection refused")

        report = R.verify_chain("https://hop.test/x", fetch=boom)
        assert report["dead"] and report["ok"] is False
        assert "DEAD" in R.describe(report)

    def test_an_unknown_hop_is_refused_with_the_list(self):
        with pytest.raises(R.RedirectError):
            R.build_chain("https://lure.test", hops=("nope",))

    def test_a_chain_without_a_destination_is_refused(self):
        with pytest.raises(R.RedirectError):
            R.build_chain("")


# ============================================================== heartbeat =====
class TestHeartbeatAndRdap:
    def test_an_rdap_fetch_that_raises_is_reported_not_treated_as_old(self):
        def boom(url, timeout):
            raise RuntimeError("RDAP answered 503")

        out = HB.rdap_lookup("x.test", fetch=boom)
        assert out["ok"] is False and "503" in out["error"]
        assert "error" in HB.describe(out)

    def test_a_non_dict_rdap_answer_is_an_error(self):
        out = HB.rdap_lookup("x.test", fetch=lambda u, t: "not a dict")
        assert out["ok"] is False and "unexpected" in out["error"]

    def test_a_non_domain_is_refused_before_any_call(self):
        out = HB.rdap_lookup("not-a-domain")
        assert out["ok"] is False and "not a domain" in out["error"]

    def test_a_stale_heartbeat_names_the_campaign_as_stopped(self):
        hb = HB.Heartbeat(os.path.join(tempfile.mkdtemp(), "hb.json"), window=60)
        now = hb.beat("running")
        stale = HB.check(hb.path, window=60, now=now + 300)
        assert stale["state"] == "stale" and "campaign has stopped" in stale["action"]


# ============================================================ import slug ======
class TestImportSlugSafety:
    def test_safe_slug_never_contains_a_separator_or_dotdot(self):
        from tools.import_site import _safe_slug
        assert "/" not in _safe_slug("../../evil")
        assert ".." not in _safe_slug("../../evil")
        assert "/" not in _safe_slug("a/b")
        assert _safe_slug("") == "import"
        assert _safe_slug("ACME SSO") == "acme-sso"

    def test_an_import_with_a_traversal_slug_stays_inside_the_root(self, tmp_path,
                                                                  monkeypatch):
        import tools.import_site as imp
        fake = tmp_path / "templates"
        fake.mkdir()
        monkeypatch.setattr(imp, "TEMPLATES", str(fake))
        res = imp.import_site(file=os.path.join("tests", "fixtures", "custom_login.html"),
                              name="Evil", slug="../../evil", index=1)
        root = os.path.realpath(str(fake))
        assert os.path.realpath(res["dir"]).startswith(root + os.sep)
        assert os.path.isfile(os.path.join(res["dir"], "index.html"))

    def test_an_imported_otp_page_escapes_the_operator_name(self):
        from tools.import_site import otp_page
        page = otp_page('<script>alert(1)</script>', "#123456", "x")
        assert "<script>alert(1)" not in page
        assert "&lt;script&gt;" in page

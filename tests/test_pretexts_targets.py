"""Pretexts and targets: the message layer and the per-target personalisation.

The pretexts are data, so the tests check the data is complete (every field it declares is
one it uses, every pretext has a follow-up script) and that a missing field is reported
BEFORE a send. The targets are checked for the two failure modes that matter: personalising
a page with the WRONG person's data, and writing a value into a password field.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import TEMPLATES, free_port  # noqa: E402

from core import pretexts as P  # noqa: E402
from core import server as srv  # noqa: E402
from core import targets as T  # noqa: E402

pytestmark = pytest.mark.unit


class TestThePretextLibrary:

    def test_every_pretext_is_complete(self):
        assert P.names(), "the library is empty"
        for name in P.names():
            p = P.get(name)
            for key in ("roles", "locales", "subject", "body", "fields", "second_ask", "tell"):
                assert p.get(key), f"{name} has no {key}"
            assert p["roles"] and p["locales"]

    def test_every_declared_field_appears_in_the_body_or_subject(self):
        # a field nobody uses is a field the operator is asked for nothing
        for name in P.names():
            p = P.get(name)
            text = p["subject"] + p["body"] + p["second_ask"]
            for field in p["fields"]:
                assert "{{" + field + "}}" in text, f"{name}: {field} is never used"

    def test_a_render_substitutes_every_field(self):
        for name in P.names():
            p = P.get(name)
            ctx = {f: f"<{f}>" for f in p["fields"]}
            subject, body = P.render(name, ctx)
            assert "{{" not in subject and "{{" not in body, name

    def test_a_missing_field_is_reported(self):
        ctx = {"To_FirstName": "Ravi", "Phish_URL": "https://x.test/l/1"}
        missing = P.missing_fields("it_password_expiry", ctx)
        assert "Brand" in missing and "From_Name" in missing
        assert P.missing_fields("it_password_expiry",
                                {**ctx, "Brand": "Acme", "From_Name": "IT"}) == []

    def test_the_second_ask_is_rendered_too(self):
        ask = P.second_ask("invoice_hold", {"Invoice_ID": "INV-9"})
        assert "INV-9" in ask and "{{" not in ask

    def test_an_unknown_pretext_names_the_available_ones(self):
        with pytest.raises(KeyError) as ei:
            P.get("nope")
        assert "it_password_expiry" in str(ei.value)

    def test_each_pretext_carries_a_tell(self):
        for name in P.names():
            assert len(P.get(name)["tell"]) > 10, name

    def test_a_json_override_replaces_a_built_in(self, tmp_path):
        (tmp_path / "custom.json").write_text(json.dumps({
            "it_password_expiry": {"roles": ["x"], "locales": ["en"], "subject": "S",
                                   "body": "B {{Phish_URL}}", "fields": ["Phish_URL"],
                                   "second_ask": "A", "tell": "T"}}), encoding="utf-8")
        loaded = P.load_dir(str(tmp_path))
        try:
            assert "it_password_expiry" in loaded
            assert P.get("it_password_expiry")["subject"] == "S"
        finally:
            P.PRETEXTS["it_password_expiry"] = _ORIGINAL

    def test_a_broken_override_file_is_skipped_not_fatal(self, tmp_path, capsys):
        (tmp_path / "broken.yaml").write_text("not: [valid: yaml", encoding="utf-8")
        (tmp_path / "bad.json").write_text("{oops", encoding="utf-8")
        loaded = P.load_dir(str(tmp_path))          # must not raise
        assert isinstance(loaded, list)


_ORIGINAL = dict(P.PRETEXTS["it_password_expiry"])


class TestTheTargetList:

    def _csv(self, tmp_path, rows):
        p = tmp_path / "targets.csv"
        p.write_text("email,name,role,token,dept\n" + "\n".join(rows), encoding="utf-8")
        return str(p)

    def test_a_csv_loads_with_only_an_email_column(self, tmp_path):
        p = tmp_path / "t.csv"
        p.write_text("email\nravi@corp.test\nsita@corp.test\n", encoding="utf-8")
        store = T.load(str(p))
        assert len(store) == 2 and store.emails() == ["ravi@corp.test", "sita@corp.test"]

    def test_extra_columns_reach_the_context(self, tmp_path):
        store = T.load(self._csv(tmp_path, ["ravi@corp.test,Ravi Kumar,finance,tok-1,APAC"]))
        t = store.by_token("tok-1")
        ctx = t.context()
        assert ctx["To_FirstName"] == "Ravi" and ctx["Role"] == "finance"
        assert ctx["Dept"] == "APAC" and ctx["To_Address"] == "ravi@corp.test"

    def test_a_json_list_loads(self, tmp_path):
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"targets": [{"email": "a@b.test", "name": "A B"}]}),
                     encoding="utf-8")
        assert T.load(str(p)).by_email("a@b.test").name == "A B"

    def test_a_missing_file_is_reported(self):
        with pytest.raises(FileNotFoundError):
            T.load("/nonexistent/targets.csv")

    def test_matching_a_request_by_token_or_address(self):
        store = T.Targets([{"email": "ravi@corp.test", "token": "tok-1"},
                           {"email": "sita@corp.test", "token": "tok-2"}])
        assert store.for_request("/l/tok-2").email == "sita@corp.test"
        assert store.for_request("/login", "?t=tok-1").email == "ravi@corp.test"
        assert store.for_request("/login", "?email=ravi%40corp.test").email == "ravi@corp.test"
        assert store.for_request("/login") is None
        assert store.for_request("/login", "?t=unknown") is None

    def test_the_cookie_wins_over_the_query(self):
        store = T.Targets([{"email": "a@b.test"}, {"email": "c@d.test"}])
        hit = store.for_request("/login", "?email=c@d.test", cookie_email="a@b.test")
        assert hit.email == "a@b.test"

    def test_the_first_name_is_derived_when_the_list_has_none(self):
        t = T.Target(email="ravi.kumar@corp.test")
        assert t.first_name == "Ravi"

    def test_the_summary_reports_the_roles(self):
        store = T.Targets([{"email": "a@b.test", "role": "finance", "token": "t"},
                           {"email": "c@d.test", "role": "it"}])
        s = store.summary()
        assert s["targets"] == 2 and s["with_token"] == 1 and s["roles"] == ["finance", "it"]


class TestPrefill:

    PAGE = ('<form method="post"><input id="email" name="email" type="email" '
            'placeholder="you@example.com"><input name="password" type="password">'
            '<input name="remember" value="1" type="checkbox"></form>')

    def test_the_identity_input_is_filled(self):
        out = T.prefill_html(self.PAGE, T.Target(email="ravi@corp.test"))
        assert 'name="email" type="email" placeholder="you@example.com" value="ravi@corp.test"' in out

    def test_a_password_field_is_never_filled(self):
        out = T.prefill_html(self.PAGE, T.Target(email="ravi@corp.test"))
        assert 'name="password" type="password" value=' not in out

    def test_a_non_identity_field_is_left_alone(self):
        out = T.prefill_html(self.PAGE, T.Target(email="ravi@corp.test"))
        assert 'name="remember" value="1"' in out

    def test_an_existing_value_is_not_overwritten(self):
        page = '<input name="email" value="someone@else.test">'
        out = T.prefill_html(page, T.Target(email="ravi@corp.test"))
        assert "someone@else.test" in out and "ravi@corp.test" not in out

    def test_a_microsoft_style_form_is_recognised(self):
        page = '<input name="loginfmt" type="email" id="i0116">'
        out = T.prefill_html(page, T.Target(email="ravi@corp.test"))
        assert 'value="ravi@corp.test"' in out

    def test_a_page_with_no_identity_input_is_untouched(self):
        page = '<form><input name="q" type="search"></form>'
        assert T.prefill_html(page, T.Target(email="ravi@corp.test")) == page

    def test_no_target_means_no_change(self):
        assert T.prefill_html(self.PAGE, None) == self.PAGE

    def test_identity_fields_lists_what_it_found(self):
        assert T.identity_fields(self.PAGE) == ["email"]


class TestPrefillOverHTTP:
    """The end-to-end case: a visit that carries the target's token gets that target's own
    address in the form, and a visit that carries nothing gets a clean page."""

    def _serve(self, targets):
        db_path = os.path.join(tempfile.mkdtemp(prefix="bh_targets_"), "t.db")
        port = free_port()
        httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, db_path,
                             geo_provider="off", site_name="google", campaign="t",
                             targets=targets)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.25)
        return httpd, port

    def _get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", path, headers={"Host": "127.0.0.1",
                                          "User-Agent": "Mozilla/5.0",
                                          "Accept": "text/html,*/*;q=0.8"})
        r = conn.getresponse()
        out = r.read().decode("utf-8", "replace")
        conn.close()
        return out

    def test_a_token_visit_gets_its_own_address(self):
        store = T.Targets([{"email": "ravi@corp.test", "token": "tok-1"},
                           {"email": "sita@corp.test", "token": "tok-2"}])
        httpd, port = self._serve(store)
        try:
            page = self._get(port, "/?t=tok-2")
            assert 'value="sita@corp.test"' in page
            assert "ravi@corp.test" not in page, "another target's address leaked"
        finally:
            httpd.shutdown()

    def test_an_unknown_token_gets_a_clean_page(self):
        store = T.Targets([{"email": "ravi@corp.test", "token": "tok-1"}])
        httpd, port = self._serve(store)
        try:
            page = self._get(port, "/?t=nope")
            assert "ravi@corp.test" not in page
            assert 'name="email"' in page
        finally:
            httpd.shutdown()

    def test_without_a_target_list_the_page_is_unchanged(self):
        httpd, port = self._serve(None)
        try:
            page = self._get(port, "/?t=tok-1")
            assert 'value="ravi@corp.test"' not in page
        finally:
            httpd.shutdown()

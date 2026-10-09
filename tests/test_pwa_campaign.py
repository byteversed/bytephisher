"""Installable lures and the cohort table.

The assignment must be STABLE for a target: a different page on the second visit is how a
target notices, and it also corrupts the A/B result by counting one person twice.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import campaign as C  # noqa: E402
from core import pwa  # noqa: E402

pytestmark = pytest.mark.unit


class TestThePwa:

    def test_a_manifest_needs_a_name(self):
        with pytest.raises(ValueError):
            pwa.manifest(name="")

    def test_the_manifest_carries_what_a_home_screen_needs(self):
        m = pwa.manifest(name="Contoso Portal", start_url="/portal")
        assert m["name"] == "Contoso Portal" and m["short_name"] == "Contoso Port"
        assert m["start_url"] == "/portal" and m["display"] == "standalone"
        assert {i["sizes"] for i in m["icons"]} == {"192x192", "512x512"}

    def test_the_worker_caches_the_shell_and_falls_back_to_it(self):
        js = pwa.service_worker(assets=["/", "/login"])
        assert "caches.open" in js and "skipWaiting" in js
        assert "caches.match('/')" in js and '"/login"' in js

    def test_injection_adds_the_link_and_the_registration(self):
        page = pwa.inject("<html><head><title>x</title></head><body>hi</body></html>")
        assert '<link rel="manifest" href="/manifest.webmanifest">' in page
        assert "serviceWorker.register('/sw.js')" in page
        assert page.index("manifest.webmanifest") < page.index("</head>")
        assert page.index("serviceWorker") < page.index("</body>")

    def test_injection_is_idempotent(self):
        once = pwa.inject("<html><head></head><body></body></html>")
        assert pwa.inject(once) == once

    def test_injection_survives_a_page_without_head_or_body_tags(self):
        page = pwa.inject("<div>bare</div>")
        assert "manifest.webmanifest" in page and "serviceWorker" in page

    def test_the_install_prompt_is_optional(self):
        with_prompt = pwa.inject("<html><head></head><body></body></html>", prompt=True)
        without = pwa.inject("<html><head></head><body></body></html>", prompt=False)
        assert "beforeinstallprompt" in with_prompt
        assert "beforeinstallprompt" not in without
        assert "pwa-install" in pwa.install_hint()

    def test_the_description_admits_the_secure_context_requirement(self):
        text = pwa.describe({"name": "X", "display": "standalone", "start_url": "/",
                             "manifest_path": pwa.MANIFEST_PATH, "sw_path": pwa.SW_PATH,
                             "secure_context": False})
        assert "secure context" in text


class TestTheCohortTable:

    def _campaign(self):
        c = C.Campaign(name="wave1", salt="s1")
        c.add("control", 1, variant="link", pretext="invoice_hold")
        c.add("qr-arm", 1, variant="qr", pretext="it_password_expiry")
        return c

    def test_a_target_always_lands_on_the_same_cohort(self):
        c = self._campaign()
        for target in ("a@x.test", "b@x.test", "c@x.test"):
            assert c.assign(target).name == c.assign(target).name

    def test_the_salt_changes_the_assignment(self):
        one = C.Campaign(name="w", salt="one")
        one.add("a", 1, variant="link")
        one.add("b", 1, variant="qr")
        other = C.Campaign(name="w", salt="two")
        other.add("a", 1, variant="link")
        other.add("b", 1, variant="qr")
        moved = [t for t in (f"t{i}@x" for i in range(40))
                 if one.assign(t).name != other.assign(t).name]
        assert moved, "a different salt must be able to move at least one target"

    def test_a_zero_weight_cohort_is_never_served(self):
        c = C.Campaign()
        c.add("off", 0, variant="never")
        c.add("on", 1, variant="link")
        assert {c.assign(f"t{i}").name for i in range(30)} == {"on"}

    def test_the_split_covers_every_target_once(self):
        c = self._campaign()
        targets = [f"t{i}@x.test" for i in range(20)]
        split = c.split(targets)
        flat = [t for rows in split.values() for t in rows]
        assert sorted(flat) == sorted(targets)
        assert set(split) == {"control", "qr-arm"}

    def test_an_empty_campaign_assigns_nothing(self):
        assert C.Campaign().assign("a@x") is None
        assert C.variant_of("a@x", "ask") in C.VARIANTS["ask"]

    def test_an_unknown_dimension_is_refused(self):
        with pytest.raises(KeyError):
            C.variant_of("a@x", "nope")

    def test_a_dimension_comes_from_the_cohort_when_there_is_one(self):
        cohorts = [{"name": "one", "weight": 1, "variant": "qr", "pretext": "mfa_enrolment"}]
        assert C.variant_of("a@x", "pretext", cohorts=cohorts, salt="s") == "mfa_enrolment"

    def test_the_summary_counts_from_what_happened(self):
        rows = [{"variant": "qr", "state": "clicked", "credentials": 1},
                {"variant": "qr", "state": "clicked"},
                {"variant": "link", "state": "visited"},
                {"variant": "link", "state": "sent"}]
        summary = C.summarise(rows)
        assert summary["qr"]["targets"] == 2 and summary["qr"]["credentials"] == 1
        assert summary["qr"]["credential_rate"] == 0.5
        assert summary["link"]["click_rate"] == 0.5
        assert "targets=" in C.describe(summary)

    def test_an_empty_summary_says_it_needs_data(self):
        assert "needs data" in C.describe(C.summarise([]))

    def test_the_description_reports_each_cohorts_share(self):
        text = self._campaign().describe()
        assert "50.0%" in text and "qr-arm" in text and "invoice_hold" in text

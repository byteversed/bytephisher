"""The second act (replies), the paste layer (ClickFix), and the two "too late" checks.

The inbox classification is deliberately blunt: a missed refusal is expensive, a wrong label is
cheap. ClickFix ships a page and the detection notes, never a payload. The heartbeat is the
dead-man's switch, and the domain age is the filter both providers apply first.
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import clickfix as CF  # noqa: E402
from core import heartbeat as HB  # noqa: E402
from core import inbox as IB  # noqa: E402

pytestmark = pytest.mark.unit


class TestTheInbox:

    @pytest.mark.parametrize("subject,body,want", [
        ("Re: invoice", "what is this? why do you need it", "hesitant"),
        ("Re: invoice", "I am not interested, stop emailing me", "refused"),
        ("Re: invoice", "Out of office until Monday", "auto_reply"),
        ("Re: invoice", "Forwarded to IT, looping in security", "forwarded"),
        ("Re: invoice", "my password is hunter2", "credentials"),
        ("Re: invoice", "ok, which portal again?", "question"),
        ("Re: invoice", "thanks", "unknown"),
    ])
    def test_a_reply_is_classified(self, subject, body, want):
        assert IB.classify(subject, body)[0] == want

    def test_a_refusal_is_never_answered(self):
        out = IB.suggest("refused")
        assert out["send"] is False and "report" in out["why"]

    def test_credentials_arriving_stop_the_thread(self):
        out = IB.suggest("credentials")
        assert out["send"] is False and "reported" in out["why"]

    def test_a_forward_is_treated_as_a_burn(self):
        assert IB.suggest("forwarded")["send"] is False

    def test_an_unknown_pretext_still_sends_but_says_why(self):
        out = IB.suggest("question", pretext="nope")
        assert out["send"] is True and "unknown pretext" in out["why"]

    def test_a_question_gets_the_pretext_script(self):
        out = IB.suggest("question", pretext="invoice_hold", locale="en")
        assert out["send"] is True and "script" in out

    def test_an_unclassified_reply_is_read_not_answered(self):
        assert IB.suggest("unknown")["send"] is False

    def test_replies_thread_against_the_campaign_message_ids(self):
        messages = [{"message_id": "<r1@x>", "in_reply_to": "<camp-1@us>", "references": "",
                     "subject": "Re: hello", "from": "a@b.test", "body": "?"},
                    {"message_id": "<r2@x>", "in_reply_to": "", "references": "<camp-1@us>",
                     "subject": "Re: hello", "from": "c@d.test", "body": "hi"},
                    {"message_id": "<r3@x>", "in_reply_to": "", "references": "",
                     "subject": "Re: another", "from": "e@f.test", "body": "hi"}]
        threads = IB.thread(messages, campaign_ids=["<camp-1@us>"])
        assert len(threads["<camp-1@us>"]) == 2
        assert len(threads) == 2

    def test_threading_falls_back_to_the_subject_when_nothing_references_us(self):
        messages = [{"subject": "Re: Re: Fwd: invoice", "from": "a@b", "body": ""}]
        threads = IB.thread(messages)
        assert list(threads) == ["invoice"]

    def test_fetching_without_a_host_is_refused(self):
        with pytest.raises(IB.InboxError):
            IB.fetch()

    def test_fetching_reads_an_injected_client(self):
        class Fake:
            def __init__(self):
                self.raw = (b"From: a@b.test\r\nSubject: Re: hi\r\n"
                            b"Message-ID: <m1@x>\r\n\r\nwhat is this?\r\n")

            def select(self, folder):
                return "OK", [b"1"]

            def search(self, *a):
                return "OK", [b"1"]

            def fetch(self, num, spec):
                return "OK", [(b"1", self.raw)]

            def logout(self):
                return "BYE", []

        rows = IB.fetch(client=Fake())
        assert len(rows) == 1 and rows[0]["subject"] == "Re: hi"
        assert "what is this" in rows[0]["body"]
        assert "inbox:" in IB.describe(rows)


class TestClickFix:

    def test_a_page_copies_the_operators_command_and_beacons(self):
        page = CF.build_page(command="powershell -w hidden -c \"x\"", platform="windows",
                             beacon_url="/__bh/beacon", brand="Contoso")
        assert "powershell -w hidden" in page
        assert "/__bh/beacon" in page and "navigator.clipboard" in page
        assert "Contoso" in page

    def test_the_page_shows_the_platform_steps(self):
        for platform, step in (("windows", "Windows key"), ("macos", "Command and Space"),
                               ("linux", "Ctrl+Alt+T")):
            page = CF.build_page(command="cmd", platform=platform)
            assert step in page

    def test_a_page_without_a_command_is_refused(self):
        with pytest.raises(CF.ClickFixError):
            CF.build_page(command="")

    def test_an_unknown_platform_is_refused(self):
        with pytest.raises(CF.ClickFixError):
            CF.build_page(command="cmd", platform="amiga")
        with pytest.raises(CF.ClickFixError):
            CF.instructions("amiga")

    def test_the_operators_command_is_json_escaped_into_the_script(self):
        page = CF.build_page(command='a"b</script><script>alert(1)</script>')
        assert "</script><script>alert(1)" not in page
        assert "\\u003c/script" in page or "\\\"" in page

    def test_the_command_shapes_name_the_platform_idioms(self):
        assert "powershell -enc" in CF.COMMAND_SHAPES["windows"]["powershell-encoded"]
        assert "curl" in CF.COMMAND_SHAPES["linux"]["curl-pipe"]

    def test_the_detection_notes_cover_clipboard_process_network_and_log(self):
        notes = CF.detection_notes()
        assert set(notes) >= {"clipboard", "process", "network", "log", "user_side"}
        assert "powershell -enc" in notes["process"]

    def test_the_description_lists_the_steps_and_the_detection(self):
        text = CF.describe({"platform": "windows", "bytes": 10,
                            "steps": CF.instructions("windows"), "beacon": True,
                            "detection": CF.detection_notes()})
        assert "windows" in text and "detection[clipboard]" in text


class TestHeartbeat:

    def test_a_missing_heartbeat_says_so(self):
        status = HB.check(os.path.join(tempfile.mkdtemp(), "none.json"))
        assert status["state"] == "missing" and status["action"]

    def test_a_fresh_heartbeat_is_ok_and_a_stale_one_is_not(self):
        hb = HB.Heartbeat(os.path.join(tempfile.mkdtemp(), "hb.json"), window=60)
        now = hb.beat("running")
        assert HB.check(hb.path, window=60, now=now)["state"] == "ok"
        stale = HB.check(hb.path, window=60, now=now + 120)
        assert stale["state"] == "stale" and "campaign has stopped" in stale["action"]

    def test_a_broken_file_reads_as_missing_not_as_fresh(self):
        path = os.path.join(tempfile.mkdtemp(), "hb.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{oops")
        assert HB.check(path)["state"] == "missing"

    def test_the_heartbeat_is_written_atomically(self):
        hb = HB.Heartbeat(os.path.join(tempfile.mkdtemp(), "hb.json"))
        hb.beat("one")
        at, note = hb.read()
        assert note == "one" and at > 0
        assert not os.path.exists(hb.path + ".tmp")

    def test_a_young_domain_is_a_filter_tell(self):
        out = HB.domain_age_verdict(5)
        assert out["verdict"] == "young" and "first" in out["why"]

    def test_the_verdicts_scale_with_age(self):
        assert HB.domain_age_verdict(90)["verdict"] == "maturing"
        assert HB.domain_age_verdict(900)["verdict"] == "established"
        assert HB.domain_age_verdict(None)["verdict"] == "unknown"

    def test_an_rdap_answer_is_read_for_the_registration_date(self):
        def fetch(url, timeout):
            return {"events": [{"eventAction": "registration",
                                "eventDate": "2020-01-01T00:00:00Z"}],
                    "entities": [{"roles": ["registrar"],
                                  "vcardArray": ["vcard", [["fn", {}, "text", "Acme"]]]}]}

        out = HB.rdap_lookup("example.test", fetch=fetch)
        assert out["ok"] is True and out["registrar"] == "Acme"
        assert out["age_days"] > 365

    def test_an_rdap_failure_is_reported_not_treated_as_old(self):
        def fetch(url, timeout):
            raise RuntimeError("RDAP answered 404")

        out = HB.rdap_lookup("nope.test", fetch=fetch)
        assert out["ok"] is False and "404" in out["error"]
        assert HB.describe(out).count("error") >= 1

    def test_a_non_domain_is_refused_before_the_call(self):
        out = HB.rdap_lookup("not-a-domain")
        assert out["ok"] is False and "not a domain" in out["error"]

    def test_the_description_of_a_live_answer_names_the_registrar(self):
        def fetch(url, timeout):
            return {"events": [{"eventAction": "registration",
                                "eventDate": "2019-06-01T00:00:00Z"}],
                    "entities": [{"roles": ["registrar"],
                                  "vcardArray": ["vcard", [["fn", {}, "text", "Acme"]]]}]}

        text = HB.describe(HB.rdap_lookup("example.test", fetch=fetch))
        assert "registered 2019-06-01" in text and "Acme" in text

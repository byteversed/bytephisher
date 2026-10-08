"""Delivery tests: the message that actually goes on the wire.

A minimal SMTP server accepts the connection and captures the DATA block, so every
assertion here is made against the bytes a mail server would have received - not against
the object we built. The `.ics` is additionally parsed by `icalendar` and the QR is
decoded back out of the PNG pixels with PIL, both test-only dependencies.
"""
import io
import os
import socket
import socketserver
import sys
import threading
import time
from email import message_from_bytes
from email.utils import parsedate_to_datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ics, qr  # noqa: E402
from mailer import blast, qr_html, qr_image, render, send_smtp, to_html  # noqa: E402

pytestmark = pytest.mark.integration


class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 test.local ESMTP\r\n")
        in_data, buf = False, []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            if in_data:
                if line.strip() == b".":
                    self.server.messages.append(b"".join(buf))
                    buf, in_data = [], False
                    self.wfile.write(b"250 OK queued\r\n")
                    continue
                buf.append(line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith((b"EHLO", b"HELO")):
                self.wfile.write(b"250-test.local\r\n250 SIZE 10485760\r\n")
            elif cmd.startswith(b"MAIL") or cmd.startswith(b"RCPT"):
                self.server.rcpts.append(line.strip().decode())
                self.wfile.write(b"250 OK\r\n")
            elif cmd.startswith(b"DATA"):
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif cmd.startswith(b"QUIT"):
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.messages = []
        self.rcpts = []


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def smtp():
    port = free_port()
    srv = _SMTPServer(("127.0.0.1", port), _SMTPHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    yield srv, port
    srv.shutdown()
    srv.server_close()


class TestTheMessageOnTheWire:

    def test_identity_headers_are_all_present(self, smtp):
        srv, port = smtp
        send_smtp("127.0.0.1", port, "it@corp.test", "", "Payroll Q3",
                  "<p>Open it</p>", "ravi@corp.test", html=True,
                  from_name="IT Support", reply_to="helpdesk@corp.test",
                  to_name="Ravi Kumar", in_reply_to="<thread-1@corp.test>",
                  references="<thread-1@corp.test>")
        assert len(srv.messages) == 1
        msg = message_from_bytes(srv.messages[0])
        assert msg["From"] == "IT Support <it@corp.test>"
        assert msg["To"] == "Ravi Kumar <ravi@corp.test>"
        assert msg["Reply-To"] == "helpdesk@corp.test"
        assert msg["In-Reply-To"] == "<thread-1@corp.test>"
        assert msg["References"] == "<thread-1@corp.test>"
        assert msg["Message-ID"], "a missing Message-ID is a bulk-mail tell"
        assert msg["Date"], "a missing Date is a bulk-mail tell"
        parsedate_to_datetime(msg["Date"])                 # must be a real date

    def test_the_envelope_recipient_is_the_target(self, smtp):
        srv, port = smtp
        send_smtp("127.0.0.1", port, "it@corp.test", "", "s", "body", "ravi@corp.test")
        assert any("ravi@corp.test" in r for r in srv.rcpts)

    def test_a_calendar_invite_attaches_and_parses(self, smtp):
        icalendar = pytest.importorskip("icalendar", reason="test-only parser")
        srv, port = smtp
        blob = ics.invite("inv-9@byteversed.test", "Q3 payroll review",
                          "https://login.example.test/auth?t=abc",
                          organizer="it@corp.test",
                          attendees=[("ravi@corp.test", "Ravi Kumar")])
        send_smtp("127.0.0.1", port, "it@corp.test", "", "Invitation",
                  "<p>See attached</p>", "ravi@corp.test", html=True,
                  attachments=[("invite.ics", blob, "text/calendar")])
        msg = message_from_bytes(srv.messages[0])
        parts = [p for p in msg.walk() if p.get_content_type() == "text/calendar"]
        assert parts, "no text/calendar part in the message"
        cal = icalendar.Calendar.from_ical(parts[0].get_payload(decode=True))
        events = list(cal.walk("VEVENT"))
        assert len(events) == 1
        assert str(events[0].get("URL")) == "https://login.example.test/auth?t=abc"
        assert str(cal.get("METHOD")) == "REQUEST"

    def test_the_qr_is_inline_and_decodes_back_to_the_lure(self, smtp):
        Image = pytest.importorskip("PIL.Image", reason="test-only checker")
        srv, port = smtp
        url = "https://login.example.test/auth?t=abc123"
        cid, png, mime = qr_image(url)
        send_smtp("127.0.0.1", port, "it@corp.test", "", "Scan",
                  qr_html(url, cid=cid), "ravi@corp.test", html=True,
                  inline_images=[(cid, png, mime)])
        msg = message_from_bytes(srv.messages[0])
        html = [p for p in msg.walk() if p.get_content_type() == "text/html"][0]
        assert f"cid:{cid}" in html.get_payload(decode=True).decode()
        related = [p for p in msg.walk() if p.get_content_type() == "image/png"]
        assert related, "the QR image was not attached inline"
        # decode the attached PNG back to a matrix and compare with the encoder
        im = Image.open(io.BytesIO(related[0].get_payload(decode=True)))
        im.load()
        px = im.load()
        matrix = qr.encode(url, ecc="M")
        scale, border = 6, 4
        assert im.size == ((len(matrix) + 2 * border) * scale,) * 2
        for r in range(len(matrix)):
            for c in range(len(matrix)):
                x = (c + border) * scale + scale // 2
                y = (r + border) * scale + scale // 2
                assert px[x, y] == (0 if matrix[r][c] else 255), (r, c)

    def test_no_host_means_build_only(self):
        msg = send_smtp("", 0, "it@corp.test", "", "s", "body", "a@b.test",
                        from_name="IT")
        assert msg["From"] == "IT <it@corp.test>" and msg["Subject"] == "s"

    def test_a_rendered_template_carries_the_lure(self):
        subject, body = render("security_alert", {"Phish_URL": "https://x.test/l/abc",
                                                  "From_Name": "IT", "To_Address": "a@b.test"})
        assert "https://x.test/l/abc" in body
        html = to_html(body, base="https://x.test/l/abc")
        assert "https://x.test/l/abc" in html


class TestPacing:

    def test_the_first_message_is_immediate_and_the_rest_wait(self):
        slept = []
        sent = []
        results = blast("h", 25, "u", "p", ["a@x.test", "b@x.test", "c@x.test"],
                        "security_alert", {}, min_delay=20, max_delay=90,
                        sleep=slept.append, send=lambda *a, **k: sent.append(a[6]))
        assert len(slept) == 2, "the first recipient must not be delayed"
        assert all(20 <= d <= 90 for d in slept), slept
        assert sent == ["a@x.test", "b@x.test", "c@x.test"]
        assert all(ok for _addr, ok, _d in results)

    def test_jitter_varies_the_gap(self):
        slept = []
        blast("h", 25, "u", "p", ["a@x.test"] * 12, "security_alert", {},
              min_delay=10, max_delay=40, sleep=slept.append, send=lambda *a, **k: None)
        assert len({round(d, 3) for d in slept}) > 1, "pacing had no jitter"

    def test_one_failure_does_not_stop_the_batch(self):
        def flaky(*args, **kwargs):
            if args[6] == "b@x.test":
                raise RuntimeError("relay refused")
        results = blast("h", 25, "u", "p", ["a@x.test", "b@x.test", "c@x.test"],
                        "security_alert", {}, send=flaky)
        assert [ok for _a, ok, _d in results] == [True, False, True]
        assert "relay refused" in results[1][2]

    def test_no_pacing_means_no_sleep(self):
        slept = []
        blast("h", 25, "u", "p", ["a@x.test", "b@x.test"], "security_alert", {},
              sleep=slept.append, send=lambda *a, **k: None)
        assert slept == []


class TestTheInvite:

    def test_long_urls_are_folded_not_broken(self):
        url = "https://login.example.test/auth?token=" + "a" * 120
        blob = ics.invite("u@x.test", "Review", url)
        for line in blob.decode().split("\r\n"):
            assert len(line.encode("utf-8")) <= 75
        # unfolding must give the URL back intact
        assert ics.parse_fields(blob)["URL"] == url

    def test_text_escaping_round_trips(self):
        icalendar = pytest.importorskip("icalendar", reason="test-only parser")
        text = "Meeting; with, commas\\and slashes"
        blob = ics.invite("u@x.test", text, "https://x.test")
        raw = blob.decode()
        assert "SUMMARY:Meeting\\; with\\, commas\\\\and slashes" in raw, raw
        # a real parser returns the text unescaped, which is the contract
        cal = icalendar.Calendar.from_ical(blob)
        event = list(cal.walk("VEVENT"))[0]
        assert str(event.get("SUMMARY")) == text
        # parse_fields reports the raw (escaped) value, by design
        assert ics.parse_fields(blob)["SUMMARY"].startswith("Meeting\\;")

    def test_the_times_are_utc_and_ordered(self):
        start = time.time() + 600
        blob = ics.invite("u@x.test", "s", "https://x.test", start=start, minutes=45)
        fields = ics.parse_fields(blob)
        assert fields["DTSTART"].endswith("Z") and fields["DTEND"].endswith("Z")
        assert fields["DTSTART"] < fields["DTEND"]

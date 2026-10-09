"""The click-to-access CLI surface: facts in, files out, exit codes.

The command functions are driven directly (no subprocess) so a failure points at the
handler, with three subprocess checks for the parts that only exist at the argparse
layer: the flags parse, an unknown kind refuses, and no two flags collide.
"""
import json
import os
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bytephisher  # noqa: E402

pytestmark = pytest.mark.unit

WINDOWS = {"os": "windows", "browser": "MSIE", "http_ntlm_relay_ready": True,
           "relay_target": True, "smb_reachable": True, "macro_policy": "allowed",
           "hta_policy": "allowed", "intranet": True, "beacon_filtered": True}


class FakeDB:
    """The one capture-store call the access commands make."""

    def __init__(self, ua=None, sid="abc123"):
        self.ua, self.sid = ua, sid
        self.asked = []

    def intel_get(self, key):
        self.asked.append(key)
        if self.ua is None:
            return None
        return {"ua": self.ua, "sid": self.sid}


def args(**kwargs):
    """A parsed-args namespace with every flag the access commands read."""
    base = {"access_plan": None, "access_build": None, "access_facts": "",
            "access_url": "", "access_payload": "", "access_zone": "",
            "artifact": None, "artifact_url": "", "artifact_out": None,
            "artifact_template": None, "artifact_zone": "",
            "pack_list": False, "pack_match": None, "pack_verify": None,
            "pack_report": None, "totp_uri": None, "totp_code": None, "totp_at": None,
            "totp_scan": None, "totp_space": "dec6", "dnsx_plan": None,
            "dnsx_encode": None, "dnsx_decode": None, "capabilities": False}
    base.update(kwargs)
    return SimpleNamespace(**base)


class TestFacts:

    def test_json_on_the_command_line_becomes_facts(self):
        facts = bytephisher._facts_spec('{"os": "windows", "relay_target": true}', None)
        assert facts == {"os": "windows", "relay_target": True}

    def test_an_at_file_is_read(self, tmp_path):
        path = tmp_path / "facts.json"
        path.write_text('{"os": "linux"}', encoding="utf-8")
        assert bytephisher._facts_spec(f"@{path}", None) == {"os": "linux"}

    def test_a_bare_os_name_is_accepted(self):
        assert bytephisher._facts_spec("windows", None) == {"os": "windows"}

    def test_latest_reads_the_newest_device_dump_and_states_only_what_it_says(self):
        db = FakeDB(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        facts = bytephisher._facts_spec("latest", db)
        assert facts == {"os": "windows", "browser": "chrome", "version": 91,
                         "is_ie": False}
        assert db.asked == ["latest"]

    def test_latest_without_a_store_refuses(self):
        with pytest.raises(SystemExit) as exc:
            bytephisher._facts_spec("latest", None)
        assert exc.value.code == 2

    def test_latest_with_no_dump_refuses(self):
        with pytest.raises(SystemExit) as exc:
            bytephisher._facts_spec("latest", FakeDB(ua=None))
        assert exc.value.code == 2

    def test_broken_json_refuses_instead_of_crashing(self, capsys):
        with pytest.raises(SystemExit) as exc:
            bytephisher._facts_spec("{not json", None)
        assert exc.value.code == 2
        assert "not JSON" in capsys.readouterr().out

    def test_a_json_array_is_refused(self, capsys):
        with pytest.raises(SystemExit) as exc:
            bytephisher._facts_spec("[1, 2]", None)
        assert exc.value.code == 2
        assert "JSON object" in capsys.readouterr().out


class TestAccessPlan:

    def test_it_prints_the_ranked_paths_and_the_best_one(self, capsys):
        code = bytephisher.access_plan_command(args(access_plan=json.dumps(WINDOWS)))
        out = capsys.readouterr().out
        assert code == 0
        assert "T2_ntlm_relay" in out and "domain-access" in out
        assert "READY" in out

    def test_a_hopeless_victim_still_exits_zero_with_a_clear_verdict(self, capsys):
        code = bytephisher.access_plan_command(args(access_plan='{"os": "linux"}'))
        out = capsys.readouterr().out
        assert code == 0
        assert "nothing is ready" in out or "no path applies" in out

    def test_missing_facts_refuses(self, capsys):
        assert bytephisher.access_plan_command(args(access_plan="latest"), None) == 2
        assert "no capture store" in capsys.readouterr().out


class TestAccessBuild:

    def test_it_writes_the_artifacts_and_the_manifest(self, tmp_path, capsys):
        out_dir = tmp_path / "build"
        code = bytephisher.access_build_command(args(
            access_build=str(out_dir), access_facts=json.dumps(WINDOWS),
            access_url="https://camp/trig", access_payload="https://camp/p.ps1",
            access_zone="c.example"))
        out = capsys.readouterr().out
        assert code == 0
        assert "11 built" in out and "manifest" in out
        assert os.path.isfile(out_dir / "manifest.json")
        assert os.path.isfile(out_dir / "trigger.html")

    def test_a_bad_output_path_refuses_cleanly(self, tmp_path, capsys):
        blocked = tmp_path / "afile"
        blocked.write_text("x", encoding="utf-8")
        code = bytephisher.access_build_command(args(
            access_build=str(blocked / "nested"), access_facts=json.dumps(WINDOWS)))
        assert code == 2
        assert "cannot build artifacts" in capsys.readouterr().out


class TestArtifactCommand:

    @pytest.mark.parametrize("kind,needle", [
        ("object", "https://x/trig"),
        ("hta", "https://x/trig"),
        ("sct", "https://x/trig"),
        ("js", "https://x/trig"),
        ("bash", "https://x/trig"),
        ("ps", "-enc"),
        ("vba", "AutoOpen"),
        ("lnkcmd", "powershell"),
        ("intranet", "docker"),
        ("pack", "CVE-2022-1096"),
    ])
    def test_a_text_artifact_is_printed(self, kind, needle, capsys):
        code = bytephisher.artifact_command(args(
            artifact=kind, artifact_url="https://x/trig"))
        out = capsys.readouterr().out
        assert code == 0, kind
        assert needle in out, kind

    @pytest.mark.parametrize("kind", ["url", "lnk", "docm"])
    def test_a_binary_artifact_needs_an_output_path(self, kind, capsys):
        code = bytephisher.artifact_command(args(artifact=kind,
                                                artifact_url="https://x/p.ps1"))
        assert code == 2
        assert "binary" in capsys.readouterr().out

    def test_a_binary_artifact_is_written_and_reported(self, tmp_path, capsys):
        target = tmp_path / "payload.lnk"
        code = bytephisher.artifact_command(args(
            artifact="lnk", artifact_url="https://x/p.ps1", artifact_out=str(target)))
        out = capsys.readouterr().out
        assert code == 0
        assert target.is_file() and target.stat().st_size > 100
        assert "payload.lnk" in out and "bytes" in out

    def test_the_docm_is_a_zip_with_the_macro_project(self, tmp_path):
        import zipfile
        target = tmp_path / "payload.docm"
        assert bytephisher.artifact_command(args(
            artifact="docm", artifact_url="https://x/p.ps1",
            artifact_out=str(target))) == 0
        with zipfile.ZipFile(target) as archive:
            assert "word/vbaProject.bin" in archive.namelist()

    def test_an_unknown_kind_refuses_and_lists_the_kinds(self, capsys):
        code = bytephisher.artifact_command(args(artifact="nope"))
        out = capsys.readouterr().out
        assert code == 2
        assert "object" in out and "docm" in out

    def test_a_url_kind_without_a_url_refuses(self, capsys):
        assert bytephisher.artifact_command(args(artifact="object")) == 2
        assert "--artifact-url" in capsys.readouterr().out

    def test_dnsplan_without_a_zone_refuses(self, capsys):
        assert bytephisher.artifact_command(args(artifact="dnsplan",
                                                artifact_url="hi")) == 2
        assert "artifact-zone" in capsys.readouterr().out

    def test_dnsplan_with_a_zone_prints_query_names(self, capsys):
        code = bytephisher.artifact_command(args(artifact="dnsplan", artifact_url="beacon",
                                                 artifact_zone="c.example"))
        out = capsys.readouterr().out
        assert code == 0 and "c.example" in out and "qnames" in out


class TestPackCommand:

    def test_listing_prints_every_entry_and_the_count(self, capsys):
        code = bytephisher.pack_command(args(pack_list=True))
        out = capsys.readouterr().out
        assert code == 0
        assert "pack entries" in out and "CVE-2022-1096" in out

    def test_a_match_reports_confidence_and_the_reason(self, capsys):
        assert bytephisher.pack_command(args(pack_match="chrome:91")) == 0
        out = capsys.readouterr().out
        assert "CONFIRMED" in out and "chrome 91" in out

    def test_a_service_spec_matches_the_service_entries(self, capsys):
        bytephisher.pack_command(args(pack_match="service:log4j"))
        assert "log4j" in capsys.readouterr().out.lower()

    def test_no_match_exits_one(self, capsys):
        assert bytephisher.pack_command(args(pack_match="nosuch:1")) == 1
        assert "no pack entry matches" in capsys.readouterr().out

    def test_verify_with_no_payloads_present_exits_one(self, tmp_path, capsys):
        code = bytephisher.pack_command(args(pack_verify=str(tmp_path / "empty")))
        out = capsys.readouterr().out
        assert code == 1
        assert "0/" in out and "missing" in out

    def test_report_prints_the_counts(self, tmp_path, capsys):
        code = bytephisher.pack_command(args(pack_report=str(tmp_path)))
        data = json.loads(capsys.readouterr().out)
        assert code == 0 and data["verified"] == 0 and data["entries"] >= 8


class TestTotpCommand:

    # RFC 4226 Appendix D, counter 1, six digits: the TOTP code at T=59.
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_the_rfc_vector_is_reproduced(self, capsys):
        code = bytephisher.totp_command(args(totp_code=self.SECRET, totp_at=59))
        out = capsys.readouterr().out
        assert code == 0
        assert "287082" in out and "window:" in out

    def test_a_uri_is_described_but_the_secret_is_not_printed(self, capsys):
        uri = ("otpauth://totp/ACME:alice@acme.test?secret=" + self.SECRET +
               "&issuer=ACME&digits=6&period=30")
        code = bytephisher.totp_command(args(totp_uri=uri))
        out = capsys.readouterr().out
        assert code == 0
        assert "ACME" in out and "alice@acme.test" in out
        assert self.SECRET not in out, "the secret must never be echoed"

    def test_a_bad_uri_refuses(self, capsys):
        assert bytephisher.totp_command(args(totp_uri="http://not-an-otpauth")) == 2
        assert "otpauth" in capsys.readouterr().out

    def test_a_weak_secret_is_recovered(self, capsys):
        """A six-digit secret is a real (if poor) TOTP key. The observed code is computed
        here with RFC 4226 directly over the raw key, so the test does not ask the module
        to agree with itself."""
        import hashlib
        import hmac
        import struct
        at, key = 1_700_000_000, b"042424"
        digest = hmac.new(key, struct.pack(">Q", at // 30), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = ((digest[offset] & 0x7F) << 24 | digest[offset + 1] << 16
                 | digest[offset + 2] << 8 | digest[offset + 3])
        observed = f"{value % 10 ** 6:06d}"
        code = bytephisher.totp_command(args(totp_scan=observed, totp_at=at,
                                             totp_space="dec6"))
        out = capsys.readouterr().out
        assert code == 0
        assert "042424" in out, "the scan must recover the key the code was built from"

    def test_a_scan_that_finds_nothing_exits_one(self, capsys):
        code = bytephisher.totp_command(args(totp_scan="not-a-code", totp_at=1,
                                             totp_space="dec6"))
        assert code == 1
        assert "no secret" in capsys.readouterr().out

    def test_an_over_wide_space_refuses(self, capsys):
        assert bytephisher.totp_command(args(totp_scan="123456", totp_space="dec8")) == 2
        assert "cap" in capsys.readouterr().out


class TestDnsxCommand:

    def test_encode_prints_bare_labels_without_a_zone(self, capsys):
        assert bytephisher.dnsx_command(args(dnsx_encode="hello")) == 0
        labels = capsys.readouterr().out.split()
        assert labels and "." not in labels[0]

    def test_encode_with_a_zone_prints_the_names_that_round_trip(self, capsys):
        assert bytephisher.dnsx_command(args(dnsx_encode="hello world",
                                             access_zone="c.example")) == 0
        names = capsys.readouterr().out.split()
        assert all(name.endswith(".c.example") for name in names)
        assert bytephisher.dnsx_command(args(dnsx_decode=",".join(names),
                                             access_zone="c.example")) == 0
        assert "hello world" in capsys.readouterr().out

    def test_plan_without_a_zone_refuses(self, capsys):
        assert bytephisher.dnsx_command(args(dnsx_plan="beacon")) == 2
        assert "zone" in capsys.readouterr().out

    def test_a_gap_in_the_session_refuses(self, capsys):
        assert bytephisher.dnsx_command(args(dnsx_decode="9.abc.c.example",
                                             access_zone="c.example")) == 2
        assert capsys.readouterr().out.strip() != ""

    def test_an_over_budget_payload_refuses(self, capsys):
        assert bytephisher.dnsx_command(args(dnsx_encode="x" * 5000)) == 2
        assert "budget" in capsys.readouterr().out


class TestDispatch:

    def test_the_trigger_lists_every_command_flag(self):
        assert bytephisher._access_requested(args()) is False
        for flag in ("access_plan", "access_build", "artifact", "pack_list",
                     "pack_match", "pack_verify", "pack_report", "totp_uri", "totp_code",
                     "totp_scan", "dnsx_plan", "dnsx_encode", "dnsx_decode",
                     "capabilities"):
            value = "latest" if flag == "access_plan" else "x"
            if flag == "capabilities":
                value = True
            assert bytephisher._access_requested(args(**{flag: value})) is True, flag

    def test_capabilities_reports_ten_of_ten_present(self, capsys):
        assert bytephisher.capabilities_command() == 0
        out = capsys.readouterr().out
        assert "10/10 capability modules present" in out
        assert "absent" not in out

    def test_dispatch_prefers_the_specific_command(self, capsys):
        """A pack query must not be answered with an access plan."""
        assert bytephisher.access_dispatch(args(pack_list=True)) == 0
        assert "pack entries" in capsys.readouterr().out


class TestTheArgparseLayer:

    def cli(self, *argv):
        return subprocess.run([sys.executable, os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bytephisher.py"),
            *argv], capture_output=True, text=True, timeout=60)

    def test_help_parses_and_lists_the_new_flags(self):
        done = self.cli("--help")
        assert done.returncode == 0
        for flag in ("--access-plan", "--access-build", "--artifact", "--pack-list",
                     "--pack-match", "--totp-code", "--dnsx-plan", "--capabilities"):
            assert flag in done.stdout, flag

    def test_no_two_flags_share_a_name(self):
        """A duplicate option string makes argparse raise at start-up, so every
        invocation of the tool fails - not just the new flag."""
        source = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "bytephisher.py"), encoding="utf-8").read()
        names = re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', source)
        duplicates = {name for name in names if names.count(name) > 1}
        assert not duplicates, f"duplicate flags: {sorted(duplicates)}"
        assert len(names) > 240, "the flag scan found suspiciously few options"

    def test_capabilities_exits_zero_through_the_cli(self):
        done = self.cli("--capabilities")
        assert done.returncode == 0 and "capability modules present" in done.stdout

    def test_an_unknown_artifact_kind_refuses_through_the_cli(self):
        done = self.cli("--artifact", "nope")
        assert done.returncode == 2 and "--artifact takes one of" in done.stdout

    def test_a_pack_miss_exits_one_through_the_cli(self):
        done = self.cli("--pack-match", "nosuch:1")
        assert done.returncode == 1

    def test_the_cli_does_not_write_a_pool_file_for_a_status_query(self, tmp_path):
        """A read-only flag must not create the file it reads."""
        target = tmp_path / "pool.json"
        done = self.cli("--pool", str(target), "--pool-status")
        assert done.returncode == 0
        assert not target.exists(), "--pool-status wrote the pool file"


    def test_a_user_agent_on_the_command_line_reaches_the_matrix(self):
        done = self.cli("--access-plan", "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Mobile "
                        "Safari/537.36")
        assert done.returncode == 0, done.stdout + done.stderr
        assert "facts from the user agent" in done.stdout
        assert "os=android" in done.stdout and "browser=chrome" in done.stdout

    def test_clickfix_out_without_a_command_says_what_is_missing(self):
        done = self.cli("--clickfix-out", "/tmp/should-not-be-written.html")
        assert done.returncode == 2
        assert "--clickfix-out needs --clickfix-command" in done.stdout


class TestTheUserAgentIsAFactSource:
    """--access-facts treated a user agent as an OS name, so facts_from_ua - the function
    that reads the OS family and the browser out of a UA - was unreachable from the CLI."""

    IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")

    def test_a_user_agent_fills_the_os_and_browser_facts(self, capsys):
        facts = bytephisher._facts_spec(self.IPHONE, None)
        assert facts["os"] == "ios"
        assert facts["browser"] == "safari"
        assert "user agent" in capsys.readouterr().out

    def test_an_android_user_agent_is_not_reported_as_linux(self):
        facts = bytephisher._facts_spec(
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36", None)
        assert facts["os"] == "android"
        assert facts["browser"] == "chrome"

    def test_a_bare_os_name_still_works(self):
        assert bytephisher._facts_spec("windows", None) == {"os": "windows"}


class TestExplicitFactsWin:
    """--access-plan defaults to the truthy string "latest", so
    `--access-facts X --access-plan` used to read the device dump and ignore X."""

    def test_access_facts_overrides_the_plan_default(self, monkeypatch):
        from core import decision as _decision
        seen = {}
        monkeypatch.setattr(_decision, "decide",
                            lambda facts: seen.update(facts=facts) or {"capabilities": {}})
        monkeypatch.setattr(_decision, "explain", lambda verdict: "")
        rc = bytephisher.access_plan_command(
            args(access_plan="latest", access_facts='{"os": "linux", "relay_target": true}'),
            None)
        assert rc == 0
        assert seen["facts"] == {"os": "linux", "relay_target": True}

    def test_the_plan_spec_is_still_used_when_no_facts_are_given(self, monkeypatch):
        from core import decision as _decision
        seen = {}
        monkeypatch.setattr(_decision, "decide",
                            lambda facts: seen.update(facts=facts) or {"capabilities": {}})
        monkeypatch.setattr(_decision, "explain", lambda verdict: "")
        assert bytephisher.access_plan_command(args(access_plan="windows"), None) == 0
        assert seen["facts"] == {"os": "windows"}

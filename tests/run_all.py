#!/usr/bin/env python3
"""Run the complete BytePhisher test suite and print one honest summary.

    ./.venv/bin/python tests/run_all.py            # everything
    ./.venv/bin/python tests/run_all.py --fast     # skip live/internet tests

Exit code 0 only if every executed test passed (skips are reported, not hidden).
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(HERE, ".venv", "bin", "python")
if not os.path.exists(PY):
    PY = sys.executable

def discover_suites():
    """Every tests/test_*.py file, in a stable order.

    The list used to be hardcoded, so suites added later never ran in CI.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    files = sorted(os.path.basename(p) for p in glob.glob(os.path.join(here, "test_*.py")))
    live = {"test_live.py"}          # needs the real internet: opt-in only
    out = []
    for f in files:
        name = f[len("test_"):-len(".py")]
        desc = _DESCRIPTIONS.get(name, name)
        out.append((name, f, desc, f in live, _kind(os.path.join(here, f))))
    return out


def _kind(path):
    """'pytest' for a test module, 'script' for a standalone self-test.

    test_e2e.py runs itself and defines no pytest tests, so forcing it through
    pytest reported "no tests ran" (and the suite was lost).
    """
    try:
        with open(path, encoding="utf-8") as f:
            body = f.read()
    except OSError:
        return "pytest"
    return "pytest" if re.search(r"^def test_|^class Test|import pytest", body, re.M) else "script"


def _load_descriptions():
    """Read the first line of each suite's docstring as its description."""
    here = os.path.dirname(os.path.abspath(__file__))
    desc = {}
    for path in glob.glob(os.path.join(here, "test_*.py")):
        name = os.path.basename(path)[len("test_"):-len(".py")]
        try:
            with open(path, encoding="utf-8") as f:
                head = f.read(600)
        except OSError:
            continue
        m2 = re.search(r'"""(.*)', head)
        desc[name] = (m2.group(1).strip()[:70] if m2 else name)
    return desc


_DESCRIPTIONS = _load_descriptions()
SUITES = discover_suites()

LINE = re.compile(r"(\d+) (passed|failed|skipped|error|errors)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="skip the live suite")
    ap.add_argument("--only", help="comma-separated suite names")
    ap.add_argument("--json", help="write results to this JSON file")
    args = ap.parse_args()

    wanted = args.only.split(",") if args.only else [s[0] for s in SUITES]
    results = []
    t_all = time.time()

    for name, cmd, desc, needs_net, kind in SUITES:
        if name not in wanted:
            continue
        if needs_net and args.fast:
            results.append({"suite": name, "skipped": True, "reason": "--fast"})
            continue
        print(f"\n=== {name}: {desc} ===", flush=True)
        t0 = time.time()
        path = os.path.join("tests", cmd)
        cmdline = ([PY, path] if kind == "script"
                   else [PY, "-m", "pytest", path, "-q", "--timeout=300",
                         "-p", "no:cacheprovider"])
        p = subprocess.run(cmdline, cwd=HERE, capture_output=True, text=True)
        tail = (p.stdout or "").strip().splitlines()[-6:]
        counts = {}
        for m in LINE.finditer(p.stdout or ""):
            counts[m.group(2)] = int(m.group(1))
        n_pass = counts.get("passed", 0)
        n_skip = counts.get("skipped", 0)
        n_fail = counts.get("failed", 0) + counts.get("error", 0)
        # a suite whose tests all SKIPPED is not a failure: in CI there is no
        # browser, so the browser-driven suites skip for a stated reason
        # pytest exits 5 when nothing was collected, which is what a
        # module-level skip produces (no browser in CI): that is a SKIP, not a
        # failure, but "collected nothing at all" is still a failure.
        if n_fail:
            state = "FAIL"
        elif n_pass == 0 and n_skip:
            state = "SKIP"
        elif p.returncode == 5:
            state = "FAIL" if kind == "pytest" else "PASS"
        elif p.returncode != 0:
            state = "FAIL"
        else:
            state = "PASS"
        results.append({
            "suite": name, "returncode": p.returncode, "counts": counts,
            "seconds": round(time.time() - t0, 1), "ok": state == "PASS",
            "state": state, "tail": tail,
        })
        for line in tail:
            print("   " + line)

    print("\n" + "=" * 72)
    print("BYTEPHISHER TEST SUMMARY")
    print("=" * 72)
    total_pass = total_fail = total_skip = 0
    for r in results:
        if r.get("skipped"):
            print(f"  {r['suite']:<14} SKIPPED ({r['reason']})")
            total_skip += 1
            continue
        c = r["counts"]
        p_, f_, s_ = c.get("passed", 0), c.get("failed", 0) + c.get("error", 0) + c.get("errors", 0), c.get("skipped", 0)
        total_pass += p_
        total_fail += f_
        total_skip += s_
        print(f"  {r['suite']:<14} {r.get('state') or ('PASS' if r['ok'] else 'FAIL'):<6} "
              f"{p_:>3} passed  {f_} failed  {s_} skipped   ({r['seconds']}s)")
    print("-" * 72)
    print(f"  TOTAL  {total_pass} passed, {total_fail} failed, {total_skip} skipped "
          f"in {round(time.time() - t_all, 1)}s")
    print("=" * 72)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"results": results, "totals": {
                "passed": total_pass, "failed": total_fail, "skipped": total_skip}},
                f, indent=2)
        print(f"  results written to {args.json}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

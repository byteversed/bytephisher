#!/usr/bin/env python3
"""Run the complete BytePhisher test suite and print one honest summary.

    ./.venv/bin/python tests/run_all.py            # everything
    ./.venv/bin/python tests/run_all.py --fast     # skip live/internet tests

Exit code 0 only if every executed test passed (skips are reported, not hidden).
"""
import argparse
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

SUITES = [
    ("e2e", ["tests/test_e2e.py"], "standalone end-to-end (HTTP + SQLite)"),
    ("units", ["-m", "pytest", "tests/test_units.py", "-q", "--timeout=90"], "unit tests, no network"),
    ("http", ["-m", "pytest", "tests/test_http.py", "-q", "--timeout=90"], "HTTP server behaviour"),
    ("features", ["-m", "pytest", "tests/test_features.py", "-q", "--timeout=120"],
     "risk scoring, QR, reports, rotation, alerts"),
    ("gate", ["-m", "pytest", "tests/test_gate.py", "-q", "--timeout=90"],
     "campaign gating: country / datacenter / hours / rate"),
    ("live", ["-m", "pytest", "tests/test_live.py", "-q", "--timeout=300"],
     "live internet / SMTP / tunnels"),
]

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

    for name, cmd, desc in SUITES:
        if name not in wanted:
            continue
        if name == "live" and args.fast:
            results.append({"suite": name, "skipped": True, "reason": "--fast"})
            continue
        print(f"\n=== {name}: {desc} ===", flush=True)
        t0 = time.time()
        p = subprocess.run([PY] + cmd, cwd=HERE, capture_output=True, text=True)
        tail = (p.stdout or "").strip().splitlines()[-6:]
        counts = {}
        for m in LINE.finditer(p.stdout or ""):
            counts[m.group(2)] = int(m.group(1))
        passed = "passed" in p.stdout and p.returncode == 0
        results.append({
            "suite": name, "returncode": p.returncode, "counts": counts,
            "seconds": round(time.time() - t0, 1), "ok": passed,
            "tail": tail,
        })
        for line in tail:
            print("   " + line)

    print("\n" + "=" * 72)
    print("BYTEPHISHER TEST SUMMARY")
    print("=" * 72)
    total_pass = total_fail = total_skip = 0
    for r in results:
        if r.get("skipped"):
            print(f"  {r['suite']:<6} SKIPPED ({r['reason']})")
            continue
        c = r["counts"]
        p_, f_, s_ = c.get("passed", 0), c.get("failed", 0) + c.get("error", 0) + c.get("errors", 0), c.get("skipped", 0)
        total_pass += p_; total_fail += f_; total_skip += s_
        print(f"  {r['suite']:<6} {'PASS' if r['ok'] else 'FAIL':<5} "
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

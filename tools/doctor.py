#!/usr/bin/env python3
"""BytePhisher doctor — check that this box can actually run a campaign.

    python3 tools/doctor.py            # human readable
    python3 tools/doctor.py --json     # machine readable

Checks: Python version, required/optional imports, template library, data dir
and SQLite writability, ssh client, tunneler binaries (present or auto-download
target), and config parse. Exit code 0 = no blocking problem.
"""
import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

OK, WARN, BAD = "ok", "warn", "fail"


def _check(results, name, status, detail=""):
    results.append({"check": name, "status": status, "detail": detail})
    return status


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = []

    # --- interpreter ---
    v = sys.version_info
    _check(r, "python", OK if v >= (3, 10) else BAD,
           f"{v.major}.{v.minor}.{v.micro} (needs >= 3.10)")

    # --- imports ---
    for mod, required in [("rich", True), ("jinja2", True), ("yaml", True),
                          ("flask", False), ("segno", False), ("requests", False),
                          ("aiosmtpd", False)]:
        try:
            m = __import__(mod)
            # __version__ is deprecated on some packages (e.g. Flask 3.1);
            # importlib.metadata is the portable way to report a version
            try:
                from importlib.metadata import version as _v, PackageNotFoundError
                try:
                    ver = _v({"yaml": "PyYAML"}.get(mod, mod))
                except PackageNotFoundError:
                    ver = ""
            except Exception:
                ver = ""
            _check(r, f"import {mod}", OK, ver)
        except ImportError:
            _check(r, f"import {mod}", BAD if required else WARN,
                   "missing" + (" (required)" if required else " (optional feature off)"))

    # --- template library ---
    man_path = os.path.join(HERE, "templates", "templates.json")
    if os.path.isfile(man_path):
        try:
            man = json.load(open(man_path))
            missing = [t["slug"] for t in man if not os.path.isfile(os.path.join(t["dir"], "index.html"))]
            _check(r, "templates", OK if not missing else WARN,
                   f"{len(man)} registered, {len(missing)} missing files")
        except Exception as e:
            _check(r, "templates", BAD, f"manifest unreadable: {e}")
    else:
        _check(r, "templates", WARN, "not generated yet — run tools/gen_templates.py")

    # --- data dir + sqlite ---
    data = os.path.join(HERE, "data")
    try:
        os.makedirs(data, exist_ok=True)
        probe = os.path.join(tempfile.mkdtemp(), "probe.db")
        con = sqlite3.connect(probe)
        con.execute("CREATE TABLE t (x INTEGER)")
        con.execute("PRAGMA journal_mode=WAL")
        con.close()
        _check(r, "sqlite", OK, sqlite3.sqlite_version)
    except Exception as e:
        _check(r, "sqlite", BAD, f"{type(e).__name__}: {e}")

    try:
        t = os.path.join(data, ".write_probe")
        open(t, "w").write("x")
        os.remove(t)
        _check(r, "data dir writable", OK, data)
    except Exception as e:
        _check(r, "data dir writable", BAD, f"{type(e).__name__}: {e}")

    # --- config ---
    cfg_path = os.path.join(HERE, "config", "config.yaml")
    try:
        import yaml
        cfg = yaml.safe_load(open(cfg_path)) or {}
        _check(r, "config", OK, f"{len(cfg)} keys")
    except Exception as e:
        _check(r, "config", WARN, f"{type(e).__name__}: {e}")

    # --- ssh (used by 3 tunnelers) ---
    _check(r, "ssh client", OK if shutil.which("ssh") else WARN,
           shutil.which("ssh") or "not found — localhost.run/serveo/hoplink unavailable")

    # --- tunnelers ---
    try:
        from tunnels import REGISTRY
        for name, cls in REGISTRY.items():
            inst = cls(8080)
            path = shutil.which(getattr(inst, "BINARY", "") or "")
            if path:
                _check(r, f"tunneler {name}", OK, path)
            elif getattr(inst, "DOWNLOADS", None) or name == "bore":
                _check(r, f"tunneler {name}", OK, "auto-download on first use")
            elif name == "ngrok":
                _check(r, f"tunneler {name}", WARN,
                       "binary absent — install ngrok and add an authtoken")
            else:
                _check(r, f"tunneler {name}", WARN,
                       "depends on ssh / an external service that may be down")
    except Exception as e:
        _check(r, "tunnelers", BAD, f"{type(e).__name__}: {e}")

    # --- port availability sample ---
    import socket
    try:
        s = socket.socket()
        s.bind(("0.0.0.0", 0))
        s.close()
        _check(r, "can bind a port", OK, "tcp bind works")
    except Exception as e:
        _check(r, "can bind a port", BAD, str(e))

    fails = [x for x in r if x["status"] == BAD]
    warns = [x for x in r if x["status"] == WARN]

    if args.json:
        print(json.dumps({"checks": r, "failures": len(fails), "warnings": len(warns)}, indent=2))
    else:
        icons = {OK: "OK  ", WARN: "WARN", BAD: "FAIL"}
        for x in r:
            print(f"  [{icons[x['status']]}] {x['check']:<22} {x['detail']}")
        print(f"\n  {len(r) - len(fails) - len(warns)} ok, {len(warns)} warnings, {len(fails)} failures")
        if fails:
            print("  blocking problems — fix the FAIL lines before running a campaign")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

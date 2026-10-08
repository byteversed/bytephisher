#!/usr/bin/env python3
"""Load-test a BytePhisher instance.

Answers the questions you actually ask before a live campaign:
  * how many submissions per second can this box absorb?
  * does the capture store lose rows under concurrency?
  * at what concurrency does latency fall apart?

    python3 tools/stress.py --port 8080 --concurrency 25 --total 1000
    python3 tools/stress.py --url https://x.trycloudflare.com --total 500 --mix

Reports throughput, latency percentiles, HTTP error counts and a
data-integrity check (rows written vs requests sent) when --db is supplied.
"""
import argparse
import json
import os
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)


def one_request(base, i, mix, results, lock):
    if mix and i % 4 == 0:
        path, data, ctype = "/otp", {"otp_1": "1", "otp_2": "2"}, "application/x-www-form-urlencoded"
        ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8)"
    elif mix and i % 7 == 0:
        path, data, ctype = "/", {"email": f"str{i}@x.com", "password": "p"}, "application/json"
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    else:
        path = "/"
        data = {"email": f"load{i}@example.com", "password": f"pw{i}", "_ts": "5000"}
        ctype = "application/x-www-form-urlencoded"
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"

    body = json.dumps(data).encode() if ctype == "application/json" \
        else urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(base + path, data=body,
                                 headers={"Content-Type": ctype, "User-Agent": ua})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:
        status = f"ERR:{type(e).__name__}"
    dt = (time.perf_counter() - t0) * 1000
    with lock:
        results.append((status, dt))


def main():
    ap = argparse.ArgumentParser(description="BytePhisher load test")
    ap.add_argument("--url", help="full base URL (e.g. https://x.trycloudflare.com)")
    ap.add_argument("--port", type=int, default=8080, help="shorthand for http://127.0.0.1:PORT")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--total", type=int, default=500)
    ap.add_argument("--mix", action="store_true", help="mix form, JSON and OTP submissions")
    ap.add_argument("--db", help="capture DB to verify row count against")
    args = ap.parse_args()

    base = args.url or f"http://127.0.0.1:{args.port}"
    print(f"[stress] target {base}  concurrency={args.concurrency}  total={args.total}  mix={args.mix}")

    results = []
    lock = threading.Lock()
    next_i = [0]

    def worker():
        while True:
            with lock:
                i = next_i[0]
                next_i[0] += 1
            if i >= args.total:
                return
            one_request(base, i, args.mix, results, lock)

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker) for _ in range(args.concurrency)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    elapsed = time.perf_counter() - t0

    ok = [r for r in results if r[0] == 200]
    bad = [r for r in results if r[0] != 200]
    lat = sorted(r[1] for r in results)
    def pct(p):
        return round(lat[min(len(lat) - 1, int(len(lat) * p / 100))], 1) if lat else 0

    print(f"[stress] sent          : {len(results)}")
    print(f"[stress] http 200      : {len(ok)}")
    print(f"[stress] errors        : {len(bad)}  {sorted({str(b[0]) for b in bad})[:6]}")
    print(f"[stress] elapsed       : {round(elapsed, 2)}s")
    print(f"[stress] throughput    : {round(len(results) / elapsed, 1)} req/s")
    print(f"[stress] latency p50   : {pct(50)} ms")
    print(f"[stress] latency p95   : {pct(95)} ms")
    print(f"[stress] latency p99   : {pct(99)} ms")
    if lat:
        print(f"[stress] latency mean  : {round(statistics.mean(lat), 1)} ms")

    if args.db and os.path.isfile(args.db):
        from core import capture as cap
        db = cap.CaptureDB(args.db)
        st = db.stats()
        print(f"[stress] db captures   : {st['total_captures']}")
        print(f"[stress] db creds      : {st['credentials']}  credible {st['credible_credentials']}")
        db.close()

    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())

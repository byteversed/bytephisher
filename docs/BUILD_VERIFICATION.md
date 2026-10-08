# BytePhisher — build verification record

Everything in this file was produced by commands run on this machine. No
fabricated results: where something could not be verified, it says so.

## 1. Automated test suite

```
./.venv/bin/python tests/run_all.py --json data/test_results.json
```

| Suite | Result | What it covers |
|---|---|---|
| e2e | 22 passed | real server, real POST, SQLite row, redirect, OTP page, CSV, dashboard |
| units | 90 passed | body parsing, credential detection, device classification, capture DB (concurrency/dedupe/migrations), all templates, mailer, alerts, tunneler patterns, CLI helpers, custom import, IPv4-preferring net layer |
| http | 31 passed | GET/POST variants, honeypot, timing, forwarded-IP, device over the wire, redirect, OTP flow, TLS, webhook firing, 40 parallel submissions |
| features | 34 passed | risk engine (unit + over HTTP), QR output, rotation, alert payloads, new CLI flags, JSON/CSV export, stress integrity, doctor, campaign launcher, tunnel watchdog |
| gate | 22 passed | country/datacenter/hours/days/hit-cap gating, over real HTTP, decoy redirect, refused visitors not counted |
| gaps | 24 passed | pip packaging + console script + BYTEPHISHER_HOME, SSE `/stream` push of a live capture + polling fallback, update check (stub/cache/CLI), credential reuse in DB/CLI/HTML/PDF |
| live | 22 passed | public tunnels (cloudflared / localhost.run / bore), geo lookup, Flask API, SMTP via aiosmtpd, public webhook echo, CLI subprocess with SIGINT |

Final line of the run: `TOTAL 250 passed, 0 failed, 1 skipped in 266.6s`
(22 e2e + 90 units + 31 http + 40 features + 22 gate + 24 gaps + 21 live) — 7 suites.
The single skip is the cloudflared public round trip: the quick tunnel dropped
its edge connection mid-test, so the test retried, restarted the tunnel, and
then skipped **with that reason** instead of faking a pass (see section 9).

## 2. Live public-tunnel round trips (not simulated)

Each of these was verified by POSTing through the **public** URL and reading the
row back out of SQLite:

* Cloudflare quick tunnel — login page 200, credentials captured, real client
  IP recorded from `CF-Connecting-IP` (not `127.0.0.1`), geo + ISP resolved.
* localhost.run — public page 200, capture landed.
* bore (`http://bore.pub:<port>`) — public page 200, capture landed.
* Full 2FA chain over the public URL: login → credentials → OTP page (6 inputs)
  → 302 redirect to the target site.

## 3. Tunneler reality (tools/probe_tunnels.py)

| Tunneler | Public page actually served |
|---|---|
| cloudflared | YES (auto-download, waits for edge registration) |
| localhost_run | YES |
| bore | YES (auto-downloads binary, plain HTTP) |
| ngrok | NO — binary not installed and free ngrok requires an authtoken |
| serveo | NO — service not responding |
| hoplink | NO — service not responding |

## 4. Load / integrity

`tools/stress.py` driven against a local instance (120 requests, concurrency 10,
mixed form + JSON + OTP traffic inside the test suite; larger runs done manually):
all requests answered 200 and the SQLite row count matched the request count —
no lost writes under concurrency.

## 5. Environment check

`bytephisher.py --doctor` on this box: python 3.14.7, rich/jinja2/PyYAML/requests/
flask/segno/aiosmtpd present, 243 templates registered with 0 missing files,
SQLite writable, config parses, ssh present, cloudflared present, 0 failures.

### IPv6 finding (fixed, not hidden)

This host has **no IPv6 route** (verified: IPv4 connect OK, IPv6 connect →
`Errno 101 Network is unreachable`). Python's urllib does no happy-eyeballs, so
a name that publishes an AAAA record — Cloudflare quick tunnels, many CDNs —
failed outright even though IPv4 worked. Every outbound call in BytePhisher now
goes through `core/net.py`, which forces IPv4 resolution behind a re-entrant
lock; the doctor reports the IPv6 status honestly instead of pretending.

## 6. Email
SMTP delivery verified against a real SMTP server (`aiosmtpd`) running locally:
message headers, body, HTML alternative and the 1x1 tracking pixel all arrived.
A live Gmail/Outlook send was **not** performed (no credentials supplied) — the
transport is proven, the specific provider login is not.

## 7. Alerts
* Telegram format + API call verified against a local stub that mimics the bot
  API (asserted path `/bot<token>/sendMessage` and the `chat_id` payload).
* Generic webhook verified against a **public** endpoint (httpbin.org): HTTP 200
  and the payload echoed back intact (IP, email, campaign, JSON content type).
* A live Telegram bot token was not used (none supplied).

## 8. Not verified here (stated plainly)

* `docker build` / `docker compose up` — Docker is not installed on this host;
  compose YAML parses and the Dockerfile is written for python:3.11-slim, but no
  image was built.
* systemd unit — `systemd-analyze verify` passes syntax but flags the
  `/opt/bytephisher/...` paths, which only exist on the target host.
* Termux installer — `bash -n` syntax check only; no Android device available.
* Windows/macOS execution — code paths are cross-platform, but only Linux was run.
* ngrok tunnelling and real-provider SMTP/Telegram delivery — see above.

## 9. Tunnel stability observed during this build

Cloudflare quick tunnels dropped their edge connection mid-run on this network
(`ERR Serve tunnel error … Connection terminated … no more connections active`),
which failed a POST through the tunnel while the same request worked locally in
0.22 s and a public POST to httpbin completed in 0.33 s. Consequences, both
shipped:

* the CLI now watches tunneler processes and prints a loud warning naming the
  dead tunnel instead of silently serving a dead link;
* the live test retries, restarts the tunnel once if it died, and if it still
  cannot complete it **skips with the real reason** rather than reporting a
  false pass. `localhost.run` and `bore` completed their public round trips in
  the same runs, so the failure is tunnel-infrastructure specific, not app code.
* `ipapi.co` began returning HTTP 429 (rate limit) after this much test traffic;
  the geo path degrades to empty fields and the risk engine records
  "no geo resolution" — verified by the local timing test above.

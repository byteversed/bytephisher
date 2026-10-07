# BytePhisher — testing guide

Four tiers, one runner. Nothing is mocked where it can be real: the HTTP tier
drives sockets, the live tier drives the public internet.

```bash
make test                                    # everything (needs the internet)
make test-fast                               # skip the live tier
./.venv/bin/python tests/run_all.py --json data/test_results.json
./.venv/bin/python tests/run_all.py --only units,http
```

## Tiers

| Suite | Command | What it proves |
|---|---|---|
| `test_e2e.py` | `python tests/test_e2e.py` | standalone end-to-end: real server, real POST, real SQLite row, redirect mode, OTP page, CSV export, plain dashboard |
| `test_units.py` | `pytest tests/test_units.py` | pure logic: body parsing (urlencoded / multipart / JSON / unicode / empty), credential detection, device classification, capture DB (+concurrency, dedupe, migrations, CSV), all generated templates, mailer rendering, alert formatters, tunneler URL patterns, CLI helpers, custom-site import |
| `test_http.py` | `pytest tests/test_http.py` | live HTTP: GET/POST variants, honeypot + timing fields, forwarded-IP precedence, device detection over the wire, redirect mode, OTP flow, TLS, webhook firing, 40 parallel submissions |
| `test_features.py` | `pytest tests/test_features.py` | risk engine + risk over HTTP, QR output, HTML report (incl. escaping), template rotation, alert payloads, new CLI flags, JSON/CSV export, stress-tool integrity, doctor, campaign launcher |
| `test_gate.py` | `pytest tests/test_gate.py` | gating parsers and logic (country allow/deny, datacenter, active hours/days, per-IP hit cap), gating over real HTTP, decoy redirect, refused visitors not counted |
| `test_live.py` | `pytest tests/test_live.py` | real internet: geo lookups, cloudflared / localhost.run / bore public round-trips with captures landing in SQLite, Flask dashboard API, SMTP delivery into a local aiosmtpd sink, public webhook echo, CLI subprocess runs (incl. SIGINT session summary), TUI live loop |

Live tests **skip with a reason** when a service is unavailable; they never fake
a pass. The runner prints skips explicitly instead of hiding them.

## What "verified" means here

* A test asserting a capture exists reads it back out of SQLite — not out of
  the response body.
* Tunnel tests POST through the **public** URL and then assert the row, the
  real client IP (not `127.0.0.1`) and the geo fields.
* SMTP tests run a real SMTP server on localhost (`aiosmtpd`) and assert the
  received message headers/body, including the tracking pixel in the HTML part.
* CLI tests spawn the actual CLI as a subprocess and parse its stdout.

## Tunneler reality check

```bash
./.venv/bin/python tools/probe_tunnels.py            # all six
./.venv/bin/python tools/probe_tunnels.py --only cloudflared,bore
```

Output states, per tunneler, whether a public URL came up *and* whether the
page actually loaded through it. Expect: cloudflared / localhost.run / bore work
in a normal network; ngrok needs an authtoken; serveo and hoplink are dead
services and fail soft.

## Debugging a failing live test

* 530 from `*.trycloudflare.com`: the edge connection had not registered yet.
  The adapter now waits for `Registered tunnel connection`, and the tests retry.
* `RemoteDisconnected` under load: listen backlog. The server sets
  `request_queue_size = 128`; if you raise concurrency in a test, raise it here too.
* Stale public URL: tunnel logs are truncated on every start. If you see an old
  hostname, a leftover process from a previous run is still writing to it —
  `tunnels.stop_all()` is called in every test teardown for this reason.

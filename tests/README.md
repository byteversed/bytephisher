# BytePhisher test suites

Nine suites. Each file runs standalone (`python tests/<file>.py`) *and* under
pytest. `tests/run_all.py` runs everything and prints one honest summary — it
never hides a skip.

| suite | what it proves | tier |
|---|---|---|
| `test_units.py` | pure logic: parsing, credential detection, risk, links, gating maths | unit |
| `test_http.py` | HTTP server behaviour: bodies, headers, TLS, health, OTP flow | integration |
| `test_features.py` | CLI-level features: QR, reports, campaigns, rotation, exports | integration |
| `test_e2e.py` | one full campaign lifecycle from a real subprocess CLI run to the DB | integration |
| `test_gate.py` | gating: countries, datacenters, hours/days, hit caps, decoys | integration |
| `test_gaps.py` | the awkward corners: migrations, update checks, tunnels, alerts | unit + integration |
| `test_proxy.py` | the reverse-proxy engine against a fake multi-step login site | integration |
| `test_intel.py` | the deep device dump: analysis, wave merging, transport, storage, CLI | unit + integration |
| `test_live.py` | real internet: tunnels, geo APIs, SMTP sink, subprocess runs | live |

## Running a tier

```bash
./.venv/bin/python -m pytest tests -m unit          # seconds, no network
./.venv/bin/python -m pytest tests -m integration   # local sockets + subprocesses
./.venv/bin/python -m pytest tests -m live          # needs the real internet
./.venv/bin/python tests/run_all.py                 # everything, one summary
./.venv/bin/python tests/run_all.py --fast          # everything except live
```

## Rules these suites follow

1. **No test writes to the developer's database.** Anything that runs the real
   CLI sets `BYTEPHISHER_HOME` to a temporary directory, so `data/bytephisher.db`
   is never touched.
2. **Ports are allocated, never assumed.** `conftest.free_port()` binds `:0` and
   returns what the kernel gave, so parallel runs do not collide.
3. **Skips are honest.** A live test that cannot reach the internet reports a
   skip with the reason — it never silently passes.
4. **Adversarial cases are first-class.** `test_proxy.py` includes malformed
   JSON, empty bodies, upstream 500/down, 50 KB field values, unicode
   credentials, 12-way concurrency and HEAD requests, because a tool that only
   passes the happy path is a liability in a live engagement.

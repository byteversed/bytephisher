# BytePhisher test suites

Thirty-four suites (34 test files). Every file is run by the one runner:
`tests/run_all.py` discovers each `tests/test_*.py`, runs a
standalone self-test as a script and a pytest module through pytest, and prints
one summary — it never hides a skip, and a suite where everything skipped is
reported as a skip with the reason (that is what happens to the browser suites on
a machine without Chrome).

`test_e2e.py` is a **self-contained script**: it drives the whole campaign
lifecycle itself with its own `check()` calls and defines no pytest test
functions, so `pytest tests/test_e2e.py` collects nothing (exit 5) and only
`run_all.py` (or `python tests/test_e2e.py`) runs it. Every other file carries a
module-level `pytestmark` for its tier, so `-m unit`, `-m integration` and
`-m live` all select something real.

| suite | what it proves | tier (pytest marker) |
|---|---|---|
| `test_blocklist.py` | researcher filtering: orgs, ranges, user agents, own file, through the real proxy | integration |
| `test_botgate.py` | fingerprint scoring and refusal through the real proxy (incl. JA3-only) | integration |
| `test_chains.py` | post-exploitation chains: tasks, error isolation, keyword hunt, auto-chain | unit |
| `test_crossplatform.py` | AST invariants: encodings, POSIX-only imports/paths, shell=True | unit |
| `test_e2e.py` | one full campaign lifecycle from a real subprocess CLI run to the DB | script (run_all only) |
| `test_evasion.py` | relocatable hook path + per-session renaming, **executed under Node** | integration |
| `test_exploits.py` | the local-service exploit library against real local stubs (Docker, Jenkins, …) | integration |
| `test_features.py` | CLI-level features: campaigns, rotation, exports, doctor | integration |
| `test_forge.py` | phishlet forge from a saved page: credential selection, token scoping | integration |
| `test_gaps.py` | the awkward corners: migrations, update checks, packaging, alerts | integration |
| `test_gate.py` | gating: countries, datacenters, hours/days, hit caps, decoys | integration |
| `test_http.py` | HTTP server behaviour: bodies, headers, TLS, health, OTP flow | integration |
| `test_intel.py` | the deep device dump: analysis, wave merging, transport, storage, CLI | live |
| `test_intel_harvest.py` | the collector in a real browser (skips with a reason without Chrome) | live |
| `test_live.py` | real internet: tunnels, geo APIs, SMTP sink, subprocess runs | live |
| `test_ops.py` | live-session operations: credential validation verdicts, keepalive | integration |
| `test_phishlet.py` | phishlet v2: two-host chains, sub-filters, tokens, YAML round-trip | integration |
| `test_portability.py` | packaging + launcher portability (no venv required) | integration |
| `test_proxy.py` | the reverse-proxy engine against a fake multi-step login site | integration |
| `test_realtime.py` | live input stream + **server-side OTP completion** against a fake MFA upstream | integration |
| `test_rebind.py` | DNS rebinding: wire format and the proven public→loopback flip over real UDP | integration |
| `test_security.py` | adversarial: SSRF, XSS, session/cookie handling, limits, CSV, deadlocks | integration |
| `test_session.py` | session vault, cookie export/import, validation, takeover (replay-based) | live |
| `test_telegram.py` | control channel: parsing, dispatch, operator-only rule, poll loop, buttons | unit |
| `test_transport.py` | the upstream leg's TLS fingerprint: our own outbound ClientHello captured and fingerprinted with `core/tls_fp` (JA3 vs Python, extension permutation, fallback, cookie scoping) | integration |
| `test_fingerprint_headers.py` | header hygiene: no Python banner, exactly one Server and one Date, upstream's relayed, empty value omits | integration |
| `test_deep_harvest.py` | deeper device detail: voices, keyboard layout, controllers, heap, IndexedDB names, XR, sensors, chrome internals, PWA state | integration |
| `test_import_mirror.py` | clone realism: the page's own assets mirrored locally, beacons removed, SRI stripped, no Referer sent to the brand | integration |
| `test_no_fetch_attack.py` | no-fetch attack paths: the real collector executed under Node submits the form into a hidden frame and reads the same-origin answer | integration |
| `test_operations_safety.py` | panic stop, data wipe, and the dashboard/API token (401 without it, 200 with header or query) | integration |
| `test_websocket.py` | WebSocket relay (handshake with the victim's cookie jar, echo round-trip, Origin rewrite) + meta-tag CSP removal | integration |
| `test_modern_login.py` | modern login shapes: chunked request bodies relayed and captured, JSON and nested-JSON logins, non-credential JSON ignored | integration |
| `test_template_brands.py` | the expanded brand batch: shape, slug rules, colour format, ASCII-only text, a password-ish field, no duplicates | integration |
| `test_units.py` | pure logic: parsing, credential detection, risk, gating maths, templates, tunnels | unit |

## Running a tier

```bash
./.venv/bin/python -m pytest tests -m unit          # seconds, no network
./.venv/bin/python -m pytest tests -m integration   # local sockets + subprocesses
./.venv/bin/python -m pytest tests -m live          # needs the real internet
./.venv/bin/python tests/run_all.py                 # everything, one summary
./.venv/bin/python tests/run_all.py --fast          # everything except the live suite
./.venv/bin/python tests/run_all.py --only realtime,blocklist
```

## Verification that runs the thing

Three suites do not just read code, they execute it:

| suite | how |
|---|---|
| `test_realtime.py` | a fake MFA site really receives the streamed code; the session flips to captured only when it does |
| `test_evasion.py` | `tests/js_harness.js` runs the randomised collector under Node with a stubbed DOM and asserts it still beacons |
| `test_blocklist.py` | a scanner user agent and a browser are sent through the real proxy; only one of them gets the phishlet |

## Rules these suites follow

1. **No test writes to the developer's database.** Anything that runs the real
   CLI sets `BYTEPHISHER_HOME` to a temporary directory, so `data/bytephisher.db`
   is never touched.
2. **Ports are allocated, never assumed.** `conftest.free_port()` binds `:0` and
   returns what the kernel gave, so parallel runs do not collide.
3. **Skips are honest.** A live or browser test that cannot run reports a skip
   with the reason — it never silently passes, and an all-skipped suite is not
   counted as a failure.
4. **A generated artifact is not a source file.** `templates/` is produced by
   `tools/gen_templates.py`; a session fixture generates it on a fresh checkout so
   the suite works on a clean clone and in CI.
5. **Adversarial cases are first-class.** Malformed JSON, empty bodies, oversized
   bodies, upstream 500/down, unicode credentials, concurrency, HEAD requests, a
   foreign chat commanding the bot, a rejected OTP: a tool that only passes the
   happy path is a liability in a live engagement.

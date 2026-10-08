# BytePhisher — feature matrix: what was planned vs what exists

Every row says what is implemented, where it lives, and how it is verified.
Anything partial or unverified says so explicitly.

## Core engine (original blueprint)

| Planned | Status | Where | Evidence |
|---|---|---|---|
| Real-world preflight (`lab_check`) | **DONE** | `tools/lab_check.py` | `tests/test_lab_check.py` (16) + a live run that reports BLOCKED on this box |
| Device-code / OAuth tokens in the vault | **DONE** | `session.add_oauth`, `--devicecode` wiring | `tests/test_oauth_vault.py` (23), verified live across a restart |
| Evidence per action (unproven is recorded as unproven) | **DONE** | `session.add_evidence`/`evidence_from_task` | `tests/test_resume_and_evidence.py` |
| Session restore after a restart | **DONE** | `engine.restore_sessions`, `--resume-hours` | same suite, verified live with a `kill -9` and a restart |
| Pre-serve human challenge | **DONE** | `core/challenge.py`, `--verify-first` (proxy mode; static mode says so instead of ignoring it), `--verify-brand` (neutral by default), `tools/campaign.sh` | `tests/test_challenge.py` (20, incl. the real proxy end to end), `test_audit_fixes.py` (the Accept gate, the verify flood, the forwarded-proto trust) |
| Session id never handed to the page | **DONE** | attribution from the HttpOnly cookie; `page_token()` | `test_proxy.py::test_hook_js_carries_no_session_id_at_all` |
| Per-campaign cookie/attribute names | **DONE** | `core/symbols.py`, `--symbols random`, `tools/campaign.sh` | `tests/test_symbols.py` (10) |
| Hook stealth (patched `fetch`/XHR look native) | **DONE** | `--hook-stealth` (default), `STEALTH_JS` in `core/proxy.py` | `tests/test_stealth_hook.py` (12; the real hook executed under Node, stealth-on vs stealth-off) |
| Upstream browser fingerprint by default | **DONE** | `transport.effective_profile`, `--no-impersonate` | `tests/test_transport.py` (6) + a live proxy round trip |
| Device-code relay (RFC 8628) | **DONE** | `core/devicecode.py`, `--devicecode` | `tests/test_devicecode.py` (28; incl. the CLI end to end and a `live` probe of Microsoft's/Google's real endpoints) |
| Pure-Python HTTP server, no PHP | **DONE** | `core/server.py` | `tests/test_http.py` (31 tests), live tunnel round trips |
| TLS option | **DONE** | `serve(tls=..., cert_path=...)`, `--tls --cert` | `test_http.py::TestBehaviourModes::test_tls_mode` |
| Full request logging | **DONE** | every POST stored with headers-derived IP/UA + `source_url` | `test_http.py::TestPost` |
| SQLite capture store (ts, URL, IP, UA, device, geo) | **DONE** | `core/capture.py` (WAL, write lock, migrations) | `test_units.py::TestCaptureDB`, 40-parallel-submission test |
| Datacenter / hosting flag | **DONE** | `core/risk.py` (ISP markers) + `core/gate.py` | `test_features.py::TestRiskEngine`, `test_gate.py` |
| VPN flag | **DONE** | `core/blocklist.py` (commercial VPN + Tor orgs), `core/intel.py` (`vpn_suspected_score`), `core/risk.py` | `test_blocklist.py::TestOrganisations`, `test_intel.py` VPN scoring |
| Field-level capture + hidden honeypot | **DONE** | `hp_email` in every template, all fields stored | `test_http.py::TestPost::test_honeypot_value_recorded` |
| Keystroke-level timing | **DONE** | live stream (`core/assets/intel.js` → `/__bh/live`) with per-event ms, plus `_ts` form-open duration and behaviour tracking | `test_realtime.py::TestLiveParsing`, `test_units.py` behaviour module |
| Jinja2 template engine | **DONE** | `core/templates.py` | `test_units.py::TestTemplates` |
| 670 templates, per-template OTP page | **DONE (exceeded)** | 670 templates, each with `index.html` + `otp.html` | `test_units.py` renders every site and asserts the contract |
| Custom template builder | **DONE** | `tools/import_site.py` (assets absolutised, forms neutralised, fields extracted) | `test_units.py::TestCustomImport` (import → serve → capture) |
| Deep device dump on page open | **DONE** | `core/assets/intel.js` + `core/intel.py` (48 modules: device dump, live input, autofill escalation, clipboard, media, LAN recon, service worker, kill chain) | `test_intel.py` (29 tests) + verified in a real Chromium via Playwright (190/243 APIs collected) |
| Reverse-proxy engine (`--proxy`) | **DONE** | `core/proxy.py` (phishlet YAML, per-victim cookie jar, header/HTML rewrite, hook injection, `/__bh/capture`), CLI wiring in `bytephisher.py` | `test_proxy.py` (27 tests: fake multi-step login upstream + 3 CLI runs) and a live run against a real public site |

## Advanced matrix (original blueprint)

| Planned | Status | Where | Evidence |
|---|---|---|---|
| 6 tunneler adapters | **DONE** | `tunnels/__init__.py` | `test_units.py::TestTunnels` (patterns, interface) |
| …actually serving publicly | **3 of 6 verified live** | cloudflared, localhost.run, bore | `tests/test_live.py` + `tools/probe_tunnels.py` |
| ngrok | **UNVERIFIED** | adapter exists | binary absent + free ngrok needs an authtoken |
| serveo / hoplink | **REMOVED** | both dead on this build (hoplink: the domain does not resolve at all; serveo: no URL in 20s, twice) - shipping an adapter for a service that does not exist is worse than shipping fewer | probe output |
| URL shadowing / social preview | **DONE** | OG meta tags in all 670 templates | `grep -c "og:title" templates/*/index.html` |
| Live TUI dashboard | **DONE** | `dashboard.make_frame` / `live_loop` (rich) | `test_live.py::TestTUILive` |
| Web dashboard, real-time | **DONE (SSE, not WebSocket)** | `/stream` Server-Sent Events + polling fallback | `test_gaps.py::TestSSEStream` (push of a live capture) |
| Spear-phishing email module (4 templates, variables, tracking pixel) | **DONE** | `mailer/` | `test_live.py::TestSMTPLive` (real SMTP sink, HTML + pixel) |
| …live provider (Gmail/Outlook) | **UNVERIFIED** | — | no credentials supplied |
| Campaign mode / one-command pipeline | **DONE** | `tools/campaign.sh`, `--campaign`, `--rotate` | `test_features.py::TestCampaignLauncher` |
| OTP / 2FA flow | **DONE** | login → credentials → OTP page → redirect | `test_http.py::TestBehaviourModes::test_otp_flow` + live tunnel test |
| Credential-reuse check | **DONE** | `db.reuse_stats()`, `--reuse` (CLI + dashboard) | `test_gaps.py::TestCredentialReuse` |
| Export CSV / JSON | **DONE** | `--export` (extension decides), `export_csv`/`export_json` | `test_features.py::TestDataExport` |
| Dockerfile | **DONE (unbuilt here)** | `Dockerfile`, `docker-compose.yml` | compose YAML parses; Docker absent on this host |
| PIP-installable | **DONE** | `pyproject.toml`, console script | `test_gaps.py::TestPackaging` (`bytephisher --version` from `/tmp`) |
| Termux / cross-platform | **PARTIAL** | `deploy/install-termux.sh`, cross-platform code | script syntax-checked; no Android/Windows/macOS run |
| Troubleshooter | **DONE** | `--doctor` (deps, templates, DB, ssh, tunnelers, port, network) | `test_features.py::TestDoctor` |

## This release: the offensive harvest layer

| Capability | Status | Where | Evidence |
|---|---|---|---|
| Live keystroke/field streaming | **DONE** | `core/assets/intel.js` (debounced beacon, flush on blur/submit/pagehide), `core/intel.py::normalise_live`, `/__bh/live` on both servers, `live_input` table | `test_realtime.py` (25 tests: storage, alert, bounds, malformed/oversized rejection) |
| Server-side OTP completion | **DONE** | `ProxyEngine.complete_with_otp` + `pending_login`, replaying the remembered credential POST with the streamed code | `test_realtime.py::test_streamed_code_completes_the_login_upstream` (fake MFA upstream really receives the code), `test_a_wrong_code_does_not_capture` |
| Autofill escalation | **DONE** | load-time snapshot + re-read on first gesture, diff reported | `test_realtime.py::TestLiveParsing` (kind=autofill), collector executed under Node |
| Clipboard watch | **DONE (permission-gated)** | read on first gesture + every paste/copy in the live stream | `test_realtime.py` live-event coverage; runs under `--intel-perms` |
| Media capture | **DONE (permission-gated)** | webcam frame, 1.5 s mic clip, screen frame on gesture, every capture bounded and its refusal reported | collector executed under Node (`tests/test_evasion.py::TestCollectorStillRuns`) |
| Researcher/scanner filtering | **DONE** | `core/blocklist.py` + `Gate(block_researchers=)` + both servers + CLI | `test_blocklist.py` (52 tests incl. a scanner and a browser through the real proxy) |
| Decoy leaks nothing | **DONE (bug fixed)** | decoy mode serves upstream markup with no collector and no `__bhs` cookie | `test_blocklist.py::test_a_scanner_never_sees_the_phishlet` |
| Telegram control channel | **DONE** | `core/telegram.py` + `--telegram-c2`: 12 commands, inline-keyboard callbacks, operator-only chat, long-poll loop that survives a dead network | `test_telegram.py` (48 tests) + a real CLI run against a stub API |
| Alert action buttons | **DONE** | `core/alerts.py::_buttons_for` → Takeover / Live / Session / Block IP | `test_telegram.py::TestAlertButtons` |
| Relocatable hook path | **DONE** | `--hook-path` → `engine.path_of()` on every route **and** the injected tag | `test_evasion.py::test_the_injected_tag_uses_the_custom_path` |
| Per-session script renaming | **DONE** | `intel.randomize_symbols`, deterministic per session | `test_evasion.py` (unit) + the collector executed under Node with a stubbed DOM |

| Local-service exploit library | **DONE** | `core/exploits.py` (17 services), collector `killChain`, `--exploit-list` / `--exploit-ports` / `--exploit-limit` | `test_exploits.py` (19 tests: payload shapes + fake Docker/Jenkins end to end) |
| Router takeover plan | **DONE** | `core/exploits.py::ROUTERS` / `router_plan`, `--router-plan` | `test_exploits.py::TestRouterPlan` |
| DNS rebinding | **DONE** | `core/rebind.py` (wire format, per-client policy, threaded UDP responder), `--rebind-domain` + friends, `probe_script` | `test_rebind.py` (29 tests incl. a real UDP flip) |
| Local service map | **DONE** | `core/rebind.py::LOCAL_SERVICES`, collector `rebindProbe` | `test_evasion.py` (the collector, executed under Node, fetches the Docker API port) |
| LAN existence probe | **DONE** | collector `lanRecon`, bounded | executed under Node; the limit is stated in `docs/PROXY.md` |
| Service-worker persistence | **DONE** | `core/assets/sw.js`, `/__bh/sw.js` on both servers, IndexedDB queue, background sync | `test_evasion.py::TestServiceWorkerLogic` + `tests/sw_harness.js` |
| Ordered keystroke log | **DONE** | collector `keystrokeLog`, `intel.normalise_live` | `test_evasion.py` (executed under Node), `test_realtime.py` (parsing) |
| Post-exploitation chains | **DONE** | `core/chains.py` + takeover tasks in `core/session.py`, `--run-chain` / `--chains` / `--chain-json`, Telegram `/chain` | `test_chains.py` (25 tests: ordering, error isolation, findings, report, task variables) |
| Gating parity in proxy mode | **DONE (bug fixed)** | `ProxyHandler.do_GET` runs the whole gate; `ProxyEngine.geo_cached` | `test_blocklist.py::TestThroughTheProxy` (country, datacenter, hit cap, active window) |
| Country rules vs the geo layer | **DONE (bug fixed)** | `country_code` carried by both geo layers, matched alongside the name in `Gate.check` | `test_gate.py::TestCountryMatching` (7 tests) |
| Live-input retention | **DONE** | `CaptureDB.prune_live` / `live_purge` / `live_count`, `--keep-days`, `--live-purge` | `test_realtime.py` (retention + CLI tests) |
| The live stream in the CLI | **DONE** | `--session SID` prints the latest value per field | `test_realtime.py::TestCliSessionShowsTheStream` |

## Built beyond the original plan

* Risk scoring 0–100 with reasons + "credible (low risk)" counts (`core/risk.py`).
* Campaign gating: country allow/deny, datacenter refusal, active hours/days,
  per-IP hit cap, decoy redirect, refusals logged (`core/gate.py`, `blocked` table).
* Blocked-visitor reporting (excluded from visitor/submission counts).
* Telegram + generic-webhook alerts per capture, with a public-endpoint test.
* Email open-tracking pixel served by the tool itself (`/px.gif`).
* Tunnel watchdog + `--tunnel-restart` auto-heal.
* IPv4-preferring outbound transport (`core/net.py`) fixing `Errno 101` on hosts
  without an IPv6 route.
* `tools/stress.py` load test with row-count integrity check.
* `tools/probe_tunnels.py` live tunneler reality check.
* `tools/doctor.py` environment self-check (also `--doctor`).
* 34 test suites with a single runner that discovers them, classifies an
  all-skipped suite as a skip (not a failure) and never hides a skip.
* Hardening: no open forward proxy (SSRF), escaped dashboard
  rendering, validated 128-bit session ids, bounded sessions/recording/bodies,
  CSV formula neutralisation, shared credential/device/ASN classification.
* Reverse-proxy engine with per-victim upstream sessions and a device
  fingerprint (canvas, WebGL renderer, WebRTC IP, headless hints).
* One SQLite connection per thread in the capture store — a single shared
  connection segfaulted the process under concurrent dashboard/server/TUI use.

## Known limits, stated plainly

1. **VPN/proxy detection** on the *server* side is limited to hosting/datacenter
   ASNs; the device dump adds client-side WebRTC/timezone/language inference.
2. **Timing capture** is per-event in the live stream (`ms` on every input/key
   event) plus the form-open duration; it is not a full keystroke recorder (key
   *names* are streamed, not a keylogger's ordered log with modifiers).
3. **Real-time dashboard uses SSE**, not WebSocket (same effect, fewer deps).
4. **Docker image, systemd unit, Termux, Windows/macOS** were not executed here.
5. **ngrok** was not verified live (the free service now needs an authtoken;
   dead services).
6. **Real provider SMTP/Telegram delivery** needs the operator's credentials.
7. One live test (cloudflared public round trip) skips with a reason when the
   quick tunnel drops its edge connection mid-run.
8. **Proxy mode applies the researcher filter and the bot gate, but not the
   country/datacenter/hours gating** (the CLI still warns when those flags are
   combined with `--proxy`).
9. **Proxy mode does not tunnel WebSocket upgrades** and speaks HTTP/1.1 to the
   upstream; sites that force h2 or depend on WS break visibly (documented in
   `docs/PROXY.md`). MFA is relayed, never bypassed.
10. **No report generator, by owner decision.** Captures leave the tool through
    the CSV/JSON export, the dashboard API and the SQLite store.

| upstream TLS impersonation (`--impersonate`) | DONE | `core/transport.py`, `tests/test_transport.py` (JA3 measured against our own outbound request) |
| websocket relay (handshake with the victim's jar, then verbatim pumping) | DONE | `core/proxy.py` `_websocket`, `tests/test_websocket.py` |
| meta-tag CSP removal (header **and** `<meta http-equiv>`) | DONE | `core/proxy.py` `rewrite_html`, `tests/test_websocket.py` |
| no-fetch attack paths (form into a hidden frame) | DONE | `core/exploits.py` `forms`, `core/assets/intel.js` `formAttack`, `tests/test_no_fetch_attack.py` |
| deeper device detail (voices, layout, gamepads, heap, IndexedDB names, XR, sensors, chrome internals, PWA state) | DONE | `core/assets/intel.js`, `tests/test_deep_harvest.py` |
| panic stop + data wipe from the control channel | DONE | `panic_handlers()` in `bytephisher.py`, `core/capture.py` `wipe()`, `tests/test_operations_safety.py` |
| panic stop + wipe from the **console** | DONE | `--panic` / `--kill --yes` (the same handlers, so a console operator has a panic path without Telegram), `tests/test_operator_surface.py` |
| dashboard/API token | DONE | `dashboard/__init__.py` (`--api-token`) |
| clone asset mirroring | DONE | `tools/import_site.py` (`--mirror`), `tests/test_import_mirror.py` |
| response-header hygiene (`--server-header`) | DONE | `core/server.py`, `core/proxy.py`, `tests/test_fingerprint_headers.py` |

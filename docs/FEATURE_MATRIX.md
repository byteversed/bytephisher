# BytePhisher — feature matrix: what was planned vs what exists

Every row says what is implemented, where it lives, and how it is verified.
Anything partial or unverified says so explicitly.

## Core engine (original blueprint)

| Planned | Status | Where | Evidence |
|---|---|---|---|
| Pure-Python HTTP server, no PHP | **DONE** | `core/server.py` | `tests/test_http.py` (31 tests), live tunnel round trips |
| TLS option | **DONE** | `serve(tls=..., cert_path=...)`, `--tls --cert` | `test_http.py::TestBehaviourModes::test_tls_mode` |
| Full request logging | **DONE** | every POST stored with headers-derived IP/UA + `source_url` | `test_http.py::TestPost` |
| SQLite capture store (ts, URL, IP, UA, device, geo) | **DONE** | `core/capture.py` (WAL, write lock, migrations) | `test_units.py::TestCaptureDB`, 40-parallel-submission test |
| Datacenter / hosting flag | **DONE** | `core/risk.py` (ISP markers) + `core/gate.py` | `test_features.py::TestRiskEngine`, `test_gate.py` |
| VPN flag | **NOT DONE** | — | only datacenter/hosting ASN detection exists; VPN/proxy detection is not implemented |
| Field-level capture + hidden honeypot | **DONE** | `hp_email` in every template, all fields stored | `test_http.py::TestPost::test_honeypot_value_recorded` |
| Keystroke-level timing | **PARTIAL** | `_ts` records form-open duration, not per-key timings | `test_http.py::test_timing_field_recorded` |
| Jinja2 template engine | **DONE** | `core/templates.py` | `test_units.py::TestTemplates` |
| 80 templates, per-template OTP page | **DONE (exceeded)** | 243 templates, each with `index.html` + `otp.html` | `test_units.py` renders every site and asserts the contract |
| Custom template builder | **DONE** | `tools/import_site.py` (assets absolutised, forms neutralised, fields extracted) | `test_units.py::TestCustomImport` (import → serve → capture) |
| Deep device dump on page open | **DONE** | `assets/intel.js` + `core/intel.py` (26 modules, device token, bot + VPN scoring) | `test_intel.py` (28 tests) + verified in a real Chromium via Playwright (190/243 APIs collected) |
| Reverse-proxy engine (`--proxy`) | **DONE** | `core/proxy.py` (phishlet YAML, per-victim cookie jar, header/HTML rewrite, hook injection, `/__bh/capture`), CLI wiring in `bytephisher.py` | `test_proxy.py` (27 tests: fake multi-step login upstream + 3 CLI runs) and a live run against a real public site |

## Advanced matrix (original blueprint)

| Planned | Status | Where | Evidence |
|---|---|---|---|
| 6 tunneler adapters | **DONE** | `tunnels/__init__.py` | `test_units.py::TestTunnels` (patterns, interface) |
| …actually serving publicly | **3 of 6 verified live** | cloudflared, localhost.run, bore | `tests/test_live.py` + `tools/probe_tunnels.py` |
| ngrok | **UNVERIFIED** | adapter exists | binary absent + free ngrok needs an authtoken |
| serveo / hoplink | **DEAD SERVICES** | adapters fail soft | probe output; reported honestly |
| URL shadowing / social preview | **DONE** | OG meta tags in all 243 templates | `grep -c "og:title" templates/*/index.html` |
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
| Auto-update check | **DONE** | `core/update.py`, `--check-update`, cached startup notice | `test_gaps.py::TestUpdateCheck` |
| Troubleshooter | **DONE** | `--doctor` (deps, templates, DB, ssh, tunnelers, port, network) | `test_features.py::TestDoctor` |

## Built beyond the original plan

* Risk scoring 0–100 with reasons + "credible (low risk)" counts (`core/risk.py`).
* Campaign gating: country allow/deny, datacenter refusal, active hours/days,
  per-IP hit cap, decoy redirect, refusals logged (`core/gate.py`, `blocked` table).
* Blocked-visitor reporting (excluded from visitor/submission counts).
* QR codes (PNG/SVG/terminal) for the live link.
* Telegram + generic-webhook alerts per capture, with a public-endpoint test.
* Email open-tracking pixel served by the tool itself (`/px.gif`).
* Tunnel watchdog + `--tunnel-restart` auto-heal.
* IPv4-preferring outbound transport (`core/net.py`) fixing `Errno 101` on hosts
  without an IPv6 route.
* `tools/stress.py` load test with row-count integrity check.
* `tools/probe_tunnels.py` live tunneler reality check.
* `tools/doctor.py` environment self-check (also `--doctor`).
* 10 test suites (`e2e`, `units`, `http`, `features`, `gate`, `gaps`, `proxy`,
  `intel`, `security`, `live`) with a single runner that never hides a skip.
* Adversarial audit fixes: no open forward proxy (SSRF), escaped dashboard
  rendering, validated 128-bit session ids, bounded sessions/recording/bodies,
  CSV formula neutralisation, shared credential/device/ASN classification.
* Reverse-proxy engine with per-victim upstream sessions and a device
  fingerprint (canvas, WebGL renderer, WebRTC IP, headless hints).
* One SQLite connection per thread in the capture store — a single shared
  connection segfaulted the process under concurrent dashboard/server/TUI use.

## Known limits, stated plainly

1. **VPN/proxy detection** on the *server* side is limited to hosting/datacenter
   ASNs; the device dump adds client-side WebRTC/timezone/language inference.
2. **Timing capture** is form-open duration, not per-keystroke telemetry.
3. **Real-time dashboard uses SSE**, not WebSocket (same effect, fewer deps).
4. **Docker image, systemd unit, Termux, Windows/macOS** were not executed here.
5. **ngrok, serveo, hoplink** were not verified live (missing binary/authtoken or
   dead services).
6. **Real provider SMTP/Telegram delivery** needs the operator's credentials.
7. One live test (cloudflared public round trip) skips with a reason when the
   quick tunnel drops its edge connection mid-run.
8. **Proxy mode does not apply campaign gating yet** (the CLI prints a warning
   when gating flags are combined with `--proxy`).
9. **Proxy mode does not tunnel WebSocket upgrades** and speaks HTTP/1.1 to the
   upstream; sites that force h2 or depend on WS break visibly (documented in
   `docs/PROXY.md`). MFA is relayed, never bypassed.
10. **No report generator, by owner decision.** Captures leave the tool through
    the CSV/JSON export, the dashboard API and the SQLite store.

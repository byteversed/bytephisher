# Changelog

All notable changes to BytePhisher. Format: keep it factual — what changed and
why, with the verification evidence where a change came from a live bug.

## v1.0.0

### Core
* Pure-Python threaded HTTP server (no PHP): catch-all template serving, TLS
  (`--tls --cert`), `/health`, 128-deep listen backlog.
* Body parsing for `application/x-www-form-urlencoded`, `multipart/form-data`
  (stdlib `email` parser, quoted-printable safe) and `application/json`.
* Credential detection with exact-name list plus a substring heuristic so
  imported/custom field names (`login_id` + `passwd`) are still recognised.
* OTP/2FA flow: login page first → credentials → 6-digit OTP page → redirect.
* Honeypot field (`hp_email`) and a form-open timing field (`_ts`).
* Real client IP behind tunnels: `CF-Connecting-IP` → `True-Client-IP` →
  `X-Real-IP` → first `X-Forwarded-For` hop → socket address.
* Geo/ISP enrichment (ipapi / ipinfo / off) and device classification
  (iOS/Android/Windows/macOS/Linux).

### Capture store
* SQLite in WAL mode with a write lock: 40 concurrent submissions verified with
  zero lost or crossed writes.
* `captures` + `visitors` tables; visitors de-duplicated by `(ip, ua)` with a
  UNIQUE index (before that fix, "unique visitors" over-counted).
* In-place migrations for `campaign`, `risk`, `risk_reasons` columns.
* CSV export, per-campaign stats, campaign breakdown.

### Templates
* 179 generated templates (brand colours, correct field names, OTP page, OG
  meta tags, demonstration footer) plus `tools/import_site.py` to turn any real
  login page into a template (asset absolutisation, form neutralisation,
  field extraction, auto-registered index).
* Generator validation: bad `login_with`, mixed-case or duplicate slugs and
  malformed colours fail fast with a readable error instead of generating junk.

### Tunnels
* Six adapters: cloudflared (auto-download + waits for edge registration so the
  first hit is not a 530), localhost.run, bore (auto-downloads the musl binary
  from GitHub releases), ngrok, serveo, hoplink.
* Child processes are tracked and terminated on exit; tunnel logs are truncated
  per start so a stale public URL can never be reported as live.
* Verified live in this build: cloudflared, localhost.run, bore. Dead services
  (serveo, hoplink) and unconfigured ngrok fail soft and are reported honestly.

### Campaign engineering
* `--campaign` tagging, `--rotate a,b,c` A/B template rotation per request.
* Risk scoring 0–100 with reasons: automation user-agents, datacenter/hosting
  ISPs, filled honeypot, inhumanly fast submits, unrecognised devices, missing
  geo. Reports expose "credible (low risk)" counts next to raw credential
  counts so numbers stay honest.

### Monitoring and output
* rich live TUI (campaign, geo, risk, credential flag, fields) + plain refresher
  mode for logs/systemd, plus Flask dashboard with `/api/captures`,
  `/api/stats`, `/api/campaigns` and campaign filtering.
* Telegram and generic-webhook alerts per capture (daemon thread, failures
  swallowed so a dead webhook can never break a capture).
* Self-contained HTML campaign report (KPIs, campaigns, geo/device/ISP bars,
  hourly timeline, risk-labelled rows, optional QR) via `tools/report.py`.
* QR code generation (PNG/SVG/terminal) for the live link.
* Email module: 4 templates, variable substitution, HTML rendering, 1x1
  `/px.gif` open-tracking pixel served by the tool itself.

### CLI and ops
* `-o -t -u -p -m --otp --tls --cert --geo --list --tunnels --export --no-tui
  --telegram --webhook --mailto --mail-template --campaign --qr --report
  --rotate --doctor --version`.
* `--doctor` environment self-check (python, deps, templates, SQLite, data dir,
  config, ssh, tunneler binaries, port binding) with `--json` output.
* `tools/stress.py` load test for your own instance: throughput, p50/p95/p99
  latency, HTTP error counts, and a row-count integrity check against the DB.
* Capture export in both formats — `.json` writes the full machine-readable
  dump (stats + campaigns + captures with risk), anything else writes CSV.
* Line-buffered stdout so piped/logged runs show the tunnel URL and captures
  as they happen (block buffering used to hide everything until exit).
* Dockerfile, docker-compose.yml, systemd unit, Termux installer, Makefile.
* Session summary on Ctrl+C (runtime, captures, credentials, visitors, links,
  tunneler shutdown count).

### Tests
* 5 suites: `test_e2e.py`, `test_units.py`, `test_http.py`, `test_features.py`,
  `test_live.py` — unit, HTTP, feature and live tiers; `tests/run_all.py`
  prints one honest summary and never hides a skip.
* Live tier touches the real internet on purpose: public tunnel round trips,
  geo lookups, SMTP delivery into a local aiosmtpd sink, CLI subprocess runs.
* Bugs found and fixed by these tests: visitor de-duplication, class-attribute
  notifier binding, TLS key-path derivation, listen backlog exhaustion,
  port-derived DB path collisions, stale tunnel logs and the 530 window on
  cloudflared, CLI block buffering, and `login_id`/`passwd` credential misses.

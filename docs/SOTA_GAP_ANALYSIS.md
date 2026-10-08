# AiTM / phishing framework state of the art (2026) vs BytePhisher — ranked build plan

Scope: what the leading real-world frameworks and PhaaS kits do in 2026, what
BytePhisher does today **with the file that proves it**, what is genuinely
missing, and a ranked plan with exact files, data structures, effort and the test
that would prove each item works. Every "BytePhisher has it" claim below was
checked in this repo, not remembered.

## Verification status (what was actually run)

| Check | Command | Result |
|---|---|---|
| CLI works | `./.venv/bin/python bytephisher.py --version` | `BytePhisher 0.1.0` |
| chains | `--chains` | 6 chains incl. `own` (probe→forward-submit→password-change→sessions-kill) |
| tasks | `--tasks` | 13 built-ins incl. `mfa-enroll`, `forward-submit`, `password-change` |
| tests | `pytest --collect-only -q` | **848 tests collected**, 38 test files |
| templates | `ls -d templates/*/` | 670 |
| phishlet model | read `core/phishlet.py` (588 lines) | v2: proxy_hosts, sub_filters, js_inject, auth_tokens, auth_urls, credentials, force_post, params |
| proxy engine | read `core/proxy.py` (1792 lines) | rewrite_headers/rewrite_html, cookie jar, WS relay, `complete_with_otp`, `maybe_complete` |
| absence greps | `grep -rniI` for `oauth/consent/device_code/webauthn/passkey/dpop/token binding/bitb/clickfix/qrlogin/pkce` | **0 hits** for device_code, passkey(s), dpop, fido, tabnabbing, clickfix, qrlogin, pkce, refresh_token, access_token |

Labels used below: **HAS** = present and verified by reading the file;
**PARTIAL** = a related mechanism exists but not the technique; **MISSING** =
no code.

---

## Part A — the SOTA landscape, technique by technique

### A1. Evilginx 3 / Evilginx Pro — the phishlet model

The reference reverse-proxy. Phishlet format is now `v3.0.0` and richer than
v2: `proxy_hosts` (multi-host, `session`, `is_landing`, new `auto_filter`),
`sub_filters` (MIME-targeted search/replace with `{hostname}`, `{orig_hostname}`,
`{basedomain}` and `*_regexp` variables), a full `rewrite` section
(locator/action/`chained_value`, capture-group `${1}` substitution, load
replacement from a file), `capture` (cookies **and** arbitrary tokens, required
vs optional, value reshaping from capture groups), `intercept` (short-circuit a
request *before* upstream — block telemetry, serve local static, swap resources),
`params` (child phishlets), and `triggers` with **Evilpuppet** — a background
browser session that runs configured actions (`{username}`, `{password}`, enter,
click) to forge a token the site requires, caught by interceptors.
*(Source: help.evilginx.com phishlet-format / rewrite / capture / intercept.)*

**BytePhisher:** **HAS** the core model (`core/phishlet.py`: `ProxyHost`,
`SubFilter`, `JsInject`, `AuthToken` with `:regexp/:opt/:always`, `AuthUrl`,
`CredentialField` post/json/header, `ForcePost`, `params`/`child()`).
**PARTIAL** on `rewrite` (it has `apply_sub_filters` + `rewrite_html`, not the
locator/chain model). **MISSING** `intercept` and **MISSING** `triggers`/Evilpuppet.

### A2. EvilnoVNC — live browser takeover

Streams a **real Chromium over noVNC** into the victim's browser; the victim
operates the attacker's real browser, so the real site sees a real browser and
2FA completes; the operator watches live, decrypts cookies in real time, extends
cookie life, saves downloads, and dumps the whole browser profile (cookies,
saved passwords, history). *(Source: github.com/JoelGMSec/EvilnoVNC README —
"2FA bypassing by using a real browser over a noVNC connection".)*

**BytePhisher:** **PARTIAL/different**. It has a real-Chrome *operator-side*
takeover (`core/session.py::validate_browser`, Playwright `channel="chrome"`)
used **after** capture, not a victim-facing live browser. It defeats 2FA by
relay (`complete_with_otp`), which is the Evilginx model, not the noVNC model.

### A3. 2FA-relay-as-a-service kits

- **Tycoon 2FA** (Storm-1747): large-scale AiTM PhaaS; proxied M365 login with
  MFA relay. *(Microsoft Security blog, 2026-03-04; Europol/Trend Micro takedown.)*
- **Greatness** (tracked as *HoneyStorm*): $289/mo Telegram PhaaS that packages
  **AiTM + device-code phishing + OAuth consent abuse** in one panel, 11+ lure
  templates incl. QR, centralized backend, benign decoy redirect after capture,
  then token replay + Graph enumeration from VPN exits. *(ZeroBEC, 2026-08-04.)*
- **Sneaky 2FA** (Sneaky Log): M365 AiTM that talks to the **real Microsoft API**
  (not a raw reverse proxy), with autograb (email prefilled from a URL param,
  base64), a **Cloudflare Turnstile gate** in front, anti-debug + HTML/JS
  obfuscation, datacenter/VPN filtering → redirect to a Wikipedia page via
  `href.li`, and a multi-step relay (password → 2FA-method choice → code).
  *(Sekoia, Dec 2024.)*
- **Dadsec / Storm-1575**, **Caffeine/ONNX**: M365 AiTM PhaaS, QR lures, open
  registration, shared infra. *(Microsoft, Dark Reading, Google TI.)*

The common shape: reverse-proxy login + **multi-step MFA relay**, a **bot/captcha
gate**, **IP reputation filtering** with a benign decoy, and **lure templates**.
**BytePhisher:** **HAS** the relay (`complete_with_otp`), the gate
(`core/gate.py`, `core/blocklist.py`, `--bot-gate`, decoy), and lures
(`core/lures.py`). **MISSING** the captcha gate, the device-code and OAuth
consent lures, and the "benign decoy after capture" default.

### A4. Device-code phishing (RFC 8628)

The attacker starts a device-authorization grant against the real IdP
(`POST /devicecode` with a **legitimate public client id**), gets a `user_code`,
and sends the victim to the **real** verification page (e.g.
microsoft.com/devicelogin). The victim types the code and completes real MFA;
the attacker polls `/token` with the `device_code` and receives **access +
refresh tokens** (M365 refresh tokens last ~90 days). No lookalike domain, no
proxy, no credential entry on attacker infrastructure. *(Microsoft Storm-2372
blog, 2025-02-13; Greatness bundles it.)*

**BytePhisher:** **MISSING** (`grep device_code/devicecode` = 0).

### A5. OAuth consent / illicit-consent-grant phishing

Two variants: (1) register an attacker app in the IdP requesting delegated
scopes (`Mail.Read`, `offline_access`, …) and phish the victim to the **real**
consent page; the attacker's app then holds a **refresh token** that survives a
password change; (2) AiTM-proxy the `/authorize` consent page and **capture the
authorization code** at the attacker-registered `redirect_uri`, then exchange it
(PKCE) for tokens inside the victim's session. *(Microsoft: "Protect against
consent phishing", "Detect and remediate illicit consent grants".)*

**BytePhisher:** **MISSING** (only keyword hints in `core/forge.py`).

### A6. QR-login relay (QRLJacking) and hybrid/passkey QR abuse

- **QRLJacking** (OWASP): the attacker harvests the victim's *live* QR login code
  from the real service and displays it on their page; the victim scans it with
  an already-authenticated app; the attacker's session is approved.
- **PoisonSeed** (Expel, 2025-07): AiTM proxy relays credentials, then **forces
  the real page into the hybrid (cross-device) WebAuthn transport**, captures the
  caBLE QR it generates, and shows it to the victim; the victim approves on their
  phone and the **attacker's browser session** receives the assertion.
  *(scyscan/Expel.)*

**BytePhisher:** **MISSING** (no QR, no hybrid transport).

### A7. Browser-in-the-browser (BitB) and reverse tabnabbing

- **BitB**: a DOM-rendered fake browser window (fake address bar + popup) used
  for **credential phishing** — no token theft. *(mrd0x; Mimecast; QR-BiTB arXiv
  2505.18944.)*
- **Reverse tabnabbing**: a `target=_blank` page navigates `window.opener` to a
  phish. **Largely dead**: modern evergreen browsers apply implicit
  `rel=noopener`. *(OWASP "Update 2023".)*

**BytePhisher:** **MISSING** both. BitB is a static-template trick; tabnabbing is
mostly neutralised — see the drop list.

### A8. Session-token theft + replay, DPoP / device-bound sessions

Cookie replay is the classic takeover. Modern defenses: **DPoP** (RFC 9449)
sender-constrains access tokens to a client-held key (each use needs a signed
proof JWT); **device-bound** tokens and **token protection** (Windows), plus
**conditional access "compliant device"** and risk engines that flag a session
replayed from a new IP/UA/geo. Token Binding (RFC 8471/8473) is effectively dead
(Chrome removed it). *(Curity/RFC 9449; Obsidian Security.)*
Key nuance: DPoP stops **bearer replay of a stolen token**; it does **not** stop
device-code phishing, because there the attacker's own client legitimately
obtained the token and holds the key.

**BytePhisher:** **PARTIAL**. It captures the cookie jar (`core/proxy.py
::jar_to_dicts`), exports Cookie-Editor JSON and replays it
(`core/session.py::to_cookie_editor`/`validate_http`/`validate_browser`), and its
own docs flag the replay-trips-risk-engine limit (`docs/PROXY.md` limit #5). It
has **no DPoP concept** and assumes bearer.

### A9. ClickFix / fake-CAPTCHA / clipboard delivery

A landing page shows a fake "verify you are human" widget; JS writes a command
to the clipboard and instructs the user to `Win+R` → paste → Enter (or macOS
Terminal). The command runs PowerShell/mshta to fetch an infostealer that grabs
the browser's **cookie database directly** — session theft without any proxy.
Delivered by phishing email, malvertising and compromised sites. *(Microsoft
"Think before you Click(Fix)", 2025-08-21; SentinelOne; Malwarebytes.)*

**BytePhisher:** **PARTIAL/MISSING**. It **reads** the clipboard (harvest,
`core/assets/intel.js` `clipboardWatch`, permission-gated) but has no clipboard
**write**, no fake-CAPTCHA page, and no command-delivery module.

### A10. Passkeys / WebAuthn — what a relay can and cannot do

WebAuthn binds the credential to the **RP ID** (registrable domain) and the
assertion signs **origin + challenge**. A proxy at `evil.com` **cannot** call
`navigator.credentials.get()` with `rpId=real.com` — the browser rejects an RP ID
that is not a suffix of the origin. So the plain AiTM proxy **breaks passkeys**.
What still works:
1. **Downgrade** — if the site still offers a password path, the AiTM uses it.
2. **Hybrid (caBLE) relay** — the PoisonSeed path: force the real page into
   cross-device mode, relay its QR, the victim approves on their phone, the
   attacker's session gets the assertion. Fails when the authenticator is a
   **plugged-in hardware key** (no hybrid) or a **platform authenticator bound to
   the browser/OS context**, and where a **proximity/BLE check** is enforced.
3. **Session-hijack then enroll** — steal the session by any other means, then
   register an **attacker-controlled passkey** from inside the live session.
4. **Deployment bugs** — PASSKEYS-ATTACKER (USENIX Security 2026, Jannett et al.)
   found 15 WebAuthn attack types (2 critical CVSS) on 18/103 sites, taking over
   accounts, deleting passkeys, or locking users out. Real passkey deployments
   are frequently buggy.
*(USENIX Security 2026 "The State of Passkeys"; arXiv 2604.20826; PoisonSeed.)*

**BytePhisher:** **MISSING** the technique. The only trace is a **capability
probe** (`core/assets/intel.js:597` reports `!!navigator.credentials`), not a relay.
Its takeover chains already include `mfa-enroll` (`core/session.py`
`BUILTIN_TASKS`) — the analogue for adding an attacker MFA device — so the
"enroll" pattern already exists for TOTP/SMS but not for passkeys.

---

## Part B — gap summary

| Technique | BytePhisher today | Proof file | Gap |
|---|---|---|---|
| Evilginx-class phishlet | **HAS** | `core/phishlet.py` | `intercept`, `triggers`/Evilpuppet, rewrite chains |
| Live victim browser (EvilnoVNC) | **PARTIAL** (operator-side only) | `core/session.py::validate_browser` | victim-facing noVNC |
| MFA/OTP relay | **HAS** | `core/proxy.py::complete_with_otp` | — |
| Captcha gate in front | **MISSING** | — | Turnstile/reCAPTCHA gate |
| Device-code phishing | **MISSING** | grep = 0 | whole flow |
| OAuth consent / code capture | **MISSING** | `core/forge.py` hints only | whole flow |
| QR-login / hybrid relay | **MISSING** | grep = 0 | whole flow |
| BitB | **MISSING** | grep = 0 | template only (low ROI) |
| Reverse tabnabbing | **MISSING** | grep = 0 | mostly dead — drop |
| Token replay | **HAS** | `core/session.py` | DPoP/device-bound awareness |
| DPoP / token binding | **MISSING** | grep = 0 | whole concept |
| ClickFix / fake-CAPTCHA | **MISSING** (clipboard read only) | `core/assets/intel.js` | whole flow |
| Passkey relay / enroll | **MISSING** | `core/assets/intel.js:597` probe only | whole flow |
| SAML/OIDC assertion capture | **MISSING** | grep = 0 | whole flow |

---

## Part C — ranked top-7 build plan

Ordered by (strategic value × feasibility) ÷ effort. Each names the exact files,
the data structures/flags, effort in dev-days, the risk, and the test.

---

### 1. Device-code relay (RFC 8628) — the single highest-value addition

**(a) Technique.** Start the real device-authorization grant, hand the victim the
`user_code` + the **real** verification URL, poll for tokens after they approve.
No reverse proxy, no lookalike domain; defeats MFA and usually passkeys.

**(b) What leaders do.** Greatness ships it as a lure type; Storm-2372 used it at
scale (Microsoft, 2025-02-13). No public open-source framework does it well —
this is where BytePhisher can beat Evilginx, which has no device-code mode.

**(c) BytePhisher today.** **MISSING** (grep `device_code` = 0).

**(d) Implementation.**
- New `core/devicecode.py`: `class DeviceCodeFlow` with
  `provider, client_id, tenant, scope, verification_uri, device_code, user_code,
  interval, expires_at, status`; `start()` → `POST {issuer}/devicecode`;
  `poll()` → loop `POST {issuer}/token` honouring `authorization_pending` /
  `slow_down` / `expired_token`, storing `access_token`/`refresh_token`.
  A small `PROVIDERS` table (`microsoft`, `google`, `okta`, `github`) with the
  real public client ids used by each vendor's first-party CLI.
- Vault: extend `core/session.py::new_record` with an `oauth` block
  (`{"provider","refresh_token","access_token","expires_at","dpop":false}`);
  add `session.add_oauth(rec, tokens)`.
- Serving the landing: a new local page served by `core/server.py` (a route
  `/dc/<token>`) showing the code + a copy button + a link to the real
  `verification_uri`; wire a `--devicecode PROVIDER [--dc-client-id]` flag in
  `bytephisher.py`.
- C2: a new `core/alerts.py` alert type `devicecode` with a **Re-poll** button;
  a `/dc <sid>` command in `core/telegram.py`.
- Tests: `tests/test_devicecode.py`.

**(e) Effort.** 3–5 days.

**(f) Risk.** Detection is straightforward on the IdP side (device-code grant by
a public client from an unmanaged device); conditional access "require compliant
device" and M365's device-code hardening block it. Operational risk is low (the
verification page is genuine). Honest limit: **fails against a tenant that
blocks device-code flow or requires a compliant/managed device**; the refresh
token is scoped to the client's permissions.

**Test that proves it:** a fake IdP (`http.server`) exposing `/devicecode`
(returns `device_code`,`user_code`,`verification_uri`,`interval`) and `/token`
(returns `authorization_pending` twice, then a token). Assert: `start()` yields a
user_code; `poll()` terminates with tokens; the tokens land in the vault and an
alert fires. Real proof: run against Microsoft's real `/devicecode` with a public
client id and a lab tenant account.

---

### 2. Passkey/WebAuthn — detect, post-capture enroll, hybrid relay

**(a) Technique.** (i) detect the target uses passkeys and pick a path;
(ii) **enroll** an attacker passkey from a captured session; (iii) **hybrid
(caBLE) relay** — force cross-device mode, relay the QR, capture the assertion.

**(b) What leaders do.** EvilnoVNC sidesteps passkeys by giving the victim a real
browser; PoisonSeed relays the hybrid QR. Nothing open-source does the enroll
path cleanly.

**(c) BytePhisher today.** **MISSING** (only the `PublicKeyCredential` probe at
`core/assets/intel.js:597`).

**(d) Implementation.**
- Detect: extend `core/assets/intel.js` to report a `passkey_offered` signal when the
  login page exposes a WebAuthn button / `navigator.credentials`; fold it into
  the existing `core/intel.py` summary so the operator sees it.
- Enroll: add a `BUILTIN_TASK "passkey-enroll"` in `core/session.py` beside
  `mfa-enroll`, driving the existing Playwright launch with **CDP
  `WebAuthn.addVirtualAuthenticator`** to register an operator-controlled
  credential on the account's security page.
- Hybrid relay: new `core/webauthn.py::PasskeyRelay` that (1) drives a headless
  Chrome to the real login, (2) selects "sign in on another device", (3)
  extracts the caBLE QR (canvas → PNG), (4) serves it to the victim through a new
  proxy route, (5) polls until the ceremony completes and captures the resulting
  session cookies into the vault.
- Tests: `tests/test_webauthn.py`.

**(e) Effort.** 6–9 days (the enroll path is ~2; the hybrid relay is the rest).

**(f) Risk.** High operational complexity. Honest limits: the relay **cannot**
defeat a **plugged-in hardware key** (no hybrid transport), a **platform
authenticator bound to the browser/OS context**, or an RP enforcing **BLE
proximity**; it also fails if the site requires **phishing-resistant MFA** in
conditional access. Enroll requires the site to allow adding a passkey from a
live session (often with re-auth). Detection: passkey ceremonies and credential
enrollment are audited.

**Test that proves it:** (i) Node-executed collector reports `passkey_offered`
with a stubbed `navigator.credentials`; (ii) Playwright + CDP virtual
authenticator adds a credential to a fake "security settings" page and the vault
records it; (iii) a fake RP returning a caBLE QR → the relay extracts and serves
it and, on a simulated approval, its browser session receives the session cookie.

---

### 3. OAuth consent / authorization-code relay

**(a) Technique.** Relay the real `/authorize` consent page and capture the
**authorization code** at the attacker-registered `redirect_uri`, then exchange it
(PKCE) for a **refresh token** that survives a password change.

**(b) What leaders do.** Greatness bundles OAuth consent abuse (ZeroBEC).

**(c) BytePhisher today.** **MISSING** (only keyword hints in `core/forge.py`).

**(d) Implementation.**
- New `core/oauth.py`: `start_authorize(provider, client_id, redirect_uri, scope,
  pkce=True)` → `/authorize?...&code_challenge=…&code_challenge_method=S256`;
  `capture_code(query)`; `exchange_code(...)` → `POST /token` with
  `code_verifier`; store `access`/`refresh` in the vault `oauth` block.
- Phishlet: add an `OauthSpec` to `core/phishlet.py`
  (`authorize_host, token_host, client_id, redirect_uri, scope, pkce`); the
  consent page is already proxyable — add a **code-capture rule** so the proxy
  reads `?code=` on the redirect path and exchanges it in `core/proxy.py`
  `note_tokens`/`maybe_complete`.
- Post-capture: add a `BUILTIN_TASK "graph-enum"` in `core/session.py` that calls
  Graph/API with the token and reports mailboxes.
- Tests: `tests/test_oauth.py`.

**(e) Effort.** 5–7 days.

**(f) Risk.** Needs an **attacker-owned app registration** (an operational
artifact). Honest limits: **fails if the tenant disables user consent or requires
admin approval**; the code-capture variant requires the redirect to land on the
attacker's registered URI and the app registration to allow it. Detection: Entra
"Consent to application" audit events are explicit.

**Test that proves it:** a fake IdP with `/authorize` (302 to
`redirect_uri?code=…`) and `/token`. Assert the proxy captures `code` on the
redirect path, exchanges it, and stores the token; and that the PKCE
`code_verifier` matches the challenge.

---

### 4. Intercept — short-circuit requests, serve local assets, kill telemetry

**(a) Technique.** Return an operator response for matching requests *without*
contacting upstream: block fingerprinting/telemetry that leaks the proxy, serve
local favicons/JS, swap resources.

**(b) What leaders do.** Evilginx Pro `intercept` (block telemetry, serve
`@static/`, redirect-swap, `block_request:false` to modify a real response).

**(c) BytePhisher today.** **PARTIAL** — `block_paths` (never inject), decoy,
`sub_filters`; but no per-request "return this response, do not forward".

**(d) Implementation.**
- `core/phishlet.py`: `class InterceptRule(trigger{host,path}, response{status,
  body|file, mime, redirect}, block_request=True)`; add `intercept` to
  `Phishlet.__init__`/`from_dict`/`to_dict`.
- `core/proxy.py`: match rules at the top of `do_GET`/`do_POST` (before
  `_proxy`); serve local (a `static/` dir beside the phishlet); when
  `block_request=False`, forward then replace the body.
- `config/phishlets/example.yaml`: document the section.
- Tests: `tests/test_intercept.py`.

**(e) Effort.** 2–3 days.

**(f) Risk.** Low. Honest limit: blocking a script the flow needs breaks the
login; and a site whose JS must run cannot be served from a stub.

**Test that proves it:** a phishlet rule 403s `/telemetry` — the request is
answered locally and the fake upstream **never receives it**; a rule serving a
local file returns its bytes with the right mime; `block_request:false` still
forwards but replaces the body.

---

### 5. Background-browser token forging (Evilpuppet equivalent)

**(a) Technique.** For flows that need a token the site's own JS generates, spawn
a headless browser, run configured actions (`{username}`, `{password}`, enter,
click), capture the token via an interceptor, and substitute it into the proxied
request.

**(b) What leaders do.** Evilginx Pro `triggers` + Evilpuppet.

**(c) BytePhisher today.** **PARTIAL** — Playwright takeover exists
(`core/session.py::_launch`) and `complete_with_otp` replays a login, but there
is no generic inline token forging.

**(d) Implementation.**
- `core/phishlet.py`: `class Trigger(domains, paths, token, open_url,
  actions[{selector,value,enter,click,post_wait}], interceptors[...])`.
- New `core/puppet.py` reusing `core/session.py::_launch`; a per-trigger browser
  with a request interceptor that scrapes the token from a matching request.
- `core/proxy.py`: on a matching request whose body contains `token`, call
  `puppet.forge()` and rewrite the value before forwarding.
- Tests: `tests/test_puppet.py`.

**(e) Effort.** 5–7 days.

**(f) Risk.** Heavy (a browser per trigger) and detectable (automation). Honest
limit: only useful when the site needs a JS-generated token the proxy cannot
compute; most modern flows don't.

**Test that proves it:** a fake upstream login whose JS generates a token; the
puppet fills `{username}`/`{password}`, clicks, the interceptor captures the
token, and the proxied request body carries the substituted value.

---

### 6. DPoP / device-bound token awareness (and honest non-replayable reporting)

**(a) Technique.** Detect sender-constrained tokens; mint a valid DPoP proof only
when BytePhisher's own client obtained the token (device-code/consent); otherwise
report the token as **non-replayable** instead of pretending.

**(b) What leaders do.** Most kits simply fail silently against DPoP.

**(c) BytePhisher today.** **MISSING** (assumes bearer cookies).

**(d) Implementation.**
- New `core/dpop.py`: generate an EC P-256 key; mint a proof JWT
  (`htm`,`htu`,`jti`,`iat`) per request (RFC 9449).
- `core/oauth.py`/vault: record `token_type` (Bearer/DPoP) and parse the JWT for
  `typ: dpop+jwt` / `cnf.jkt`; mark bound tokens.
- `core/session.py::validate_*`: for a bound token without the key, return
  `replayable: false` with the reason.
- Tests: `tests/test_dpop.py`.

**(e) Effort.** 3–4 days.

**(f) Risk.** Low — this is about **not overclaiming**. Honest limit: DPoP does
**not** stop device-code phishing (the attacker legitimately obtained the token
with its own key); it only stops bearer replay of a *stolen* token.

**Test that proves it:** a token with `cnf.jkt` is flagged non-replayable; a
device-code token obtained by BytePhisher's own client mints a proof whose
signature and `htm`/`htu` verify and a fake API accepts it; a bearer token still
replays.

---

### 7. ClickFix / fake-CAPTCHA clipboard delivery

**(a) Technique.** A fake "verify you are human" page whose JS writes a command
to the clipboard and instructs the user to run it; the payload fetches an
infostealer that grabs the browser's cookie database directly.

**(b) What leaders do.** ClickFix is a mainstream delivery technique (Microsoft,
2025-08-21) bundled by PhaaS kits.

**(c) BytePhisher today.** **PARTIAL/MISSING** — reads the clipboard
(`core/assets/intel.js` `clipboardWatch`), no write, no fake-CAPTCHA, no delivery.

**(d) Implementation.**
- New `core/clickfix.py`: builds the page (fake CAPTCHA widget + clipboard-write
  JS), the OS-appropriate command (PowerShell/`mshta` for Windows; `curl|sh` or
  Terminal for macOS), and a per-campaign C2 URL.
- Templates under `templates/clickfix_*/`; served by `core/server.py` (or as a
  proxy local page). Reuse `core/lures.py` for per-campaign tracking.
- Tests: `tests/test_clickfix.py`.

**(e) Effort.** 3–4 days.

**(f) Risk.** **High** detection/operational — the command lands in RunMRU /
PowerShell logs and AV flags it. Honest limit: needs user cooperation; fails on
locked-down endpoints (Run dialog disabled); macOS requires Terminal.

**Test that proves it:** the generated page contains a fake-CAPTCHA widget and JS
calling `navigator.clipboard.writeText` with the campaign command; the command
matches the OS profile; the page is served by the static server; and (Node, with
a stubbed clipboard) the write happens.

---

## Part D — honest limits that matter more than the marketing

| Technique | Cannot do |
|---|---|
| Device-code relay | Fails if the tenant blocks device-code flow or requires a compliant/managed device; token scoped to the client's permissions. |
| Passkey hybrid relay | Fails on plugged-in hardware keys, platform authenticators bound to the browser/OS context, and enforced BLE proximity; defeated by "require phishing-resistant MFA". |
| Passkey enroll | Needs the site to allow adding a passkey from a live session (often with re-auth). |
| OAuth consent | Fails if user consent is disabled / admin approval required; needs an attacker app registration; code capture needs an allowed redirect URI. |
| Intercept | Breaking a needed script breaks the flow; can't replace JS that must execute. |
| Evilpuppet forging | Only for flows that need a JS-generated token; automation is detectable; expensive. |
| DPoP awareness | Does not stop device-code/consent theft (attacker holds the key); only stops bearer replay of a stolen token. |
| ClickFix | Needs user cooperation; blocked by disabled Run dialog; noisy in endpoint logs. |
| Cookie replay (existing) | Trips risk engines from a new IP/UA/geo (`docs/PROXY.md` limit #5); not a guaranteed takeover. |
| Reverse tabnabbing | Effectively dead in evergreen browsers (implicit `rel=noopener`) — do not build. |
| BitB | Credential phishing only (no token); a static template, not a proxy feature — low marginal value once you own a real domain. |

## Part E — dropped (cannot be implemented usefully in this codebase, or not worth it)

1. **Reverse tabnabbing** — neutralised by implicit `rel=noopener` in modern
   browsers (OWASP, 2023). Implementable as a `js_inject` one-liner but near-zero
   ROI. **Drop.**
2. **BitB popup** — a DOM fake window is a static-template trick; against a real
   reverse proxy (which already has a real domain) it adds nothing. Optionally a
   template, **not** a proxy feature.
3. **Victim-facing EvilnoVNC (full noVNC + Chromium + Docker)** — a different
   architecture; the unique value (defeat passkeys / flag a headless relay) is
   largely covered by items 2 and 5. High effort, low ROI for a pure-Python
   codebase. **Defer.**
4. **TLS Token Binding (RFC 8471/8473)** — not deployed (Chrome removed it). No
   point.
5. **SAML assertion capture** — implementable (~3 days) but lower value than the
   top 7 for the common M365/Entra/Google target set. **Backlog.**

## Part F — one-line verdict

BytePhisher today is a **strong Evilginx-class engine with an unusually deep
harvest/intel layer** (848 tests, WS relay, DNS rebinding, exploit library, C2)
that is **missing the 2025–2026 offensive frontier**: device-code relay, OAuth
consent/code capture, passkey handling, request interception, background-browser
token forging, DPoP awareness, and ClickFix delivery. Items **1, 2, 3** move it
ahead of the open-source field; **4 and 5** bring it to Evilginx-Pro parity;
**6** keeps it honest; **7** adds the complementary endpoint path.

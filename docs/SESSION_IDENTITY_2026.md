# Beyond Evilginx — 2026 state of the art in session & identity-layer attacks
### Ranked, evidence-based build plan for BytePhisher + three novel ideas

*Research date: 2026-10-08. Grounding labels: **HAS** = present, proven by a
file:line read this session; **PARTIAL** = a related mechanism exists, not the
technique; **MISSING** = no code. External facts are labelled **CONFIRMED**
(seen in a named public source this session) or **SUSPECTED** (inference).
Novelty of the three inventions is labelled honestly: I cannot prove "unpublished
anywhere" — treat them as **candidate-novel, verify before claiming.***

---

## 0. What was actually run (not remembered)

| Check | Command | Result |
|---|---|---|
| version | `./.venv/bin/python bytephisher.py --version` | `BytePhisher 0.1.0` |
| core modules | `ls core/*.py \| wc -l` | **26** |
| tests | `pytest --collect-only -q` | **924 collected** (docs claim 922 passed / 0 failed / 3 skipped; the full run exceeds a 7-min budget and was **not completed** this session) |
| templates | `ls -d templates/*/ \| wc -l` | **670** |
| absence greps (core/ + assets/) | `grep -rI` | `pkce` **0**, `code_challenge` **0**, `code_verifier` **0**, `redirect_uri` **0**, `dpop` **0**, `PRT` **0**, `primary_refresh` **0**, `session_key` **0**, `cf_bm` **0**, `TS01` **0**, `device_bound` **0**, `TokenBinding` **0** |
| near-absences | `grep -rI` | `passkey` / `webauthn` **1 each**, only `core/assets/intel.js:597` (`"WebAuthn": !!w.PublicKeyCredential` — a probe); `consent` / `authorize` **2 each**, only `core/forge.py:38,496,529` (keyword lists) |

Key code facts read this session:
- `core/devicecode.py:51` `PROVIDERS` (microsoft / google / okta / github / custom); `DeviceCodeFlow` (:132), `DeviceCodeManager` (:297), `serve()` (:427) with routes `/dc/<tag>` and `/__bh/dc/<tag>/status`; captured tokens kept **in memory** (`self.captured`, :307).
- `core/session.py:29` `new_record()` carries `"tokens": {}` but **no `"oauth"` block**; `grep add_oauth` = **none**. `BUILTIN_TASKS` (:467) already has `forward-submit` (:497), `password-change` (:514), `mfa-enroll` (:529), `sessions-kill` (:560); `validate_browser` (:264) drives real Chrome.
- `core/proxy.py:639` `complete_with_otp`, `:678` `note_tokens`, `:706` `maybe_complete`, `:534` `jar_to_dicts`, `:120` `pending_login`.
- `core/phishlet.py:178` `AuthToken`, `:391` `auth_tokens`, `:333/:486` `block_paths` (no `intercept`).
- `core/chains.py:32` six chains (`recon/inbox/takeover/lockout/own/full`).
- `core/rebind.py:130` `RebindPlan`, `:162` `RebindServer`. `core/telegram.py:74` `C2`, `:93` `register()`.

---

## 1. The frame that matters: authentication phishing → authorization phishing

The 2023–2024 AiTM model (Evilginx-class: relay the *login*, steal the session
cookie) is now the **mature, declining-value** half of the market. The 2026
frontier moves *after* authentication: **authorization phishing** — abusing
OAuth consent, device-code grants and token exchanges so MFA and even passkeys
are irrelevant because the victim authenticates correctly and the attacker
abuses the *authorization* decision that follows. *(Push Security, "How
authorization phishing attacks bypass MFA and passkeys" — CONFIRMED.)*

Consequences that drive every ranking below:
1. **Passkeys do not stop authorization phishing.** They protect the login, not
   the grant. A device-code or consent flow completes on the real IdP.
2. **The valuable artifact changed** from a session cookie (dies on password
   change / revocation / CAE) to a **refresh token** (90-day rolling on M365,
   survives password resets) and, at the top, a **PRT** (device-bound SSO).
3. **The commoditized tooling is PhaaS, not frameworks.** 2026 saw EvilTokens
   (Feb 2026; 12,000+ inboxes / 10,000+ orgs / 340+ orgs across 5 countries;
   disrupted by Microsoft DCU 2026-09-22; tracked **Storm-2992**), **Kali365**
   (FBI IC3 warning 2026-05-21), **ConsentFix v1→v3** (Push Security, Dec 2025 →
   v3 May 2026), Octopi365, FlowerStorm, Mirage2FA (LinX Coders). All CONFIRMED.

**Honest caveat on every "at scale" number below:** it is the vendor's count, not
independently reproduced here.

---

## 2. Technique-by-technique

Format per item: **(a)** mechanics · **(b)** defeats / cannot · **(c)** real-world
usage + public tooling · **(d)** BytePhisher today with proof · **(e)**
implementation here · **(f)** effort · **(g)** detection/ops risk.

---

### T1. Device-code relay at scale (RFC 8628) — *Storm-2372 / EvilTokens*
**Rank: 1 (already built; the vault write is the only gap).**

**(a)** Attacker starts a real device-authorization grant with a public client,
gets a `user_code`, sends the victim to the **genuine** `microsoft.com/devicelogin`,
polls `/token`, receives access + refresh tokens. EvilTokens' innovation was
**dynamic code generation at click-time** (the 15-min clock starts when the
victim clicks, not when the mail is sent) plus AI-personalised lures.

**(b)** Defeats: MFA of every kind, passkeys, mail/URL scanners (the link *is*
microsoft.com). Cannot: **CA "block device code flow"**, **"require compliant
device"** (device-code inherently cannot supply device state — Microsoft docs
state the grant control is unsupported for it), and tenant device-code
hardening. Session is protocol-tracked (`originalTransferMethod: deviceCodeFlow`)
and persists across refreshes.

**(c)** Public tooling: `TokenTacticsV2` (PowerShell), `roadtx` (ROADtools),
`GraphRunner`; PhaaS: EvilTokens/Kali365/Octopi365. Evilginx itself has **no**
device-code mode (CONFIRMED — help.evilginx.com).

**(d) BytePhisher: HAS the whole flow.** `core/devicecode.py` (`PROVIDERS` :51,
`DeviceCodeFlow` :132, `serve()` :427), 28 tests, live-probed MS/Google
endpoints. **Gap:** tokens are in-memory only (`self.captured` :307); no vault
write — `add_oauth` is absent, `new_record` has no `oauth` block. So a restart
loses the token.

**(e)** `core/session.py`: add `oauth` block to `new_record` and an `add_oauth(rec,
tokens)` that writes `{provider, client_id, refresh_token, access_token,
expires_at, token_type, dpop:false, obtained_at}`; call it from the
`on_token` callback in `bytephisher.py:1124+` and `core/devicecode.py:343`.
Add a Telegram `/dc <sid>` re-poll command (`core/telegram.py` `register`) and an
`alerts` type.

**(f)** 1–2 days. **(g)** Low. Detection is entirely IdP-side; nothing to remove.

---

### T2. OAuth consent / illicit consent grant + authorization-code relay with PKCE
**Rank: 2 (highest-value *missing* capability).**

**(a)** Two variants. (1) *Illicit consent grant*: register an app with delegated
scopes (`Mail.Read`, `offline_access`, `Files.ReadWrite`), phish the victim to
the real consent screen; the app holds a refresh token that **survives password
change**. (2) *Code relay*: AiTM-proxy the real `/authorize` consent page, let the
code land on an attacker-registered `redirect_uri`, exchange it (PKCE) inside the
victim's session.

**(b)** Defeats: MFA, passkeys, and (for the app-grant variant) password resets.
Cannot: tenant that **disables user consent / requires admin approval**; needs an
**attacker-owned app registration** (an operational artifact that is itself
discoverable); the code variant needs the redirect URI to be registered and
allowed.

**(c)** Greatness/EvilTokens bundle consent abuse; ConsentFix targets
**first-party pre-approved apps** (see T3). Public open-source frameworks do
**not** do this cleanly — this is genuine whitespace.

**(d) BytePhisher: MISSING.** `grep pkce/code_challenge/code_verifier/redirect_uri`
= 0. Only keyword hints: `core/forge.py:38` (`"oauth","sso",…` in a field-name
hint list) and `:496,529` (`consent` in `STATIC_TOKEN_HINTS`). No `/authorize`
capture, no `/token` exchange, no PKCE.

**(e)** New `core/oauth.py`: `start_authorize(provider, client_id, redirect_uri,
scope, pkce=True)` → build `/authorize?...&code_challenge=…&code_challenge_method=S256`;
`capture_code(query)`; `exchange_code(code, code_verifier)` → `POST /token`; store
in the vault `oauth` block. Add an `OauthSpec` to `core/phishlet.py` and a
code-capture rule wired into `core/proxy.py:note_tokens`/`maybe_complete`.
Add a `graph-enum` `BUILTIN_TASK` in `core/session.py:467` to spend the token.

**(f)** 5–7 days. **(g)** Medium — the app registration is a durable IOC; Entra
"Consent to application" audit events are explicit. **PKCE does not help the
attacker** — it is the *defence* against code interception; the attacker must
satisfy it because they *start* the flow (they hold the verifier). Worth stating
plainly: the report phrase "relay with PKCE" means the attacker completes PKCE,
not defeats it.

---

### T3. ConsentFix-class: localhost-redirect code capture + session reuse
**Rank: 3 (the 2026 escalation; cheap and high-impact).**

**(a)** Targets the authorization-code grant against **pre-approved first-party
apps** (so user-consent restrictions don't apply). Combines ClickFix-style
clipboard injection with an app that uses a `http://localhost` redirect URI: the
victim pastes a localhost URL carrying the `code` into an attacker page, which
captures it. **v3 (May 2026) eliminates victim action almost entirely via session
reuse**: if the victim already has a live Entra browser session (near-universal
on a managed corporate device), the auth request completes **with no password
prompt and no MFA challenge**, and the code lands in the attacker's backend.
*(Push Security — CONFIRMED.)*

**(b)** Defeats: MFA, passkeys, and **"require compliant device"** (it rides the
already-satisfied session) and **"block device code flow"** (it's the code
grant, not device code). Cannot: Token Protection mitigates *some* ConsentFix
scenarios depending on scopes (in preview, app-limited); Microsoft locking down
reply URLs reduces the surface. There is **no single CA policy** that reliably
blocks all ConsentFix variants (Push Security — CONFIRMED).

**(c)** ConsentFix (APT29 late-2025 → criminal v3 2026). Not in open-source
frameworks.

**(d) BytePhisher: MISSING**, but it is *closest* of all the OAuth items: the AiTM
proxy already holds a live per-victim session (`core/proxy.py` cookie jar,
`jar_to_dicts` :534), and the chain runner can drive a real browser
(`validate_browser` :264). No code-capture, no localhost-redirect handling, no
session-reuse driver.

**(e)** In `core/oauth.py`, add a `localhost_capture` mode: an attacker page that
accepts a pasted `localhost` URL and extracts `?code=`; and a `session_reuse`
driver that (re)uses the vault's live Entra cookie jar to issue the auth request
server-side, so the grant completes against the existing session. Vault stores
the resulting refresh token via `add_oauth`.

**(f)** 4–6 days (reuses T2 plumbing). **(g)** Medium; browser-layer detection is
the only real visibility (network/EDR are blind to it).

---

### T4. Refresh-token replay + FOCI / scope-swap
**Rank: 4.**

**(a)** A stolen refresh token is exchanged for access tokens to any resource the
user+client may reach; **FOCI** (Family of Client IDs) lets a refresh token from
one first-party client be swapped to another (Outlook ↔ Graph ↔ Azure RM), which
is how a device-code token becomes mailbox + SharePoint + Azure access.

**(b)** Defeats: password resets, most MFA. Cannot: **CAE** (near-real-time
revocation), **Token Protection** (binds refresh token to the device TPM),
explicit `revokeSignInSessions`, and CA re-evaluation on redemption.

**(c)** TokenTactics/TokenTacticsV2 `Invoke-RefreshTo*` swap matrix; GraphRunner;
roadtx. Public and mature.

**(d) BytePhisher: PARTIAL.** It captures tokens (`note_tokens` :678,
`maybe_complete` :706) but has **no refresh-token store and no swap logic**
(`refresh_token` appears only inside `core/devicecode.py`'s own flow, 8×).
`session.validate_http` (:219) replays **cookies**, not refresh tokens.

**(e)** Extend the vault `oauth` block (T1/T2) and add `core/tokenops.py` with a
small client-id map (Azure CLI `04b07795-…`, AAD PowerShell `1b730954-…`, MS
Office `d3590ed6-…` — CONFIRMED from Elastic's PRT rule) and
`swap(refresh_token, target_client, target_resource)`.

**(f)** 2–3 days (after T1/T2). **(g)** Low; token-endpoint traffic is IdP-side.

---

### T5. Token-binding / DPoP realities + Microsoft Token Protection
**Rank: 5 (honesty feature — prevents overclaiming).**

**(a)** **DPoP** (RFC 9449) sender-constrains tokens to a client-held key: each
use needs a fresh proof JWT (`htm`,`htu`,`jti`,`iat`), and the access token
carries `cnf.jkt` (SHA-256 thumbprint). **Token Protection** is the Microsoft
equivalent for the *sign-in session*: a CA session control that only accepts
device-bound tokens (PRTs), enforced for Exchange/SharePoint/Teams (native) and
Azure RM (browser, preview); Windows GA, Apple preview. *(Microsoft Learn —
CONFIRMED.)*

**(b)** Defeats: bearer replay of a *stolen* token. **Cannot stop device-code /
consent theft** — there the attacker's own client legitimately obtained the token
*with its own key* and holds it. Also note the honest nuance: DPoP's strength is
only as strong as key storage — a key in browser IndexedDB/software is stealable;
TPM/Secure Enclave keys are not. A 2026 CVE (Spring Security DPoP replay,
CVE-2026-41707) shows DPoP implementations are themselves buggy.

**(c)** Tooling: `dpop-proof-of-possession` demo; roadtx has limited DPoP
support. Most kits fail silently against DPoP.

**(d) BytePhisher: MISSING** (`grep dpop` = 0, `device_bound` = 0). It assumes
bearer cookies everywhere.

**(e)** New `core/dpop.py`: EC P-256 keygen; mint a proof JWT per request when
BytePhisher's *own* client obtained the token; parse `cnf.jkt`/`typ: dpop+jwt` in
`note_tokens`; mark bound tokens and have `session.validate_*` return
`replayable:false` **with the reason** instead of failing silently.

**(f)** 3–4 days. **(g)** Low. This item's value is **not overclaiming** in the
engagement report.

---

### T6. Entra PRT theft & phantom-device registration (DRS) + Intune self-report
**Rank: 6 (the CA-bypass crown jewel).**

**(a)** Storm-2372 (from Feb 2025) used the **Microsoft Authentication Broker**
client ID so a phished refresh token could be exchanged for a **Device
Registration Service (DRS)** token, register an attacker-controlled device, and
request a **PRT** — device-bound SSO that survives password resets. The 2026
Cyderes/Howler Cell writeup ("One Password, No Device, Full Tenant", 2026-05-05)
productised the chain: from a **single password blocked by CA
(`AADSTS53003`)** → DRS token (DRS is **not covered by standard CA** unless
explicitly targeted) → `roadtx` device join (software RSA keypair, no TPM) →
PRT request signed by the phantom device key → `x-ms-RefreshTokenCredential`
cookie to `/authorize` → Graph access with `amr:[pwd,rsa]` + `deviceid` claims
that satisfy "joined/compliant device". Intune compliance was achieved on a
**Linux laptop with no TPM/BitLocker/Secure Boot** because missing attestation
was treated as **"not applicable"**, not non-compliant. *(Cyderes + Lyrie +
winadminhub — CONFIRMED.)*

**(b)** Defeats: **"require compliant device"**, **"require Hybrid Azure AD-joined
device"** (`SyncJoined` claim), and any CA that evaluates *claims* rather than
hardware. Cannot: **"require phishing-resistant MFA" authentication strength**
(rejects the factor at policy time), **TPM-attested device certificates at
registration** (the phantom device has a software key), **Health Attestation
Service**-validated compliance, and **Azure AD Connect Sync absent** (a
`SyncJoined` claim against a tenant with no on-prem sync is rejected). The
password-less variant fails for **passkey-only** users with no password fallback.

**(c)** Public tooling is **mature and open**: `roadtx` (roadtools — device
registration + PRT request/renew), `AADInternals` (`Join-AADIntDeviceToAzureAD`,
`Set-AADIntDeviceCompliant`, `Get-AADIntUserPRTToken`), `TokenTacticsV2`,
`GraphRunner`, `AzureHound`. The *productized* integration (password → phantom
device → PRT → Graph, with CA-posture reporting) is what PhishU ships; no
open-source **phishing framework** ships it.

**(d) BytePhisher: MISSING.** No device-registration, PRT, DRS, Intune or
`x-ms-RefreshTokenCredential` code anywhere (`PRT`/`primary_refresh` = 0). It
has the *inputs*: password capture (`core/session.py:add_credentials`),
a browser takeover (`validate_browser`), and chains (`core/chains.py:32`).

**(e)** New `core/entra_device.py`: RSA-2048 keygen → CSR → DRS enrollment
(`SyncJoined` type) → PRT request (JWT-bearer signed by the device key, cert in
the JWT header) → unwrap session key → exchange PRT for a Graph token. Gate it
behind a `phantom-device` `BUILTIN_TASK`/chain. Vault: a `device` block
(`{device_id, cert_pem, key_pem, prt, session_key, compliant}`). **Crucially,
report which CA policies fired (`AADSTS` codes) and whether the claim was
accepted** — honest per-engagement posture output.

**(f)** 6–9 days (DRS/PRT is fiddly; roadtx is the reference). **(g)** Medium;
new device registrations + `amr:[pwd,rsa]` from an unmanaged ASN are the
detections (Elastic ships a rule: "Entra ID OAuth PRT Issuance to Non-Managed
Device"). The phantom device is itself an IOC.

---

### T7. "Register our own MFA method" after a password capture
**Rank: 7 (a cheap win *if* the tenant left the gap).**

**(a)** With only a password, navigate to `mysignins.microsoft.com/security-info`
and add an attacker authenticator/phone; then satisfy MFA with it and take over.
The gap exists when the **"Register security information" CA user-action is not
protected**.

**(b)** Defeats: accounts with no registered MFA, or where the registration
action isn't gated. Cannot: a CA policy on **Register security information**
requiring MFA/authentication strength (the standard fix), Entra ID Protection
risk-blocking, and the **bootstrap catch-22** means tenants often *can't* fully
enforce without TAP — which is where the residual gap lives. Starting
2026-07-06 CA on Register-security-information also applies to Windows Hello /
macOS Platform SSO registration. *(decryptiondigest + Microsoft Learn —
CONFIRMED.)*

**(c)** No dedicated public tool; done with roadtx/AADInternals or a browser.

**(d) BytePhisher: PARTIAL.** `mfa-enroll` (`core/session.py:529`) and
`mfa-add` (:551) drive the *security page* in a browser, but there is no
password-only HTTP registration path and no CA-gap detection.

**(e)** Add a `security-info-enroll` task that runs the Graph/`security-info`
registration over the captured session, plus a pre-flight probe that reports
whether the action is CA-protected (record the `AADSTS` code).

**(f)** 2–3 days. **(g)** Medium — "User registered security info" audit events
are explicit and high-signal.

---

### T8. Conditional-access bypass patterns (2026 consolidated)
**Rank: 8 (this is a *routing* capability, not a single exploit).**

**(a)** The observable pattern set:
1. **Flow-not-covered**: CA must target each auth flow; **DRS / device-code**
   flows are the usual omissions (T6).
2. **Report-only**: 13 policies report-only in the Cyderes tenant; two would have
   broken the chain (CONFIRMED).
3. **Evaluation timing**: **authentication strength evaluates *after* initial
   auth** — a password is still accepted as first factor; the strength gates
   *resource* access, so it doesn't gate the registration/consent flow (T2/T7).
4. **Device claim forgery**: CA trusts `deviceid`/`amr` claims a phantom device
   can manufacture (T6).
5. **Session reuse**: ConsentFix completes inside an existing session, so no
   fresh CA evaluation (T3).

**(b)** Cannot: phishing-resistant authentication strength, TPM attestation,
HAS, CAE, enforced (not report-only) flow blocks.

**(d) BytePhisher: MISSING** as a concept, but it already *classifies* risk/device
(`core/classify.py`, `core/risk.py`) and gates (`core/gate.py`).

**(e)** Add a `ca_posture` recorder: log every `AADSTS`/error observed during a
capture and emit a per-tenant "which control fired" report; feed it into an
auto-router that picks device-code vs consent vs phantom-device. **(f)** 2–3 days.
**(g)** Low (defensive/reporting value).

---

### T9. Session-key theft — Cloudflare `__cf_bm` / `cf_clearance` / F5 `TS*`
**Rank: 9 (and an honest correction).**

**(a)** *Correction to the brief's framing:* `__cf_bm` is Cloudflare's **Bot
Management** cookie (30-min inactivity TTL, per-site, encrypted bot-score +
optional session id) — **not** an auth session key. `cf_clearance` is the
**challenge-passed** cookie. `TSxxxx` cookies are **F5 BIG-IP ASM** session
tracking, not Cloudflare. What is actually replayable-and-valuable is
`cf_clearance`: it lets an attacker skip the interstitial *if* they replay the
**exact** User-Agent + IP + TLS/header order that earned it — moving it to a
different machine/exit is rejected. *(Cloudflare docs + roundproxies —
CONFIRMED.)*

**(b)** Defeats: bot gates / interstitials (so the attacker can reach the real
app behind Cloudflare). Cannot: it is not an identity — it grants *edge
clearance*, not an account. Replay is bound to UA/IP/fingerprint.

**(c)** Tooling: FlareSolverr/Byparr, `nodriver`, Camoufox (all public).

**(d) BytePhisher: MISSING.** No `cf_bm`/`cf_clearance`/`TS` handling. Its
`core/tls_fp.py` is JA3-only.

**(e)** Add `cf_clearance`/`__cf_bm` capture to the cookie jar and a
"replay-with-bound-fingerprint" path (pin UA + JA3 + egress IP when replaying a
clearance cookie). **(f)** 2–3 days. **(g)** Low; but note the honest limit — it
is a *clearance* artifact, not a session.

---

### T10. Cloud-console session hijacking (AWS / Azure / GCP web sessions)
**Rank: 10.**

**(a)** Real 2026 campaigns: **AWS console AiTM kits** (Datadog: Feb 2026 cluster
`signin.aws.cloud-recovery[.]net` + June 2026 "input_24" React kit, PoisonSeed
lineage) clone the console login and relay **email/SMS/TOTP** second factors; the
`input_24` kit gates rendering on an encrypted `input_24` param (sandbox-evading)
and **asks whether the user is root or IAM**, branching `/email|/sms|/gauth`.
Operator console access observed **20 min** after capture from a Mullvad exit.
The kit copies the real `client_id=arn:aws:signin:::console/canvas` +
`code_challenge=SHA-256` PKCE params to look genuine. *(Datadog + Threadlinqs +
TRUV.IS — CONFIRMED.)*

**(b)** Defeats: phishable MFA on console logins. Cannot: **FIDO2/passkeys for
root and IAM** (not relayable), CloudTrail impossible-travel detection (the
replay itself is the tell), and the fact that console **session cookies** are
short-lived (access keys remain the bigger AWS target).

**(c)** Kit "input_24" (PoisonSeed lineage). Azure console sessions are covered
by T6/T7; GCP is thinner in public reporting.

**(d) BytePhisher: MISSING** for the cloud-console *flow*, though the AiTM engine
is generic and could be pointed at it with a phishlet.

**(e)** A `templates/aws-console/` phishlet + a console-session vault block; reuse
`complete_with_otp` for the MFA-type branch. **(f)** 3–4 days. **(g)** Medium.

---

### T11. Browser-in-the-browser (BitB) — 2026 state
**Rank: 11 (low ROI; report-only).**

**(a)** A DOM-rendered fake browser popup with a fake address bar, used for
**credential phishing only** (no token theft). 2026 variants add QR (BiTB). It is
"on the rise" in commodity campaigns *(Help Net Security 2026-01-13; arXiv
2505.18944 — CONFIRMED)*.

**(b)** Defeats: a user who trusts a "popup window". Cannot: defeat a real
reverse proxy (which already has a real domain and a real address bar) — it is a
static-template trick. Against BytePhisher's AiTM it adds nothing.

**(d) BytePhisher: MISSING** (`grep` = 0). **(e)** Optional template. **(f)** 1
day. **(g)** Low value — **drop or template-only**, consistent with the repo's own
SOTA_GAP_ANALYSIS Part E.

---

### T12. Cookie theft from browser profiles + pass-the-cookie vs device-bound
**Rank: 12.**

**(a)** Infostealers harvest the browser cookie DB directly. 2026 shift:
**server-side decryption** (Storm infostealer, Apr 2026) ships encrypted files to
the operator's server, and the panel **auto-restores the session** with a
geo-matched SOCKS5 proxy — session hijack as a service. Scale claim: a single
infection yields ~44 passwords but ~**1,861 cookies**; ~**8.6B** stolen session
cookies in circulation; **BigBear 2.0** (June 2026) runs M365 session-hijack at
scale. *(BleepingComputer + tech-insider + CloudSEK — CONFIRMED, vendor counts.)*

**(b)** The defender response is **device-binding**: **DBSC** (Chrome 145/146
Windows, Mar/Apr 2026; macOS pending) binds the session to a TPM/Secure-Enclave
key and rotates short-lived cookies; a stolen cookie without the key expires.
**Cannot defeat: the device it was issued to.** The 2026 bypass is **CDP session
hijacking** (SpecterOps "CDP-Enable-BOF", DeathFlamingo Dec 2025; CSA note Aug
2026): drive the victim's *own* authenticated browser over the DevTools protocol
and never extract the key — the browser *is* the credential, so DBSC's guarantee
holds trivially and is bypassed. *(Google/Chrome + CSA — CONFIRMED.)*

**(c)** Tooling: Lumma/RedLine/Vidar/Rhadamanthys/Storm stealers; CDP-Enable-BOF;
EvilnoVNC for the same "use the real browser" idea.

**(d) BytePhisher: PARTIAL.** It exports/replays cookies
(`session.to_cookie_editor` :158, `validate_http` :219, `validate_browser` :264)
and drives real Chrome — i.e. it already has the **CDP/local-browser** primitive
that beats DBSC. It has **no DBSC/device-bound awareness** and no CDP-hijack
path.

**(e)** Add a `dbsc` marker to the vault (detect `Secure-Session-Registration`
headers / refresh behaviour) and prefer the **local-browser takeover** path over
cookie replay when DBSC is present — reporting honestly when a session is
non-replayable. **(f)** 2–3 days. **(g)** Low; browser-side is where detection
lives.

---

### T13. Passkeys / WebAuthn under a relay
**Rank: 13 (the technique everyone cites and few can actually land).**

**(a)** WebAuthn binds the credential to the **RP ID** (registrable domain) and
signs origin+challenge. A proxy at `evil.com` **cannot** call
`navigator.credentials.get({rpId:'real.com'})` — the browser rejects an RP ID
that isn't a suffix of the origin. So a plain AiTM proxy **breaks passkeys**.
What remains:
1. **Downgrade** to a password path if the site offers one.
2. **Hybrid (caBLE) relay** — force the real page into cross-device mode, relay
   the QR to the victim, victim approves on their phone. The BSides-Munich 2026
   analysis (inovex) shows the attacker can **request the RP's options, strip the
   hybrid-transport limitation, and relay the QR**; but the response's
   attachment/transport fields are unsigned and manipulable, and the
   cryptographic tunnel is derived from the QR secret.
3. **Session-hijack then enroll** an attacker passkey from a live session.
4. **Deployment bugs** — "The State of Passkeys" (USENIX Sec 2026, Jannett et
   al.) found 15 WebAuthn attack types on 18/103 sites.

**(b) The honest limit is the headline.** The famous PoisonSeed "FIDO bypass" was
**retracted by Expel**: the user's credentials and a QR *were* obtained, but **all
subsequent MFA challenges failed** — hybrid transport **requires local proximity**
(BLE) to the client that generated the QR, and without it the ceremony times out.
So the relay **cannot** beat: a **plugged-in hardware key** (no hybrid transport),
a **platform authenticator bound to the browser/OS context**, an RP enforcing
**BLE proximity**, or **"require phishing-resistant MFA"** in CA. *(Expel
retraction + The Hacker News — CONFIRMED; inovex BSides Munich 2026 — CONFIRMED.)*

**(c)** PoisonSeed (retracted), EvilnoVNC (sidesteps passkeys with a real
browser), `webauthn-authenticator-rs` cable module, `roadtx` has a WebAuthn
client. **Nothing open-source does the enroll path cleanly.**

**(d) BytePhisher: MISSING.** Only the probe `core/assets/intel.js:597`
(`!!w.PublicKeyCredential`). Its `mfa-enroll` task (`core/session.py:529`) is the
TOTP/SMS analogue — the enroll *pattern* exists, not for passkeys.

**(e)** `core/webauthn.py`: (i) detect (extend `intel.js` + `core/intel.py`);
(ii) **enroll** via CDP `WebAuthn.addVirtualAuthenticator` (Playwright already
launched in `_launch` :418) from a captured session; (iii) hybrid relay that
drives the real login to cross-device mode, extracts the caBLE QR (canvas→PNG),
serves it through a proxy route, and captures the resulting session. **(f)** 6–9
days. **(g)** High complexity; passkey ceremonies and credential enrolment are
audited. Report the retraction reality — the relay usually *fails* against
proximity-enforcing authenticators.

---

## 3. Top-6 ordered build list

Ordered by *(strategic value × feasibility) ÷ effort*, on top of what already
exists. Each row's proof/limit is in the corresponding T-section above.

1. **Device-code vault write + Telegram re-poll** (T1) — *1–2 days.* Closes the
   one hole in an already-shipped, live-verified flow. Highest ROI in the repo.
2. **OAuth consent / auth-code relay with PKCE + vault `oauth` block** (T2) —
   *5–7 days.* The other half of the M365/Google target set; genuine open-source
   whitespace; the vault block also unblocks T3/T4.
3. **ConsentFix-class session-reuse code capture** (T3) — *4–6 days.* Rides the
   live session to defeat "compliant device" and "block device-code"; no CA policy
   reliably stops it.
4. **PRT / phantom-device chain + CA-posture reporting** (T6 + T8) — *6–9 days.*
   The CA-bypass crown jewel; inputs already exist; report which control fired.
5. **Refresh-token store + FOCI/scope-swap** (T4) — *2–3 days* after #2. Turns a
   captured token into mailbox + SharePoint + Azure RM reach.
6. **DBSC/device-bound awareness + prefer local-browser (CDP) takeover** (T12) —
   *2–3 days.* The 2026-correct answer to device-bound sessions; also keeps the
   tool honest about non-replayable sessions.

*Explicit non-goals (do not build):* BitB popup (T11, template-only), reverse
tabnabbing (dead — implicit `rel=noopener`), TLS Token Binding (undeployed), and
"DPoP as a bypass" (it isn't — build T5 as an *honesty* feature, not a bypass).

---

## 4. Three candidate-novel ideas (built from BytePhisher primitives)

> **Novelty caveat, stated first:** "unpublished anywhere" is not something I can
> prove by search. Each idea below is a combination of primitives this tool
> already has (`core/devicecode.py`, the AiTM session/`core/proxy.py`, the vault
> `core/session.py`, `core/chains.py`, `core/rebind.py`, `core/telegram.py`). I
> list the adjacent published work and why the combination is, to my knowledge,
> not productized. Verify before claiming novelty.

### INV-1 — "Consentless device grant": fuse the device-code relay with the AiTM proxy
**Primitives:** `core/devicecode.py` + `core/proxy.py`.
**Mechanic.** Public kits split into two camps: EvilTokens/black-queen do
device-code **without** a proxy (the genuine `microsoft.com/devicelogin` URL is
the point, but it is also the detection signal and the thing CA blocks); Evilginx
proxies **without** device-code. Fuse them: the AiTM proxy serves the device-login
page, relays the victim's code entry to the **real** `/devicelogin` *inside the
proxied session*, and — because the poller is BytePhisher's — receives the
refresh token, **while simultaneously capturing the resulting ESTSAUTH session
cookie**. One flow, two artifacts (session + refresh token), and the victim never
sees a `microsoftonline.com` address bar.
**Defeats:** the "look at the URL" advice and URL scanners (they see our domain);
yields a refresh token that survives password reset *and* a live cookie jar.
**Honest limit (the important part):** this **trades the device-code advantage
for the proxy's disadvantages** — it reintroduces a lookalike domain, and the
grant still originates from an unmanaged client, so **CA "block device code
flow" and "require compliant device" still win**, and proxying `/devicelogin`
may break its anti-framing/integrity checks. It is a *detection-surface trade*,
not a bypass. The honest framing in a report is: "widens the capture to two
artifacts at the cost of the genuine-URL property."
**Effort:** 4–6 days. **Ops risk:** medium (our domain becomes the visible one).

### INV-2 — "Token laundering on capture": auto-upgrade an AiTM session into a surviving grant
**Primitives:** the AiTM capture (`core/proxy.py:maybe_complete` :706) + a
browser takeover (`validate_browser` :264) + `core/oauth.py`/`core/devicecode.py`
+ the vault.
**Mechanic.** A captured session cookie is fragile (dies on password change,
`revokeSignInSessions`, CAE). On the *capture event*, BytePhisher immediately
loads the fresh cookie jar into a background browser and silently runs a
**FOCI authorization-code (or device-code) exchange** for an
attacker-registered client — laundering the ephemeral session into a **90-day
refresh token bound to our client**, stored in the vault. The chain runner then
*prefers* the refresh token over the cookie.
**Defeats:** password-reset remediation and session revocation — the refresh
token outlives them (until CAE/Token Protection).
**Adjacent published work:** ConsentFix v3 does *session reuse* to get a code, but
user/clipboard-driven and not vault-integrated; this is **operator-automated and
artifact-managed**. That is the novel part — the *automation and the artifact
model*, not the protocol.
**Honest limit:** needs an attacker app registration and the client's consent
(FOCI restrictions apply); **CAE** and **Token Protection** kill it; if the
session is passkey-only with no fallback, the silent exchange has no factor to
complete with. On a hard tenant this produces a *reported refusal*, not a token.
**Effort:** 3–5 days (on top of T2). **Ops risk:** low; the exchange is
server-side and IdP-visible only in token logs.

### INV-3 — "Localhost-first phishing": rebind + local-service library + Telegram C2 as a no-lookalike-domain pivot
**Primitives:** `core/rebind.py` (`RebindServer` :162), the 17-service exploit
library (`core/exploits.py`), the vault, and `core/telegram.py` (`C2` :74).
**Mechanic.** Instead of a lookalike domain, deliver a lure that resolves (via DNS
rebinding) to the victim's **own** network: the victim's browser — on the
corporate network, with the corporate session — is turned against **internal /
localhost services** (`127.0.0.1` and RFC1918 targets) using the existing exploit
library, and any harvested session/token is written to the vault and exfiltrated
over the **existing Telegram C2** rather than an HTTP callback. The address bar
shows *our* benign-looking domain the whole time; the payload is "the victim's
browser attacking the victim's own perimeter."
**Defeats:** external-domain reputation scoring, mail-gateway URL rewriting and
the "never enter creds on a lookalike" heuristic — because there is no lookalike
login page at all.
**Adjacent published work:** DNS-rebinding is old (Singularity/`rebind.network`);
local-service exploitation is old; the *combination with a per-victim vault +
C2-as-exfil* and the "no external auth page" framing is, to my knowledge, not
packaged in an open framework.
**Honest limit:** rebinding is increasingly blocked — **DNS pinning**, browser
**DoH**, and **Private Network Access** preflights; and few internal services are
auth-bearing web consoles worth stealing. Realistic yield is low against modern
browsers; it is a *research direction*, not a reliable path.
**Effort:** 3–4 days (plumbing mostly exists). **Ops risk:** low external
footprint; the rebind responder is the only new artifact.

---

## 5. Honest limits that matter more than the marketing

| Technique | What it genuinely cannot do |
|---|---|
| Device-code (T1) | Dies to "block device code flow" / "require compliant device"; token is client-scoped; approval is visible to the victim. |
| Consent / code relay (T2) | Dies to disabled user consent / admin-approval-required; needs an attacker app registration (a durable IOC). PKCE is the *defence*, not a bypass. |
| ConsentFix-class (T3) | Token Protection mitigates some cases; no single CA policy blocks all variants; needs a live session. |
| Refresh-token swap (T4) | CAE, Token Protection, `revokeSignInSessions`. |
| DPoP / Token Protection (T5) | **Does not stop device-code/consent theft** (attacker holds the key); only stops bearer replay. |
| PRT / phantom device (T6) | Dies to phishing-resistant authentication strength, TPM-attested device certs, HAS-validated compliance, and a tenant with no AD Connect Sync. Needs a password (not passkey-only). |
| Register-own-MFA (T7) | Dies to a CA policy on "Register security information"; audited loudly. |
| CA bypass patterns (T8) | All defeated by *enforced* (not report-only) flow blocks + phishing-resistant MFA + attestation. |
| `cf_clearance` replay (T9) | It is edge clearance, not an identity; bound to UA/IP/fingerprint. |
| Cloud-console AiTM (T10) | Dies to FIDO2/passkeys on the console; the replay itself is the CloudTrail tell. |
| BitB (T11) | Credential-only; adds nothing over a real proxy domain. |
| Cookie theft (T12) | DBSC kills cross-device replay — but **CDP on the victim's own browser bypasses DBSC entirely**; DBSC only raises the cost of *export + replay*. |
| Passkey relay (T13) | **The headline: PoisonSeed's FIDO bypass was retracted — the ceremony failed.** Dies to plugged-in hardware keys, browser/OS-bound platform authenticators, and enforced BLE proximity. |
| INV-1 | Trades the genuine-URL advantage for a lookalike domain; CA still wins. |
| INV-2 | Needs an app registration + consent; CAE/Token Protection kill it; fails on passkey-only users. |
| INV-3 | DNS pinning, DoH and Private Network Access block rebinding; low realistic yield. |

---

## 6. Primary sources consulted (2026)

- Microsoft Security / Entra: PRT concept, Token Protection, CA "Register
  security information", device-code hardening, CA authentication-flow condition,
  Storm-2372 (2025-02-13) and the AI-enabled device-code campaign (2026-04-06).
- Cyderes Howler Cell — "One Password, No Device, Full Tenant" (2026-05-05);
  Lyrie + winadminhub breakdowns.
- Push Security — "How authorization phishing attacks bypass MFA and passkeys"
  (ConsentFix v1→v3).
- Cloud Security Alliance research notes: device-code surge (2026-04-05), consent
  phishing / EvilTokens (2026-05-21), CDP session hijacking vs DBSC (2026-08-17).
- Datadog Security Labs — AWS console AiTM kits (Feb + June 2026); Threadlinqs
  TL-2026-0935 (input_24 / PoisonSeed lineage); TRUV.IS TT-20261001-63.
- Expel — PoisonSeed FIDO-bypass **retraction**; The Hacker News follow-up.
- inovex / BSides Munich 2026 — "Phishing for Passkeys" (hybrid-transport relay);
  USENIX Security 2026 — "The State of Passkeys" (PASSKEYS-ATTACKER).
- Google/Chrome — DBSC GA (Chrome 145/146 Windows, 2026); W3C DBSC spec.
- BleepingComputer / cyberinsider — Storm infostealer server-side cookie restore
  (2026-04-13); BigBear 2.0 (CloudSEK, 2026-06).
- Cloudflare docs — `__cf_bm` / `cf_clearance`; roundproxies `cf_clearance` replay
  binding (2026).
- ROADtools `roadtx` / AADInternals / TokenTacticsV2 / GraphRunner; Elastic PRT
  detection rule; Unit 42 "ROADtools and Nation-State Tactics".
- Evilginx Pro (help.evilginx.com) — Phishlets 2.0, intercept, Evilpuppet; Lexfo
  misconfigured-server analysis (2026-04).

*BytePhisher-internal: `docs/ROADMAP.md`, `docs/SOTA_GAP_ANALYSIS.md`,
`docs/DEVICECODE.md`, and the greps/file reads in §0.*

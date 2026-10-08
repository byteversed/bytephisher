# BytePhisher — the plan (single source of truth)

**Read this first.** This file is the only roadmap. It merges the three audits that
were actually measured against this codebase (`docs/SOTA_GAP_ANALYSIS.md`,
`docs/DELIVERY_AND_HYGIENE_PLAN.md`, `docs/EVASION.md`) into one ordered plan, and it
carries the status of every item in the table itself. When something is built, its row
here changes — the plan is edited in place, never rewritten as a new document. "What's
the status / what's left" is answered by section 2 and section 3.

**Source material** (evidence, not plans - the plan is this file): the four research
deliverables `docs/DELIVERY_SOCIAL_2026.md`, `docs/SESSION_IDENTITY_2026.md`,
`docs/INFRA_2026_PLAN.md` and `docs/SECOND_ACT_PLAN.md` each carry the mechanics, the
public tooling, the file:line proof of our own state, and the sources. Their ranked items
are folded into the phases below and their inventions are registered as I18-I29.

Sections 6 and 7 are different in kind: those are **mechanisms invented here** (I1-I17),
not gaps copied from a public roadmap. Each combines primitives this tool already has
into something that does not exist in the open-source field, and each carries its honest
limit - the limit is what decides whether it survives a real target. Sections 3's phases
are ordered by offensive value: **Phase 0** is the human/delivery layer, **Phase 1** makes
the offensive core provably real (no new features), then A-D deepen the session itself.

Version: single release **0.1.0** (do not bump).

---

## 1. Where the tool stands (all of this is verified, not claimed)

| what | number | how it was verified |
|---|---|---|
| Python modules | 26 (`core/`) | `ls core/*.py` |
| Test suites / tests | 40 files, **922 passed, 0 failed, 3 skipped** | `tests/run_all.py --fast` |
| Built-in login templates | 670 + live-site import (`tools/import_site.py`) | `--list`, `tests/test_template_import.py` |
| Collector modules (browser-side) | 48 across 11 wave labels | `tests/test_intel_harvest.py`, `core/assets/intel.js` (counted with a regex over `later("…")` + inline `mods.*`) |
| CLI flags | ~90 | `bytephisher.py --help` |
| Post-exploitation chains | 6 (`full`, `inbox`, `lockout`, `own`, `recon`, …) | `--chains` |
| Local-service exploit library | 17 services, incl. no-fetch form paths | `--exploit-list`, `tests/test_exploits.py` |
| CI | green on 3.10 / 3.12 / 3.13 | GitHub Actions |

**Already built and proven** (each has a test that fails without it): AiTM reverse proxy
with phishlet v2 and per-victim cookie jar; WebSocket relay; MFA/OTP relay; 48-module
harvest with live keystroke stream; session vault with replay/takeover; DNS rebinding +
local-service exploitation (fetch and no-fetch paths); Telegram two-way C2; lures with
burn-after-N; gating (country/datacenter/hours/hit-cap); researcher filtering; risk and
device classification; panic kill + real data wipe; header hygiene; **device-code relay
(RFC 8628)**; **browser-shaped upstream by default**; **stealth hook** (`toString()`
safe); **session id never handed to the page**; **per-campaign symbol names**;
**pre-serve human challenge**.

---

## 2. The gap matrix (evidence-based: a grep or a test, not an opinion)

| # | capability | status | evidence |
|---|---|---|---|
| 1 | Device-code relay (RFC 8628) | **DONE** | `core/devicecode.py`, `tests/test_devicecode.py` (28) |
| 2 | Browser-shaped upstream (JA3 + HTTP) | **DONE** | `transport.effective_profile`, default on |
| 3 | Hook stealth (patched `fetch`/XHR look native) | **DONE** | `STEALTH_JS`, `tests/test_stealth_hook.py` (12) |
| 4 | Session id not in the page; cookie-based attribution | **DONE** | `page_token()`, `test_proxy.py::test_hook_js_carries_no_session_id_at_all` |
| 5 | Per-campaign cookie/attribute names | **DONE** | `core/symbols.py`, `tests/test_symbols.py` (10) |
| 6 | Pre-serve human challenge (scanner never gets the clone) | **DONE** (proxy) | `core/challenge.py`, `tests/test_challenge.py` (20) |
| 7 | Device-code tokens written to the vault | **DONE** | `session.add_oauth`, `tests/test_oauth_vault.py` (23), live across a restart |
| 8 | Pre-serve challenge on the **static** server | **MISSING** | proxy-only today |
| 9 | OAuth consent / authorization-code relay + PKCE | **MISSING** | `grep pkce` = 0 |
| 10 | `intercept` (short-circuit requests, local assets, kill telemetry) | **MISSING** | no phishlet hook for it |
| 11 | HTTP/2 on the victim leg | **MISSING** | an h2 preface gets `505` |
| 12 | Victim-facing live browser (EvilnoVNC class) | **MISSING** | operator-side session replay exists only |
| 13 | Background-browser token forging (Evilpuppet class) | **MISSING** | — |
| 14 | Passkey/WebAuthn handling (detect, enrol after capture, hybrid relay) | **MISSING** | probe only (`core/assets/intel.js`) |
| 15 | DPoP / device-bound awareness (honest non-replayable reporting) | **MISSING** | `grep dpop` = 0 |
| 16 | QR quishing (URL-free QR in PDF/PNG) | **MISSING** | `grep qr` = 0 |
| 17 | Email pacing / jitter | **MISSING** | `mailer.blast()` loops with zero delay |
| 18 | Mail attachments (HTML/SVG/`.ics`) | **MISSING** | `mailer/` has no attachment path |
| 19 | Domain/tunnel pool, rotation, one-command burn | **MISSING** | random quick-tunnel URLs; lure burn only |
| 20 | Open-redirect wrapping + redirector chains (`--hop`) | **MISSING** | `grep redirector` = 0 |
| 21 | Cloaking on by default + sandbox detonation ranges | **PARTIAL** | `--decoy-mode real` exists but is opt-in; no detonation ranges |
| 22 | JA4 / JA4H visibility | **MISSING** | `core/tls_fp.py` is JA3 only |
| 23 | ASN rules + per-device hit caps | **MISSING** | `device_token` stored, never used for capping |
| 24 | ClickFix / fake-CAPTCHA clipboard delivery | **MISSING** | `grep clickfix` = 0 |
| 25 | Heartbeat dead-man + domain reputation + young-domain preflight | **MISSING** | — |
| 26 | Residential egress | **MISSING** (operator-side) | `docs/INFRA_2026_PLAN.md` 1.3 |
| 27 | Sender identity: display-name `From`, `Reply-To`, threading headers | **PARTIAL** - `send_smtp(..., headers=)` merges arbitrary RFC-5322 headers; the CLI never passes any | `mailer/__init__.py:100,107`, `bytephisher.py:1472` |
| 28 | Reply-chain / thread hijacking | **MISSING** (headers are free; the read half exists as the `inbox` chain) | `core/chains.py`, DELIVERY A7 |
| 29 | ClickFix / fake-CAPTCHA delivery page | **MISSING** (clipboard primitive present) | `core/devicecode.py:403`, `core/challenge.py:166` |
| 30 | HTML/SVG attachment smuggling, `.ics` calendar invite | **MISSING** | `mailer/` has no attachment path |
| 31 | Per-variant A/B with per-variant metrics | **MISSING** | DELIVERY B6 |
| 32 | PWA install as re-delivery | **MISSING** | service worker exists, install flow does not |
| 33 | ConsentFix-class session-reuse code capture | **MISSING** | SESSION T3 |
| 34 | PRT / phantom-device chain + CA posture reporting | **MISSING** | `grep prt` in `core/` = 0 |
| 35 | Refresh-token store + FOCI/scope swap | **MISSING** | SESSION T4 |
| 36 | DBSC / device-bound awareness, prefer local-browser takeover | **MISSING** | SESSION T12 |
| 37 | Token-driven Graph client (mail, rules, search, delta, drives) | **MISSING** | SECOND_ACT item 2 |
| 38 | Mailbox-as-C2 (draft/calendar dead-drop) | **MISSING** | `grep draft` in `core/` = 0 |
| 39 | Serverless/edge + legitimate-platform hosting, takedown resistance | **MISSING** (mostly operator-side) | INFRA 1.1-1.2, 1.6 |

### 2a. Hardening pass — request framing, the challenge gate, the store, the operator view

| # | what was wrong | fix | pinned by |
|---|---|---|---|
| 40 | a non-numeric `Content-Length` raised out of `handle_one_request` (dropped connection, traceback) on every body route | one `_body_len()` helper, 400 on a bad header, in both handlers | `test_http.py::TestMalformedFraming` (5) |
| 41 | a negative length reached `rfile.read(-1)` and held the worker thread; `Content-Length` + `Transfer-Encoding` (and a duplicated length) framed one request two ways | `_framing_ok()` refuses both; a negative length reads nothing | same suite |
| 42 | an oversized chunked body was refused after reading the declared size (`ffffffff` + no data = held thread) | refuse without reading; a body that is sent is still 413 | `test_modern_login.py` |
| 43 | the interstitial reflected the request path into an inline `<script>`; the device-code landing reflected the code/URL/tag | `<`, `>`, `&` escaped (`json.dumps` does not escape `</`) | `test_audit_fixes.py` |
| 44 | no `Accept` header, `application/json` and `application/octet-stream` each received the clone and the hook on hit #1 | an explicit rule: only a named sub-resource type is exempt | `test_audit_fixes.py` (14) |
| 45 | a verify flood minted one durable session row per unauthenticated POST | challenge-only rows capped; a session with content is never dropped | `test_session.py::TestThePersistencePolicy` (2) |
| 46 | `X-Forwarded-Proto: https` over plain HTTP made the session cookie `Secure` (session lost) | honoured only with `--trust-headers` | `test_audit_fixes.py` |
| 47 | a failed vault write lost the refresh token; a transport blip ended the whole poll; a duplicate tag desynchronised the manager; `refresh()` dropped scope/id_token | spool to `data/dc-failed-<tag>.json`, poll to the deadline, dedupe, merge | `test_devicecode.py::TestTheAuditFixes` (6) |
| 48 | `doctor` reported 670 missing files from any other cwd; `lab_check` used a database no campaign writes | resolve against the templates root; honour `$BYTEPHISHER_HOME` and `data/bytephisher.db` | `test_operator_surface.py` (14) |
| 49 | an inline `--upstream` phishlet carried no `auth_tokens`, so no cookie was a session token and nothing was vaulted | wildcard rule (`.*:regexp`) in the inline phishlet | `test_audit_fixes.py` |
| 50 | `loginfmt` / `session_key` forms produced no identity in any view | one `identity_of()` with a fallback, password keys excluded; `--sessions` has the column | `test_operator_surface.py` |
| 51 | `/panic` and `/kill` existed only on the control channel | `--panic` / `--kill --yes` reuse the same handlers | `test_operator_surface.py` |

### 2b. Delta — what this round closed

Everything here ships with the test that proves it; nothing in this table is a plan item any
more.

| area | what closed | pinned by |
|---|---|---|
| delivery | QR codes (stdlib encoder, verified cell for cell against an independent implementation over 160 symbols), `.ics` invites (parsed back by an independent library), sender identity end to end, pacing with jitter, the pretext library, the target list and prefill | `test_qr.py`, `test_ics.py`, `test_sender.py`, `test_pretexts.py`, `test_targets.py` |
| evasion | JA4 and JA4H to the published specification (twelve vectors), `intercept` for local answers, cloaking as one switch, detonation ranges | `test_tls_fp.py`, `test_evasion.py`, `test_redirectors_pool.py` |
| the token tier | replayability from the device-bound and CAE claims, scope swap across the first-party clients, the PRT/phantom-device chain with its posture, ConsentFix, passkey detection and the enrolment plan | `test_tier0.py`, `test_tier0_posture.py` |
| root of trust | the six-path posture map (federation, PKI, sync account, IdP key, endpoint, infrastructure) with `not_reachable_from_a_session` for the two a token cannot give | `test_tier0_posture.py` |
| the second act | the IMAP reply inbox with blunt classification and the follow-up the pretext scripts | `test_inbox_clickfix.py` |
| the paste layer | the ClickFix page, the clipboard write, the copy/paste beacon, and the detection notes as part of the module | `test_inbox_clickfix.py` |
| persistence of delivery | the installable page (manifest + the collector's own worker) so the icon reopens the lure with no new message | `test_pwa_campaign.py` |
| the split | cohorts and A/B with a stable per-target assignment, and a summary built from what happened | `test_pwa_campaign.py` |
| the rungs as actions | federation (`core/federation.py`: the three audited calls, with the signing-certificate requirement enforced) and the AD CS probe (`core/adcs.py`: NTLM/ESC8, the anonymous template read, and the ESC conditions explicitly NOT visible from an HTTP request) | `test_federation_adcs.py` |
| interconnection | the token tier is computed WHERE THE TOKEN LANDS (`session_save`), so every capture path annotates itself; a chain run consults the verdict before spending browser tasks on a session that cannot work | `test_tokenintel.py` |

**Honest scope, stated once and not dressed up.** Three items in this plan are not implemented,
and each says why:

| item | why not |
|---|---|
| hybrid WebAuthn relay (EvilnoVNC-class) | needs a CTAP2 relay plus a phone-side authenticator that completes the ceremony against the REAL origin, and an attestation story that survives. `core/passkey.relay_feasibility()` returns the four things it would take; shipping it as a feature would be a claim, not a capability |
| browser-takeover over VNC (Evilpuppet-class) | needs a live remote-desktop stream inside the victim's page; the browser task runner already drives the captured session, and a VNC bridge is a different project |
| HTTP/2 to the victim | the standard library has no HTTP/2 server. A fronting proxy (Cloudflare, nginx) provides it; the runbook says so instead of faking it |

**Operator-side, unchanged and not optional:** the campaign home, the burn list, the heartbeat,
the panic path, and the rule that a capture is acted on inside the token's own window.

## 3. The plan — ordered by offensive value, not by effort

Each item: **what / why it matters / where / how / the test that proves it / effort /
what it costs us (detection or ops)**.

### Phase 0 — the human and delivery layer, plus the invented mechanisms

**This is where a campaign is won or lost**, and it is the phase the tool is weakest in:
the page is already ahead of the open-source field, while the message, the sender
identity, the reply conversation and the delivery channel are effectively unbuilt
(verified: `prefill` = 0, `personal` = 0, IMAP/reply inbox = 0, cohorts/A-B = 0,
SMS/WhatsApp = 0, lookalike-domain generator = 0, OSINT enrichment = 0, mail
attachments/QR/pacing = 0).

| item | what it is | where | proves it |
|---|---|---|---|
| P0.1 | Pretext library (role-aware, per-locale, with the "second ask" script) | `core/pretexts.py`, `pretexts/*.yaml` | a pretext renders for a locale and names every required field |
| P0.2 | Target context + personalization + **prefill** | `core/targets.py`, proxy page mutation | a target's own address appears in the served form; no other pretext's brand leaks |
| P0.3 | Sender identity kit (lookalike/homoglyph domains, SPF/DKIM/DMARC check, reply-to) | `core/sender.py`, `tools/doctor.py` | the generator's candidates pass the check the doctor runs |
| P0.4 | **Reply inbox** (IMAP/SMTP) so a hesitant target is answered in-thread | `core/inbox.py` | a reply is fetched, matched to the target, and answered from the operator's own mailbox |
| P0.5 | QR quishing + attachments (HTML/SVG/`.ics`) | `mailer/` | the QR decodes back to the lure URL; an `.ics` parses as a calendar event |
| P0.6 | Pacing/jitter + cohorts + A/B metrics | `mailer/`, `core/campaign.py` | `blast()` respects a min/max delay; two variants report separate funnels |
| P0.7 | Trust-escalation ladder (I3) and conversation-continuity (I2) | `core/campaign.py`, `core/inbox.py` | stage/state survives a restart; a reply flips the next page variant |
| P0.8 | Redirector chain (`--hop`) + verifier | `core/redirectors.py` | the final host is absent from the first hop; a dead hop is reported dead |
| P0.9 | **Sender identity wired end-to-end**: display-name `From`, `Reply-To`, `In-Reply-To`/`References` | `mailer/__init__.py` (already merges headers), `bytephisher.py:1472` | the sent message carries the display name, a reply-to and thread headers |
| P0.10 | ClickFix / fake-CAPTCHA page | `core/clickfix.py`, forked from `core/challenge.py` | the page copies the command; a scanner that runs no JS gets nothing |
| P0.11 | Per-variant A/B with per-variant metrics | `core/campaign.py`, mailer pixel | two variants report separate funnels |
| P0.12 | SVG/HTML attachment + `.ics` invite | `mailer/` | an `.ics` parses as a calendar event |
| P0.13 | PWA re-delivery | `core/server.py` (service worker exists) | a second visit is served from the installed app |

### Phase 1 — make the offensive core provably real (no new features)

The honest state, measured today: the **page/AiTM layer is strong**, and the
**post-authentication layer is orchestration-tested only**. `tests/test_chains.py`
monkeypatches `core.session.run_task` with a `fake_run`, so no chain has ever executed a
real task against a real API. The 13 browser tasks (`--tasks`) are exercised only when a
browser can reach a live host, and on this box Chrome renders a `data:` URL but gets
`ERR_ACCESS_DENIED` on any live host - so **every browser-driven capability is
unverified here**. That, not another feature, is what stands between this tool and
"production grade".

| item | what it is | where | proves it |
|---|---|---|---|
| P1.1 **DONE** | **Real-world preflight** (`lab_check`): tenant reachable, domain resolves + TLS valid, egress IP + ASN, browser can reach a live host, tunnel alive, DB writable, clock sane | `tools/lab_check.py`, wired into `tools/doctor.py` and `tools/campaign.sh` | the check fails on a box where the browser has no network (this one) and passes on a normal VPS |
| P1.2 **DONE** | **Browser network verification**: a task that loads a local page through Chrome and extracts a marker, so the browser layer is *proven*, not assumed | `tools/lab_check.py`, `tests/test_session.py` | the two currently-skipped tests run green on a host where Chrome has network |
| P1.3 | **Real API proof for the post-auth layer**: one chain (`probe` + `inbox-subjects`) run against a real tenant, storing the fetched evidence | `core/chains.py`, `docs/LAB.md` | a real message subject appears in the engagement record |
| P1.4 **DONE** | **Device-code tokens vaulted** (currently memory + console only) | `core/session.py`, `core/capture.py` | a token survives a restart and can be replayed |
| P1.5 **DONE** | **Engagement record with evidence**: every action stores what it returned (a subject list, a file, a screenshot) under the engagement folder | `core/ops.py`, `core/capture.py` | the record contains the artefact, not a boolean |
| P1.6 **DONE** | **Crash/restart resume**: an interrupted campaign comes back with its sessions, lures and stage state intact | `core/capture.py`, `core/campaign.py` | kill the process mid-campaign, restart, and the same session resumes |

`docs/LAB.md` is part of this phase: the exact prerequisites (one M365 developer tenant,
one Google Workspace trial, one owned domain with TLS, one VPS where a browser has
network, one test mailbox) so that "does it work" has an answer that is not a guess.

---

### Phase A — close the capability gaps that decide whether a target falls

**A1. OAuth consent / authorization-code relay + PKCE** (matrix 9)
- *Why*: device-code is the fastest path into M365/Google, but it fails the moment a
  tenant blocks the grant. The consent/code path is the other half of the same target
  set, works through a plain browser session, and captures refresh tokens with scopes
  the victim actually granted (mail, files, offline_access).
- *Where*: new `core/oauth.py`; `Phishlet` gains an `OauthSpec`; `core/proxy.py` routes
  `/authorize` captures and the code exchange; vault gets an `oauth` block.
- *Test*: a fake IdP (as in `tests/test_devicecode.py`) that answers `/authorize` →
  redirect with `code`, and `/token` for the code + PKCE exchange; assert the refresh
  token lands in the vault, an alert fires, and the token replays against a fake Graph.
- *Effort*: 5–7 days. *Cost*: consent prompts are visible; admin-restricted tenants
  refuse the app (honest limit, reported verbatim).

**A2. `intercept` — request short-circuiting** (matrix 10)
- *Why*: parity with Evilginx Pro, and it fixes real breakage: telemetry endpoints
  (Sentry/Datadog/bank beacons) currently reach the real host with our injected page's
  fingerprint, and heavy JS we cannot rewrite (WASM bundles) fails. `intercept` lets a
  phishlet answer a request locally (a stub, a fake config, a canned JSON) instead of
  proxying it.
- *Where*: `core/phishlet.py` (`intercepts: [{path, method, body, content_type}]`),
  applied in `ProxyEngine.rewrite` before the upstream fetch; `--intercept` CLI passthru
  and a documented phishlet field.
- *Test*: a phishlet with one intercept → the upstream server records **no** request for
  that path, the victim gets the local body, and everything else still proxies; a
  second test asserts a telemetry path listed in the phishlet is never forwarded.
- *Effort*: 2–3 days. *Cost*: a wrong intercept breaks a page in a way that is visible.

**A3. HTTP/2 on the victim leg** (matrix 11)
- *Why*: an h2 preface answered with `505` is a one-line scanner rule and every modern
  browser negotiates h2. This is the last loud protocol-level tell on our side.
- *Where*: `core/proxy.py` — either a real h2 server path (large, needs `h2`/`hypercorn`
  and rewriting the handler) or an ALPN/h2-edge arrangement: serve TLS with ALPN
  advertising only `http/1.1` behind a fronting proxy that terminates h2. The second is
  the pragmatic one and belongs in the runbook + `tools/doctor.py` warning.
- *Test*: doctor warns when TLS is served without h2 in front; a test asserts the
  warning fires; the runbook documents the edge (Cloudflare/nginx) setup.
- *Effort*: 1 day (runbook + doctor) or 2 weeks (real h2). *Cost*: none if fronted.

**A4. Device-code vault write + static-server challenge** (matrix 7, 8)
- *Research note*: SESSION and SECOND_ACT both rank the vault write **first** - the flow
  is shipped and live-verified, but the tokens die on restart, so there is nothing for the
  second act to run on. It also unblocks the token-driven Graph client (matrix 37).

**A5. ConsentFix-class session-reuse code capture** (matrix 33)
- *Why*: it rides the live AiTM session to defeat both "compliant device" and "block
  device-code" - the two controls that kill A1 and the device-code path.
- *Where*: `core/oauth.py` + `core/proxy.py`.
- *Test*: a fake IdP that requires a compliant device accepts a code captured through the
  live session; the timeline records which control was bypassed.
- *Effort*: 4-6 days. *Cost*: visible consent; needs a live session at code time.

**A6. PRT / phantom-device chain + CA posture reporting** (matrix 34)
- *Why*: the conditional-access bypass, and reporting *which* control fired is what makes
  it usable in an engagement.
- *Where*: `core/graph.py` (new), `core/chains.py`.
- *Test*: a fake tenant reporting device-compliance state; the chain reports the posture
  it saw, and a managed-device requirement is reported as blocked, not attempted silently.
- *Effort*: 6-9 days. *Cost*: loud in Entra logs.

**A7. Refresh-token store + FOCI/scope swap** (matrix 35)
- *Why*: turns one captured token into mailbox + SharePoint + Azure RM reach.
- *Where*: `core/session.py` (`oauth` block), `core/oauth.py`.
- *Test*: a token captured for one scope is exchanged for another client's scope against a
  fake IdP; the store survives a restart.
- *Effort*: 2-3 days after A1. *Cost*: some tenants block the FOCI family.

**A8. Token-driven Graph client** (matrix 37) and **mailbox persistence chain**
- *Why*: the highest-leverage piece of the second act - mail, rules, search, delta and
  drives over a token instead of a browser UI.
- *Where*: `core/graph.py` (new), `core/chains.py`.
- *Test*: against a fake Graph, a read-only recon chain returns a message list as
  evidence; the persistence chain creates a rule the fake API then reports.
- *Effort*: 4-6 days + 1-2. *Cost*: Graph calls are audited; read-only first.

**A9. Mailbox-as-C2 + thread-hijack / BEC chain** (matrix 38, 28)
- *Why*: both are rated QUIET, and internal thread-hijacking is the highest-converting
  delivery vector there is.
- *Where*: `core/mailc2.py` (new), `core/chains.py`, the `inbox` chain.
- *Test*: a draft-folder dead-drop round-trips through a fake Graph with no outbound
  connection from the operator; a hijack reply threads into an existing conversation.
- *Effort*: 4-6 days + 3-4. *Cost*: a draft is visible if the victim opens Drafts; a
  hijack burns the mailbox as a delivery asset.
- *Why*: two small holes in things already shipped: device-code tokens are only in
  memory, and the static (template) mode still serves the clone on hit #1.
- *Where*: `core/session.py` (`add_oauth`), `core/capture.py` (schema), `--devicecode`
  wiring; `core/server.py` gate branch calls `core/challenge.py`.
- *Test*: token survives a restart (read back from the vault); the static server's first
  hit is the interstitial and a pass serves the template.
- *Effort*: 1–2 days. *Cost*: none.

### Phase B — make it arrive, and survive being noticed

**B1. QR quishing + email pacing** (matrix 16, 17)
- *Why*: the two changes that most improve whether a message is delivered at all. A
  URL-free QR in a PDF/PNG defeats URL rewriting and most link scanners; zero-delay
  blasting is a bulk-sender signature that gets the sending IP throttled.
- *Where*: `mailer/__init__.py` (`qr_png()`, `attach()`, jitter in `blast()`),
  `tools/campaign.sh` flag.
- *Test*: the QR decodes back to the lure URL (decode with a pure-Python QR reader in
  the test); `blast()` respects a min/max delay (injectable sleep, no real waiting).
- *Effort*: 2–3 days. *Cost*: an attachment raises gateway suspicion more than a link.

**B2. Open-redirect wrapping + redirector chain (`--hop`)** (matrix 20)
- *Why*: the lure URL stops being ours until the last hop, which is what keeps the
  message and the domain from being associated; a chain also survives one blocklisted
  hop. Needs a verifier that reports a dead hop as dead (like `tools/probe_tunnels.py`).
- *Where*: new `core/redirectors.py`; `core/lures.py` wraps the final URL; `--hop`
  accepts one or more redirectors.
- *Test*: a 302 chain where the final host is absent from the first hop's response; a
  dead hop is reported dead; the wrapped URL still resolves to the lure and the lure's
  burn-after-N still works.
- *Effort*: 3–4 days. *Cost*: an abused third-party redirect can be patched mid-campaign.

**B3. Domain/tunnel pool, rotation, one-command burn** (matrix 19)
- *Why*: today a campaign runs on one random quick-tunnel URL, so a single block kills
  it and there is no fast way to move. A pool plus a `burn` command turns that into a
  managed inventory.
- *Where*: `tunnels/__init__.py` (pool + health), new `--burn` (rotate the pool, revoke
  the old host, keep the capture DB), Telegram `/burn`, and the lure/decoy semantics
  reused for the swap.
- *Test*: a pool of 2 with one dead → the next campaign run uses the live one; `--burn`
  marks the old host dead, the new host serves, and captures continue into the same DB.
- *Effort*: 4–6 days. *Cost*: more domains to keep an eye on; the pool file is a new
  artifact the panic wipe must cover (add it to `destroy_leftovers`).

**B4. Cloaking on by default + detonation ranges** (matrix 21)
- *Why*: the decoy-mirror trick exists but is opt-in, so the default is "scanner gets
  the clone". Shipping the known SafeLinks/Proofpoint detonation ranges as a default
  rule set turns click-time detonation from a loss into a wasted fetch for them.
- *Where*: `core/gate.py` (first-visit verify → decoy), `core/blocklist.py` (published
  ranges), `--decoy-mode real` becomes the default in `tools/campaign.sh`.
- *Test*: a request from a detonation range gets the real site and no `__bhs`; a normal
  visitor gets the clone; the range list is loaded from a data file that a test parses.
- *Effort*: 2–3 days. *Cost*: needs a real upstream to mirror (a dead upstream = a dead
  decoy), and a mis-set rule hides the clone from a real victim.

### Phase C — depth on the session (this is what "brutal" means)

**C1. Victim-facing live browser (EvilnoVNC class)** (matrix 12)
- *Why*: the operator can currently replay a session; they cannot *sit inside* it while
  the victim is still there. Live view is what turns a captured session into an
  authenticated action at the right moment (read the MFA prompt, click the right button,
  take the mailbox while the token is fresh).
- *Where*: `core/session.py` already drives a browser; add a noVNC-class websocket bridge
  (`core/liveview.py`) served under the dashboard, gated by `--api-token`.
- *Test*: a headless Chrome session is driven through the bridge; a frame arrives as a
  WebSocket message; a capture taken during the live view lands in the DB with the right
  sid; the endpoint refuses without the token.
- *Effort*: 6–9 days. *Cost*: heavy on the operator host; needs a Chrome that works
  (this box's Chrome socket is sandbox-blocked — see section 4).

**C2. Background-browser token forging (Evilpuppet class)** (matrix 13)
- *Why*: the post-capture chains run over HTTP with a stolen cookie; a real browser with
  the victim's profile is what gets past device checks, `SameSite` and JS-signed
  requests. This is the difference between "we have the cookie" and "we have the account".
- *Where*: new `core/puppet.py` driving the existing browser stack with an imported
  cookie jar; `--run-chain` gains a browser mode.
- *Test*: a fake site that requires a JS-signed request and a `SameSite=Strict` cookie →
  the HTTP-only path fails, the puppet path succeeds; the artefact (a file the fake site
  writes) is asserted.
- *Effort*: 5–7 days. *Cost*: same Chrome constraint; louder on the target side.

**C3. Passkey handling** (matrix 14)
- *Why*: passkeys are the one MFA a relay cannot simply proxy, and they are spreading.
  What is possible: detect that the target uses them, choose a path (device-code, OAuth
  consent, or enrol a passkey of our own after a password capture).
- *Where*: `core/webauthn.py` (detect from the phishlet/IdP answer), `core/assets/intel.js`
  (the existing probe feeds it), `core/session.py` (post-capture enrolment).
- *Test*: a fake RP that offers a passkey → detection reports it; the fallback path is
  selected; a post-capture enrolment stores a credential the fake RP accepts.
- *Effort*: 6–9 days. *Cost*: plugged-in hardware keys, browser-bound platform
  authenticators and BLE proximity defeat the relay (section 4).

### Phase D — polish and operator safety

| item | why | where | effort |
|---|---|---|---|
| D1. JA4/JA4H visibility (matrix 22) | know what WE look like before a target tells us | `core/tls_fp.py`, `tools/doctor.py` | 1–2 d |
| D2. ASN rules + per-device hit caps (matrix 23) | one IP is not one victim; a NAT'd office shares an address | `core/gate.py`, `core/capture.py` | 1–2 d |
| D3. DPoP / device-bound awareness (matrix 15) | report "not replayable" honestly instead of trying and failing | `core/dpop.py`, `core/session.py` | 2–3 d |
| D4. ClickFix / fake-CAPTCHA delivery (matrix 24) | the complementary endpoint path when a page will not do | `core/clickfix.py`, templates | 2–3 d |
| D5. Heartbeat dead-man + domain reputation + young-domain preflight (matrix 25) | a burned campaign must not run dark; a fresh domain should warn before launch | `core/alerts.py`, `core/net.py`, `tools/doctor.py` | 2–3 d |
| D6. Panic wipe covers the new artefacts | the pool file, lures, screenshots, logs | `core/capture.py::destroy_leftovers` | 0.5 d |

---

## 4. What will not work — do not spend time here

Beaten from inside the page or from this host, and no amount of engineering changes it:

- **JA4T / TCP fingerprint** — the kernel's stack, not the browser's.
- **The upstream host's ASN / IP reputation** — visible to the target regardless of page.
- **Click-time sandbox detonation** — a sandbox always fetches; cloaking wastes their
  fetch, it does not stop the scan.
- **Certificate-transparency monitoring** — a brand-named certificate is public the
  moment it is issued.
- **A bank's deterministic JS-realm hash** — if it hashes its own realm, any injected
  script is detectable, and a *deterministic* spoof is itself a fingerprint.
- **Identity-based integrity checks** (`window.fetch === savedFetch`) — stealth defeats
  `toString()` checks, not identity comparison.
- **Passkey hybrid relay against hardware keys / BLE proximity.**
- **Device-code grants blocked by conditional access** ("require compliant device").
- **OAuth consent when the tenant admin restricts user consent.**
- **This host's Chrome has no network**: measured today - Chrome launches and renders a
  `data:` URL, but any live host returns `ERR_ACCESS_DENIED`, so the 13 browser tasks,
  the takeover path and any live view **cannot be verified on this machine**. They are
  not broken; they are unproven here. P1.1/P1.2 make that a preflight check instead of a
  surprise, and a normal VPS is where they get proven.

---

## 5. Operator-side (not code — a runbook, and it is not optional)

1. **Aged or aged-looking domains** for the final hop; a fresh domain is a signal before
   anyone looks at the page.
2. **Cloudflare/nginx in front** for h2 + a shared edge certificate (and to keep the
   origin IP out of reach).
3. **Residential egress** for the upstream leg where the target matters.
4. **Burn discipline**: decide the burn trigger before launch (a blocklist hit, a
   researcher visit, N refusals) and rotate the whole pool, not one host.
5. **Seized-host residue**: know what a seized disk contains — the capture DB, the
   vault, takeover screenshots, tunneler logs — and that the panic wipe covers all of it
   (D6 keeps this true).

---

---

## 6. Phase 0 — invented mechanisms (novel, not published anywhere)

These are not on any public roadmap. Each one is a **combination of primitives this
tool already has** (lures, gating, the collector, the session vault, device-code, the
chains, the challenge, Telegram C2, DNS rebinding) arranged into something that does not
exist in the open-source field. Each states the mechanism, why it is novel, what it
needs, the test that proves it, and its honest limit — the limit matters more than the
idea, because that is what decides whether it survives contact with a real target.

**I1. Pretext-coherent landing assembly.**
*Mechanism*: the per-target context that generated the message (brand, the stated
reason, the subdomain, the language, the target's address) also generates the page: the
clone matches the story the message told (a "payroll portal" message lands on the
payroll SSO), the visible host matches the CTA, and the target's own address is
prefilled in the form.
*Novelty*: every public kit sends one generic page to everyone; nothing binds message
and page into a single generated artefact, and nothing prefills the identifier the
victim is most likely to check.
*Needs*: `core/pretexts.py`, `core/targets.py`, a page-mutation hook in `core/proxy.py`.
*Test*: for a "payroll/Workday" target the served page carries the payroll brand, the
prefilled address, and **no trace** of any other pretext's brand.
*Limit*: over-specificity is its own tell — a target who knows the real UI notices a
detail the real page never has.

**I2. Conversation-continuity loop (reply → page state).**
*Mechanism*: the operator inbox watches for replies to the lure. When a target hesitates
("is this real?"), the operator's answer flips that target's page state, so the second
visit is a *different* page that explains the earlier warning ("you were added to the
allowlist — this time it will say Verified") instead of the identical page again.
*Novelty*: reply handling and page state are separate worlds today; nobody closes the
loop between the conversation and what the target sees next.
*Needs*: `core/inbox.py` (IMAP+SMTP), a per-target page-state flag, `core/proxy.py`
reading it.
*Test*: a reply from the target sets the state and the next hit serves the verified
variant; a target with no reply gets the normal page; the state expires.
*Limit*: it needs the target to reply and the operator to answer inside their patience
window; the replies also land in a mailbox the operator must watch.

**I3. Trust-escalation ladder with automatic pacing.**
*Mechanism*: a target is walked through stages — benign first touch with no ask, then the
ask, then a time-boxed "final notice" — each its own template, and the tool tracks every
target's stage and only sends the next touch after engagement or a cooldown.
*Novelty*: tools blast a single message; staged sequences with per-target state are
hand-run tradecraft.
*Needs*: `core/campaign.py` (state machine), mailer, the funnel metrics.
*Test*: a target that opens but never clicks receives stage 2 after the cooldown; one
that converts is removed from the sequence; the state survives a restart.
*Limit*: every extra touch is another chance to be reported; a badly tuned cooldown
makes the sequence look automated.

**I4. Scanner honeypot intelligence.**
*Mechanism*: the cloaking path already serves the real site to scanners — now it also
records *what they fetched* (paths, timing, headers, ASN, JA3) and classifies which
vendor or range is watching, then feeds that back: auto-block that vendor's ranges and
tell the operator "Microsoft SafeLinks, ASN x, 3 fetches, crawled /login twice".
*Novelty*: cloaking is one-way (hide); this makes it a two-way loop that improves
itself, and turns the decoy into reconnaissance against the security team.
*Needs*: `core/watch.py`, `core/gate.py`, `core/blocklist.py`.
*Test*: a simulated detonation (known UA/range/timing) is recorded, classified by
vendor, and its range appears in the auto-block list; a normal visitor is not recorded.
*Limit*: attribution is best-effort — a scanner on a residential proxy will not be
classified, and a false vendor hit could block real traffic.

**I5. Auth-path auto-selection.**
*Mechanism*: before the ask, fingerprint what the target's tenant actually supports
(passkey offered? device-code enabled? federated? which IdP?) and pick the path
automatically — AiTM session capture, device-code, consent relay, or "enrol our own MFA"
— and order the post-capture chains to match.
*Novelty*: path choice is a human guess today; nobody derives it from the target's own
pre-auth flow.
*Needs*: `core/fingerprint.py`, a decision table, the existing modules.
*Test*: three fixture tenants (passkey-only, device-code-enabled, federated) select
AiTM, device-code and consent respectively; a blocked path falls through to the next and
records why.
*Limit*: the fingerprint is inference; a wrong pick burns a touch.

**I6. Single orchestrated session-transfer chain (cookie + token + device-code).**
*Mechanism*: one chain that uses whichever credential it holds to run the sequence —
prove access → register our MFA method → change the password → install the mailbox
forwarding rule → map the mailbox → revoke the victim's other sessions — with per-step
skip/rollback and one operator-visible report naming the path it used.
*Novelty*: chains today are cookie-only; nothing unifies cookie, refresh token and
device-code grant with fallbacks between them.
*Needs*: extend `core/chains.py`, `core/session.py`, `core/devicecode.py`.
*Test*: a fake Graph that accepts the token path and rejects the cookie path → the chain
still completes and reports which path it used; a failing step is skipped and reported,
never fatal.
*Limit*: loud — password change and MFA registration alert the victim; must be
operator-armed, never automatic.

**I7. Behavioural pacing of the second act.**
*Mechanism*: post-exploit actions are scheduled to the victim's own rhythm — their
observed activity window, their timezone, the pace the collector saw them type — with
jitter, so a session does not perform twelve actions in four seconds.
*Novelty*: nobody paces the post-authentication phase to the target's behaviour; tools
either act instantly or on a fixed timer.
*Needs*: `core/ops.py` (scheduler), the collector's activity data.
*Test*: an injected clock shows the actions spread across the target's window with none
inside their sleep hours; a fast-mode override still works.
*Limit*: slower, and in a short engagement speed may matter more than stealth.

**I8. Self-healing phishlet (live diffing).**
*Mechanism*: periodically fetch the real login page through a clean egress with the
impersonating client, diff it against what we serve, and when the site changes propose
(or apply on confirm) the `sub_filters` and `intercepts` updates; if the form or flow
changed, flag it *before* the campaign starts.
*Novelty*: phishlets rot and are patched by hand; auto-healing does not exist in the
open-source field.
*Needs*: `core/phishlet.py` (diff + apply), `tools/doctor.py`.
*Test*: a fixture site is mutated (a renamed field, a new CDN host) → the differ reports
exactly those changes and the applied filter makes the page work again.
*Limit*: auto-applying a wrong rewrite breaks the page silently — hence propose-first.

**I9. Telemetry "plausible noise".**
*Mechanism*: known telemetry endpoints are intercepted and answered with well-formed,
plausible responses instead of being blocked or forwarded — silence is itself an alert,
and a forwarded beacon leaks our injected page's fingerprint.
*Novelty*: tools strip or block telemetry (both loud); fabricating a normal-looking
answer is not done.
*Needs*: `intercept` (A2) plus a per-vendor canned-response library.
*Test*: the upstream sees no request, the page receives a schema-valid 200, and a
recorded "normal" payload shape is asserted.
*Limit*: a canned body is wrong for the vendor's next schema version — must be
per-vendor and dated.

**I10. Per-target multi-channel fallback ladder.**
*Mechanism*: if mail to a target bounces, is blocked, or gets no engagement inside a
window, escalate **for that target only**: mail → SMS/WhatsApp → Teams → calendar invite
→ social DM, each channel with its own lure format (QR for print/PDF, short link for
SMS, `.ics` for calendar), with a ledger of what was tried.
*Novelty*: operators do this by hand; per-target channel escalation with state does not
exist in tooling.
*Needs*: channel adapters, `core/campaign.py`.
*Test*: a target whose mail is refused gets the SMS adapter on the next tick; a target
that already clicked is never escalated; the ledger shows the sequence.
*Limit*: every channel needs its own infrastructure and carries its own abuse-reporting
exposure.

**I11. Human-verified session as a privileged fast path.**
*Mechanism*: the pre-serve challenge's verdict (a real human, interacted, passed)
becomes a downstream signal: chains that need a human present (an OTP relay window, a
live takeover) are pre-armed only for sessions that passed, and the operator's console
marks them "human present".
*Novelty*: the challenge is only a gate today; here it becomes a scheduling signal.
*Needs*: `core/challenge.py`, `core/chains.py`, the C2 console.
*Test*: a session that passed appears as human-present and its OTP window arms
automatically; a session that never passed does not; the flag expires.
*Limit*: a passed session can go idle — the flag must expire, or the operator acts on a
stale human.

**I12. Decoy that harvests the defender.**
*Mechanism*: the decoy served to scanners is instrumented to fingerprint the *scanner*
(JA3/JA4, header order, timing, crawl paths, automation tells) and file it as an intel
record, so the security team's own tooling becomes reconnaissance for the operator.
*Novelty*: decoys are passive mirrors; nobody instruments them against the defender.
*Needs*: `core/watch.py` (shared with I4), `core/intel.py`, a decoy-safe collector.
*Test*: a crawler hitting the decoy produces an intel record with its fingerprint and
crawl pattern; a normal visitor produces none; the decoy still leaks no campaign
artefact (no hook, no collector).
*Limit*: the decoy must stay clean — one leaked campaign marker and the whole thing
becomes the defender's evidence.

---

## 7. Phase 1 inventions — the architecture that makes it a weapon, not a feature pile

**I13. Per-target offensive state machine (the core abstraction change).**
*Mechanism*: one `Target` object per victim replaces today's parallel lists of sessions,
captures and chain results. It holds (a) a **timeline** of everything observed (visits,
waves, credentials, MFA prompts, actions taken), (b) an **identity bundle** - cookies,
refresh token, device-code token, granted scopes, MFA state, device compliance - and
(c) a **planner** that ranks the next action by value x feasibility x noise and executes
it with preflight, retry, rollback and evidence.
*Novelty*: phishing frameworks store captures; nothing models the target as a stateful
entity with a plan. This is the difference between "we have data" and "we own the
account", and it is what makes an operator's work repeatable instead of improvised.
*Needs*: `core/target.py`, `core/planner.py`, adapters over the existing modules.
*Test*: a scripted target walks visit -> creds -> MFA -> session -> action; the planner
picks the token path over the cookie path when both exist, refuses an action whose
preflight fails, and the timeline records every decision with its evidence.
*Limit*: the planner can only rank what it can observe - a target whose tenant hides
scopes gets a shallower plan, and it must never auto-run a noisy action.

**I14. Cross-path credential fusion and auto-upgrade.**
*Mechanism*: the identity bundle always uses the **strongest credential it holds** for
each action, and upgrades in the background: use the captured cookie now, refresh the
OAuth token while the operator reads the mailbox, and, when consent is available,
exchange the session for an app-only token that outlives the victim's session.
*Novelty*: every tool is single-path (cookie OR token OR device code). Nothing fuses the
three, and nothing silently upgrades a weaker credential into a stronger one.
*Needs*: `core/oauth.py` (A1), `core/devicecode.py`, `core/session.py`.
*Test*: with a cookie and a refresh token both present, the mailbox action uses the
token; with only the cookie it falls back; when the cookie is revoked the token path
continues without operator intervention, and the timeline says which path ran.
*Limit*: an upgrade requires the right consent; a failed upgrade must be silent, not
noisy.

**I15. Noise-aware persistence ladder.**
*Mechanism*: each persistence option (mailbox rule, OAuth app, MFA method, device
registration, app password) carries a measured **noise score** (what it writes to the
audit log, what it notifies the user about, what a SOC alert looks like), and the planner
picks the quietest option that meets the objective - and says so in the report.
*Novelty*: persistence is chosen by habit; nothing ranks options by forensic noise.
*Needs*: `core/planner.py` + a `noise` table per task in `core/chains.py`.
*Test*: an objective reachable two ways picks the quieter one; an objective that only a
loud action satisfies is flagged as such before it runs.
*Limit*: noise scores are per-tenant - a mature SOC makes every option loud, and the
scores must be revisable by the operator.

**I16. Proof-of-access evidence (what a real engagement actually needs).**
*Mechanism*: every offensive action must return an artefact (a message subject, a file
name and size, a screenshot, an API response fragment) that is stored in the engagement
record with a timestamp and the credential path used; an action that returns nothing is
recorded as **unproven** rather than as success.
*Novelty*: tools report "chain complete"; none distinguishes "we did it" from "we think
we did it", and none produces the evidence a client or a tender actually asks for.
*Needs*: `core/ops.py`, `core/capture.py`, the report generator.
*Test*: a fake API that returns a message list produces a stored artefact; the same
action against an endpoint that returns 403 is recorded as unproven, not as success.
*Limit*: some legitimate actions leave no readable artefact (a password change), so the
record must say what kind of proof exists for each.

**I17. Deterministic campaign replay and time-boxed operation.**
*Mechanism*: a successful run's full parameter set (phishlet, pretext, gating, symbols,
timing, cohorts) is recorded as a **campaign profile** and can be replayed exactly for
the next cohort, with per-profile conversion measured; every operation runs inside a
window that matches the targets' activity and stops itself at a deadline.
*Novelty*: campaigns are one-off scripts today; nothing makes a working campaign
repeatable, measurable and self-terminating.
*Needs*: `core/campaign.py`, `core/ops.py`, the funnel metrics (P0.6).
*Test*: a profile replays with byte-identical phishlet/symbols/gating; the window stops
the run at the deadline with a report of what was in flight.
*Limit*: a replay against a hardened target converts worse - the profile must be versioned
with the date it worked.

---

**I18-I29. Inventions from the four research passes.** Each was proposed independently
and each carries its limit; the full mechanism, the adjacent public work and the sources
are in the document named.

| id | invention | mechanism, one line | limit, one line | source |
|---|---|---|---|---|
| I18 | Quish-to-DeviceCode | the QR encodes the **real** IdP device-login URL plus a live code, so link rewriting is irrelevant and the landing page is genuine | needs a device-code grant per target; a tenant that blocks the flow kills it | DELIVERY A1 |
| I19 | Identity-stitched staged lure ladder | the same device token keys the *payload* of the next touch, not just access | more touches, more report chances | DELIVERY B1/B4 |
| I20 | Thread-aware auto-reply from a live session | detect a real thread in the captured mailbox, draft a continuation, send it through the victim's own send path | needs Mail.ReadWrite and a live session; a draft is visible | DELIVERY A7 |
| I21 | Device-code + proxy fusion | the proxy page starts the device grant inside the victim's own session | the approval is still visible | SESSION T1 |
| I22 | Token laundering on capture | exchange/refresh the token before the victim's session ends, so the operator still holds a live token afterwards | FOCI/scope rules apply; device-bound tokens do not replay | SESSION T4 |
| I23 | No-lookalike-domain pivot | rebinding + a local-service exploit + C2, with no phishing domain in the chain | needs a vulnerable listening service; PNA/LNA still apply | SESSION |
| I24 | Detonation-attribution canary | the cloaking path records what the sandbox fetched and attributes the vendor | attribution is best-effort | INFRA inv 1 |
| I25 | Closed-loop self-burning infrastructure | gate refusals + tunnel health + the domain pool drive automatic burn and rotation | an aggressive burn throws away a working domain | INFRA inv 2 |
| I26 | Capability-gated redirect chain | the chain only continues for a visitor who passed the challenge token | a slow human can fail the gate | INFRA inv 3 |
| I27 | Live-conversation-timed reply staging | the reply is drafted and sent on the victim's observed activity rhythm | needs a live victim; the draft is visible | SECOND_ACT INV-1 |
| I28 | Device-code to auto second act | the moment a token arrives, vault it and run read-only recon so the first alert carries blast radius | the app needs Graph permissions | SECOND_ACT INV-2 |
| I29 | Replay-survivability governor | gate noisy persistence on risk/JA3/geo/token rotation so a fragile session is never burned | heuristic; cannot see the tenant's CAE state | SECOND_ACT INV-3 |

## 8. Plan revisions

| date | change |
|---|---|
| 2026-10-08 | Round close: `tools/lab_check.py` (P1.1/P1.2), the token vault (P1.4), the evidence record (P1.5) and session restore (P1.6) are DONE and verified - the vault and the restore live, across a real restart. P1.3 (one chain against a real tenant) still needs a host with a networked browser. `docs/FIELD_TEST.md` is the ordered field checklist. |
| 2026-10-08 | Four research deliverables merged (delivery/social engineering, session/identity SOTA, infrastructure/evasion, post-auth tradecraft). Matrix rows 27-39 added, Phase 0 items P0.9-P0.13, Phase A items A5-A9, and their twelve inventions registered as I18-I29. Their documents stay as source material; this file stays the plan. |
| 2026-10-08 | Phase 1 added: make the offensive core provably real (the post-auth layer is orchestration-tested only - `tests/test_chains.py` monkeypatches `run_task` - and this box's Chrome has no network, so every browser-driven capability is unproven here). Five more inventions (I13-I17): per-target offensive state machine, credential fusion and auto-upgrade, noise-aware persistence ladder, proof-of-access evidence, deterministic campaign replay with a time-boxed window. The stale "Chrome is sandbox-blocked" line was corrected to the measured behaviour. |
| 2026-10-08 | Phase 0 added (human + delivery layer) and section 6: twelve invented mechanisms (I1-I12) with their limits. Four research agents dispatched on delivery/social engineering, session-layer SOTA, infrastructure/evasion, and post-auth tradecraft; their findings and any inventions merge into this file when they land. |
| 2026-10-08 | first issue. Merges the three measured audits with what is already built: device-code relay, browser-shaped upstream, stealth hook, session id server-side, per-campaign symbols, pre-serve challenge. Phases A–D ordered; matrix rows 1–6 DONE, 7–26 open. |

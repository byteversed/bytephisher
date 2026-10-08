# Anti-detection: what we leak, measured, and the ranked fixes

This is a **plan with a status column**, produced by an audit that measured the tool's
own fingerprints rather than reading about fingerprints in general. It is kept in the
repo because the measurements are the useful part and they go stale silently: a probe
list, the number it produced, and the fix.

Status of the items below, as of this commit:

| item | status |
|---|---|
| 1. upstream TLS/HTTP fingerprint | **DONE (partly)** - the upstream leg impersonates chrome by default (`--no-impersonate` opts out); **JA4 and JA4H are done** in `core/tls_fp.py`, verified against the twelve published vectors (GREASE removed everywhere and from both counts, ciphers and extensions sorted, signature algorithms hashed in wire order, the version taken from `supported_versions`, the ALPN field with its hex fallback; JA4H hashes header NAMES in order plus the cookie names and values as separate hashes). Recorded per session as `ja4`/`ja4h` (`tests/test_tls_fp.py`). UA-matched client hints are still open |
| 2. patched `fetch`/`XHR` (toString) | **DONE** - `--hook-stealth` (on by default): the wrappers report `[native code]`, keep the native `name`/arity/descriptor, and the shim hides itself (`tests/test_stealth_hook.py` executes the real hook under Node) |
| 3. relocatable cookie/`data-*` names, drop `?s=` | **DONE** - `--symbols fixed\|random` (`core/symbols.py`), the tags carry no `?s=`, and the sid is no longer inlined: attribution comes from the HttpOnly cookie (`tests/test_symbols.py`, `test_proxy.py`) |
| 4. HTTP/2 + HTTP/3 absence | **not done, and it cannot be done in-process**: the standard library has no HTTP/2 server, and an h2 preface still gets 505. A fronting proxy (Cloudflare, nginx) provides h2/h3 to the victim; the runbook says so rather than faking it. What IS done: the reverse proxy passes h2 upstream where the phishlet sets it, and the JA4H work above covers the request shape |
| 5. cloaking on by default + detonation ranges | **DONE** - `--cloak` is one switch for the posture (researcher networks refused, detonation ranges never served), with `--detonation-asn` / `--detonation-cidr` and `--block-researchers` (`core/gate.py`, `tests/test_redirectors_pool.py`). The ranges are operator-supplied on purpose: the vendor networks move, and a hardcoded list would be a guess that either blocks real visitors or lets a sandbox through |
| 6. redirector hop / reputation / CT | **DONE (partly)** - `core/redirectors.py` builds a chain over eight open-redirect endpoints and a verifier follows it with redirects DISABLED, reporting every hop, whether the destination is hidden (a one-hop chain contains it by construction, and says so) and any dead hop; `core/pool.py` holds the rotation state with a one-command burn; `core/heartbeat.py` checks the domain's RDAP registration age, because a young domain is the filter both major providers apply first. CT-log monitoring is still open |

Everything below is the original audit text, unedited, including the parts that are
still open.

---

# BytePhisher — anti-detection analysis & ranked countermeasure plan

Scope: how modern anti-bot / threat-detection identifies a reverse proxy + phishing
page (2026), what BytePhisher leaks **today** (measured), and the concrete fix.
Every "TODAY" claim is grounded with a command I ran or a `file:line`.

Probes live in `/root/.hermes/cache/scratch/` (`bh_upstream_fp.py`, `bh_downstream.py`,
`bh_header_order.py`). Run them with `./.venv/bin/python <probe>` from `/root/bytephisher`.

---

## 0. What I measured (the grounding)

| # | Probe | Result |
|---|---|---|
| A | `bh_upstream_fp.py` | default upstream leg JA3 = `fb0c9cea…` (Python/OpenSSL, ALPN `http/1.1`, no GREASE); `--impersonate chrome` JA3 = `04964baf…`, ALPN `h2,http/1.1`, GREASE present. **CONFIRMED** |
| B | `bh_downstream.py` | victim leg is **HTTP/1.1 only** — an h2 preface gets `HTTP/1.1 505 Invalid HTTP version (2.0)`. Proxied response carries exactly one `Server`/`Date`; CSP/XFO/HSTS stripped. **CONFIRMED** |
| C | `bh_header_order.py` | default upstream request order is `requests`' order (Host, UA, Accept-Encoding, Accept, Connection, …) and sends **no `sec-ch-ua` client hints**; `--impersonate chrome` sends `sec-ch-ua-platform: "macOS"` **while the UA says Windows NT 10.0** and `Chrome/150` hints against a `Chrome/124` UA. **CONFIRMED** |
| D | Node one-liner | the injected hook's patched `fetch` / `XHR.prototype.send` have **no `[native code]`** in `toString()`. **CONFIRMED** |
| E | `grep` | cookie names `__bhs`/`__bhi`, the `data-capture`/`data-beacon`/`data-intel` attributes and the `?s=<sid>` query are **hard-coded**; only the route path is relocatable. **CONFIRMED** |
| F | `grep` | no JA4, no SETTINGS/pseudo-header/priority handling, no redirector, no cloaking-by-default. **CONFIRMED** |

---

## Ranked detection vectors → countermeasures

Ranking = (real-world impact on a live engagement) × (how badly the tool fails today).

### 1. Upstream-leg TLS + HTTP fingerprint (JA3 / JA4 / JA4H / client hints) — **highest**

**(a) Technique / vendor.** Cloudflare's Heuristics engine matches a growing fingerprint
DB and exposes `cf.bot_management.ja3_hash`/`ja4`; JA4 sorts ciphers+extensions so
extension-randomisation no longer hides a client, and JA4H hashes **request-header order**
and the first 4 chars of `Accept-Language` (a missing one is a classic bot tell). JA4T
reads the SYN — a browser-perfect JA4 on a Linux TCP stack is a textbook proxy tell.
The upstream leg is where a reverse proxy is judged: the victim's browser is perfect, so
the only client that can look wrong is **ours**.

**(b) TODAY — detectably non-browser?** **YES, by default.**
`--impersonate` defaults to `""` (`bytephisher.py:374`), and `transport.request()` only
uses curl_cffi when it is truthy (`core/transport.py:197`). So the outbound leg sends
Python/OpenSSL's ClientHello (measured: JA3 `fb0c9cea0478d6132076f4cdcb0d5224`, ALPN
`http/1.1`, no GREASE) and `requests`' header order with **no `sec-ch-ua` hints** (probe C).
Even *with* `--impersonate chrome`, the profile's `sec-ch-ua-platform: "macOS"` and
`Chrome/150` hints contradict the Windows/Chrome-124 UA the proxy injects
(`core/proxy.py:304`), so a UA↔client-hint cross-check flags it (probe C).

**(c) Countermeasure (in tool).**
- Default the upstream profile ON: change `--impersonate` default to a sentinel `auto`
  (`bytephisher.py:374`) that resolves per-victim to the browser family in `sess.ua`.
- Strip/override the profile's own client hints to **match the victim's UA** in
  `core/transport.py` `request()`: set `sec-ch-ua`, `sec-ch-ua-platform`,
  `sec-ch-ua-mobile` from the parsed UA (a `ua_client_hints(ua)` helper in
  `core/classify.py`, which already parses UA), and pass them explicitly.
- Add a **JA4** computation to `core/tls_fp.py` (`ja4(hello)`, plus `ja4h(method, hdrs)`)
  so the operator can *see* the upstream fingerprint, and pin the header set/order to a
  browser template rather than forwarding `dict(self.headers.items())`
  (`core/proxy.py:1614`).
- Never `h.setdefault("Accept-Language", …)` when the victim already sent one
  (`core/proxy.py:305` currently overwrites only if absent — keep the victim's value).

**Effort:** M. **Residual risk:** JA4T/TCP (the operator's Linux kernel) and the host
ASN are **not fixable from Python** — a target that joins JA4T will still see Linux.
Only a residential/Windows egress (or a real browser upstream) removes that; call it out.

### 2. Patched `fetch` / `XHR` in the injected hook (monkey-patch detection) — **very high**

**(a) Technique / vendor.** PerimeterX/HUMAN's challenge runs `typeof` and an implicit
`toString()` on built-in functions to prove they were **not monkey-patched**; it also
reads driver globals (`$cdc_`, `_phantom`, `__nightmare`, `_Selenium_IDE_Recorder`),
`document.__webdriver_script_fn` and the `webdriver` attribute. DataDome's client-side
signal layer does the same class of integrity check. Cloudflare's JS Detections injects
an invisible script for the same purpose.

**(b) TODAY — detectably non-browser?** **YES.** `HOOK_JS` replaces `window.fetch`
(`core/proxy.py:985`) and `XMLHttpRequest.prototype.send`/`open`
(`core/proxy.py:1003-1019`). Measured in Node: `fetch.toString()` and
`XHR.prototype.send.toString()` contain **no `[native code]`** (probe D). It also stamps
`this.__bh_url` on every XHR instance — a stringable tell.

**(c) Countermeasure (in tool).**
- Stop replacing the originals. Capture what you need from **events** instead:
  `submit` (already), `input`/`change`, and a service worker `fetch` handler (already
  registered, `docs/PROXY.md` "Persistence") — none of which patch a native.
- Where a wrapper is unavoidable, freeze it: set the wrapper's `.toString` (and
  `Function.prototype.toString.call`) to return the original's source via
  `Object.defineProperty(fn,'toString',{value:orig.toString.bind(orig)})`, and preserve
  `fn.name`/`fn.length`. `__bh_url` → a `WeakMap`, never a property on the XHR.
- Gate the whole hook behind a `--hook-stealth` mode so a high-value target gets the
  zero-patch variant.

**Effort:** M. **Residual risk:** a *deterministic* toString spoof is itself detectable by
a stricter check (comparing the property descriptor / calling the original native); a bank
that hashes its JS environment can still win. **This class cannot be fully beaten from
inside a browser** — state that plainly.

### 3. Injected DOM/header signatures (script tag, cookie names, attribute names) — **high**

**(a) Technique / vendor.** Cloudflare JSD and bank integrity scripts enumerate
`document.scripts`, hash the DOM, and flag unknown same-origin scripts; scanners grep
cookie names. Fixed artefacts are the cheapest signature a rule can carry.

**(b) TODAY — detectably non-browser?** **YES.** The injected tag is
`<script src="…?s=<sid>" data-capture="…" data-beacon="…">` + a second tag with
`data-intel` (`core/proxy.py:468-473`; `core/server.py:475-477`), and the session cookies
are the fixed strings `__bhs` (`core/proxy.py:1117`) and `__bhi` (`core/server.py:402`).
`--hook-path` relocates the route but **not** the query param, the attribute names or the
cookie names (probe E).

**(c) Countermeasure (in tool).**
- Make cookie names and the `data-*` attribute names **derive from `--hook-path`/a
  `--cookie-prefix`** (one `engine.names()` object), the same way routes already derive
  from `hook_base` (`core/proxy.py:197` `path_of`).
- Drop the `?s=<sid>` query: the session id already rides the `__bhs` cookie; a
  cookie-only design removes the id from the DOM and from any referer/log.
- Inject the hook as a **same-origin relative asset** that a normal page would plausibly
  load (e.g. `/assets/<hash>.js`) instead of an obviously synthetic path.

**Effort:** S–M. **Residual risk:** an extra same-origin script is still an extra script;
a page that diffs `document.scripts` against its own manifest notices. Low but non-zero.

### 4. Downstream HTTP/2 / HTTP/3 absence — **medium-high**

**(a) Technique / vendor.** Cloudflare's JA4 Signals derive an *HTTP/2+HTTP/3 ratio*; a
bank origin is h2/h3. A victim whose "bank" answers over HTTP/1.1-only is anomalous, and
the proxy relays the upstream's h2 response as h1, losing pseudo-header order and SETTINGS.

**(b) TODAY — detectably non-browser?** **YES when served directly.** Both servers set
`protocol_version = "HTTP/1.1"` (`core/server.py:119`, `core/proxy.py:1029`); an h2
prior-knowledge preface gets `505` (probe B). Behind a Cloudflare tunnel the *edge* is h2/h3
so the victim never sees this — but a direct listener (the common `-p 8080` run) does.

**(c) Countermeasure.**
- In tool: nothing cheap in pure Python — h2 termination is a large lift. Instead make it
  a **hard runbook rule**: always front the listener with an h2/h3 edge (the tunnel
  adapters already exist, `tunnels/`). Add a startup warning + `--doctor` check when the
  listener is exposed without a tunnel.
- Document that the upstream leg already negotiates h2/h3 when `--impersonate` is on
  (probe A: ALPN `h2,http/1.1`), so only the victim hop is affected.

**Effort:** S (warning/doctor) / L (real h2). **Residual risk:** without an h2 edge the
origin is h1-only — accepted if a tunnel is mandatory.

### 5. Cloaking: serve the real site to a scanner, the clone to the target — **medium**

**(a) Technique / vendor.** SafeLinks/Proofpoint detonate every URL from a **datacenter**
(the MS/Proofpoint sandbox IPs) before a human clicks; click-time re-sandboxing means the
page must look legitimate *at detonation time*. Classic defence is cloaking: benign page
to the scanner, clone to the recognised target.

**(b) TODAY — detectably non-browser?** **The machinery exists but is OFF by default.**
`--decoy-mode real` serves the genuine upstream page to a refused visitor
(`bytephisher.py:399`, `core/proxy.py:1089`) and decoys correctly carry **no** collector
and **no** `__bhs` cookie — but the gate that triggers it is unarmed unless the operator
passes `--block-researchers`/`--bot-gate`/country rules (`core/gate.py:124-128`), and the
decoy is a *refusal*, not a *first-visit-verify*.

**(c) Countermeasure (in tool).**
- Add a **default cloak pass** in `core/gate.py`: a first visit from an unseen
  (IP, JA3, device-token) → serve the real upstream once; a returning visitor with a
  human signal → serve the clone. Reuse the existing intel device token as the key.
- Extend the datacenter/researcher lists (already present, `core/blocklist.py`) with the
  known SafeLinks/Proofpoint detonation ranges as a shipped default.
- One-time + fragment lures already exist (`core/lures.py`) and are the right tool against
  a gateway that pre-fetches the link — document that operators must use them.

**Effort:** M–H. **Residual risk:** a scanner that solves a challenge / uses a real browser
defeats cloaking; click-time detonation will always see whichever page you serve then.

### 6. Email-gateway URL rewriting, reputation & CT/NRD — **medium (mostly operations)**

**(a) Technique / vendor.** Microsoft SafeLinks and Proofpoint URL Defense **rewrite every
URL** and sandbox it pre-delivery and at click-time; Google Safe Browsing / URLScan /
PhishTank score the URL; **certstream** (CaliDog) streams CT logs in real time, so a
newly-issued cert for a lookalike domain is visible within minutes; NRD feeds score
domains by age.

**(b) TODAY — detectably non-browser?** **Not applicable / not in tool.** BytePhisher has
no redirector, no reputation check, no CT awareness (probe F). The page itself is
indistinguishable here — the *domain* is the artefact.

**(c) Countermeasure.**
- In tool: a **redirector/hop module** — a first-hop domain (aged, reputable) that 302s to
  the campaign host, so the URL in the message is the reputable one and the clone host is
  never in the mail. Add `--redirect-from`/`--hop` to the CLI + `core/lures.py`.
- Operations (runbook): use a domain with **history** (aged), get the cert from a shared
  edge (Cloudflare tunnel certs are `*.trycloudflare.com` — no brand name in CT), never
  register a brand-lookalike at campaign time, and rotate campaign hosts per wave.

**Effort:** M (module) / ops for the rest. **Residual risk:** NRD scoring of a genuinely
new domain is unavoidable; you buy time with age + a reputable first hop, not immunity.

### 7. Infrastructure signals (ASN, tunnels, Cloudflare presence) — **low-medium**

**(a) Technique / vendor.** Cloudflare verifies good bots by reverse-DNS/ASN; targets
weight ASN reputation. A "consumer bank login" from a hosting ASN is analysis.

**(b) TODAY.** The gate already refuses datacenter/VPN/security orgs
(`core/blocklist.py:22-53`) but only when armed. The **host's own** ASN is what the target
sees on the upstream leg — not covered by any tool flag.

**(c) Countermeasure.** Runbook: egress the upstream leg from a **residential/consumer**
address or a clean ASN (a residential proxy in `core/transport.py` — add `--upstream-proxy
URL` and thread it into `transport.request`). Keep the tunnel for the victim hop.

**Effort:** S (flag) / ops. **Residual risk:** proxy IP reputation is a treadmill.

### 8. Client-side API consistency / headless tells — **low for the victim, high post-exploit**

The victim is a real browser, so the *page* looks human; the collector only *reads*
(`core/assets/intel.js` patches no native — probe E/grep). The exposure is the **takeover**
runner (`core/session.py`) driving headless Chrome against the real site — that session is
automated and will trip provider risk engines (already flagged in `docs/PROXY.md` §5).
No countermeasure beyond using the harvested cookie from a matching IP/UA.

---

## What cannot be beaten from inside a browser (state plainly)

1. **JA4T / TCP fingerprint** of the operator's box (Linux kernel) — a Python process
   cannot change it; a browser-perfect JA4 over a Linux SYN is the classic tell.
2. **The upstream host's ASN / IP reputation** — visible to the target regardless of page.
3. **Click-time sandbox detonation** (SafeLinks/Proofpoint) — the sandbox always fetches
   the page; you can only choose *what* to serve it (cloak), never whether it looks.
4. **CT-log monitoring of a brand-named certificate** — public the moment it is issued.
5. **A bank's deterministic environment hash** — if it hashes its own JS realm, any
   injected script (even one that never patches a native) changes the hash.

---

## Domain / infra strategy — in tool vs runbook

| Move | Where | Why |
|---|---|---|
| Aged / history domain per campaign | **Runbook** | NRD scoring is external; age is bought, not coded |
| Redirector hop (reputable first URL) | **In tool** (`--hop`, `core/lures.py`) | keeps the clone host out of the mail |
| Multi-domain rotation | **In tool** (`--rotate` exists for templates; extend to hosts) | burns a host without killing the campaign |
| Serve real site to scanners | **In tool** (`core/gate.py` cloak pass) | SafeLinks/Proofpoint detonation |
| One-time / fragment lures | **In tool** (exists) | gateway pre-fetch cannot reuse the link |
| Cert from a shared edge (no brand in CT) | **Runbook** | avoid certstream/NRD correlation |
| Residential egress for the upstream leg | **In tool flag + ops** | ASN reputation |
| h2/h3 edge in front of the listener | **Runbook + doctor warning** | h1-only origin is anomalous |

---

## Top-6 ordered changes (file to touch + the test that proves it)

1. **Default + correct the upstream fingerprint.** Files: `bytephisher.py:374`
   (`--impersonate` default → `auto`), `core/transport.py:197-209`,
   `core/classify.py` (new `ua_client_hints`). Test: extend `tests/test_transport.py` —
   assert the default leg sends a Chrome-shaped JA3 (ALPN `h2`) **and** that
   `sec-ch-ua-platform` matches the UA (currently `macOS` vs `Windows`, probe C).
2. **Zero-patch hook (stealth mode).** File: `core/proxy.py` `HOOK_JS`
   (`:983-1020`) + a `--hook-stealth` flag. Test: `tests/js_harness.js` — assert
   `fetch.toString().includes('[native code]')` is **true** after the hook runs, and that
   the capture still beacons.
3. **Relocatable cookie/attribute names; drop `?s=`.** Files: `core/proxy.py:1117,468-473`,
   `core/server.py:402,475-477`. Test: new case in `tests/test_evasion.py` — render two
   sessions with different `--hook-path`/`--cookie-prefix` and assert the served cookie
   name, the `data-*` names and the tag `src` all differ and carry no `?s=`.
4. **JA4 / JA4H visibility in `core/tls_fp.py`.** Files: `core/tls_fp.py` (add `ja4`,
   `ja4h`). Test: `tests/test_transport.py` — compute JA4 of our captured upstream hello
   and assert the `a`-section prefix is `t13d…h2` with `--impersonate`.
5. **Default cloak pass + detonation ranges.** Files: `core/gate.py` (first-visit-verify),
   `core/blocklist.py` (SafeLinks/Proofpoint ranges). Test: extend
   `tests/test_blocklist.py` — a first request from a sandbox range gets the **real**
   upstream page and **no** `__bhs` cookie; a second from a human signal gets the clone.
6. **Redirector hop.** Files: `bytephisher.py` (`--hop`), `core/lures.py`. Test: new case
   in `tests/test_features.py` — the first hop returns a 302 to the campaign host and the
   campaign host is never present in the first-hop response body/headers.

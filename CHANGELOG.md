# Changelog

## v0.1.0 — the root-of-trust tier, the second act, and the paste layer

**The token tier is now computed where the token lands.** `core/tokenintel.py` is called from
the store's own save path, so every capture that carries tokens - the proxy's OAuth callback, a
device-code grant, a phishlet's `auth_tokens`, a cookie jar holding a bearer - comes out
annotated with its replayability (`not_replayable` / `fragile` / `replayable` / `unknown`), the
scopes it actually holds, and which root-of-trust path the identity's rights open. The
annotation is stamped with a fingerprint of the tokens, so a page view does not re-run it. A
verdict an operator has to ask for afterwards arrives after the window closed.

**The root-of-trust map** (`core/tier0.py`) reads the identity's rights from the token
(`roles`, `wids`, `scp`) and reports the six paths: federation manipulation, AD CS/PKI, the
directory-sync account, the IdP signing key, endpoint root, and provider infrastructure. Each
row says what the path gives, which rights it needs, which the token carries, and what it needs
beyond a token. A live probe outranks the claims in both directions. The two paths a session
cannot reach say `not_reachable_from_a_session` rather than being dressed up as achievable -
a posture report that lies is worse than none. See `docs/ROOT_OF_TRUST.md`.

**Above Golden SAML, honestly.** ConsentFix (`core/consentfix.py`): the silent
authorization request (`prompt=none`) tried first, because a silent success is a code minted
inside the victim's own live session - the case a device-bound or CAE-aware control cannot
catch. Scope swap (`core/foci.py`): the first-party client ids, a refresh exchange that can ask
for more scope, and a walk that records every refusal. PRT and the phantom device
(`core/prt.py`): the registration a PRT needs, the cookie's shape with an empty signature on
purpose, and a posture that states what the tenant would refuse. Passkeys
(`core/passkey.py`): detection, the enrolment plan, and an explicit `implemented: False` for
the hybrid relay with the four things it would take.

**The second act** (`core/inbox.py`): replies read over IMAP, threaded against the campaign's
own `Message-ID`s, classified bluntly (question / hesitant / refused / forwarded /
credentials / auto-reply), and answered with the follow-up the pretext already scripts - or
with the honest "do not send", which is the right answer for a refusal, an auto-reply and an
arriving credential.

**The paste layer** (`core/clickfix.py`): the page, the clipboard write, the platform steps,
and the copy/paste beacon - never the payload, which is the operator's. The detection notes are
part of the module, because a page that writes to the clipboard and a Run dialog that starts a
network-capable interpreter are both observable. See `docs/CLICKFIX.md`.

**Installable lures** (`core/pwa.py`): a manifest, the collector's own worker (two workers
cannot share a scope), and a post-processing injection into the served page, so the icon
reopens the lure with no new message and no new link.

**Cohorts and A/B** (`core/campaign.py`): a hash-of-target assignment, so a target always sees
the same page - a different page on the second visit is how a target notices, and it corrupts
the result by counting one person twice. The summary is built from what happened.

**Delivery and infrastructure**: redirector chains with a verifier that follows the chain with
redirects disabled (a one-hop chain hides nothing, and says so), a domain/tunnel pool with
rotation and a one-command burn, and detonation-range cloaking (`--detonation-asn`,
`--detonation-cidr`, `--cloak`). The detonation ranges are operator-supplied on purpose: the
vendor networks move, and a hardcoded list would be a guess that either blocks real visitors or
lets a sandbox through.

**The heartbeat and the domain age** (`core/heartbeat.py`): a dead-man's switch, because a
campaign that has stopped looks exactly like a campaign nobody clicked, and an RDAP age check,
because a domain registered last week is the filter both major providers apply first.

**A chain run now consults the token tier first**: a device-bound session is called out before
the browser tasks run, instead of after they fail.


## v0.1.0 — hardening: request framing, the challenge gate, the store, the operator view

**Request framing.** A non-numeric `Content-Length` raised `ValueError` out of
`handle_one_request`, which does not suppress it: the connection was dropped and the
traceback reached the operator's log, on every body route including the victim's own login
POST. All seven sites now share one `_body_len()` helper that answers 400 (the static
server had its own copy of the same bug in a different shape). A negative length reached
`rfile.read(-1)`, which reads to EOF and holds the worker thread until the client closes.
`Content-Length` together with `Transfer-Encoding`, and a duplicated `Content-Length`, let
a client frame one request two ways and smuggle a second one inside the first body's
bytes; both are refused (`_framing_ok()`). An oversized chunked body was refused *after*
reading the declared size, so a client announcing `ffffffff` and sending nothing held the
thread forever: it is refused without reading, and an oversized body that is actually sent
is still a 413. A `HEAD` request that met the challenge got a response body; it is
headers-only.

**The pre-serve challenge could be skipped.** Only `Accept: text/html` and `*/*` were
challenged, so a request with no `Accept` header, or `Accept: application/json`, or
`application/octet-stream`, received the clone *and* the hook on the first hit. The rule is
now explicit: a sub-resource fetch names the specific type it wants (`text/css`, `image/…`,
`application/javascript`, `font/…`, `video/…`, `application/wasm`) and is exempt;
everything else - including a bare `*/*`, which is what curl sends - is a navigation and
meets the challenge. POST and HEAD to a page meet it too, the collector-route exemption is
an exact match (a `startswith()` let `/__bh/verify/` through), and `X-Forwarded-Proto` is
honoured only with `--trust-headers`: over plain HTTP it made the session cookie `Secure`,
so the victim's browser never sent it back and the session was lost silently.

**Reflected input.** The interstitial's `<title>` was the campaign name, so the one page
whose purpose is to look brand-neutral announced the brand; it is neutral unless
`--verify-brand` names one. The interstitial reflected the request path into an inline
`<script>`, and `</script><script>…` closed the tag and injected - `json.dumps` escapes
quotes but not `<`. The device-code landing reflected the provider's code, URL and tag the
same way. All three escape now.

**The store.** A cookie-less page view minted a session and wrote a durable row for it, so
a scanner burst bloated the store with phantom sessions; the engine no longer saves at
session mint, and the paths that capture something (credentials, cookies, tokens, intel, a
scanner verdict, a challenge outcome) still write one. Challenge-only rows - an
unauthenticated POST to the verify route mints one each time - are capped, so the refusal
signal is kept without unbounded growth, and a session with real content is never dropped
by the cap. `session_save` itself is unchanged: it saves what it is given. The first run
against an empty `$BYTEPHISHER_HOME` raised `FileNotFoundError` out of `sqlite3.connect`
because `data/` did not exist; the store creates its own directory. With `--hook-path`, the
injected tag advertised the relocated intel route while the POST check still looked for the
default one, so the 48-module device dump fell through to the credential branch and was
stored as a junk capture; the check resolves through `_path_of` now. The static server
adopted any client-supplied 8-64 hex intel cookie verbatim - session fixation - and the
cookie was script-readable; it is server-minted unless the id names a known session, and
`HttpOnly`.

**Device-code / vault.** A failed vault write printed twelve characters of the access token
and lost the refresh token for good; the full set is spooled to `data/dc-failed-<tag>.json`
and the path is printed. One provider blip one second into an eight-second poll window
ended the whole poll: a transport failure is not a verdict, so `poll()` keeps trying until
the deadline. An unreachable issuer escaped as `URLError` and an empty one as `ValueError:
unknown url type`, both reaching the CLI as raw tracebacks; both are `DeviceCodeError`, and
the empty-issuer message says what to pass. A duplicate flow tag desynchronised the
manager's `order`/`flows` maps. `refresh()` replaced the whole token set, dropping `scope`,
`id_token` and `token_type` from the flow's own view; it merges. A hand-edited `expires_at`
made the session readers raise; an unreadable expiry means "no expiry recorded".

**The operator view.** `doctor` resolved each template directory against the current
working directory and reported 670 missing files from anywhere else: `670 registered, 0
missing files`. `lab_check` reported and created `data/campaigns.db`, a file no campaign
writes (the default is `data/bytephisher.db`), and ignored `$BYTEPHISHER_HOME`.
`--verify-first` was a silent no-op in static mode while `tools/campaign.sh` passed it
anyway; the CLI says the challenge is proxy-only and the script's default matches that. An inline `--upstream` phishlet carried no `auth_tokens`, so no cookie was ever a
session token: the session never flipped to captured and nothing was vaulted. The inline
phishlet carries a wildcard rule now (`.*:regexp`; a bare `*` is not a wildcard in
`AuthToken.matches`), and the builder is a function so a test can build one without a
server. `reuse_stats` and the session list recognised only a fixed list of identity field
names, so a form posting `loginfmt` (Microsoft) or `session_key` (LinkedIn) produced no
identity anywhere; one `identity_of()` serves both, with the password keys excluded so a
secret is never an identity, and `--sessions` gained the identity column. `--session`
showed nothing for a vaulted device-code token set; it prints the provider, the client id,
the granted scopes and the expiry. `/panic` and `/kill` existed only on the control
channel: `--panic` and `--kill --yes` are the console equivalents, reusing the same
handlers, so a console operator has a panic path without Telegram.

## v0.1.0 — production readiness: real-world preflight, a token vault, evidence, resume

Four gaps that only show up when the tool is used for real, each with the test that
proves it.

* **`tools/lab_check.py` - what this host can actually do.** Tenant reachable, domain
  resolves and its TLS is valid, egress ASN, clock drift, database writable, and the
  decisive one: **can a browser reach a live host**. On this development box it cannot
  (`ERR_ACCESS_DENIED` on any live host), so the 13 browser tasks, the takeover path and
  any live view are unverifiable there - the check says exactly that instead of a campaign
  failing halfway. `VERDICT: BLOCKED` names the checks and the fix.
* **Device-code tokens are vaulted.** They lived in memory and on the console, so the
  access token, the refresh token and the granted scopes died with the process and the
  second act had nothing to run on. `session.add_oauth()` writes them into the session
  record (keyed `dc-<tag>`, same database as every other session) and
  `oauth_valid`/`oauth_summary` read them back. Verified live: a fresh process reads the
  token, its scopes and its expiry out of the database.
* **Evidence, not booleans.** A task that ran and returned nothing was indistinguishable
  from one that worked. Every task result now becomes evidence - extracted values, files,
  assertions - and a task that produced no artefact is recorded as **UNPROVEN** with its
  error count, never as a success.
* **A restart does not orphan a session.** The durable rows were in SQLite while the
  engine's live objects were not, so a victim's next request after a crash started a
  brand-new session and the campaign looked like it had lost its targets.
  `--resume-hours` (default 12) restores the recently active sessions at startup,
  rebuilding their cookie jars. Verified live: kill the process, restart, and the same
  cookie resolves to the same session.
* `docs/FIELD_TEST.md` is the ordered list of what to run on a real host and what to look
  for at each step.

## v0.1.0 — the page is not served on the first hit (pre-serve human challenge)

The delivery audit's #1 finding: the decision to serve the clone came from the TLS
fingerprint and the User-Agent only, and the device signals that expose a headless
browser were collected by the page itself - i.e. AFTER the clone had been handed over.
A scanner with a clean UA and a browser-shaped JA3 got the page on hit #1, every time.

* `--verify-first` (`core/challenge.py`): a first visit gets a small brand-neutral
  interstitial instead of the page. It waits for real interaction (pointer, click, key,
  touch) and reads the passive tells a headless client usually cannot keep consistent
  (WebGL renderer, plugin list, timezone, languages, touch on a mobile UA). Only then
  does the server issue a signed, **session-bound**, short-lived token, and only a
  request carrying that token sees the clone.
* Two tells are disqualifying on their own: `navigator.webdriver`, and no interaction
  at all when the challenge requires it - a scanner that runs our script but never
  moves a mouse must not pass, which is the entire point.
* The interstitial carries no hook, no collector, no brand and no login form, and the
  test asserts that: there is nothing on it to fingerprint. Assets, the hook and the
  verify route are never challenged, or a visitor could not pass it.
* Refusals are recorded on the session (score + reasons) and in the challenge's own
  ring buffer, so the operator can see who was turned away and why - the signal the old
  pre-serve decision never had.
* A hostile report cannot break the route: the score reads every value defensively
  (a `"interactions": "abc"` used to raise inside the handler).
* 20 tests: token binding/tampering/expiry, the scoring rules, the interstitial's
  contents, and the real proxy end to end (first hit is the challenge; a pass issues a
  token and then serves the clone with the hook; a headless report leaves it hidden; a
  forged token and another session's token are both refused; without the flag nothing
  changes). `tools/campaign.sh` enables it (`CAMPAIGN_VERIFY=0` opts out).
* Honest trade-off: a real visitor pays one extra round trip (~2 s) that looks like an
  ordinary "checking your browser" step, and automation driving a real browser with a
  real mouse still passes - this raises the cost, it does not make the page unreachable.

## v0.1.0 — the session id stays server-side, and the names stop being a signature

Two more findings from the same measurement pass (`docs/EVASION.md`), both about
handles the page should never have.

* **The sid travelled in the page.** The injected tags carried `?s=<sid>` and both the
  hook and the collector had the id inlined as `var SID = "<sid>"`, so the page's own
  scripts (and anything inspecting `document.scripts`) could read the handle that
  identifies the victim. Attribution now comes from the **HttpOnly session cookie**:
  the page gets a meaningless per-render token, the tags carry no `?s=`, and a payload
  `sid` is honoured only when it names a live session - so a page cannot write into a
  session it merely observed or guessed. The regression test asserts the absence of the
  id AND that a cookie-only beacon still lands in the right session.
* **`--symbols fixed|random`.** `__bhs`, `__bhi`, `data-capture`, `data-beacon` and
  `data-intel` were constants, so a single signature covered every campaign. A new
  `core/symbols.py` derives a fresh, validated set per campaign and both servers write
  and read through it; the historical names remain the default so existing tooling and
  runbooks keep working, and `tools/campaign.sh` now passes `--symbols random`.
* Two bugs of my own, caught by running the tests rather than by reading them: the
  name validator rejected the historical `__bhs` (its own default), and
  `rewrite_html` called `self.engine.symbols` although it IS the engine.

## v0.1.0 — the injected hook stops looking like an injected hook

An audit measured the tool's own fingerprints instead of reasoning about fingerprints
in general (`docs/EVASION.md`), and the worst finding was ours: the hook replaced
`window.fetch` and `XMLHttpRequest.prototype.send` with plain JS wrappers, so
`fetch.toString()` returned the wrapper's source instead of `[native code]`.
PerimeterX, HUMAN and most bank integrity scripts check exactly that, which made the
hook the single most detectable thing we inject - louder than any header mismatch.

* `--hook-stealth` (on by default, `--no-hook-stealth` to debug): the wrappers report
  `function fetch() { [native code] }`, `Function.prototype.toString.toString()` is
  native too (a naive spoof is one call away from being caught), and the replacement's
  `name`, arity and property descriptor - enumerability included - are copied from the
  native it replaced, so a window global stays enumerable and a DOM prototype method
  stays non-enumerable.
* The collector is captured as a local (`collect`) before the wrappers are built: a
  named function expression binds its own name, so the XHR wrapper named `send` was
  calling ITSELF instead of the collector and silently dropping every XHR credential.
  The harness test that reports a real XHR body is what caught it.
* `tests/test_stealth_hook.py` executes the served hook - the real string, not a copy -
  in a fake page under Node and reads what an integrity script reads. The
  stealth-off case is asserted too, so the suite proves the difference rather than
  passing on a hook that patched nothing.
* Verified live through the CLI: `/__bh/hook.js` served by a running campaign carries
  the layer by default, and `--no-hook-stealth` serves `var stealth = null;`.

## v0.1.0 — device-authorization relay (RFC 8628)

A second path to the same prize that shares nothing with the reverse proxy: start the
provider's own device grant, hand the victim the code and the provider's **genuine**
verification page, and take the tokens when they approve. No lookalike domain to
classify, no cloned page to keep in step, no proxy TLS to fingerprint; MFA happens on
the real site and a passkey works, because the ceremony is where it belongs.

* `core/devicecode.py` - `DeviceCodeFlow` (start / poll / refresh, honouring
  `authorization_pending`, `slow_down`, `expired_token`, `access_denied`),
  `DeviceCodeManager` (live flows, status, capped history) and `serve()` (the landing
  page, the status route, and a poller that reports completed flows).
* Endpoints are explicit per provider, because a guessed one is a silent failure: a
  live probe showed Microsoft's `/devicecode` + `/token` and Google's `/device/code` +
  `/token` answering real OAuth errors, while Google's `/devicecode` and
  `/oauth2/token` are 404s. GitHub's paths are documented-only (an unregistered client
  id is answered with 404). A `live`-marked test keeps this honest.
* `/devicecode` needs `--dc-client-id` and refuses to guess: a wrong id fails silently
  on the provider's side, so the flag is mandatory and the tenant's refusal
  (`unauthorized_client`) is surfaced verbatim instead of being disguised as success.
* The landing page imitates nothing - the status poll is the only thing it adds - and
  the test asserts there is no provider hostname or password field in it.
* Honest state: tokens are held in memory and printed; the vault write is not
  implemented yet. Tenants that disable the grant or require a compliant device block
  the technique outright.
* 28 tests, including the `custom`-provider CLI in a real subprocess.

## v0.1.0 — proxy correctness (session cookies), the kill chain that finishes, real wipe

Each fix carries a test that fails without it.

### The upstream never received a session cookie

`transport.cookie_header` delegated to `CookieJar.add_cookie_header`, which needs a
request object with urllib's private attributes; passing a plain `Request` raised
`AttributeError`, the blanket `except` swallowed it, and the function returned an
empty string for **every** input. The upstream therefore saw no cookies at all: a
victim could log in and every following request was served the login page again.
Matching is now implemented directly (RFC 6265 domain/path/secure rules), which also
fixes the intranet and loopback upstreams this tool proxies - the stdlib policy
treats a dotless host such as `localhost` as `localhost.local` and drops valid
cookies. The regression test asserts the positive case as well as the negative one;
the suite had passed while the function returned `""` because it only checked that a
foreign cookie was *not* forwarded.

Also fixed on the same path:

* a Date-less upstream crashed `rewrite_headers` (`date_time_string` lives on the
  HTTP handler, not on the engine) and the victim got nothing;
* `Origin`/`Referer` were forwarded verbatim, so the upstream saw the proxy's origin
  and every Origin-checked login was rejected;
* `Secure` was stripped from `__Host-`/`__Secure-`/`SameSite=None` Set-Cookies over
  plain HTTP, which browsers discard, so the captured session never stuck;
* `Access-Control-Allow-Origin` went through the URL rewriter, which turned an
  unmappable origin into `/`;
* `Sec-Fetch-*` and `Upgrade-Insecure-Requests` were stripped, although a real
  browser always sends them;
* a body whose encoding could not be decoded was shipped with its collector prefix
  in front of it, and an unknown `Content-Encoding` made the transport return zero
  bytes while the declared `Content-Length` still described the original body, which
  hung the client.

### The kill chain now finishes

* **Chained steps execute.** `exploit_plan` dropped every step whose URL contains
  `{id}`, so the Docker plan created a privileged container and never started it: the
  flagship host-access path did nothing. The steps travel marked `needs_id` and the
  collector substitutes the id it reads out of the create response.
* **One hung service no longer loses the rest.** No fetch had a deadline and the
  report was gated on `Promise.all`, so a service that accepted a connection and
  never answered suppressed the whole kill wave. Each step now races a 4 s timeout.
* **It waits for the flip.** The chain ran at page load, while the browser still held
  the cached public answer for the campaign name, so its requests went to the
  operator's own address; it now starts past the rebind TTL and retries once when
  nothing answered.

### Attacker safety

* `wipe()` turned `secure_delete` on, checkpoints the WAL and truncates it, so a
  panic wipe followed by a hard exit no longer leaves the plaintext passwords in the
  `.db` or the `.db-wal` (the test reads the raw file bytes).
* `destroy_leftovers()` removes what the database never held: takeover screenshots,
  per-session result files and the tunneler logs that carry the public URL.
* The rebinding responder counted queries per source address, so every victim behind
  one resolver shared a counter and only the first saw the public answer; counting is
  keyed on the queried name (which carries a per-session label) and the map is capped.

## v0.1.0 — WebSocket relay, meta-tag CSP, and an honest capability list

* **WebSocket relay.** `Upgrade: websocket` was unhandled, so any flow that opened a
  socket froze at the handshake. The proxy now performs the upstream handshake with
  the victim's cookie jar, answers the client's `101`, rewrites the Origin, and
  pumps bytes verbatim both ways. Verified against a real socket server on loopback.
* **Meta-tag CSP.** The response header was already dropped, but a policy delivered
  as `<meta http-equiv="Content-Security-Policy">` (or the legacy `X-` form) was left
  in the body, where it would refuse the injected collector. Both forms are removed.
* **README.** The PyPhisher/ZPhisher/BlackEye comparison table is gone: those projects
  have been unmaintained for years, and comparing against them undersells the tool.
  In its place is a capability list, with every claim pointing at
  `docs/FEATURE_MATRIX.md` for the file and the test that backs it.

## v0.1.0 — deeper harvest, no-fetch attack paths, panic, clone realism

### No-fetch attack paths

* A `fetch()` to a victim's local services is what a browser refuses first: CORS
  needs a readable response, the local-network rules gate a public page reaching a
  private address, and a JSON content type forces a preflight. A **form submission**
  is a navigation, so none of that applies.
* Seven services carry a form path in `core/exploits.py` (`forms`): Jenkins
  `/scriptText` (Groovy over a form POST), Grafana `/login`, CouchDB `/_session`,
  Jupyter `/login`, RabbitMQ `/api/whoami`, CUPS `/admin/`, Prometheus-style
  `delete_series`.
* The collector submits each form into a hidden named iframe and reads the answer
  back through it while the frame is same-origin, so the output is reported with the
  rest of the kill chain. Verified by executing the real collector under Node
  (`tests/test_no_fetch_attack.py`).

### Deeper device detail

* Ten modules added to the collector: the OS voice list, the keyboard layout map,
  connected controllers, the JS heap limit, the profile's IndexedDB database names,
  OPFS availability, XR support per mode, the sensor APIs, Chrome's internal timing
  objects, and the PWA/activation state.
* The harness's DOM stub now installs its `navigator` with `defineProperty`: Node
  ships its own read-only `navigator`, so the old assignment silently did nothing
  and the collector was reading Node's.
* Stated plainly in `docs/HARVEST.md`: the web cannot reach IMEI, IMSI, the phone
  number, SMS or contacts - that needs a native app with permissions. The closest
  identity is the Client Hints `model` plus the GPU/audio/canvas fingerprints.

### Panic and attacker safety

* Telegram `/panic` (stop serving) and `/kill` (stop and wipe captures, sessions,
  intel, live input, blocked rows and lures, then vacuum), both from
  `panic_handlers()` so they can be tested without Telegram.
* `--api-token` gates every dashboard route, and binding the dashboard off-loopback
  without one now prints a warning: that API serves captured credentials.

### Clone realism

* `tools/import_site.py --url` mirrors the page's own assets (CSS, JS, images and
  the fonts a stylesheet pulls in) into `<template>/assets/`, rewrites every
  reference to a local relative path, removes third-party beacon scripts, strips SRI
  and `crossorigin` from the rewritten tags, and reports what it mirrored, removed
  and left remote. Absolute asset URLs used to put the victim's IP in the brand's
  CDN logs with a Referer from the campaign domain.

## v0.1.0 — the upstream leg stops looking like a script

### Upstream fingerprint (`--impersonate`)

* `core/transport.py` is the one place the proxy reaches the real site: it uses
  `curl_cffi` (a captured Chrome/Firefox/Safari ClientHello - cipher order,
  extensions, curves, GREASE, HTTP settings, header order) or falls back to
  `requests` with the victim's cookie jar. `--impersonate chrome` selects it.
* The extension order is permuted per request, as Chrome does, so two requests do
  not share a JA3. Verified by capturing our own outbound ClientHello and
  fingerprinting it with the project's own `core/tls_fp` - the parser that
  fingerprints visitors (`tests/test_transport.py`).
* The cookie jar stays authoritative (domain/path/secure), and duplicate
  `Set-Cookie` values survive both engines.
* Without `curl_cffi` nothing breaks: the plain transport is used and
  `--impersonate` is refused with a reason.

### Header hygiene (`--server-header`)

| mode | was | is |
|---|---|---|
| static | `Server: BaseHTTP/0.6 Python/3.14.7` | `Server: nginx` (configurable; empty omits it) |
| proxy | our `Server: nginx ` **plus** the upstream's `Server: gunicorn/19.9.0`, and `Date` twice | the upstream's `Server`/`Date`, once; ours only when it labelled itself with nothing |

## v0.1.0 — link click → system access, then a hardening pass

Same release, second pass.

### Link click → the victim's own network

* **DNS rebinding (`--rebind-domain`)** — the tool runs an authoritative responder
  for the campaign name: the first answer is the operator's public address (so the
  page loads), then, after a 1-second TTL, `127.0.0.1` (or a LAN address you
  choose). The browser now treats `http://<name>:<port>/…` as **same-origin**, so
  there is no CORS preflight and a JSON POST is allowed. The wire format is
  dependency-free and the flip is proven over a real UDP exchange
  (`tests/test_rebind.py`).
* **Local-service exploit library (`--exploit-list`)** — seventeen services taken
  from real deployments, highest payoff first: Docker API (privileged container
  with `Binds: ["/:/host"]` → host root), Jenkins `/scriptText` (Groovy → RCE),
  kubelet exec, Jupyter kernel, Ollama file read/write, Portainer, Elasticsearch,
  CouchDB, Consul, Grafana, RabbitMQ, Transmission, CUPS, Selenium Grid, Home
  Assistant, Tomcat. `tests/test_exploits.py` proves the Docker and Jenkins
  payloads against local stubs with real HTTP.
* **Router takeover plan (`--router-plan`)** — twelve panels that ship deployed,
  their default credentials, and the payoff: the LAN resolver points at this
  responder, then a port forward.
* **Service-worker persistence** — a campaign-origin worker with an IndexedDB
  queue and background sync, so a credential POST still lands when the tab is
  closed. Executed under Node in `tests/test_evasion.py`.
* **Ordered keystroke log** — modifiers, per field, IME composition and
  contenteditable, on top of the existing field-value stream.
* **Chains that act (`own`, `--auto-chain`)** — `forward-submit` creates the mail
  forwarding rule, `password-change` changes the password, `sessions-kill` ends
  the other sessions. `--auto-chain` fires on a session capture on its own thread,
  once per sid, and reports failures through the same notifier.

### Hardening

| finding | fix |
|---|---|
| `/__bh/intel` accepted `Content-Length: -1`, so `read(-1)` read to EOF with no cap and held the thread | clamp to 0, like the live and capture routes |
| the proxy trusted `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` unconditionally, so a spoofed header decided country rules, the hit cap and the researcher ranges | `trust_headers` on the engine + `--no-trust-headers` wired for proxy mode |
| `intel_scores` kept one entry per attacker-chosen sid | capped, newest half kept |
| `Gate._hits` never dropped an IP key | capped and empty keys pruned |
| `live_input` rows were unbounded per session in proxy mode | newest 2000 rows kept per session |
| the static server's `POST /intel` used the fixed path while `do_GET` used `_path_of`, so `--hook-path` silently broke the device dump | both routes relocate |
| Telegram `chunk()` emitted a single over-long line as one over-limit part, which Telegram rejects (operator loses the message) | long lines are hard-split |
| a captured cookie `Domain=` was adopted without checking it against the host, and `_guess_home` turned it into the takeover navigation URL | a foreign domain is ignored |
| `templates.json` stored absolute template dirs, so a copied checkout still pointed at the original path | relative dirs, resolved at load (verified in a moved checkout) |
| no test carried the documented `unit`/`integration` tiers, so `make test-unit` collected nothing and exited 5 | every file carries its tier marker; `-m unit` (225), `-m integration` (420), `-m live` (91) all select |
| `make proxy` opened a public tunnel although it is documented as a local demo | `-t none` |
| the proxy-mode banner printed `0 templates` | prints the mode |
| `--intel-list`'s "browser" column showed a truncated raw user agent | shows the derived browser/OS |

### Test-quality fixes

* The e2e dashboard check was vacuous (`plain is None or …` against a function
  that prints and returns `None`): stdout is captured and the capture text is
  asserted.
* `test_e2e.py` hardcoded ports 8099/8100 (its own suite rule says ports are
  allocated, never assumed): it allocates them.
* `test_gaps.py` rewrote the tracked `config/config.yaml` and restored it in
  `finally`: it points the CLI at a temporary `BYTEPHISHER_HOME` instead.
* The active-window test used `00:00-00:01` and skipped itself for the two
  minutes a day the host clock really fell inside it: the clock is now fixed
  inside `core.gate`'s namespace, and both directions (inside → served, outside →
  refused) are asserted.
* `--chains` / `--run-chain` / `--chain-json` had no CLI coverage: added
  (including the exit codes and the report keys).
* The rebind suite could hand two tests the same free port and let a lingering
  socket answer the next one: the port is released before the next test, and the
  responder logs the answer **before** it sends it, so a reply in hand always has
  a log row.
* Weak assertions made specific (exact status, exact host mapping, the derived
  browser) and the fake upstream now answers `HEAD` like a real site.

## v0.1.0 — first release

Pure-Python phishing and adversary-in-the-middle toolkit. No PHP, no web server,
no external binaries beyond the optional tunnel client.

### Delivery

* **Reverse-proxy engine (`--proxy`)** — mirrors a live site and injects the
  capture hook into the pages you select, so the victim stays on your host while
  the upstream session is genuine. Handles multi-host login chains, rewrites
  absolute URLs, neutralises `Set-Cookie` scoping, drops SRI/CSP/HSTS headers and
  relays redirects so the victim's browser performs every hop through the proxy.
  MFA is relayed, not bypassed.
* **Phishlet v2** (`config/phishlets/*.yaml`) — `proxy_hosts` for per-host
  routing, `sub_filters` for MIME-scoped rewrites, `js_inject`, `auth_tokens` and
  `auth_urls` for session-completion detection, `credentials` for field
  extraction from POST bodies and JSON, `force_post`, decoy modes, template
  parameters and child phishlets. The flat one-host form is also accepted.
* **Phishlet forge (`--phishlet-create URL`)** — builds a phishlet from a live
  login page: every host it contacts (split into domain and subdomain, CDNs
  marked `session=false`), the form's own field names, cookie names, post-login
  URLs, rewrite filters and inject points, each carrying a confidence label.
  `--forge-snapshot FILE` runs the same analysis offline against a saved copy.
* **Static mode (`-o <1-670>`)** — 670 brand templates generated with three
  layout variants, inline SVG favicons and theme colours, a honeypot field and a
  form-timing beacon. `tools/import_site.py` turns any real login page into a
  template.
* **Tunnels** — adapters for cloudflared, localhost.run, ngrok, bore and pinggy
  (serveo and hoplink were removed: both are dead services) with automatic client
  download, public-URL scraping from the
  tunneler's log, a health watchdog with restart, and per-adapter failure
  reasons.
* **Email delivery (`--mailto`)** — SMTP send with four templates, a tracking
  pixel and the live link substituted in.

### Real-time harvest (the live loop)

* **Live keystroke/field stream** — the collector beacons every input, key,
  paste and copy to its own endpoint (`/__bh/live`), debounced to ~700 ms and
  flushed on blur, submit, page hide and a 4 s interval, so the final value of a
  field always leaves the browser. Values are capped (300 chars, 40 events per
  beacon, 800 events per session, 2 MB per request) and stored in a `live_input`
  table; the operator is alerted as it arrives, not on the next page view.
* **Server-side OTP completion** — the relayed credential POST is remembered
  (`pending_login`); when a streamed value looks like a one-time code (4-8
  digits, or any 6-digit value) the proxy replays that request with the code
  appended, inside the same upstream session, and marks the session captured the
  moment the site accepts it. A rejected code is reported as rejected — the
  session stays open instead of showing a false "we own the account".
* **Autofill escalation** — every field is snapshotted at load and re-read on the
  first user gesture, because a browser keeps an autofilled password unreadable to
  script until then; the diff is the browser's own autofill.
* **Clipboard watch** — the clipboard is read once on the first gesture
  (permission-gated) and every paste/copy is streamed, because passwords and codes
  are pasted.
* **Media capture** — permission-gated webcam frame, a 1.5 s microphone clip and a
  screen frame on a gesture, each bounded and each refusal reported with its
  reason instead of silently missing.

### Post-exploitation chains

* **Chains (`--run-chain SID[:CHAIN]`, `/chain SID NAME`)** — named sequences of
  browser tasks run against a captured session: `recon` (prove access, profile,
  links), `inbox` (subjects + keyword hunt), `takeover` (forwarding, app-password,
  MFA surfaces), `lockout` (active sessions), `full`. Every task reports its own
  steps, duration, extracted values and errors, so a site whose UI differs shows
  which step failed; `ok` is only true when no task errored, and a task that
  raises does not kill the chain.
* **Keyword hunt** — `mail-hunt` extracts the mailbox and the runner reports each
  high-value term with the line it came from (invoice, bank, wire, OTP, KYC,
  password, reset...), not a bare boolean. `--chain-json` writes the whole result.
* **Task variables** — `{home}`, `{mail}`, `{settings}`, `{security}`,
  `{operator}`; a session's `meta` overrides any of them, so a chain can be aimed
  at a real site without editing code.

### Link click to system access

* **Local-service exploit library (`core/exploits.py`, `--exploit-list`)** — 17
  services as data (fingerprint + exact actions), highest payoff first: the Docker
  API creates a privileged container with the host filesystem mounted (host root),
  Jenkins runs Groovy through `/scriptText`, kubelet execs inside a pod, Jupyter
  starts a kernel, Ollama writes and reads host files, Portainer is taken over,
  Elasticsearch/CouchDB/Consul/Grafana/RabbitMQ/CUPS/Transmission/Selenium/Home
  Assistant each get the step that matters. It works because rebinding makes the
  request SAME-ORIGIN, so no CORS preflight applies and a JSON POST is allowed.
  `--exploit-ports` / `--exploit-limit` control the per-page-load plan.
* **Router takeover plan (`--router-plan`)** — login paths and default credentials
  for the panels that are actually deployed (TP-Link, D-Link, Netgear, Huawei,
  ZTE, Tenda, JioFiber, Airtel, MikroTik, OpenWrt/LuCI, pfSense, ASUSWRT), and the
  payoff: point the LAN's resolver at the rebinding responder, then forward a port.
* **Verified by execution** — a fake Docker API and a fake Jenkins are started on
  loopback, the rendered collector is run under Node, and the services must receive
  `POST /containers/create` with `Binds: ["/:/host"]` and `POST /scriptText` with
  the Groovy script. The limits are stated in `docs/EXPLOITS.md`, not implied away.

### From a link click to the victim's own network

* **DNS rebinding (`--rebind-domain`, `core/rebind.py`)** — the tool is an
  authoritative DNS responder: the campaign name is answered first with the
  operator's public address (so the page loads and its script runs), then with
  `127.0.0.1` or a LAN address after a one-second TTL. The browser then treats
  `http://<campaign-host>:2375/...` as same-origin with the page, so the response
  is READABLE: a router admin panel, the Docker API, Jupyter, Elasticsearch,
  Ollama, a kubelet, Portainer, Kibana, Prometheus, Home Assistant. The wire
  format is dependency-free and unit-tested, and the flip is proven with a real
  UDP exchange. `--rebind-public auto` detects the address; the operator supplies
  the NS delegation.
* **Local service map** — the ports and paths worth reading (`core/rebind.py`),
  with `probe_script()` producing the fetch an operator can paste into a console.
* **`lanRecon` (collector)** — the always-available half: gateway guessed from the
  WebRTC address, LAN hosts probed with cheap requests, bounded to 8 hosts x 3
  ports, and honest that a load event only proves *something is listening*.
* **Reporting that outlives the visit** — the collector registers a service worker
  served from the campaign origin (`Service-Worker-Allowed: /`) with an IndexedDB
  queue: a credential POST made after our page is gone is still reported, and
  background sync drains the queue when the network returns. It clears only what
  the server accepted. Executed and verified under Node.
* **Ordered keystroke log** — modifiers (`c/s/a/m`), the field each key went to,
  IME composition (a non-latin keyboard is not lost) and `contenteditable` input,
  streamed on its own beacon kind, bounded, and carried through the live-input
  normaliser.

### Control channel

* **Telegram two-way C2 (`--telegram-c2`)** — the bot becomes a command channel:
  `/stats`, `/sessions`, `/session SID`, `/live SID`, `/otp SID`,
  `/takeover SID [task]`, `/lures`, `/block IP`, `/blockip SID`, `/unblock IP`,
  `/help`. Only the configured chat may command it; a failing command reports
  itself; the poll loop survives a dead network; long output is split on line
  boundaries.
* **Every gating rule now applies on the AiTM path** — proxy mode ran only the
  researcher filter, so a country rule, a datacenter rule, the active window and
  the hit cap did nothing there (and the cap was never counted). All of them run
  now, with a cached geo lookup so the gate costs no extra round trip per request.
* **Country rules matched a code against a name (bug fix)** — the geo layer
  returns "India" while `--block-country` takes "IN", so a code-only block was
  silently inert and an allow list refused every visitor. The geo layer carries
  the ISO code as well, and a rule matches either.
* **Live-input retention** — `--keep-days N` prunes old beacons whenever the store
  is opened and `--live-purge SID` drops one session's stream; every keystroke
  beacon is a row, so a long campaign accumulated them without limit.
* **The live stream in the CLI** — `--session SID` prints the latest value per
  field with one-time codes flagged, not just the Telegram chat.
* **Campaign-scoped counters** — `/stats` showed a campaign's captures next to a
  session count for the whole database (`31 captures, 700 sessions`); session
  counts are now scoped to the campaign and the one figure that is not
  (blocked) says so.
* **Alert action buttons** — session and OTP alerts carry inline buttons
  (Takeover, Live, Session, Block IP, and Show codes on an OTP alert), so the
  common follow-up is one tap instead of copying a session id.

### Filtering and evasion

* **Researcher/scanner filtering (`--block-researchers`)** — refuses security
  vendors, cloud and hosting ranges, commercial VPNs and Tor, scanner and crawler
  user agents and the published scanning ranges (Shodan, Censys, Googlebot,
  bingbot, BinaryEdge, Shadowserver), plus `data/blocklist.txt` for the operator's
  own entries (`name`, `ua:`, `ip:`, `net:`). Every refusal is recorded with the
  match that caused it.
* **Decoy hygiene (bug fix)** — decoy mode served the upstream page but still
  injected the collector and set the `__bhs` cookie, handing every scanner the
  endpoint, the session id and the design. A decoy is now upstream markup only.
* **Relocatable hook path (`--hook-path`)** — one value moves every collector and
  hook route *and* the injected script tag; a fixed `/__bh` is a signature.
* **Per-session script renaming** — the collector's top-level identifiers are
  renamed deterministically from the session id, so no two victims receive
  byte-identical script and a hash or YARA rule on it does not survive the next
  victim. Verified by executing the rendered script under Node.

### Capture and intelligence

* **Browser collector** (`core/assets/intel.js`, 36 modules) — client hints, screen and
  multi-monitor, canvas/WebGL/WebGPU, audio, fonts, codecs, DRM, battery, storage
  quota, permission states, media devices, WebRTC candidates, automation
  evidence, ad-block detection, crypto capabilities and, on the gesture-gated
  path, geolocation, clipboard, notifications, USB/serial/HID and local fonts.
* **Harvest modules** — storage (localStorage, sessionStorage, IndexedDB,
  CacheStorage, service workers, readable cookies), autofill values the browser
  pre-filled, password-manager and extension detection, paste and keystroke
  behaviour, and an opt-in LAN reachability probe. Stored values that look like
  tokens (JWT or long random strings) are surfaced separately.
* **Analysis** (`core/intel.py`) — merges the waves, derives a cookie-independent
  device token, a 0-100 automation score with its evidence, VPN/datacenter
  suspicion, device class and browser/OS attribution, and renders the CLI dump.
* **Risk scoring** — 0-100 per submission with human-readable reasons; bots and
  scanners are labelled rather than dropped, so the totals reconcile.
* **JA3/JA3S** — the TLS ClientHello is parsed from the raw record before the
  handshake, with GREASE filtered per spec and SNI/ALPN/groups extracted. The
  fingerprint feeds both the visit report and the bot gate.
* **Live stream analysis** — the stream is normalised and bounded on the way in,
  summarised per field for the operator, and scanned for one-time codes.

### Session operations

* **Session vault** — one record per victim: cookies with their real attributes,
  credentials, auth tokens, JA3, geo, device token, timeline and state.
  Export and import in Cookie-Editor format, plus `--session-import` for
  hand-carried jars.
* **Browser takeover (`--takeover SID --task ...`)** — runs a task against a
  captured session in a real Chrome: `probe` (proof of access plus screenshot),
  `profile`, `links`, `inbox-subjects`, `refresh`, or a custom YAML/JSON task
  (`goto`, `click`, `fill`, `press`, `extract`, `assert_text`, `screenshot`,
  `download`, `wait`). Steps are isolated; results, screenshots and a
  `result.json` land in the output directory. `--replay FILE` serves the run from
  a saved snapshot so tasks can be developed without live traffic.
* **Session validation (`--validate SID --url URL`)** — checks whether a captured
  session is still authenticated, over plain HTTP or in the browser.
* **Credential validation (`--validate-creds SID --url URL`)** — replays the
  captured credentials at the real login endpoint and reports CONFIRMED, REJECTED
  or UNKNOWN with the evidence (marker, redirect, cookies issued).
* **Keep-alive (`--keepalive SID --url URL`)** — polls an authenticated URL on a
  schedule, re-exports rotated cookies into the vault and stops when the site
  returns a login page.

### Targeting controls

* **Gating** — country allow/block, datacenter/ASN block, active hours and
  weekdays, per-IP hit cap, with an inert decoy for refusals.
* **Bot gate (`--bot-gate N`)** — scores each visit from JA3, user agent and the
  browser dump; at or above the threshold the visitor receives the decoy and the
  visit is recorded with its evidence (`--scanners`). Three decoy modes: mirror
  the real site, a static page, or a redirect.
* **Lures** — tracked entry points at `/l/<token>` or `/#l=<token>`, with
  one-time burns, per-target labels and open/unique-visitor/conversion counts
  that follow the session into the vault.

### Operator tooling

* **Dashboard** — rich TUI with a live capture feed, plus an optional Flask web
  dashboard with an SSE stream.
* **Alerts** — Telegram and generic webhook, including a session-captured alert
  carrying the cookie jar and a ready-to-run takeover command.
* **Store** — SQLite in WAL mode with a write lock, thread-safe access, campaign
  tagging, live-input storage and CSV/JSON export.
* **`tools/doctor.py`** — environment self-check: dependencies, templates,
  database, tunnelers, network route.
* **`tools/probe_tunnels.py`** — probes every tunneler against the internet.
* **`tools/stress.py`** — load test against your own instance with a database
  integrity check after the run.
* **`tools/campaign.sh`** — one-shot launcher: preflight, server, tunnels, then
  CSV export.

### CLI

`--proxy` and static mode, `--tunnels`, `--tunnel-restart`, `--campaign`,
`--rotate`, `--reuse`, `--export`, `--web-dashboard`, `--telegram`, `--webhook`,
`--mailto`, `--geo`, `--intel-*`, `--session*`, `--takeover`, `--task`,
`--validate`, `--validate-creds`, `--keepalive`, `--lure-*`, `--phishlet*`,
`--bot-gate`, `--scanners`, `--replay`, `--decoy*`, `--tls`, `--doctor`, `--list`,
`--version`. Full list: `--help`.

### Platform support

Linux, macOS, Windows and Termux. Console output is ASCII-only, since a Windows
cp437/cp1252 console cannot encode anything else, and every text file is written
with an explicit encoding so a non-ASCII value in captured data cannot break an
export or a log. All filesystem paths are built with `os.path`; process handling
uses `Popen`/`terminate`/`kill` only.

### Scope

Capture store, CSV/JSON export, the dashboard and the session vault are the
deliverables; there is no HTML/PDF report generator.

### Tests

`tests/` — units, HTTP server, reverse proxy, phishlet v2, bot gate, forge,
session vault and takeover, live-session operations, device intel and harvest,
security regressions, console portability. Browser-driven suites run against a
real Chrome; in an environment that denies the browser process network access
they use request interception or skip with the reason recorded.

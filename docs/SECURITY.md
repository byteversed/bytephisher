# Security posture

BytePhisher was audited adversarially — a hostile auditor with shell access was
pointed at the proxy, the static server, the dashboard, the store and the CLI,
told to break them, and required to prove every claim with live output.

This document records what was found, what was fixed, and — just as important —
**what could not be broken**. Every fix is pinned by a test in
`tests/test_security.py` (31 tests), so none of it can regress silently.

---

## Threat model

| actor | can reach | must NOT be able to |
|---|---|---|
| **the victim** (anyone who opens a campaign link) | the served page, the hook, the collector, the capture/intel endpoints | make the operator's box fetch an arbitrary URL, execute script in the operator's browser, exhaust memory, hijack another victim's session |
| **a scanner / researcher** | the same surface, plus every guessable path | bypass campaign gating, pollute the capture store with junk rows |
| **a local process on the operator's box** | the dashboard API on 127.0.0.1, the SQLite store | read credentials it should not (accepted limitation — see below) |

The operator is trusted. The tool is a single-tenant, operator-run instrument;
there is no multi-tenant privilege boundary to defend.

---

## Findings and fixes

### 1. SSRF / open forward proxy — HIGH, FIXED

**Was:** `ProxyEngine.fetch()` treated any request target starting with `http`
as an absolute URL and fetched it verbatim, while the handler passed the raw,
victim-controlled request target through. A single request line

```
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

made the proxy fetch that URL from the server's network position — loopback
services, internal hosts and cloud metadata included — **and it attached the
victim's upstream cookie jar to the request**, so the victim's real session
cookies could be handed to an attacker-controlled host.

**Now:** the handler normalises every request target to path+query
(`ProxyHandler._target_path()`), so the attacker's host is dropped, and
`fetch()` refuses any absolute URL that is not the configured upstream
(`ValueError: refusing to fetch a foreign absolute URL`). Test:
`TestSSRF` — the internal service is never contacted (`hits == 0`) and metadata
content never appears in a response.

### 2. Stored XSS in the dashboard — HIGH, FIXED

**Was:** the live dashboard built table rows with JS template literals and
injected them with `insertAdjacentHTML`, without escaping. Captured field
values, campaign names, IPs and device strings are all attacker-controlled
(a victim types them), so a submitted value like
`<img src=x onerror=fetch('/api/captures')>` executed in the operator's browser
and could read the whole capture feed same-origin.

**Now:** every interpolated value passes through `esc()` before it reaches the
DOM (`esc(c.campaign)`, `esc(c.ip)`, `esc(k)`, `esc(v)`, …). Test:
`TestDashboardEscaping` asserts no raw `${...}` interpolation of a captured value
survives in the row template.

### 3. Terminal / rich-markup injection — LOW, FIXED

Captured values are printed to the operator's terminal (TUI and plain mode).
A value containing `\x1b[2J` could manipulate the terminal, and `[red]`-style
text is interpreted as rich markup (formatting spoofing, or a `MarkupError` that
kills the live view). **Now:** `dashboard._safe_cell()` strips ANSI/control
characters and escapes every `[`. Test: `TestDashboardEscaping`.

### 4. Session handling — MEDIUM, FIXED

* **Weak ids accepted.** A client could supply its own session id via the
  `?s=` query parameter with as few as 6 hex characters (24 bits) and the id was
  adopted verbatim — session fixation, and guessable ids key the per-victim
  upstream cookie jar. **Now:** client-supplied ids must match
  `^[0-9a-f]{16,64}$`; anything else is replaced by a server-generated 128-bit
  id (`secrets.token_hex(16)`). The capture payload's `sid` is validated the
  same way. Test: `TestProxySessionHardening`.
* **`__bhs` cookie lacked HttpOnly/Secure.** **Now:** `HttpOnly` always;
  `Secure` whenever the victim's connection is HTTPS (direct TLS or a tunnel
  edge, detected via the connection cipher or `X-Forwarded-Proto`).
* **Upstream `Secure` flag was always stripped.** **Now:** `Domain` is always
  removed (it must be usable on our host) but `Secure` is kept when we are
  serving HTTPS, so the upstream's transport guarantee survives. Tests cover
  both the HTTP and HTTPS paths.

### 5. Resource exhaustion — HIGH/MEDIUM, FIXED

* **Unbounded session map.** Every cookie-less request minted a session and
  nothing was ever evicted. **Now:** `MAX_SESSIONS` (5000) with
  least-recently-seen eviction of a quarter at a time.
* **Unbounded recording.** A client posting 500 events in a loop grew one
  session's recording forever. **Now:** hard cap of 5000 events per session.
* **Unbounded request bodies.** `Content-Length` was trusted and read in full;
  a declared 100 MB length blocked a worker thread. **Now:** `MAX_BODY` (2 MB)
  on both servers, `413` beyond it, negative lengths clamped to 0.
  Tests: `TestResourceLimits`.

### 6. CSV formula injection — LOW, FIXED

Captured values are exported verbatim, so a value starting with `=`, `+`, `-`,
`@`, tab or CR is executed as a formula when the operator opens the CSV in
Excel/Sheets. **Now:** `_csv_safe()` prefixes an apostrophe, applied to every
cell *and* to each field value before it is joined. Test: `TestCSVExport`.

### 7. Campaign gating bypass — MEDIUM, FIXED (two ways)

* **POST-only clients were never rate-limited** — `note_hit()` was called from
  `do_GET` only, so a client that only POSTs ignored `--max-hits` entirely.
  **Now:** POST counts against the cap too.
* **Spoofed `X-Forwarded-For` / `CF-Connecting-IP`** let a client rotate its
  apparent IP and defeat the per-IP cap and the country/datacenter rules.
  The headers are trusted by default because they are *required* behind a
  tunnel (otherwise every visitor looks like 127.0.0.1). **Now:**
  `--no-trust-headers` uses the socket address instead — use it whenever the
  server is exposed directly. Tests: `TestGatingHardening`.

### 8. `--tls` without `--cert` served plaintext — LOW, FIXED

`serve()` only wrapped the socket when both were set, so an operator who
believed they were on HTTPS was not. **Now:** it raises
`ValueError("--tls needs --cert <pem>")`. Test: `TestTLSGuard`.

### 9. Credential false-positive — LOW, FIXED (data quality)

The substring heuristic matched `pin` inside `shipping`, so an address form was
stored and reported as a credential pair. **Now:** `core/classify.py` matches on
word boundaries plus camelCase/concat forms, and is the single implementation
used by both the static server and the proxy (they used to disagree). Tests:
`TestCredentialDetection`.

### 10. Blank urlencoded values dropped — LOW, FIXED

`parse_qs` defaults to `keep_blank_values=False`, so `email=&password=x` lost
the email field and the submission stopped looking like a credential pair.
**Now:** blanks are preserved. Test: `TestBlankAndDuplicateFields`.

### 11. Campaign-scoped stats leaked global visitors — LOW, FIXED

`stats(campaign=...)` returned the global visitor count (the visitors table has
no campaign column), so every per-campaign number was wrong. **Now:** a
campaign-scoped call counts the distinct `(ip, ua)` pairs that actually
submitted to that campaign. Test: `TestCampaignScopedStats`.

### 12. `file://` import — LOW, FIXED

`tools/import_site.py` passed `--url` straight to urllib, which happily reads
`file://`. CLI-only (not network-reachable), but there was no allowlist.
**Now:** only `http://` and `https://` are accepted. Test: `TestImportSite`.

### 13. Degenerate `--active-hours` silently disabled the gate — LOW, FIXED

`--active-hours 9-9` parsed to `None`, which turned the time gate *off* while
the operator believed it was on. **Now:** `parse_hours` supports `H:MM`, accepts
`24:00` as end-of-day, and raises a clear `ValueError` for empty, inverted or
unparseable windows; the CLI prints the reason and exits 2. Boundary behaviour
(`08:59` blocked, `09:00` served, `18:00` blocked) is covered by tests.

### 14. Latent SQL identifier interpolation — INFO, unchanged

`CaptureDB._ensure_column()` builds `PRAGMA table_info({table})` with an
f-string. Not reachable with untrusted input (all callers pass literals), so it
is left as-is and documented here rather than churned.

---

## Accepted limitations (stated, not hidden)

1. **The dashboard API has no authentication.** It binds to `127.0.0.1` by
   default, so it is not remotely reachable; any local process on the operator's
   box can read it. Do not bind it to `0.0.0.0` on a shared host. The stored-XSS
   fix removes the main way a *remote* party could have reached it through the
   operator's browser.
2. **The operator's box is trusted.** Capture data lives in a plain SQLite file;
   anyone with filesystem access has it. That is inherent to a single-operator
   tool.
3. **`X-Forwarded-For` is trusted by default** because tunnels require it. If you
   expose the server directly, run with `--no-trust-headers`.
4. **The proxy terminates TLS at the tunnel**, so the client↔edge hop is the
   tunnel's TLS, not ours. Cookies are marked `Secure` when that hop is HTTPS.

---

## What the audit could NOT break (verified failures)

These attacks were attempted with live output and **failed** — recorded because
a clean negative is evidence too:

* **SQL injection** through the campaign filter or any query: `real' OR '1'='1`,
  `'; DROP TABLE captures;--`, `' UNION SELECT * FROM captures--` → 0 rows, no
  error, table intact. All queries are parameterised.
* **Path traversal / arbitrary file read** in template serving:
  `/../../../../etc/passwd`, encoded variants, null bytes → the normal index
  page. `render_site()` selects fixed filenames inside a server-chosen
  directory and never joins the request path.
* **Header injection / response splitting** in the proxy: a capture with
  `sid="evil\r\nX-Injected: 1"` produced no injected header; the session id is
  validated to `[0-9a-f]{16,64}` and `http.server` refuses CRLF in header values.
* **Cross-victim cookie leakage**: each session owns its own `http.cookiejar`;
  two victims never share upstream cookies (test in `test_proxy.py`).
* **Exception / internal-message leakage to a victim**: upstream failures return
  a generic `502`, malformed captures a generic `{"ok": false}`; stack traces go
  to the operator's stderr only.
* **XSS in the served pages' captured values**: the static report generator that
  escaped correctly is gone (reports were removed by owner decision), and the
  dashboard now escapes explicitly.

---

## Re-running the audit

```bash
./.venv/bin/python -m pytest tests/test_security.py -v     # the regression pack
./.venv/bin/python tests/run_all.py --fast                  # whole tool, no internet
```

If you change the proxy, the dashboard template, the session/cookie code, the
CSV export or the gating rules, run `test_security.py` before anything else —
it is the contract that the audit produced.

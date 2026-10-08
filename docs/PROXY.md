# Reverse-proxy mode (`--proxy`)

Static templates copy a login page. Proxy mode does something different and
much stronger: your link serves the **real, live site**, and a small hook runs
inside it. The victim's browser stays on your domain, the upstream session is
genuine, and the login really completes — so nothing looks broken.

```bash
# inline definition
./bytephisher.py --proxy --upstream sso.example.com --login-path /login \
    -p 8080 -t cloudflared --campaign q3-sso

# phishlet file (recommended for anything real)
cp config/phishlets/example.yaml config/phishlets/sso.yaml
$EDITOR config/phishlets/sso.yaml
./bytephisher.py --proxy --phishlet config/phishlets/sso.yaml -t cloudflared
```

## What the proxy does to every response

| upstream header / pattern | what BytePhisher does | why |
|---|---|---|
| `Content-Security-Policy` | removed | our hook script and `/__bh/*` calls would otherwise be blocked |
| `Strict-Transport-Security` | removed | stops the browser pinning the real site's HTTPS policy |
| `X-Frame-Options` | removed | lets the proxied page render normally |
| `integrity=` / `crossorigin=` on `<script>`/`<link>` | stripped | SRI hashes break the moment the response is rewritten |
| `Set-Cookie` with `Domain=` / `Secure` | scoping removed | the cookie must be usable on *your* host |
| `Location: https://upstream/…` | rewritten to a proxy path | keeps the victim on the proxy through redirects |
| absolute `https://upstream/…` in HTML | rewritten to proxy-relative | assets, links and forms all stay on your domain |
| `Content-Length` | recomputed | the body changed |

Every response also carries your own `__bhs=<sid>` session cookie **next to**
whatever the upstream set (two `Set-Cookie` headers) — that id ties the browser,
the upstream cookie jar and the captured data together.

## The hook

Injected into the `<head>` of every page matching `inject_paths`:

- intercepts form submits and `fetch`/`XMLHttpRequest`,
- reads the form fields the victim actually typed,
- collects a device fingerprint: UA, language, timezone, screen, plugin count,
  hardware concurrency, canvas hash, WebGL renderer, `navigator.webdriver`,
  headless hints,
- reports through `navigator.sendBeacon` (survives page unload) and falls back
  to a synchronous XHR,
- **then lets the genuine submit continue**, so the real login proceeds.

That last point is the difference between a page that "looks right" and one
that behaves right: the victim sees the real dashboard, and the engagement
records the credential, the upstream session cookies and the device profile.

## Phishlet fields

| field | meaning |
|---|---|
| `name` | campaign label stored with every capture |
| `upstream` | real host (`HOST` or `HOST:PORT`) |
| `scheme` | `https` (default) or `http` |
| `login_path` | path that presents the login form |
| `capture_fields` | field names the hook prioritises (informational) |
| `capture_cookies` | cookie names to harvest; `*` = all |
| `inject_paths` | regexes of paths that receive the hook |
| `block_paths` | regexes never touched (static assets, `.js`, `.css`, fonts) |
| `redirect_after` | where to send the victim when the flow completes |
| `strip_integrity` | drop SRI attributes (keep `true` once you inject) |
| `rewrite_hosts` | extra hosts whose absolute URLs should point back at us |
| `verify_tls` | verify the upstream certificate — leave `true` in real use |

## What works, what needs per-site work

Verified in this build against a real public HTTPS site: page fetch, rewriting,
hook injection, form POST relayed to the upstream and echoed back, hook JS
served, capture stored with campaign/credential/risk flags.

Known hard cases (honest list — not marketing):

1. **Sites that pin SRI on third-party bundles.** Stripping `integrity` fixes
   it, but a site with a strict CSP *reporting* policy will notice.
2. **WebSocket-heavy apps** (chat, live dashboards) — the proxy is HTTP/1.1
   request/response; a WebSocket upgrade is not tunnelled, so those features
   break visibly.
3. **HTTP/2-only endpoints** — we speak HTTP/1.1 upstream; most sites accept it,
   a few force h2.
4. **Client-side fingerprinting that checks the TLS/JS environment** — a
   headless-driven relay will look automated (that is what the risk score is
   for).
5. **Session replay** (reusing the harvested cookie from a different IP/UA/geo)
   will trip provider risk engines; the cookie is captured and usable, but the
   provider may step up with MFA or block — expect that, do not assume a
   guaranteed takeover.
6. **MFA is relayed, not bypassed.** The victim's real second factor goes to the
   real site through the proxy. That is by design and is the honest limit.

## Operational notes

- Proxy mode does not use static templates; `--list`/template flags are ignored.
- Gating flags (`--allow-country`, `--max-hits`, …) are **not applied** in proxy
  mode yet — the CLI prints a warning when you pass them together.
- Malformed or empty capture bodies are rejected with HTTP 400 and store
  nothing, so campaign numbers stay clean.
- `--no-verify-tls` exists for lab targets with self-signed certificates; never
  use it against a real site you are mirroring for an engagement.

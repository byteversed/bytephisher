# Deep device dump (`--intel`)

Every link served by BytePhisher runs a collector (`assets/intel.js`) the moment
the page opens. It reports everything a browser volunteers to any site on the
internet, in three waves, and keeps reporting while the tab stays open.

Nothing here exploits anything: no permission is bypassed, no cross-origin read
happens, no persistence is installed. It is the same information every analytics
script, ad network and anti-fraud vendor already collects — the difference is
that this tool keeps all of it, in full detail, for the engagement record.

---

## 1. What is collected (26 modules)

| module | what it extracts | why it matters |
|---|---|---|
| `nav` | UA, appVersion, platform, vendor, language(s), cookieEnabled, DNT/GPC, cores, deviceMemory, touch points, plugin + mimeType list, `webdriver` | baseline identity; empty plugin arrays are a headless tell |
| `uaDataHigh` | client hints: architecture, bitness, model, platform version, full version list, wow64 | the **real** device/build, survives UA spoofing |
| `screen` | resolution, avail area, viewport, window, DPR, colour depth, orientation, multi-monitor, 12 media queries | device class, VM/default resolutions, dark mode, motion prefs |
| `time` | IANA timezone, locale, calendar, numbering system, offsets in Jan and Jul (DST behaviour), formatted currency/number/relative time | geography independent of IP; DST shape reveals hemisphere |
| `canvas` | multi-font/emoji/gradient render + hash, blank-canvas check | classic fingerprint; detects anti-fingerprint faking |
| `webgl` | vendor/renderer (masked + unmasked), GL version, GLSL, 29-60 extensions, hardware limits, anisotropy | GPU model; SwiftShader/llvmpipe = VM/headless |
| `webgpu` | adapter info, features, limits | modern hardware profile |
| `audio` | OfflineAudioContext DSP sum + tail | CPU/audio-stack fingerprint |
| `math` | 20 transcendental function outputs | libm/CPU signature (hardware vs emulator) |
| `fonts` | ~110 candidate fonts probed by measurement | installed software, OS locale packs, headless detection |
| `battery` | level, charging, times | device state; charging-only phones |
| `net` | connection type, downlink, RTT, saveData, navigation timing (DNS/TCP/TLS/TTFB/next-hop), JS heap limits | network quality, proxying, device class |
| `storage` | localStorage/sessionStorage/IndexedDB/caches/serviceWorker availability, cookie length, quota + usage | private mode, persistence capability |
| `permissions` | 20 permission states | headless reports deny-everything; profile of what the user granted |
| `mediaDevices` | device counts by kind, groupIds, label visibility | cameras/mics present, permissions already granted |
| `codecs` | H.264/HEVC/AV1/VP8/VP9/Theora + AAC/MP3/Opus/Vorbis/FLAC/AC-3/ALAC, MediaSource, EME | hardware decode capability = device generation |
| `drm` | Widevine / PlayReady / FairPlay / ClearKey | platform + browser build |
| `webrtc` | local IPs (mDNS-obfuscated or real), **public IP via STUN**, ICE candidate types | VPN/proxy detection, real network path |
| `features` | 190-240 API checks (WebGPU, WebUSB, WebSerial, Bluetooth, NFC, HID, WebAuthn, WebCodecs, AI APIs, CSS features, JS engine features…) | precise browser build and capability profile |
| `automation` | driver globals (`$cdc_`, `__playwright`, `_phantom`…), chrome-object consistency, ad-block bait, extension scripts, password-manager DOM markers | bot detection with the evidence attached |
| `adblock` | fetch probe to an ad URL | blocker/extension presence |
| `gamepads` | connected pads | peripheral hints |
| `page` | form structure, hidden fields, cookie string, counts | what the victim is looking at |
| `crypto` | RNG sample, subtle-crypto algorithm list, RNG timing | platform profile |
| `behaviour` | mouse moves, keystrokes, clicks, scroll depth, time on page | human vs scripted, engagement |
| `geolocation` / `clipboard` / `notifications` / `usbSerialHid` / `localFonts` | permission-gated probes, fired on the first user gesture only with `--intel-perms` | exact coordinates, clipboard content, granted devices |

Wave timing: `open` (immediately) → `deep` (2.5 s) → `deep2` (6 s) → `final`
(12 s) → `beat` (every 30 s) → `gesture` (first interaction) → `unload`/`hidden`.

## 2. What the analysis derives (`core/intel.py`)

| conclusion | method |
|---|---|
| **device token** | SHA-256 over canvas + audio + GPU renderer + CPU cores/memory + font set + math print + screen + timezone. Stable across visits and cookie clearing; changes on re-image or spoof |
| **headless score (0-100) + reasons** | automation UA (+55), `navigator.webdriver` (+45), driver globals (+40), Selenium/Puppeteer/Playwright markers (+40), headless UA (+35), software/virtual GPU (+35), Node/Electron runtime (+25), empty plugins (+20), empty mimeTypes (+15), empty languages (+15), Chrome claims without `chrome.runtime` (+10), deny-everything permissions (+20), 0-1 cores (+10), default VM resolutions (+12), blank canvas (+20), no fonts (+12) |
| **VPN/proxy suspicion + reasons** | WebRTC public IP ≠ HTTP source IP (+45), relay-only ICE (+20), timezone vs IP country (+30), language vs IP country (+15) |
| **browser / OS / device class** | UA + client hints + feature flags (Electron/Brave/Edge/Opera/Safari detection survives UA edits) |
| **installed-software hints** | font list, DRM modules, codec support, password-manager DOM markers, extension script URLs |

All scores are *labels with evidence*, never silent drops: a bot capture is
stored and flagged, so campaign numbers stay defensible.

## 3. Reading the data

```bash
./.venv/bin/python bytephisher.py --intel-list                  # table: id, ip, country, bot, vpn, token, UA
./.venv/bin/python bytephisher.py --intel-dump latest           # full human-readable dump
./.venv/bin/python bytephisher.py --intel-dump 7                # by row id
./.venv/bin/python bytephisher.py --intel-dump <session-sid>    # by session
./.venv/bin/python bytephisher.py --intel-export data/devices.json
./.venv/bin/python bytephisher.py --export data/all.json        # captures + devices
```

The dashboard API exposes the same rows through `/api/captures` and
`/api/stats`; device dumps also ride the configured Telegram/webhook alerts on
the `open`, `gesture` and `final` waves.

## 4. Verified against a real browser

Checked with Playwright/Chromium against a running BytePhisher instance:

* collector served (55 KB) with the session id and permission switch bound;
* page delivered with the collector tag injected and the `__bhi` session cookie;
* waves merged into a single record (`['open','deep','deep2','final']`);
* **190/243** API checks collected, 26 modules, device token computed;
* correctly flagged the automated browser: headless score 100 with the UA,
  SwiftShader renderer, missing `chrome.runtime` and the default 1280x720
  resolution as evidence;
* WebRTC public IP captured and compared against the HTTP source IP;
* fonts (19), GPU (SwiftShader), codecs, DRM (Widevine/ClearKey), permissions
  matrix, battery, storage quota and behaviour counters all populated.

Two real bugs were found this way and are now pinned by tests: the collector
double-encoded its JSON (every beacon answered 400) and reading an accessor off
a prototype (`HTMLMediaElement.prototype.remote`,
`AudioContext.prototype.audioWorklet`) threw *Illegal invocation* and wiped the
entire capability matrix.

## 5. Limits, stated plainly

1. **Secure-context APIs need HTTPS.** Over plain HTTP (or `file://`) WebUSB,
   WebSerial, Bluetooth, NFC, HID and geolocation are unavailable — the dump
   reports them as missing rather than pretending. A tunnel gives you HTTPS.
2. **Permission-gated probes cost a prompt.** They run only with
   `--intel-perms`, only after a real user gesture, and a denial is recorded as
   a denial (which is itself a signal: a bot denies instantly).
3. **Safari/Firefox expose less.** Client hints and some WebGL/canvas detail are
   Chromium-only; the collector degrades module by module instead of failing.
4. **Canvas/audio values can be faked** by anti-fingerprint extensions; the
   blank-canvas flag and the font/GPU cross-checks catch the obvious cases.
5. **mDNS obfuscation** hides WebRTC local IPs on modern browsers — the public
   IP still comes through STUN, which is what the VPN check needs.
6. **VPN inference is SUSPECTED, never CONFIRMED.** A corporate NAT, a mobile
   carrier CGNAT or a split-tunnel VPN all look similar. The reasons are
   reported so a human can judge.
7. **`--no-intel` disables everything.** Use it when an engagement's scope says
   "credentials only" — the tool then behaves exactly as before this feature.

## 6. Blue-team view

The collector leaves artefacts a defender can hunt (full rules in
`docs/DETECTION.md`): requests to `/__bh/intel.js` and `/__bh/intel`, the `__bhi`
cookie, and a page whose first act is to enumerate fonts, GPU, codecs and
permissions. From the victim's own network, the strongest indicator is a login
page that performs a WebRTC STUN lookup and a
`pagead2.googlesyndication.com` fetch for no visible reason.

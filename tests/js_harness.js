/* Run the (randomised) collector under Node with a stubbed DOM and report the
 * beacons it sent. Used by tests/test_evasion.py: a rename that broke the script
 * would either throw or stop the first wave, and this makes that visible.
 *
 *   node tests/js_harness.js <script.js>
 * prints one JSON line: {"ok":true,"beacons":[...],"modules":N}
 */
const fs = require("fs");
const beacons = [];
const calls = [];
const forms = [];        // submitted forms: {action, method, fields, target}
const frameAnswer = process.env.BH_FRAME_ANSWER || "";

function el(tag) {
  const o = {
    tagName: (tag || "div").toUpperCase(), style: {}, dataset: {}, children: [],
    value: "", name: "", id: "", type: "text", selectionStart: 0, files: [],
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    appendChild(c) { this.children.push(c); return c; },
    removeChild() {}, addEventListener() {}, removeEventListener() {},
    getContext: () => ({
      fillText() {}, fillRect() {}, strokeText() {}, measureText: () => ({ width: 1 }),
      getImageData: () => ({ data: new Uint8ClampedArray(4) }),
      putImageData() {}, drawImage() {}, save() {}, restore() {}, translate() {},
      rotate() {}, scale() {}, beginPath() {}, closePath() {}, fill() {}, stroke() {},
      arc() {}, moveTo() {}, lineTo() {}, clearRect() {}, setTransform() {},
      createLinearGradient: () => ({ addColorStop() {} }),
      canvas: { width: 1, height: 1 },
    }),
    toDataURL: () => "data:image/png;base64,AA==",
    play: () => Promise.resolve(), pause() {}, load() {},
    canPlayType: () => "probably",
    insertAdjacentHTML() {}, closest: () => null, contains: () => false,
    querySelector: () => null, querySelectorAll: () => [],
    focus() {}, click() {}, getBoundingClientRect: () => ({ width: 1, height: 1, top: 0, left: 0 }),
  };
  if (String(tag).toLowerCase() === "iframe") {
    // a named frame whose document is readable while same-origin, exactly as the
    // collector expects after the rebinding flip
    o.contentDocument = {
      body: { innerText: frameAnswer, appendChild() {}, },
      createElement: el, querySelector: () => null,
    };
    o.contentWindow = { document: o.contentDocument };
  }
  if (String(tag).toLowerCase() === "form") {
    o.submit = function () {
      const fields = {};
      (o.children || []).forEach((c) => { if (c.name) fields[c.name] = c.value; });
      forms.push({ action: o.action, method: o.method, target: o.target,
                   fields: fields });
      calls.push({ url: o.action, method: "POST", body: JSON.stringify(fields) });
    };
  }
  return o;
}

global.window = global;
global.self = global;
global.location = {
  href: "https://login.example.test/session", protocol: "https:",
  hostname: "login.example.test", host: "login.example.test", pathname: "/session",
  search: "", hash: "", origin: "https://login.example.test", port: "",
};
global.document = {
  cookie: "sid=1", title: "Sign in", referrer: "https://mail.example.test/",
  readyState: "complete", visibilityState: "visible", hidden: false,
  documentElement: el("html"), head: el("head"), body: el("body"),
  addEventListener() {}, removeEventListener() {}, dispatchEvent() {},
  createElement: el, createElementNS: el, getElementById: () => null,
  hasStorageAccess: () => Promise.resolve(true),
  querySelector: () => null, querySelectorAll: () => [],
  getElementsByTagName: () => [], elementFromPoint: () => null,
  hasFocus: () => true, activeElement: el("input"),
  fonts: { check: () => false, ready: Promise.resolve(), forEach() {} },
  exitFullscreen() {}, fullscreenElement: null,
};
// Node >=21 ships its own read-only `navigator`, so `global.navigator = {...}`
// silently does nothing and the collector reads NODE's navigator (that is why
// nav.ua used to read "Node.js/26"). defineProperty actually installs the stub.
const _navStub = {
  userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    + "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  language: "en-US", languages: ["en-US", "en"], platform: "Win32",
  hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0, onLine: true,
  cookieEnabled: true, doNotTrack: null, webdriver: false,
  plugins: [], mimeTypes: [],
  getGamepads: () => ([{
    id: "Xbox Wireless Controller (STANDARD GAMEPAD Vendor: 045e Product: 02fd)",
    mapping: "standard", connected: true,
    buttons: new Array(17).fill({ pressed: false }), axes: new Array(4).fill(0),
  }]),
  keyboard: { getLayoutMap: () => Promise.resolve(new Map([["keyA", "a"], ["keyZ", "z"]])) },
  xr: { isSessionSupported: (m) => Promise.resolve(m === "inline") },
  userActivation: { isActive: true, hasBeenActive: true },
  storage: { estimate: () => Promise.resolve({ quota: 1, usage: 1 }),
             getDirectory: () => Promise.resolve({}) },
  permissions: { query: () => Promise.resolve({ state: "prompt" }) },
  mediaDevices: undefined,
  sendBeacon: (u, b) => {
    const text = b && b.__text ? String(b.__text) : "";
    beacons.push({ url: String(u), size: (b && b.size) || 0, body: text });
    return true;
  },
  getBattery: () => Promise.resolve({ level: 0.9, charging: true }),
  userAgentData: { brands: [{ brand: "Chromium", version: "124" }], mobile: false, platform: "Windows" },
};
Object.defineProperty(globalThis, "navigator", { value: _navStub,
  configurable: true, writable: true });
;
const swRegistrations = [];
global.navigator.serviceWorker = {
  register: (url, opts) => {
    swRegistrations.push({ url: String(url), scope: (opts && opts.scope) || "" });
    return Promise.resolve({ scope: (opts && opts.scope) || "/", sync: { register: () => Promise.resolve() },
                             periodicSync: { register: () => Promise.resolve() } });
  },
};
global.calls = calls;
global.swRegistrations = swRegistrations;
global.screen = {
  width: 1920, height: 1080, availWidth: 1920, availHeight: 1040,
  colorDepth: 24, pixelDepth: 24, orientation: { type: "landscape-primary", angle: 0 },
};
global.performance = {
  now: () => Date.now(), timeOrigin: Date.now(),
  // Node's fetch reports resource timing through performance: the stubbed
  // object must carry those methods or every real request throws
  markResourceTiming: () => {}, measure: () => {}, mark: () => {},
  clearMarks: () => {}, clearMeasures: () => {}, clearResourceTimings: () => {},
  getEntries: () => [], getEntriesByName: () => [], getEntriesByType: () => [],
  timing: { navigationStart: 0, domainLookupEnd: 1, connectEnd: 2, responseStart: 3, loadEventEnd: 4 },
  getEntriesByType: () => [], memory: { jsHeapSizeLimit: 4294705152 },
};
global.matchMedia = () => ({ matches: false, addListener() {}, addEventListener() {}, removeEventListener() {} });
global.speechSynthesis = {
  getVoices: () => ([
    { name: "Microsoft David Desktop - English (United States)", lang: "en-US",
      localService: true, default: true },
    { name: "Google हिन्दी", lang: "hi-IN", localService: false, default: false },
  ]),
};
global.indexedDB = {
  databases: () => Promise.resolve([{ name: "ghostery" },
                                    { name: "firebaseLocalStorageDb" }]),
};
global.AmbientLightSensor = function () { this.illuminance = 42; };
global.Magnetometer = function () {};
global.Gyroscope = function () {};
global.Accelerometer = function () {};
global.chrome = {
  csi: () => ({ startE: 1.5, onloadT: 2.5, pageT: 3.5, tran: 15 }),
  loadTimes: () => ({ navigationType: "Other", wasFetchedViaSpdy: true,
                      npnNegotiatedProtocol: "h2" }),
};
global.getComputedStyle = () => ({ getPropertyValue: () => "" });
global.setInterval = () => 0;
global.clearInterval = () => {};
global.requestAnimationFrame = () => 0;
global.cancelAnimationFrame = () => {};
global.addEventListener = () => {};
global.removeEventListener = () => {};
const realFetch = globalThis.fetch;   // Node has fetch: use it for loopback
global.fetch = (u, o) => {
  const url = String(u);
  calls.push({ url, method: (o && o.method) || "GET", body: (o && o.body) || null });
  // A loopback URL is a real request: that is how the kill-chain tests prove the
  // payload actually reaches a local service. Anything else stays stubbed, so a
  // test never touches the internet.
  // BH_HANG_URL: a service that accepts the connection and never answers. The kill
  // chain must not lose every other service's results because of one of these.
  if (process.env.BH_HANG_URL && url.indexOf(process.env.BH_HANG_URL) !== -1) {
    return new Promise(() => {});                 // never settles
  }
  // BH_JSON_ANSWER: every stubbed response carries this body, which is how the
  // id-chained steps are proven (Docker answers /containers/create with {"Id": ...}).
  const stubbed = () => Promise.resolve({
    ok: true, status: 200,
    text: () => Promise.resolve(process.env.BH_JSON_ANSWER || ""),
  });
  if (/^https?:\/\/127\.0\.0\.1:/.test(url)) {
    return realFetch(url, { method: (o && o.method) || "GET",
                            headers: (o && o.headers) || {},
                            body: (o && o.body) || undefined })
      .then(r => r.text().then(t => ({ ok: r.ok, status: r.status, text: () => Promise.resolve(t) })));
  }
  return stubbed();
};
global.XMLHttpRequest = function () { this.open = () => {}; this.send = () => {}; this.setRequestHeader = () => {}; this.addEventListener = () => {}; };
global.Blob = function (parts) {
  this.__text = (parts || []).map(p => String(p)).join("");
  this.size = this.__text.length;
  this.type = "";
};
global.FileReader = function () { this.readAsDataURL = () => { if (this.onload) this.onload(); }; };
global.indexedDB = {
  open: () => ({ onsuccess: null, onerror: null,
                 result: { transaction: () => ({ objectStore: () => ({ getAll: () => ({ onsuccess: null, result: [] }) }) }) } }),
  databases: () => Promise.resolve([{ name: "ghostery" }, { name: "firebaseLocalStorageDb" }]),
};
global.caches = undefined;
global.localStorage = { length: 0, getItem: () => null, key: () => null, setItem() {}, removeItem() {} };
global.sessionStorage = global.localStorage;
global.Image = function () { this.onload = null; this.onerror = null; setTimeout(() => this.onerror && this.onerror(), 0); };
global.Audio = function () {};
global.OffscreenCanvas = function () { return el("canvas"); };
global.speechSynthesis = {
  getVoices: () => ([
    { name: "Microsoft David Desktop - English (United States)", lang: "en-US",
      localService: true, default: true },
    { name: "Google हिन्दी", lang: "hi-IN", localService: false, default: false },
  ]),
};
global.WebGLRenderingContext = function () {};
global.CanvasRenderingContext2D = function () {};
global.MediaRecorder = undefined;
global.AudioContext = undefined;
global.webkitAudioContext = undefined;
global.RTCPeerConnection = undefined;
global.crypto = require("crypto").webcrypto;
global.TextEncoder = require("util").TextEncoder;
global.URL = require("url").URL;
global.URLSearchParams = require("url").URLSearchParams;
global.HTMLInputElement = function () {};

const file = process.argv[2];
let src;
try {
  src = fs.readFileSync(file, "utf8");
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: "read: " + e.message }));
  process.exit(1);
}
let threw = null;
try {
  // indirect eval: the collector is an IIFE and runs on load
  (0, eval)(src);
} catch (e) {
  threw = (e && (e.stack || e.message)) || String(e);
}
setTimeout(() => {
  const payload = JSON.stringify({
    ok: !threw,
    error: threw,
    beacons: beacons.map(b => b.url),
    beacon_bodies: beacons.map(b => String((b && b.body) || "")),
    call_bodies: calls.map(c => {
      const b = c.body;
      if (!b) return "";
      return String(b.__text !== undefined ? b.__text : b);
    }),
    fetches: calls.map(c => c.url),
    forms: forms,
    count: beacons.length + calls.length,
    service_worker: swRegistrations,
  });
  // a file is the reliable channel for a large report: a big console.log on a pipe
  // can be truncated, which silently looked like "the collector sent nothing"
  if (process.env.BH_OUT) {
    require("fs").writeFileSync(process.env.BH_OUT, payload);
  }
  console.log(payload);
  // process.exit() here would truncate a large stdout write on a pipe, which
  // silently corrupted the JSON this harness prints
  process.exitCode = threw ? 1 : 0;
}, Number(process.env.BH_WAIT_MS || 2600));

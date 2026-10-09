# BytePhisher - outbound network helpers.
#
# Why this module exists: Python's urllib does NOT do happy-eyeballs. On a host
# with no IPv6 route, a name that publishes an AAAA record (Cloudflare quick
# tunnels, many CDNs) resolves to IPv6 first and the connection dies with
# `OSError: [Errno 101] Network is unreachable` - even though IPv4 works fine.
#
# The IPv4 preference is applied per CONNECTION (a custom http.client
# connection class), never by patching socket.getaddrinfo: a process-wide patch
# needs a process-wide lock held for the whole request, which serialises every
# outbound call and deadlocks the moment a server thread doing a geo lookup
# waits for the lock held by the client waiting on that same server.
import http.client
import json
import socket
import urllib.error
import urllib.request

from . import __version__

_DEFAULT_UA = f"bytephisher/{__version__}"


def _ipv4_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                            source_address=None, *args, **kwargs):
    """socket.create_connection, restricted to AF_INET.

    Assignable as http.client's `_create_connection` hook, so the preference
    applies to this connection only and no global state is touched.
    """
    host, port = address
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"no IPv4 address for {host!r}")
    af, socktype, proto, _canon, sa = infos[0]
    sock = socket.socket(af, socktype, proto)
    try:
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(sa)
        return sock
    except Exception:
        sock.close()
        raise


class _IPv4HTTPConnection(http.client.HTTPConnection):
    _create_connection = staticmethod(_ipv4_create_connection)


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    _create_connection = staticmethod(_ipv4_create_connection)


class _IPv4HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_IPv4HTTPConnection, req)


class _IPv4HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        # only `context` is forwarded: HTTPSConnection does not accept a
        # check_hostname keyword on every supported interpreter
        return self.do_open(_IPv4HTTPSConnection, req,
                            context=getattr(self, "_context", None))


_OPENER = urllib.request.build_opener(_IPv4HTTPHandler, _IPv4HTTPSHandler)


def urlopen(url, timeout=8, headers=None, ipv4=True):
    """urlopen with an IPv4 preference and a sane User-Agent."""
    req = url if isinstance(url, urllib.request.Request) else urllib.request.Request(
        url, headers={"User-Agent": _DEFAULT_UA, **(headers or {})})
    if ipv4:
        return _OPENER.open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_json(url, timeout=8, headers=None, ipv4=True):
    """GET + JSON decode. Raises on transport/parse errors (callers decide)."""
    with urlopen(url, timeout=timeout, headers={"Accept": "application/json",
                                                **(headers or {})}, ipv4=ipv4) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def post_json(url, payload, timeout=8, headers=None, ipv4=True):
    """POST JSON. Returns (status, body_bytes)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": _DEFAULT_UA,
                 **(headers or {})})
    with urlopen(req, timeout=timeout, ipv4=ipv4) as r:
        return r.status, r.read()


def fetch_text(url, timeout=25, headers=None, ipv4=True):
    """GET a page as text, honouring the response charset."""
    with urlopen(url, timeout=timeout, headers=headers, ipv4=ipv4) as r:
        raw = r.read()
        charset = r.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace")


def ipv6_available(timeout=3):
    """Is there a usable IPv6 route? Used by --doctor."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("2606:4700:4700::1111", 443))     # cloudflare DNS v6
        s.close()
        return True
    except Exception:
        return False

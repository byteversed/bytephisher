# BytePhisher — outbound network helpers.
#
# Why this module exists: Python's urllib does NOT do happy-eyeballs. On a host
# with no IPv6 route, a name that publishes an AAAA record (Cloudflare quick
# tunnels, many CDNs) resolves to IPv6 first and the connection dies with
# `OSError: [Errno 101] Network is unreachable` — even though IPv4 works fine.
# Verified on this box: IPv4 connect OK, IPv6 connect Errno 101, and
# urllib to an IPv6-first host fails outright.
#
# Every outbound call in BytePhisher (geo lookups, alerts, page import) goes
# through here so it prefers IPv4, with a lock so the threaded server is safe.
import json
import socket
import threading
import urllib.error
import urllib.request

_LOCK = threading.RLock()
_DEFAULT_UA = "bytephisher/1.0"


class ipv4_only:
    """Context manager: force IPv4 resolution for outbound connections.

    Re-entrant and thread-safe (an RLock guards the process-wide patch, so two
    threads can nest it without leaving getaddrinfo patched forever)."""

    def __enter__(self):
        _LOCK.acquire()
        self._orig = socket.getaddrinfo

        def _ga(host, port, family=0, type=0, proto=0, flags=0):
            # ask for IPv4 regardless of what the caller wanted
            return self._orig(host, port, socket.AF_INET, type, proto, flags)

        self._ga = _ga
        socket.getaddrinfo = _ga
        return self

    def __exit__(self, *exc):
        socket.getaddrinfo = self._orig
        _LOCK.release()
        return False


def urlopen(url, timeout=8, headers=None, ipv4=True):
    """urlopen with an IPv4 preference and a sane User-Agent."""
    req = url if isinstance(url, urllib.request.Request) else urllib.request.Request(
        url, headers={"User-Agent": _DEFAULT_UA, **(headers or {})})
    if ipv4:
        with ipv4_only():
            return urllib.request.urlopen(req, timeout=timeout)
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
    """Is there actually an IPv6 route? Used by --doctor for an honest report."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("2606:4700:4700::1111", 443))     # cloudflare DNS v6
        s.close()
        return True
    except Exception:
        return False

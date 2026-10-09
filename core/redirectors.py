# ============================================================================
"""Redirector chains: the lure URL is never in the message.

Two problems this solves. First, a link scanner reads the first hop, and a well-chosen open
redirect shows it a trusted domain. Second, a burned domain in the body text burns the whole
campaign; a chain lets the destination move without touching the mail.

The verifier is the part that matters: a hop that has been fixed is a dead link, and a chain
whose FINAL host appears in the first hop's URL has not hidden anything. Both are checked, so
the operator learns that before the send rather than from the click rate.
"""
import urllib.parse

__all__ = ["HOP_TEMPLATES", "build_chain", "verify_chain", "describe", "RedirectError"]


class RedirectError(RuntimeError):
    """A refusal the CLI can report verbatim."""


# Open-redirect endpoints that are still common, with the parameter that carries the target.
# Each entry: name, URL template ({url} is the destination), and whether it usually still
# works (a fixed one is kept in the list so the verifier can report it dead rather than
# silently dropping it).
HOP_TEMPLATES = (
    {"name": "google", "url": "https://www.google.com/url?q={url}&sa=D", "alive": True},
    {"name": "microsoft-safe-links",
     "url": "https://na01.safelinks.protection.outlook.com/?url={url}", "alive": True},
    {"name": "facebook-l",
     "url": "https://l.facebook.com/l.php?u={url}", "alive": True},
    {"name": "linkedin",
     "url": "https://www.linkedin.com/redir/redirect?url={url}", "alive": True},
    {"name": "zoom", "url": "https://zoom.us/redirect?url={url}", "alive": True},
    {"name": "atlassian",
     "url": "https://auth.atlassian.com/authorize?redirect_uri={url}", "alive": True},
    {"name": "youtube",
     "url": "https://www.youtube.com/redirect?q={url}", "alive": True},
    {"name": "hackerone",
     "url": "https://hackerone.com/redirect?url={url}", "alive": True},
)


def _encode(url):
    return urllib.parse.quote(str(url), safe="")


def build_chain(lure_url, hops=("google", "microsoft-safe-links")):
    """Wrap a lure URL in the given hops, innermost first.

    The returned URL points at the FIRST hop; the lure is only reachable by following the
    chain, so the first hop's URL does not contain the final host.
    """
    if not lure_url:
        raise RedirectError("a chain needs a destination")
    by_name = {h["name"]: h for h in HOP_TEMPLATES}
    out = str(lure_url)
    used = []
    for name in hops:
        hop = by_name.get(name)
        if hop is None:
            raise RedirectError(f"unknown hop {name!r}; have: "
                                f"{', '.join(sorted(by_name))}")
        out = hop["url"].format(url=_encode(out))
        used.append(name)
    return {"url": out, "hops": used, "destination": str(lure_url)}


def verify_chain(chain_url, fetch=None, max_hops=6, timeout=10):
    """Follow the chain with redirects DISABLED and report what each hop does.

    `fetch(url)` must return `(status, location)`; the default uses core.net with redirect
    following switched off, so a hop is observed instead of followed.
    """
    fetch = fetch or _fetch_no_redirect
    url = chain_url if isinstance(chain_url, str) else chain_url.get("url", "")
    if not url:
        raise RedirectError("no chain URL to verify")
    seen, hops, dead = [], [], []
    for _ in range(max_hops):
        if url in seen:
            dead.append({"url": url, "why": "the chain loops"})
            break
        seen.append(url)
        try:
            status, location = fetch(url, timeout)
        except Exception as e:
            dead.append({"url": url, "why": f"{type(e).__name__}: {e}"})
            break
        hop = {"url": url, "status": status, "location": location or ""}
        hops.append(hop)
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urljoin(url, location)
            continue
        break
    # the destination is where the chain ENDED: a hop that answered 200 is the destination,
    # a redirecting hop's Location is the next step
    if not hops:
        final = ""
    elif hops[-1]["status"] in (301, 302, 303, 307, 308) and hops[-1]["location"]:
        final = hops[-1]["location"]
    else:
        final = hops[-1]["url"]
    # a chain hides the destination only if neither the destination nor its percent-encoded
    # form appears in the first hop: a one-hop chain contains it by construction
    first = hops[0]["url"] if hops else ""
    encoded = urllib.parse.quote(final, safe="") if final else ""
    hidden = bool(final) and final not in first and encoded not in first
    return {
        "hops": hops,
        "dead": dead,
        "final": final,
        "length": len(hops),
        "destination_hidden": hidden,
        "ok": bool(hops) and not dead and hops[-1]["status"] in (200, 301, 302, 303, 307, 308),
    }


def _fetch_no_redirect(url, timeout=10):
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def describe(report):
    lines = [f"redirect chain: {'ok' if report.get('ok') else 'BROKEN'}"
             f" ({report.get('length', 0)} hop(s), destination hidden: "
             f"{report.get('destination_hidden')})"]
    for hop in report.get("hops") or []:
        lines.append(f"  {hop['status']} {hop['url'][:96]}")
    for dead in report.get("dead") or []:
        lines.append(f"  DEAD {dead['url'][:80]} - {dead['why']}")
    if report.get("hops") and not report.get("destination_hidden"):
        lines.append("  ! the destination is visible in the first hop: the chain hides nothing")
    return "\n".join(lines)



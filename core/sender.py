"""Sender identity: a domain that survives a glance, and the DNS facts behind it.

Two halves.

**Candidates.** The lookalike generator produces the names a target will read as their own
organisation: character swaps a font makes ambiguous (`rn`/`m`, `l`/`I`, `0`/`o`), a letter
removed or doubled, a hyphen or a word added, a different TLD, and the IDN homoglyphs (a
Cyrillic a/e/o in an otherwise Latin name). Every candidate is validated as a
hostname, and the IDN ones are marked: a punycode name in a link is a one-look giveaway, so
the operator should know which of their candidates is one.

**Facts.** A domain is only usable for mail if it can send as itself: SPF, DKIM and DMARC are
what decide whether the message is delivered or junked, and the same records tell the
operator whether someone ELSE can spoof the brand. `check()` answers that from DNS alone -
no WHOIS, no third-party API, and no network call in the tests.
"""
import ipaddress
import re

from core import net

__all__ = ["candidates", "validate_host", "dns_facts", "check", "describe", "COMMON_SELECTORS"]

# A font, not a language: these pairs are what a reader cannot tell apart at a glance.
_SWAPS = (("rn", "m"), ("m", "rn"), ("vv", "w"), ("cl", "d"), ("li", "h"), ("0", "o"),
          ("o", "0"), ("l", "i"), ("i", "l"), ("1", "l"), ("g", "q"), ("q", "g"),
          ("5", "s"), ("s", "5"), ("u", "v"), ("v", "u"))

# IDN homoglyphs: the first character is what the reader sees, the second is the real one.
_HOMOGLYPHS = {
    "a": "\u0430",
    "e": "\u0435",
    "o": "\u043e",
    "p": "\u0440",
    "c": "\u0441",
    "x": "\u0445",
    "y": "\u0443",
    "s": "\u0455",
    "i": "\u0456",
    "j": "\u0458",
    "l": "\u04cf",
    "n": "\u0578",
    "h": "\u04bb",
    "m": "\u043c",
    "t": "\u0442",
    "d": "\u0501",
    "g": "\u0261",
    "q": "\u0566",
    "w": "\u0461",
}

_PREFIXES = ("mail", "mailer", "email", "smtp", "secure", "login", "portal", "sso",
             "accounts", "verify", "service", "notify", "alerts", "support")
_SUFFIXES = ("secure", "login", "portal", "sso", "verify", "account", "accounts",
             "service", "support", "helpdesk", "mail", "cloud", "docs", "share")
_TLDS = ("com", "net", "co", "io", "org", "info", "co.in", "in", "app", "cloud",
         "online", "site", "tech", "email")

# The selectors a mail provider actually uses, most common first.
COMMON_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1",
                    "mail", "dkim", "smtp", "mandrill", "mailchimp", "sendgrid", "zoho")

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.I)


def validate_host(name):
    """(ok, reason). A candidate has to be a hostname someone could register.

    An IDN candidate is checked through the `idna` codec: the Unicode form is a real name
    (it just renders as punycode in an address bar), so rejecting non-ASCII would silently
    throw away the whole homoglyph set.
    """
    text = str(name or "").strip().lower()
    if not text or len(text) > 253:
        return False, "empty or too long"
    if "." not in text:
        return False, "no TLD"
    try:
        ipaddress.ip_address(text)
        return False, "that is an IP address, not a name"
    except ValueError:
        pass
    if any(ch.isspace() for ch in text):
        return False, "contains whitespace"
    if text.startswith(".") or text.endswith(".") or ".." in text:
        return False, "empty label"
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "not a valid internationalised name"
    labels = ascii_name.split(".")
    if len(labels) < 2:
        return False, "no TLD"
    if not all(_LABEL.match(part) for part in labels):
        return False, "invalid label"
    if not labels[-1].isalpha() or len(labels[-1]) < 2:
        return False, "invalid TLD"
    return True, ""


def _split(domain):
    parts = str(domain or "").strip().lower().split(".")
    if len(parts) < 2:
        return parts[0] if parts else "", ""
    return ".".join(parts[:-1]), parts[-1]


def candidates(domain, limit=40, include_homoglyphs=True):
    """Lookalike candidates for a domain, best (most plausible) first.

    Each entry is a dict: `name`, `kind` (swap/omission/doubling/prefix/suffix/tld/
    homoglyph/subdomain), `needs_punycode`, and `score` (0-100, higher = more plausible).
    """
    base, tld = _split(domain)
    if not base or not tld:
        return []                     # a bare label is not a brand domain to derive from
    stem = base.replace("-", "")
    seen, out = set(), []

    def add(name, kind):
        name = str(name or "").strip().lower()
        if not name or name in seen:
            return
        ok, _why = validate_host(name)
        if not ok:
            return
        seen.add(name)
        puny = any(ord(ch) > 127 for ch in name)
        out.append({"name": name, "kind": kind, "needs_punycode": puny,
                    "score": _score(name, domain, kind, puny)})

    for a, b in _SWAPS:
        if a in stem:
            add(stem.replace(a, b, 1) + "." + tld, "swap")
    if len(stem) > 3:
        for i in range(len(stem)):
            add(stem[:i] + stem[i + 1:] + "." + tld, "omission")
        for i in range(1, len(stem)):
            add(stem[:i] + stem[i] + stem[i:] + "." + tld, "doubling")
    for prefix in _PREFIXES:
        add(f"{prefix}-{base}.{tld}", "prefix")
        add(f"{prefix}{base}.{tld}", "prefix")
    for suffix in _SUFFIXES:
        add(f"{base}-{suffix}.{tld}", "suffix")
        add(f"{base}{suffix}.{tld}", "suffix")
    for other in _TLDS:
        if other != tld:
            add(f"{base}.{other}", "tld")
    add(f"{base}.{tld}.{base}.{tld}", "subdomain")
    if include_homoglyphs:
        for i, ch in enumerate(base):
            if ch in _HOMOGLYPHS:
                add(base[:i] + _HOMOGLYPHS[ch] + base[i + 1:] + "." + tld, "homoglyph")
    out.sort(key=lambda c: -c["score"])
    return out[:limit]


def _score(name, original, kind, punycode):
    """How plausible a candidate is, 0-100.

    A short name with no hyphen and no digits reads as the real thing; a punycode name is
    visible in the address bar and scores low on purpose.
    """
    base, _tld = _split(name)
    score = 70
    if punycode:
        score -= 40
    if kind == "swap":
        score += 15
    elif kind == "omission":
        score += 10
    elif kind in ("prefix", "suffix"):
        score -= 5
    elif kind == "tld":
        score += 5
    elif kind == "doubling":
        score -= 10
    elif kind == "subdomain":
        score -= 5
    score -= 8 * base.count("-")
    score -= 6 * sum(ch.isdigit() for ch in base)
    if len(base) > 22:
        score -= 10
    if base == _split(original)[0]:
        score += 5
    return max(0, min(100, score))


def _resolve(name, kind="A"):
    """One DNS answer from Google's DoH endpoint.

    `core.net.fetch_json` returns the DECODED OBJECT (its sibling `post_json` returns a
    (status, body) tuple, which is the trap here); a transport failure returns None so the
    caller can tell "no record" from "could not ask".
    """
    url = f"https://dns.google/resolve?name={name}&type={kind}"
    try:
        body = net.fetch_json(url)
    except Exception:
        return None
    if isinstance(body, tuple):                      # tolerate the (status, body) shape
        status, body = body
        if status != 200:
            return None
    return body if isinstance(body, dict) else None


def _txt(name):
    """TXT records for a name, as one flat list of strings."""
    body = _resolve(name, "TXT")
    if not body:
        return []
    out = []
    for answer in body.get("Answer") or []:
        data = str(answer.get("data") or "")
        out.append(data.strip('"').replace('" "', ""))
    return out


def _resolves(name, kind="A"):
    body = _resolve(name, kind)
    if body is None:
        return None                                  # unknown, not "no"
    return bool(body.get("Answer"))


def _policy(records, prefix):
    """The policy value out of a record set (`v=spf1 ... -all` -> `-all`)."""
    for record in records:
        if record.lower().startswith(prefix.lower()):
            return record
    return ""


def dns_facts(domain, selectors=None, txt=None, resolves=None):
    """SPF / DKIM / DMARC facts for a domain.

    `txt` and `resolves` are injectable so the tests never touch the network; the defaults
    use Google's DNS-over-HTTPS resolver through `core/net` (IPv4-preferring).
    """
    txt = txt or _txt
    resolves = resolves or _resolves
    selectors = tuple(selectors or COMMON_SELECTORS)
    spf_records = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
    dmarc_records = [r for r in txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    dkim_found = []
    for selector in selectors:
        for record in txt(f"{selector}._domainkey.{domain}"):
            # an empty `p=` is a REVOKED key (RFC 6376), and a wildcard `*._domainkey`
            # answering with a null key is not a usable selector either
            key = re.search(r"p\s*=\s*([A-Za-z0-9+/=]+)", record)
            if key and len(key.group(1)) >= 20:
                dkim_found.append(selector)
                break
    spf = _policy(spf_records, "v=spf1")
    dmarc = _policy(dmarc_records, "v=dmarc1")
    policy = ""
    if dmarc:
        m = re.search(r"p\s*=\s*([a-z]+)", dmarc, re.I)
        policy = (m.group(1).lower() if m else "")
    return {
        "domain": domain,
        "a": resolves(domain, "A"),
        "mx": resolves(domain, "MX"),
        "spf": spf,
        "spf_strict": "-all" in spf.lower(),
        "spf_soft": "~all" in spf.lower(),
        "dmarc": dmarc,
        "dmarc_policy": policy,
        "dkim_selectors": dkim_found,
    }


def check(domain, selectors=None, txt=None, resolves=None):
    """The preflight verdict for a sending domain.

    `ok` is about the operator's own deliverability: the domain resolves, has an MX, and
    publishes SPF and DKIM so it can send as itself. `spoofable` is about the brand: a
    domain with no DMARC (or `p=none`) can be forged by anyone, which is worth knowing
    before choosing a target.
    """
    facts = dns_facts(domain, selectors=selectors, txt=txt, resolves=resolves)
    reasons, warnings = [], []
    if facts["a"] is False and facts["mx"] is False:
        reasons.append("the domain does not resolve (no A or MX record)")
    if facts["mx"] is False:
        warnings.append("no MX record: it cannot receive mail, which a reply would need")
    if not facts["spf"]:
        reasons.append("no SPF record: mail sent as this domain will be treated as a forgery")
    if not facts["dkim_selectors"]:
        warnings.append("no DKIM key found on the common selectors: sign with your own "
                        "selector and publish it")
    if not facts["dmarc"]:
        warnings.append("no DMARC record: the domain is trivially spoofable by others")
    elif facts["dmarc_policy"] in ("none", ""):
        warnings.append("DMARC is p=none: reports only, no enforcement")
    facts["ok"] = not reasons
    facts["spoofable"] = (not facts["dmarc"]) or facts["dmarc_policy"] in ("none", "")
    facts["reasons"] = reasons
    facts["warnings"] = warnings
    return facts


def describe(facts, width=78):
    """A short operator-facing report."""
    lines = [f"sender identity: {facts.get('domain')}",
             f"  resolves   : A={facts.get('a')} MX={facts.get('mx')}",
             f"  SPF        : {facts.get('spf') or '(none)'}"
             + ("  [strict]" if facts.get("spf_strict") else
                "  [soft]" if facts.get("spf_soft") else ""),
             f"  DKIM       : {', '.join(facts.get('dkim_selectors') or []) or '(none found)'}",
             f"  DMARC      : {facts.get('dmarc') or '(none)'}"
             + (f"  policy={facts.get('dmarc_policy')}" if facts.get("dmarc_policy") else ""),
             f"  verdict    : {'OK' if facts.get('ok') else 'NOT READY'}"
             + ("  (spoofable by others)" if facts.get("spoofable") else "")]
    for reason in facts.get("reasons") or []:
        lines.append(f"  ! {reason}")
    for warning in facts.get("warnings") or []:
        lines.append(f"  - {warning}")
    return "\n".join(lines)

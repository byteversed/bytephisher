# ============================================================================
"""AD CS from the outside: which template issues for anyone, and can we reach it.

A certificate is accepted as possession. The two paths that end at "a certificate for a domain
admin" are ESC1 (a template that lets the enrollee supply the subject, so the certificate says
`administrator` and the CA signs it) and ESC8 (relaying to the HTTP enrolment endpoint, which
accepts NTLM).

What a session-based tool can do is the RECONNAISSANCE: is the enrolment endpoint
reachable, does it offer NTLM (the ESC8 precondition), does it answer without authentication,
and does it disclose the template list. That is what decides whether the next step is worth
attempting, and it is all observable from a normal HTTP request.

It cannot take the CA's private key, and it does not pretend to: that needs the CA host.
"""
import re
import urllib.error
import urllib.request

from core import net

__all__ = ["AdcsError", "probe", "parse_templates", "esc_findings", "describe",
           "CERTSRV_PATHS"]

# The enrolment endpoints a CA exposes by default.
CERTSRV_PATHS = ("/certsrv/", "/CertSrv/", "/certsrv/certfnsh.asp",
                 "/certsrv/certrqxt.asp", "/certsrv/certckpn.asp")

# An auth scheme that means "NTLM is accepted here" - the ESC8 precondition.
# NTLM specifically: `Negotiate` alone means Kerberos, and reporting a hardened CA as
# "NTLM offered" is a false ESC8 that costs the operator a wasted relay attempt
_NTLM_HINTS = ("ntlm",)


class AdcsError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def probe(base_url, fetch=None, timeout=10, paths=CERTSRV_PATHS):
    """What the enrolment endpoint offers, from a plain HTTP request.

    `fetch(url)` returns `(status, headers_dict, body)`; the default does a real GET.
    """
    fetch = fetch or _get
    base = str(base_url or "").rstrip("/")
    if not base:
        raise AdcsError("no CA base URL to probe")
    out = {"base": base, "endpoints": [], "ntlm_offered": False, "anonymous_read": False,
           "templates": [], "error": ""}
    for path in paths:
        url = base + path
        try:
            status, headers, body = fetch(url, timeout)
        except Exception as e:
            out["endpoints"].append({"url": url, "status": None,
                                     "error": f"{type(e).__name__}: {e}"})
            continue
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        auth = headers.get("www-authenticate", "")
        row = {"url": url, "status": status, "auth": auth,
               "server": headers.get("server", "")}
        out["endpoints"].append(row)
        if any(hint in auth.lower() for hint in _NTLM_HINTS) \
                or "negotiate, ntlm" in auth.lower() or "ntlm," in auth.lower():
            out["ntlm_offered"] = True
        # an enrolment page is identified by the certsrv MARKER, and the template list by a
        # select named Template: a generic sign-in page with <option value="en"> was reported as
        # a CA disclosing its templates (ESC8 "readable"), a false positive that sends an
        # operator at a hardened CA
        text = str(body or "")
        low = text.lower()
        # the enrolment endpoint is a certsrv URL (the body often does not repeat it), and the
        # template list is a select named Template - a generic page with <option value="en"> is
        # not a disclosure, which is the false positive this replaces
        certsrv_url = "certfnsh" in str(url).lower() or "certsrv" in str(url).lower()
        certsrv_body = "certfnsh" in low or "certsrv" in low
        template_select = "name=template" in low or 'name="template' in low \
            or "name='template" in low
        # the URL alone is not enough: a catch-all that answers 200 to every path would make
        # every CA look anonymously reachable. The page itself has to be an enrolment page (its
        # own marker) or carry the template select.
        if status == 200 and text and (certsrv_body or (certsrv_url and template_select)):
            out["anonymous_read"] = True
            out["templates"] = parse_templates(text) if template_select else []
            if not template_select:
                out["endpoints"][-1]["note"] = ("the enrolment page answered without "
                                                "authentication but carries no template "
                                                "select: the list is not disclosed here")
    return out


def parse_templates(html_text):
    """The template names an enrolment page discloses (`<option value="...">`)."""
    out, seen = [], set()
    for match in re.finditer(r"<option[^>]*value=[\"']([^\"']{1,120})[\"']", str(html_text or ""),
                             re.I):
        name = match.group(1).strip()
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out[:60]


def esc_findings(probe_report, template_names=None):
    """Which ESC conditions the probe observed, and which it cannot see from outside."""
    found = []
    names = [str(n).lower() for n in (template_names or probe_report.get("templates") or [])]
    if probe_report.get("ntlm_offered"):
        found.append({"esc": "ESC8", "verdict": "possible",
                      "why": "the enrolment endpoint offers NTLM: relaying an authentication "
                             "to it is the precondition, and only channel binding or HTTPS "
                             "with Extended Protection removes it"})
    if probe_report.get("anonymous_read"):
        found.append({"esc": "ESC8", "verdict": "readable",
                      "why": "the enrolment page answered without authentication, so the "
                             "template list is disclosed to anyone who can reach it"})
    for hint, esc, why in (("user", "ESC1", "a template whose name suggests enrollee-supplied "
                                           "subject: only a template read (or a live enrol) "
                                           "confirms it"),
                           ("machine", "ESC1", "a machine template: check for "
                                               "enrollee-supplied subject"),
                           ("web", "ESC8", "a web-server template: the classic ESC8 target")):
        if any(hint in n for n in names):
            found.append({"esc": esc, "verdict": "check", "why": f"{why} ({hint})"})
    if not found:
        found.append({"esc": "-", "verdict": "nothing-observed",
                      "why": "no NTLM offer, no anonymous read, no suggestive template name: "
                             "the endpoint is either hardened or unreachable"})
    found.append({"esc": "ESC1-ESC7", "verdict": "not_visible_from_here",
                  "why": "template ACLs, subject flags and CA permissions live in the "
                         "directory: a template read needs LDAP access, which is not an "
                         "HTTP request"})
    return found


def describe(report):
    lines = [f"AD CS probe: {report.get('base')}",
             f"  NTLM offered: {report.get('ntlm_offered')}"
             f"   anonymous read: {report.get('anonymous_read')}"
             f"   templates seen: {len(report.get('templates') or [])}"]
    for row in report.get("endpoints") or []:
        if row.get("error"):
            lines.append(f"  ERR {row['url']} - {row['error']}")
        else:
            lines.append(f"  {row['status']} {row['url']}"
                         + (f"  auth={row['auth']}" if row.get("auth") else ""))
    for item in esc_findings(report):
        lines.append(f"  [{item['esc']}] {item['verdict']}: {item['why'][:110]}")
    return "\n".join(lines)


def _get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with net.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(200000).decode("utf-8", "replace")

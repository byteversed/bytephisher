# ============================================================================
# FILE: core/adcs_esc.py
# ============================================================================
"""ESC conditions, decided from the directory instead of guessed from a web page.

The HTTP probe (`core.adcs.probe`) can only see what the enrolment endpoint reveals. The
template flags - which is where every ESC condition actually lives - are directory attributes,
and now that there is an LDAP client (`core.ldap`) they can be read properly:

  * `msPKI-Certificate-Name-Flag` bit 0 (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) is ESC1: the
    requester chooses the subject, so the certificate can say `administrator`
  * `msPKI-Enrollment-Flag` bit 1 (`PEND_ALL_REQUESTS`) means manager approval - without it,
    the request completes on its own
  * the EKU list decides what the certificate can be used for: client authentication
    (1.3.6.1.5.5.7.3.2) is the one that matters, "any purpose" (2.5.29.37.0) is ESC2, and the
    Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1) is ESC3
  * `msPKI-Certificate-Application-Policy` is the newer form of the same thing
  * the CA's `flags` bit 0x00040000 is ESC6 (`EDITF_ATTRIBUTESUBJECTALTNAME2`): the CA honours
    a SAN in the request for EVERY template

What this module will not do is invent the ACL. ESC1 needs a principal that can enrol, ESC4
needs write access to the template, and both live in `nTSecurityDescriptor` - a security
descriptor that has to be parsed against the caller's SIDs. That is stated as SUSPECTED and
handed to the operator to confirm, rather than being reported as a finding because a flag
looked right.

Every finding carries CONFIRMED (read from an attribute) or SUSPECTED (implied, needs a check).
"""
import re

__all__ = ["ESC_FLAGS", "EKU", "analyse_templates", "analyse_ca", "report", "describe",
           "sddl_principals"]

# The flags that decide the ESC conditions.
ESC_FLAGS = {
    "ENROLLEE_SUPPLIES_SUBJECT": (0x00000001, "msPKI-Certificate-Name-Flag", "ESC1"),
    "PEND_ALL_REQUESTS": (0x00000002, "msPKI-Enrollment-Flag", "manager approval"),
    "NO_SECURITY_EXTENSION": (0x00080000, "msPKI-Enrollment-Flag", "no SID in the certificate"),
    "SUBJECT_ALT_REQUIRE_UPN": (0x00000020, "msPKI-Certificate-Name-Flag", "-"),
    "SUBJECT_ALT_REQUIRE_EMAIL": (0x00000040, "msPKI-Certificate-Name-Flag", "-"),
    "SUBJECT_ALT_REQUIRE_DNS": (0x00000080, "msPKI-Certificate-Name-Flag", "-"),
    "EDITF_ATTRIBUTESUBJECTALTNAME2": (0x00040000, "flags", "ESC6"),
}

# The EKUs worth naming.
EKU = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent (ESC3)",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "EFS recovery",
    "2.5.29.37.0": "Any Purpose (ESC2)",
}


def _int(value, default=0):
    """An LDAP attribute value as an int, or `default` when it is absent.

    An UNPARSEABLE value is not the same as an absent one, and the first version collapsed them
    (a template whose flag read "abc" or "0x1" became "no flags", so an ESC1 was silently
    missed). `_flag` below reports that case instead of hiding it.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text)
    except ValueError:
        return default


def _flag(attrs, name):
    """(value, raw, parseable) for a flag attribute: the raw text is kept so a value nobody can
    read is reported instead of being treated as zero."""
    raw = (attrs or {}).get(name)
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else ""
    text = str(raw or "").strip()
    if not text:
        return 0, "", True
    try:
        return int(text), text, True
    except ValueError:
        return 0, text, False


def _attr_list(attrs, name):
    """An attribute as a list of strings, whatever shape it arrived in."""
    value = (attrs or {}).get(name)
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _name_of(attrs):
    """The template/CA name, with a plain string handled as a string (not as a sequence whose
    first character is the name)."""
    for key in ("cn", "displayName"):
        values = _attr_list(attrs, key)
        if values:
            return values[0]
    return ""


def _ekus(row):
    out = []
    for key in ("pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy"):
        values = row.get(key)
        if values is None:
            continue
        if isinstance(values, (str, int)):
            values = [values]                      # an int is a value, not a sequence
        elif not isinstance(values, (list, tuple)):
            continue
        out.extend(str(v).strip() for v in values if str(v).strip())
    return out


def analyse_templates(template_rows, low_priv_principal=""):
    """Per-template ESC findings from the directory rows.

    `template_rows` is what `LdapClient.search` returns for the template query, and
    `low_priv_principal` (e.g. `Domain Users`) is who the operator believes can enrol - used
    only to phrase the ACL check, never to claim it.
    """
    findings = []
    for row in template_rows or []:
        if not isinstance(row, dict):
            continue                      # a list/garbage row is skipped, not crashed on
        attrs = row.get("attrs")
        if not isinstance(attrs, dict):
            attrs = row
        name = _name_of(attrs)
        name_flag, name_raw, name_ok = _flag(attrs, "msPKI-Certificate-Name-Flag")
        enroll_flag, enroll_raw, enroll_ok = _flag(attrs, "msPKI-Enrollment-Flag")
        ekus = _ekus(attrs)
        # a template with NO EKU is not the same as one that permits client authentication: the
        # first version treated "no EKU" as "client auth allowed" and stamped ESC1 CONFIRMED,
        # contradicting the module's own rule that CONFIRMED requires a client-auth EKU
        client_auth = ("1.3.6.1.5.5.7.3.2" in ekus) or ("2.5.29.37.0" in ekus)
        if not name_ok or not enroll_ok:
            findings.append({
                "esc": "-", "template": name, "verdict": "SUSPECTED",
                "why": f"a flag attribute is not a number ({name_raw or enroll_raw!r}): the "
                       "template's ESC state cannot be read from it, so nothing is claimed",
                "needs": "read the raw attribute (it may be an unusual schema version)",
            })
        manager_approval = bool(enroll_flag & 0x00000002)
        supplies_subject = bool(name_flag & 0x00000001)

        if supplies_subject and client_auth and not manager_approval:
            findings.append({
                "esc": "ESC1", "template": name, "verdict": "CONFIRMED",
                "why": "msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT (0x1), no "
                       "manager approval is required, and the EKU permits client "
                       "authentication: a requester can put any subject in the certificate",
                "needs": ("an ACE that lets a principal enrol. The template's "
                          "nTSecurityDescriptor is the only place that says so - check it for "
                          f"{low_priv_principal or 'a low-privileged principal'}"
                          + (", and note that Domain Users can enrol on many default "
                             "templates" if not low_priv_principal else "")),
                "flags": {"name_flag": hex(name_flag), "enroll_flag": hex(enroll_flag)},
            })
        if "2.5.29.37.0" in ekus:
            findings.append({
                "esc": "ESC2", "template": name, "verdict": "CONFIRMED",
                "why": "the EKU is Any Purpose (2.5.29.37.0), so the certificate can be used "
                       "for anything - including client authentication",
                "needs": "the same ACE check as ESC1",
            })
        if "1.3.6.1.4.1.311.20.2.1" in ekus:
            findings.append({
                "esc": "ESC3", "template": name, "verdict": "CONFIRMED",
                "why": "the Certificate Request Agent EKU is present: a certificate from this "
                       "template can request OTHER certificates on behalf of another user",
                "needs": "a second template that trusts the agent, and an ACE on this one",
            })
        if not ekus and supplies_subject:
            findings.append({
                "esc": "ESC1", "template": name, "verdict": "SUSPECTED",
                "why": "the enrollee supplies the subject and there is NO EKU: whether the CA "
                       "then treats the certificate as client authentication is the CA's "
                       "behaviour, not something this attribute says",
                "needs": "confirm the CA's behaviour for a template without an EKU",
            })
        if not ekus and not manager_approval:
            findings.append({
                "esc": "ESC2", "template": name, "verdict": "SUSPECTED",
                "why": "no EKU is configured at all, which some CAs treat as 'any purpose'",
                "needs": "confirm the CA's behaviour for a template without an EKU",
            })
        if manager_approval and supplies_subject:
            findings.append({
                "esc": "ESC1", "template": name, "verdict": "SUSPECTED",
                "why": "the enrollee supplies the subject, but manager approval is required - "
                       "it becomes ESC1 the moment that flag is cleared",
                "needs": "who approves, and whether that queue is watched",
            })
    return findings


def analyse_ca(ca_rows):
    """CA-level findings: ESC6 (the CA honours a SAN for every template)."""
    findings = []
    for row in ca_rows or []:
        if not isinstance(row, dict):
            continue
        attrs = row.get("attrs")
        if not isinstance(attrs, dict):
            attrs = row
        name = _name_of(attrs) or (_attr_list(attrs, "dNSHostName") or [""])[0]
        flags = _int(attrs.get("flags"))
        if flags & 0x00040000:
            findings.append({
                "esc": "ESC6", "template": f"CA: {name}", "verdict": "CONFIRMED",
                "why": "the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000): it accepts a "
                       "subject alternative name from the REQUEST, for every template",
                "needs": "any template that permits enrolment - the SAN is then yours",
            })
        if name:
            findings.append({
                "esc": "ESC8", "template": f"CA: {name}", "verdict": "SUSPECTED",
                "why": "the CA is published in the directory, so its HTTP enrolment endpoint "
                       "exists; whether it accepts NTLM is decided by core.adcs.probe",
                "needs": "core.adcs.probe on the endpoint (NTLM offer) and no EPA/channel "
                         "binding",
            })
    return findings


def sddl_principals(descriptor):
    """The principals named in an SDDL string (the raw material for the ACE check).

    Reads the SIDs out of an `nTSecurityDescriptor` rendered as SDDL; it does not decide what
    they are allowed to do, because that needs the caller's own SIDs and the ACE order. It is
    here so the operator can see who is named, which is the first question the ACL asks.
    """
    text = str(descriptor or "")
    out, seen = [], set()
    # an ACE is (type;flags;rights;object;inherit;sid) and the middle fields are often EMPTY,
    # so the only reliable read is "the SIDs inside each parenthesised group"
    for match in re.finditer(r"\(([^()]*)\)", text):
        for sid in re.findall(r"S-1-[0-9-]+", match.group(1)):
            if sid not in seen:
                seen.add(sid)
                out.append(sid)
    return out


def report(templates=(), cas=(), probe=None, low_priv_principal=""):
    """One report: the ESC findings, the probe's own observations, and what to do next.

    The inputs are materialized ONCE: counting `len(list(templates))` after the analysis had
    already consumed a generator reported "0 templates seen" beside a real finding.
    """
    templates = list(templates or [])
    cas = list(cas or [])
    findings = analyse_templates(templates, low_priv_principal=low_priv_principal)
    findings += analyse_ca(cas)
    confirmed = [f for f in findings if f["verdict"] == "CONFIRMED"]
    suspected = [f for f in findings if f["verdict"] == "SUSPECTED"]
    out = {
        "templates_seen": len(templates),
        "cas_seen": len(cas),
        "findings": findings,
        "confirmed": len(confirmed),
        "suspected": len(suspected),
        "probe": probe or {},
        "next": [],
    }
    escs = {f["esc"] for f in confirmed}
    if "ESC8" in escs or (probe or {}).get("ntlm_offered"):
        out["next"].append("core.relay.Relay(<ca url>).start() - the certificate comes back to "
                           "whoever authenticated, and NTLM over HTTP has no channel binding")
    if "ESC1" in escs or "ESC6" in escs:
        out["next"].append("request the certificate with a chosen subject: the relay carries "
                           "the enrolment POST, and the SAN is what makes it an administrator")
    if "ESC3" in escs:
        out["next"].append("enrol the agent certificate, then use it to request a certificate "
                           "on behalf of a target - the agent template is the pivot")
    if not out["next"]:
        out["next"].append("nothing confirmed: the CA is either hardened or the operator's "
                           "identity cannot read the templates (check the ACL check too)")
    out["next"].append("after a certificate: PKINIT for a TGT, then DCSync for the krbtgt "
                       "hash - the AD equivalent of the IdP signing key")
    return out


def describe(facts):
    lines = [f"AD CS ESC analysis: {facts.get('templates_seen')} template(s), "
             f"{facts.get('cas_seen')} CA(s) - {facts.get('confirmed')} confirmed, "
             f"{facts.get('suspected')} suspected"]
    for item in facts.get("findings") or []:
        lines.append(f"  [{item['verdict']:<9}] {item['esc']:<5} {item['template']}")
        lines.append(f"      {item['why']}")
        if item.get("needs"):
            lines.append(f"      needs: {item['needs']}")
    if (facts.get("probe") or {}).get("ntlm_offered"):
        lines.append("  probe: the enrolment endpoint offers NTLM (the ESC8 precondition)")
    lines.append("  next:")
    for step in facts.get("next") or []:
        lines.append(f"    - {step}")
    return "\n".join(lines)

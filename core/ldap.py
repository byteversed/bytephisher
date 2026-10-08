# ============================================================================
# FILE: core/ldap.py
# ============================================================================
"""A minimal LDAP client in pure Python: BER in, directory data out.

Every AD attack needs the directory. Which accounts have preauthentication disabled (AS-REP
roasting), which accounts carry an SPN (Kerberoasting), which certificate templates let the
enrollee choose the subject (ESC1), which ones grant enrolment to Domain Users (ESC1 again),
which CA endpoints are published (ESC8), who can write `msDS-KeyCredentialLink` (shadow
credentials). All of it is an LDAP query, and none of it is guessable from the outside.

Python has no LDAP client in the standard library and the third-party one is a dependency this
tool refuses to take for a single feature, so this module implements the slice that matters:
BER encoding/decoding, a bind (simple, or NTLM through `core.relay`'s message handling), a
search with the filters these attacks need, and a modify (for the writes an attack requires).

Honest scope: it is not a full LDAP stack. No referrals, no paging beyond what a single search
returns, no SASL beyond the NTLM path. It is enough to ask the directory the questions the
attacks ask, and it says so.
"""
import contextlib
import re
import socket

__all__ = ["LdapError", "LdapClient", "encode", "decode", "parse_filter", "filters",
           "ROOT_DSE", "ATTRS", "UAC", "describe"]

# What a search should ask for, per attack. Asking for everything is a tell and a waste.
ATTRS = {
    "asrep": ["sAMAccountName", "userAccountControl", "pwdLastSet", "lastLogonTimestamp",
              "servicePrincipalName", "memberOf"],
    "kerberoast": ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "memberOf",
                   "userAccountControl", "distinguishedName"],
    "templates": ["cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                  "msPKI-Certificate-Application-Policy", "msPKI-Private-Key-Flag",
                  "pKIExtendedKeyUsage", "nTSecurityDescriptor", "objectClass", "distinguishedName"],
    "cas": ["cn", "dNSHostName", "distinguishedName", "objectClass", "certificateTemplates"],
    "shadow": ["sAMAccountName", "msDS-KeyCredentialLink", "distinguishedName",
               "nTSecurityDescriptor"],
    "domain": ["distinguishedName", "name", "objectSid", "lockoutThreshold", "minPwdLength",
               "pwdHistoryLength", "ms-DS-MachineAccountQuota", "functionalLevel"],
}

ROOT_DSE = {"base": "", "scope": "base", "filter": "(objectClass=*)",
            "attrs": ["defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
                      "schemaNamingContext", "dnsHostName", "supportedSASLMechanisms",
                      "supportedControl", "namingContexts"]}

# userAccountControl bits worth naming.
UAC = {
    0x0001: "SCRIPT", 0x0002: "ACCOUNTDISABLE", 0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT", 0x0020: "PASSWD_NOTREQD", 0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PASSWORD_ALLOWED", 0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT", 0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT", 0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD", 0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED", 0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED", 0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH", 0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}


class LdapError(RuntimeError):
    """A refusal the CLI can report verbatim."""


# ------------------------------------------------------------------ BER --
def _length(n):
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def encode(tag, value):
    """One BER TLV. `value` is bytes, an int, or a list of encoded children."""
    if isinstance(value, int):
        if value < 0:
            # `while n: n >>= 8` never terminates for a negative int (an arithmetic shift keeps
            # the sign bit), so this is a HANG, not an error - reachable from search(scope=-1)
            # and modify(operation=-1)
            raise LdapError(f"a negative integer cannot be BER-encoded: {value}")
        if value == 0:
            body = b"\x00"
        else:
            body, n = b"", value
            while n:
                body = bytes([n & 0xFF]) + body
                n >>= 8
            if body[0] & 0x80:
                body = b"\x00" + body
        return bytes([tag]) + _length(len(body)) + body
    if isinstance(value, (list, tuple)):
        body = b"".join(value)
        return bytes([tag]) + _length(len(body)) + body
    if isinstance(value, str):
        value = value.encode("utf-8")
    return bytes([tag]) + _length(len(value)) + bytes(value)


def _read_length(buf, i):
    if i >= len(buf):
        # a TCP segment can end on a lone tag byte; `buf[i]` raised IndexError, which the frame
        # reader does not catch, so a split frame crashed the reader instead of waiting
        raise LdapError("truncated BER length")
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    count = first & 0x7F
    if count == 0 or i + count > len(buf):
        raise LdapError("bad BER length")
    return int.from_bytes(buf[i:i + count], "big"), i + count


def decode(buf, offset=0):
    """One BER TLV -> (tag, value, next_offset). A constructed value is a list of children."""
    if offset >= len(buf):
        raise LdapError("BER read past the end")
    tag = buf[offset]
    length, i = _read_length(buf, offset + 1)
    end = i + length
    if end > len(buf):
        raise LdapError("BER element longer than the buffer")
    body = buf[i:end]
    if tag & 0x20:                                  # constructed
        children, j = [], 0
        while j < len(body):
            _t, _v, j = decode(body, j)
            children.append((_t, _v))
        return tag, children, end
    if tag in (0x02, 0x0A):                         # INTEGER / ENUMERATED
        return tag, int.from_bytes(body, "big", signed=bool(body and body[0] & 0x80)), end
    if tag == 0x01:
        return tag, body != b"\x00", end
    return tag, body, end


# --------------------------------------------------------------- filters --
class filters:
    """The filters these attacks actually use (RFC 4515, the subset that matters)."""

    @staticmethod
    def present(attr):
        return f"({attr}=*)"

    @staticmethod
    def equals(attr, value):
        return f"({attr}={value})"

    @staticmethod
    def contains(attr, value):
        return f"({attr}=*{value}*)"

    @staticmethod
    def bit_and(attr, flag):
        return f"({attr}:1.2.840.113556.1.4.803:={flag})"

    @staticmethod
    def not_bit_and(attr, flag):
        return f"(!({attr}:1.2.840.113556.1.4.803:={flag}))"

    @staticmethod
    def and_(*parts):
        return "(&" + "".join(parts) + ")"

    @staticmethod
    def or_(*parts):
        return "(|" + "".join(parts) + ")"

    @staticmethod
    def not_(part):
        return f"(!{part})"

    # the ready-made questions
    @staticmethod
    def asrep_roastable():
        """Accounts that do not require Kerberos preauthentication."""
        return filters.and_(filters.equals("objectCategory", "person"),
                            filters.equals("objectClass", "user"),
                            filters.not_bit_and("userAccountControl", 0x0002),
                            filters.bit_and("userAccountControl", 0x400000))

    @staticmethod
    def kerberoastable():
        """Enabled user accounts carrying an SPN (a service ticket is crackable offline)."""
        return filters.and_(filters.equals("objectCategory", "person"),
                            filters.equals("objectClass", "user"),
                            filters.not_bit_and("userAccountControl", 0x0002),
                            filters.present("servicePrincipalName"))

    @staticmethod
    def certificate_templates():
        return filters.and_(filters.equals("objectClass", "pKICertificateTemplate"),
                            filters.present("cn"))

    @staticmethod
    def enrollment_services():
        return filters.and_(filters.equals("objectClass", "pKIEnrollmentService"),
                            filters.present("dNSHostName"))


def parse_filter(text):
    """An RFC 4515 filter string -> BER bytes.

    The protocol does not take a filter string: it takes a tree of context-tagged structures
    (and[0], or[1], not[2], equality[3], substrings[4], >=[5], <=[6], present[7],
    extensibleMatch[9]). Sending the text as a `present` filter - which is what a first version
    did - gets an empty result from a real server, which is exactly how this was found.
    """
    text = str(text or "").strip()
    if not text:
        raise LdapError("an empty filter is not a filter")
    if not text.startswith("("):
        text = f"({text})"
    if not text.endswith(")") or text.count("(") != text.count(")"):
        # an unbalanced filter must be refused: `(&(a=b)` parsed to an EMPTY AND, which LDAP
        # evaluates as TRUE - a filter that matches every entry, from a typo
        raise LdapError(f"unbalanced parentheses in the filter {text!r}")
    body = text[1:-1]
    if body.startswith("&") or body.startswith("|"):
        parts = _split_filter_list(body[1:])
        if not parts:
            raise LdapError(f"an empty {body[0]!r} filter would match everything: {text!r}")
        children = [parse_filter(p) for p in parts]
        return encode(0xA0 if body[0] == "&" else 0xA1, children)
    if body.startswith("!"):
        return encode(0xA2, [parse_filter(body[1:])])
    # an extensible match: attr:rule:=value  (this is how the AD bitwise filters are written)
    match = re.match(r"^([^:()=<>~]*)((?::[^:=]*)+):=(.*)$", body, re.S)
    if match:
        attr, rules, value = match.group(1), match.group(2), match.group(3)
        rule = [r for r in rules.split(":") if r]
        parts = []
        if rule:
            parts.append(encode(0x81, rule[-1]))
        if attr:
            parts.append(encode(0x82, attr))
        parts.append(encode(0x83, value))
        return encode(0xA9, parts)
    match = re.match(r"^([^:()=<>~]+)([=<>~]+)(.*)$", body, re.S)
    if not match:
        raise LdapError(f"cannot parse the filter {text!r}")
    attr, op, value = match.group(1), match.group(2), match.group(3)
    if op == "=":
        if value == "*":
            return encode(0x87, attr)
        if "*" in value:
            pieces = value.split("*")
            subs = []
            if pieces[0]:
                subs.append(encode(0x80, pieces[0]))                # initial
            for middle in pieces[1:-1]:
                if middle:
                    subs.append(encode(0x81, middle))               # any
            if pieces[-1]:
                subs.append(encode(0x82, pieces[-1]))               # final
            if not subs:
                return encode(0x87, attr)                           # "attr=*" is a presence
            # IMPLICIT TAGS (which LDAP uses): the [4] tag REPLACES the SEQUENCE tag, so the
            # fields go in directly. Wrapping them in a SEQUENCE makes the server answer
            # protocolError with a diagnostic about attrs, which is not about attrs at all.
            return encode(0xA4, [encode(0x04, attr), encode(0x30, subs)])
        return encode(0xA3, [encode(0x04, attr), encode(0x04, value)])
    tag = {"=": 0xA3, ">=": 0xA5, "<=": 0xA6, "~=": 0xA8}.get(op)
    if tag is None:
        raise LdapError(f"unsupported filter operator {op!r}")
    return encode(tag, [encode(0x04, attr), encode(0x04, value)])


def _split_filter_list(text):
    """Split `(a=b)(c=d)` into ['(a=b)', '(c=d)'] - nesting aware."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start:i + 1])
                start = None
    return out


class LdapClient:
    """A connection: bind, search, modify. One request at a time, like the protocol."""

    def __init__(self, host, port=389, timeout=10, connect=None):
        self.host = str(host or "")
        self.port = int(port or 389)
        self.timeout = timeout
        self._connect = connect or socket.create_connection
        self.sock = None
        self.message_id = 0
        self.bound_as = ""
        self._pending = b""

    # ------------------------------------------------------------- wire --
    def open(self):
        if self.sock is None:
            self.sock = self._connect((self.host, self.port), self.timeout)
        return self

    def close(self):
        if self.sock:
            with contextlib.suppress(OSError):
                self.sock.close()
            self.sock = None

    def _next_id(self):
        self.message_id += 1
        return self.message_id

    def _send(self, message_id, op):
        payload = encode(0x30, [encode(0x02, message_id), op])
        sock = self.open().sock
        sock.sendall(payload)
        return self._read_response(message_id)

    def _recv(self, size=8192):
        return self.open().sock.recv(size)

    def _read_response(self, message_id, max_bytes=8_000_000):
        """Every body for one message, until the response is complete.

        A search arrives as many frames: one SearchResultEntry per row, then a
        SearchResultDone. Returning only the first frame loses the rows; returning only the last
        loses them too (the Done body has no entries in it). So the whole message is collected
        and the caller decides - `_parse_entries` walks the entries, `_result` reads the code
        from the Done.
        """
        bodies, buf = [], b""
        while True:
            chunk = self._recv()
            if not chunk:
                raise LdapError("the server closed the connection")
            buf += chunk
            if len(buf) > max_bytes:
                raise LdapError(f"the response exceeded {max_bytes} bytes")
            offset = 0
            while offset < len(buf):
                try:
                    _tag, value, end = decode(buf, offset)
                except LdapError:
                    break                                   # incomplete: wait for more
                offset = end
                if not isinstance(value, list) or len(value) < 2:
                    continue
                _t, got_id = value[0]
                if got_id != message_id:
                    continue
                op_tag, body = value[1]
                # keep the operation TAG: it is what tells a SearchResultEntry (0x64) from the
                # SearchResultDone (0x65), and dropping it is why a working search parsed to
                # zero rows
                bodies.append((op_tag, body))
                if _is_final(body):
                    self._pending = buf[offset:]
                    return bodies
            buf = buf[offset:]
        return bodies

    @staticmethod
    def _result(bodies):
        """(code, matched_dn, message) from the LAST body (the Done/Response one)."""
        entry = bodies[-1] if isinstance(bodies, list) and bodies else (0, [])
        body = entry[1] if isinstance(entry, tuple) and len(entry) == 2 else (entry or [])
        code, dn, msg = 0, "", ""
        strings = 0
        for tag, value in (body or []):
            if tag == 0x0A:
                code = value if isinstance(value, int) else 0
            elif tag == 0x04:
                # LDAPResult carries matchedDN and diagnosticMessage as two UNTAGGED strings,
                # so the order is the only thing that tells them apart
                strings += 1
                text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                if strings == 1:
                    dn = text
                elif strings == 2:
                    msg = text
            elif tag == 0x80:
                msg = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        return code, dn, msg

    # ------------------------------------------------------------ verbs --
    def bind(self, dn="", password="", mechanism="simple"):
        """A bind. Simple takes a DN and a password; NTLM takes the same plus a domain."""
        mid = self._next_id()
        if mechanism == "simple":
            op = encode(0x60, [encode(0x02, 3), encode(0x04, str(dn)),
                               encode(0x80, str(password))])
        else:
            raise LdapError(f"unsupported bind mechanism {mechanism!r} (use simple, or drive "
                            "NTLM through core.relay's message handling)")
        bodies = self._send(mid, op)
        code, _dn, msg = self._result(bodies)
        if code != 0:
            raise LdapError(f"bind refused ({code}): {msg or 'no message'} "
                            f"[{'invalid credentials' if code == 49 else 'see RFC 4511'}]")
        self.bound_as = dn
        return True

    def search(self, base="", scope=2, filter_text="(objectClass=*)", attrs=None,
               size_limit=1000, timeout=15, cookie=""):
        """A search: returns a list of {dn, attrs}. `scope` 0=base 1=one 2=subtree."""
        mid = self._next_id()
        attr_list = [encode(0x04, a) for a in (attrs or [])]
        op = encode(0x63, [
            encode(0x04, str(base or "")),
            encode(0x0A, int(scope)),
            encode(0x0A, 0),                                   # derefAliases: never
            encode(0x02, int(size_limit or 1000)),
            encode(0x02, int(timeout or 15)),
            encode(0x01, False),                               # typesOnly
            parse_filter(filter_text or "(objectClass=*)"),
            encode(0x30, attr_list),
        ])
        bodies = self._send(mid, op)
        code, _dn, msg = self._result(bodies)
        if code != 0:
            raise LdapError(f"search refused ({code}): {msg}")
        return self._parse_entries(bodies)

    @staticmethod
    def _parse_entries(bodies):
        """Every SearchResultEntry across the message's bodies."""
        out = []
        for row in (bodies if isinstance(bodies, list) else []):
            tag, body = row if isinstance(row, tuple) and len(row) == 2 else (0, row)
            if tag != 0x64 or not isinstance(body, list):
                continue
            for child_tag, value in body:
                if child_tag != 0x30 or not isinstance(value, list):
                    continue
                dn, attrs = "", {}
                for child_tag, child in body:
                    if child_tag == 0x04:
                        dn = child.decode("utf-8", "replace")
                    elif child_tag == 0x30 and isinstance(child, list):
                        # PartialAttributeList: one SEQUENCE { type, vals SET OF } per attribute
                        for attr_tag, attr_seq in child:
                            if attr_tag != 0x30 or not isinstance(attr_seq, list):
                                continue
                            name, values = "", []
                            for part_tag, part in attr_seq:
                                if part_tag == 0x04:
                                    name = part.decode("utf-8", "replace")
                                elif part_tag == 0x31 and isinstance(part, list):
                                    for v_tag, v in part:
                                        if v_tag == 0x04:
                                            values.append(_as_text(v))
                            if name:
                                attrs[name] = values
                out.append({"dn": dn, "attrs": attrs})
        return out

    def modify(self, dn, changes, operation=2):
        """A modify: `changes` is {attr: [values]}. operation 0=add 1=delete 2=replace."""
        mid = self._next_id()
        parts = []
        for attr, values in (changes or {}).items():
            vals = values if isinstance(values, (list, tuple)) else [values]
            parts.append(encode(0x30, [
                encode(0x0A, int(operation)),
                encode(0x30, [encode(0x04, str(attr))]
                       + [encode(0x31, [encode(0x04, str(v))]) for v in vals]),
            ]))
        op = encode(0x66, [encode(0x04, str(dn)), encode(0x30, parts)])
        bodies = self._send(mid, op)
        code, _dn, msg = self._result(bodies)
        if code != 0:
            raise LdapError(f"modify refused ({code}): {msg}")
        return True

    # ------------------------------------------------------------ queries --
    def naming_context(self):
        """The domain's base DN, read from the root DSE."""
        rows = self.search(base="", scope=0, filter_text="(objectClass=*)",
                           attrs=ROOT_DSE["attrs"])
        attrs = (rows[0]["attrs"] if rows else {})
        # defaultNamingContext is AD's own attribute; every other server publishes the
        # standard namingContexts instead, so try both before giving up
        for key in ("defaultNamingContext", "rootDomainNamingContext", "namingContexts"):
            value = attrs.get(key) or []
            if value and str(value[0]).strip():
                return str(value[0]).strip()
        raise LdapError("the server published no naming context in its root DSE")

    def domain_facts(self, base=None):
        """Lockout policy and machine-account quota: the numbers the attacks must respect."""
        base = base or self.naming_context()
        rows = self.search(base=base, scope=0, filter_text="(objectClass=*)",
                           attrs=ATTRS["domain"])
        attrs = (rows[0]["attrs"] if rows else {})
        return {k: (_as_text(v[0]) if v else "") for k, v in attrs.items()}

    def describe(self):
        return f"LDAP {self.host}:{self.port} (bound as {self.bound_as or 'anonymous'})"


def _is_final(body):
    """True when a response body carries a result code (Done / BindResponse / ModifyResponse).

    A SearchResultEntry does not, which is what makes this the right test for "the answer is
    complete" - without it the reader would return on the first entry of a search.
    """
    return any(tag == 0x0A for tag, _value in (body or []))


def _as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def describe(facts):
    if isinstance(facts, dict) and "host" in facts:
        return f"ldap: {facts['host']}:{facts.get('port', 389)}"
    return f"ldap: {facts}"

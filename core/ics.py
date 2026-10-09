"""Calendar invites, standard library only.

An `.ics` is the delivery shape that survives a suspicious recipient: the mail client
renders it as an event with a location and a link, and the attachment itself carries the
lure URL. This module writes a valid VEVENT (VCALENDAR 2.0) with the fields a client
needs to offer Accept / Maybe / Decline, and it folds long lines per RFC 5545 so a URL is
not broken in a way that stops the client parsing the file.

`icalendar` is used by the tests only, as an independent parser.
"""
import re
import time

__all__ = ["invite", "fold", "parse_fields"]

_PRODID = "-//BytePhisher//Calendar//EN"


def _stamp(ts):
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ts))


def _escape(text):
    """RFC 5545 TEXT escaping: backslash, semicolon, comma, newline."""
    out = str(text or "")
    out = out.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")
    return re.sub(r"\r?\n", "\\n", out)


def fold(line, limit=75):
    """Fold one content line to `limit` octets (continuation lines start with a space)."""
    raw = line.encode("utf-8")
    if len(raw) <= limit:
        return line
    chunks, first = [], True
    while raw:
        room = limit if first else limit - 1
        cut = min(room, len(raw))
        while cut > 0 and (raw[cut - 1] & 0xC0) == 0x80:      # never split a character
            cut -= 1
        chunks.append(raw[:cut].decode("utf-8", "replace"))
        raw = raw[cut:]
        first = False
    return "\r\n ".join(chunks)


def invite(uid, summary, url, description="", location="", organizer="",
           attendees=None, start=None, minutes=30, method="REQUEST"):
    """An .ics file as bytes: one VEVENT whose link is the lure.

    `method=REQUEST` is what makes a client offer Accept/Decline; `PUBLISH` is the shape
    for a one-way notice. Attendees are `(address, name)` pairs.
    """
    start = start if start is not None else time.time() + 3600
    end = start + max(5, int(minutes)) * 60
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        f"PRODID:{_PRODID}",
        "CALSCALE:GREGORIAN",
        f"METHOD:{method}",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{_stamp(time.time())}",
        f"DTSTART:{_stamp(start)}",
        f"DTEND:{_stamp(end)}",
        f"SUMMARY:{_escape(summary)}",
    ]
    if description:
        lines.append(f"DESCRIPTION:{_escape(description)}")
    if url:
        lines.append(f"URL:{_escape(url)}")
        lines.append(f"LOCATION:{_escape(location or url)}")
    elif location:
        lines.append(f"LOCATION:{_escape(location)}")
    if organizer:
        lines.append(f"ORGANIZER;CN={_escape(organizer)}:mailto:{organizer}")
    for addr, name in (attendees or []):
        lines.append(f"ATTENDEE;CN={_escape(name or addr)};RSVP=TRUE:mailto:{addr}")
    lines += ["SEQUENCE:0", "STATUS:CONFIRMED", "TRANSP:OPAQUE",
              "BEGIN:VALARM", "TRIGGER:-PT10M", "ACTION:DISPLAY",
              f"DESCRIPTION:{_escape(summary)}", "END:VALARM",
              "END:VEVENT", "END:VCALENDAR"]
    return ("\r\n".join(fold(line) for line in lines) + "\r\n").encode("utf-8")


def parse_fields(data):
    """Minimal reader used by the CLI to show what an .ics contains.

    Splits folded lines, then returns the VEVENT fields as a dict. The tests compare its
    view with a real parser's.
    """
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    text = re.sub(r"\r?\n[ \t]", "", text)                   # unfold
    out, inside = {}, False
    for line in text.splitlines():
        if line == "BEGIN:VEVENT":
            inside = True
            continue
        if line == "END:VEVENT":
            break
        if not inside or ":" not in line:
            continue
        key, value = line.split(":", 1)
        name = key.split(";", 1)[0].upper()
        out[name] = value
    return out

# ============================================================================
"""The reply inbox: the second act, driven by what the target actually wrote.

A campaign is not one message. The first message gets a click; what follows decides whether
there is a second one, and the difference between a template and a conversation is that the
second message answers what the target asked. That means reading the replies.

This module reads a mailbox over IMAP (stdlib only), threads each message against the
campaign's own `Message-ID`s, classifies the reply, and suggests the follow-up the pretext
already has a script for. Nothing is sent from here: the operator reads the classification and
sends, because a wrong second message is worse than none.

Classification is deliberately blunt - question / hesitant / refused / forwarded / leaked
credentials / out of office - because a wrong label is cheap to fix and a missed refusal is
not.
"""
import contextlib
import email
import imaplib
import re

from core import pretexts

__all__ = ["CLASSES", "InboxError", "classify", "thread", "fetch", "suggest", "describe"]

CLASSES = ("question", "hesitant", "refused", "forwarded", "credentials", "auto_reply",
           "unknown")

# Ordered: the first pattern that matches wins, so the strongest signals come first.
# The Hindi half of the credential pattern. Kept as a separate NON-raw literal: a raw string
# would leave `\u092e` as six literal characters, and the regex would look for them.
_HI_PASSWORD = "\u092e\u0947\u0930\u093e \u092a\u093e\u0938\u0935\u0930\u094d\u0921"

_PATTERNS = (
    ("credentials", r"(password|passcode|otp|one[- ]time|code is|verification code|"
                    + _HI_PASSWORD + r")"),
    ("refused", r"(not interested|unsubscribe|stop emailing|don'?t contact|"
                r"report(ed)? (this|you)|phish|scam|suspicious)"),
    ("forwarded", r"(forwarded|fyi|i am forwarding|passing this to|looping in|"
                  r"adding (our )?it)"),
    ("auto_reply", r"(out of office|automatic reply|auto[- ]?reply|on leave|"
                   r"currently away|will be back)"),
    ("hesitant", r"(is this (real|legit|genuine)|are you sure|how do i know|"
                 r"seems (odd|weird|strange)|who is this|why do you need)"),
    ("question", r"\?"),
)


class InboxError(RuntimeError):
    """A refusal the CLI can report verbatim."""


def classify(subject="", body=""):
    """(class, why) for one reply. The strongest signal wins, and `unknown` is allowed."""
    text = f"{subject}\n{body}".lower()
    for name, pattern in _PATTERNS:
        match = re.search(pattern, text, re.I)
        if match:
            return name, f"matched {match.group(0)[:40]!r}"
    return "unknown", "no signal matched; read it"


def thread(messages, campaign_ids=None):
    """Group replies against the campaign's own Message-IDs.

    `messages` is a list of dicts with `message_id`, `in_reply_to`, `references`, `subject`,
    `from`, `body`. A message threads to a campaign id when it references it, or when its
    subject carries the campaign tag.
    """
    campaign_ids = {str(i) for i in (campaign_ids or []) if i}
    threads = {}
    for msg in messages or []:
        refs = set()
        for field in ("in_reply_to", "references"):
            value = str(msg.get(field) or "")
            refs.update(re.findall(r"<[^>]+>", value))
            refs.update(p for p in value.split() if p)
        hit = next((r for r in refs if r in campaign_ids), "")
        key = hit or _subject_key(msg.get("subject", ""))
        threads.setdefault(key, []).append(msg)
    return threads


def _subject_key(subject):
    """A subject with EVERY reply/forward prefix stripped ("Re: Fwd: Re: x" -> "x")."""
    text = str(subject or "").strip()
    while True:
        stripped = re.sub(r"^(re|fwd|fw|aw|sv)\s*(\[\d+\])?\s*:\s*", "", text, flags=re.I)
        if stripped == text:
            break
        text = stripped
    return text.lower()[:80] or "(no subject)"


def fetch(host="", user="", password="", folder="INBOX", limit=50, search="UNSEEN",
          timeout=20, client=None):
    """Read replies over IMAP. `client` is injectable so a test needs no server.

    Returns a list of dicts: from, subject, body, message_id, in_reply_to, references, date.
    """
    if client is None:
        if not host or not user:
            raise InboxError("IMAP needs a host and a user (--inbox-host/--inbox-user)")
        client = _connect(host, user, password, timeout)
    out = []
    try:
        client.select(folder)
        typ, data = client.search(None, search or "ALL")
        if typ != "OK":
            raise InboxError(f"IMAP search refused: {typ}")
        ids = (data[0] or b"").split()
        for num in ids[-int(limit or 50):]:
            typ, raw = client.fetch(num, "(RFC822)")
            if typ != "OK" or not raw or not raw[0]:
                continue
            msg = email.message_from_bytes(raw[0][1])
            out.append(_as_dict(msg))
    finally:
        with contextlib.suppress(Exception):
            client.logout()
    return out


def _connect(host, user, password, timeout):
    try:
        client = imaplib.IMAP4_SSL(host, timeout=timeout)
    except Exception:
        client = imaplib.IMAP4(host, timeout=timeout)
    try:
        client.login(user, password)
    except Exception as e:
        raise InboxError(f"IMAP login failed: {type(e).__name__}: {e}") from e
    return client


def _as_dict(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                with contextlib.suppress(Exception):
                    body = part.get_payload(decode=True).decode("utf-8", "replace")
                    break
    else:
        with contextlib.suppress(Exception):
            body = msg.get_payload(decode=True).decode("utf-8", "replace")
    return {"from": msg.get("From", ""), "subject": msg.get("Subject", ""),
            "body": (body or "")[:4000], "message_id": msg.get("Message-ID", ""),
            "in_reply_to": msg.get("In-Reply-To", ""),
            "references": msg.get("References", ""), "date": msg.get("Date", "")}


def suggest(reply_class, pretext=None, locale="en"):
    """The follow-up the pretext already scripts, or the honest 'do not send'."""
    if reply_class == "refused":
        return {"send": False, "why": "the target refused: a second message confirms the "
                                      "campaign and turns a refusal into a report"}
    if reply_class == "auto_reply":
        return {"send": False, "why": "an automatic reply means nobody read it yet: wait"}
    if reply_class == "credentials":
        return {"send": False, "why": "credentials arrived: use them, do not keep writing - "
                                      "another message is what gets the mailbox reported"}
    if reply_class in ("question", "hesitant"):
        script = ""
        if pretext:
            try:
                script = pretexts.second_ask(pretext, {"locale": locale})
            except (KeyError, TypeError) as e:
                return {"send": True, "why": f"answer it, but {e}", "script": ""}
        return {"send": True, "why": "answer what was asked, in the pretext's own words",
                "script": script}
    if reply_class == "forwarded":
        return {"send": False, "why": "it was forwarded: assume the IT team is now reading "
                                      "and stop the thread"}
    return {"send": False, "why": "unclassified: read it before answering"}


def describe(replies, threads=None):
    lines = [f"inbox: {len(replies or [])} message(s)"]
    for msg in replies or []:
        cls, why = classify(msg.get("subject", ""), msg.get("body", ""))
        lines.append(f"  [{cls:<11}] {str(msg.get('from'))[:40]:<40} "
                     f"{str(msg.get('subject'))[:44]}")
    if threads:
        lines.append(f"  threads: {len(threads)}")
    return "\n".join(lines)

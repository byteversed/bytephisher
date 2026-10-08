# BytePhisher — SMTP spear-phishing module (package name `mailer` to avoid shadowing stdlib `email`).
# Templates: password reset, security alert, shared doc, invoice.
# Variable substitution: {{To_FirstName}}, {{To_Address}}, {{From_Name}},
# {{Phish_URL}}, etc.
import smtplib
from email.message import EmailMessage

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
              html=False, headers=None):
    """Send one message. STARTTLS and AUTH are used only when the server
    advertises them, so this also works against plain lab relays."""
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to_addr
    msg["Subject"] = subject
    for k, v in (headers or {}).items():
        msg[k] = v
    if html:
        msg.set_content("This message requires an HTML-capable client.")
        msg.add_alternative(body_html_or_text, subtype="html")
    else:
        msg.set_content(body_html_or_text)
    if host:
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
            try:
                s.quit()
            except Exception:
                pass
    return True

def blast(host, port, user, pwd, recipients, template_name, context, use_starttls=True):
    subject, body = render(template_name, context)
    for r in recipients:
        try:
            send_smtp(host, port, user, pwd, subject, body, r, use_starttls)
        except Exception as e:
            print(f"[email] failed for {r}: {e}")

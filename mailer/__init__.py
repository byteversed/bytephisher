# BytePhisher — SMTP spear-phishing module (package name `mailer` to avoid shadowing stdlib `email`).
# Templates: password reset, security alert, shared doc, invoice.
# Variable substitution: {{To_FirstName}}, {{To_Address}}, {{From_Name}},
# {{Phish_URL}}, etc.
import smtplib
import json
import os
import re
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

def send_smtp(host, port, user, pwd, subject, body_html_or_text, to_addr, use_starttls=True):
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body_html_or_text)
    if host:
        s = smtplib.SMTP(host, port, timeout=20)
        if use_starttls:
            s.starttls()
        s.login(user, pwd)
        s.send_message(msg)
        s.quit()
    return True

def blast(host, port, user, pwd, recipients, template_name, context, use_starttls=True):
    subject, body = render(template_name, context)
    for r in recipients:
        try:
            send_smtp(host, port, user, pwd, subject, body, r, use_starttls)
        except Exception as e:
            print(f"[email] failed for {r}: {e}")

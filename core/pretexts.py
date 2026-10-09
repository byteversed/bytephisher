"""Pretexts: the message that makes the click happen.

A pretext is a role-aware, locale-aware story with the fields it needs and the script for
the SECOND ask (the reply when the target hesitates). It is data, not prose buried in the
mailer: the same story has to render into an email, a landing page and a chat message, and
the operator needs to see which fields are missing before a send rather than after.

`pretexts/*.yaml` overrides a built-in of the same name when PyYAML is installed (the
package is optional everywhere else in this tool); the built-ins below need nothing.
"""
import os

__all__ = ["PRETEXTS", "names", "get", "render", "missing_fields", "second_ask",
           "load_dir", "describe"]

# Every key a pretext must carry for the accessors to work without a KeyError.
REQUIRED_PRETEXT_FIELDS = ("roles", "locales", "subject", "body", "fields",
                           "second_ask", "tell")

# Each entry: roles it fits, locales it is written for, the subject, the body, the fields it
# needs, the follow-up script, and the tell that makes it credible.
PRETEXTS = {
    "it_password_expiry": {
        "roles": ["it", "finance", "hr", "ops"],
        "locales": ["en", "en-IN", "en-GB", "en-US"],
        "subject": "Action required: your {{Brand}} password expires in 24 hours",
        "body": (
            "Hi {{To_FirstName}},\n\n"
            "Our directory sync shows your {{Brand}} password expires today. Sign-in will be "
            "blocked at 18:00 and any open sessions will be signed out.\n\n"
            "Keep the same password: {{Phish_URL}}\n\n"
            "If you have already changed it in the last 24 hours, ignore this message.\n\n"
            "{{From_Name}}\n{{Brand}} IT Service Desk"
        ),
        "fields": ["To_FirstName", "Phish_URL", "From_Name", "Brand"],
        "second_ask": (
            "Re: your password\n\n"
            "It is still showing as expired on our side - the change has to be done from the "
            "link in the previous mail (a phone or a home laptop works too). Two minutes.\n\n"
            "If it fails again, reply with a screenshot of the error and I will reset it "
            "manually."
        ),
        "tell": "a deadline that is already in the past for the recipient's timezone",
    },
    "shared_document": {
        "roles": ["finance", "legal", "sales", "ops", "hr"],
        "locales": ["en", "en-IN"],
        "subject": "{{Doc_Name}} shared with you",
        "body": (
            "Hi {{To_FirstName}},\n\n"
            "{{From_Name}} shared \"{{Doc_Name}}\" with you and asked for a review before the "
            "call.\n\n"
            "Open the document: {{Phish_URL}}\n\n"
            "It is view-only until you sign in with your work account.\n"
        ),
        "fields": ["To_FirstName", "Phish_URL", "From_Name", "Doc_Name"],
        "second_ask": (
            "Re: {{Doc_Name}}\n\n"
            "Checking in - the review was due this morning. The link needs a sign-in first, "
            "that is the permission check, not an error.\n"
        ),
        "tell": "a file name that matches the department's real naming",
    },
    "invoice_hold": {
        "roles": ["finance", "accounts"],
        "locales": ["en", "en-IN"],
        "subject": "Invoice {{Invoice_ID}} on hold - confirmation needed",
        "body": (
            "Hi {{To_FirstName}},\n\n"
            "Payment run for {{Invoice_ID}} is on hold: the bank details on file do not match "
            "the vendor's record.\n\n"
            "Confirm the remittance details: {{Phish_URL}}\n\n"
            "The run closes at 16:00 today; after that it moves to next month's cycle.\n"
        ),
        "fields": ["To_FirstName", "Phish_URL", "Invoice_ID"],
        "second_ask": (
            "Re: Invoice {{Invoice_ID}}\n\n"
            "The hold is still active. If the portal is slow, use the direct link - the "
            "confirmation is one checkbox."
        ),
        "tell": "a payment window that closes the same day",
    },
    "mfa_enrolment": {
        "roles": ["it", "ops"],
        "locales": ["en"],
        "subject": "MFA re-enrolment for {{Brand}} starts today",
        "body": (
            "Hi {{To_FirstName}},\n\n"
            "Your authenticator is being migrated. Until you re-enrol, sign-in will ask for a "
            "code you cannot generate.\n\n"
            "Re-enrol here: {{Phish_URL}}\n\n"
            "It takes one minute and keeps your current device working.\n"
        ),
        "fields": ["To_FirstName", "Phish_URL", "Brand"],
        "second_ask": (
            "Re: MFA\n\n"
            "Your old authenticator is already disabled on the directory side - that is why "
            "the codes stopped working. The link above re-enrols the same phone."
        ),
        "tell": "an explanation for a symptom the target has already noticed",
    },
    "device_code_setup": {
        "roles": ["it", "ops", "exec"],
        "locales": ["en"],
        "subject": "New laptop provisioning - approve the sign-in",
        "body": (
            "Hi {{To_FirstName}},\n\n"
            "Your replacement laptop is imaged and waiting. Microsoft is asking for an approval "
            "before it can join your account.\n\n"
            "Open {{Verification_URI}} and enter the code {{User_Code}} when prompted.\n\n"
            "Do not share the code - it is tied to your account.\n"
        ),
        "fields": ["To_FirstName", "Verification_URI", "User_Code"],
        "second_ask": (
            "Re: laptop provisioning\n\n"
            "The approval window is 15 minutes and it has to be entered on the page, not "
            "replied to me - I cannot approve it for you."
        ),
        "tell": "a code the target is told not to share (so they do not ask anyone)",
    },
}


def names():
    """Every available pretext name, sorted."""
    return sorted(PRETEXTS)


def get(name):
    """One pretext (raises KeyError with the available names)."""
    key = str(name or "").strip()
    if key not in PRETEXTS:
        raise KeyError(f"unknown pretext {name!r}; have: {', '.join(names())}")
    return PRETEXTS[key]


def _sub(text, context):
    # Defect: a non-dict context (a list, a string) raised AttributeError on
    # .items(); a caller that passed the wrong shape crashed mid-render.
    if not isinstance(context, dict):
        context = {}
    out = str(text or "")
    for k, v in context.items():
        out = out.replace("{{" + k + "}}", str(v))
    return out


def render(name, context):
    """(subject, body) with the context substituted."""
    p = get(name)
    return _sub(p.get("subject", ""), context), _sub(p.get("body", ""), context)


def missing_fields(name, context):
    """Fields the pretext needs that the context does not carry.

    Call this BEFORE a send: a body with a literal `{{Doc_Name}}` in it is the single most
    common way a campaign looks fake.
    """
    p = get(name)
    # Defect: p["fields"] raised KeyError for a pretext that loaded without a
    # fields list (a hand-written override); a missing key is not a crash.
    if not isinstance(context, dict):
        context = {}
    have = {k for k, v in context.items() if str(v or "").strip()}
    return [f for f in (p.get("fields") or []) if f not in have]


def second_ask(name, context=None):
    """The follow-up message for a target who did not act."""
    # Defect: p["second_ask"] raised KeyError on a partial pretext.
    return _sub(get(name).get("second_ask", ""), context or {})


def describe(name):
    p = get(name)
    return (f"{name}: roles {', '.join(p.get('roles') or [])} | "
            f"locales {', '.join(p.get('locales') or [])} | "
            f"fields {', '.join(p.get('fields') or [])} | tell: {p.get('tell') or '-'}")


def load_dir(path):
    """Merge `pretexts/*.yaml` (or .json) over the built-ins; returns the names loaded.

    YAML needs PyYAML, which this tool treats as optional everywhere: a .json file always
    works, and a .yaml file without PyYAML is reported and skipped rather than crashing a
    campaign.
    """
    import glob
    import json
    loaded = []
    for pattern in ("*.yaml", "*.yml", "*.json"):
        for path_ in sorted(glob.glob(os.path.join(path, pattern))):
            try:
                if path_.endswith(".json"):
                    with open(path_, encoding="utf-8") as fh:
                        data = json.load(fh)
                else:
                    import yaml
                    with open(path_, encoding="utf-8") as fh:
                        data = yaml.safe_load(fh) or {}
            except Exception as e:
                print(f"[pretexts] skipped {os.path.basename(path_)}: "
                      f"{type(e).__name__}: {e}")
                continue
            if not isinstance(data, dict):
                continue
            for key, value in data.items():
                if not isinstance(value, dict):
                    continue
                name = str(key)
                base = PRETEXTS.get(name)
                if base is not None:
                    # a partial override of a built-in is merged over it, so the
                    # accessors (missing_fields/second_ask/describe) never meet a
                    # missing key
                    merged = dict(base)
                    merged.update(value)
                    PRETEXTS[name] = merged
                    loaded.append(name)
                    continue
                # Defect: any dict with subject+body loaded as a pretext, so a
                # new entry missing 'fields'/'second_ask'/'tell' made
                # missing_fields/second_ask/describe raise KeyError later, in
                # the middle of an engagement. Refuse what cannot be validated.
                missing = [k for k in REQUIRED_PRETEXT_FIELDS if not value.get(k)]
                if missing:
                    print(f"[pretexts] skipped {os.path.basename(path_)}:{name}: "
                          f"missing {', '.join(missing)}")
                    continue
                PRETEXTS[name] = value
                loaded.append(name)
    return loaded

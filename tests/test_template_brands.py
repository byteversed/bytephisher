"""BytePhisher - tests for the extra brand library (tools/template_brands.py).

These tests validate the DATA module on its own; only the collision check in
``test_no_collision_with_existing_generator_brands`` needs ``tools.gen_templates``
(the deliverable spec explicitly allows parsing/importing it for that one check).

Run:  ./.venv/bin/python -m pytest tests/test_template_brands.py -q
"""
import os
import re
import sys

import pytest

# unit: the brand table is read and compared; nothing is served and no port is bound
pytestmark = pytest.mark.unit

# make the project importable when this file is run on its own
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from tools import template_brands as tb  # noqa: E402

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Login identifier fields that the generated form pairs with a password field.
# The 6-tuple mirrors gen_templates.SITES exactly, which carries the login
# identifier (slot 4) rather than a password field name - the generator appends
# a "password" field to every site it renders, so the entry "names" the
# credential login field that accompanies that password.
PASSWORDISH_LOGIN_FIELDS = {"email", "username", "phone", "email_or_phone", "login"}

# Verticals the batch was asked to cover.
REQUESTED_CATEGORIES = {
    "banks_india", "banks_eu", "banks_us", "payments",
    "crypto", "government", "airlines_travel", "telecom",
    "ecommerce", "couriers", "sso_identity", "cloud_dev",
    "webmail", "gaming_streaming", "saas",
}


# (a) size -------------------------------------------------------------------
def test_at_least_120_entries():
    assert len(tb.BRANDS) >= 120, f"only {len(tb.BRANDS)} entries"


# (b) every entry has every required field, non-empty ------------------------
def test_every_entry_has_every_required_field():
    n = len(tb.REQUIRED_FIELDS)
    for entry in tb.BRANDS:
        assert len(entry) == n, f"{entry!r}: expected {n} fields"
        for field, value in zip(tb.REQUIRED_FIELDS, entry, strict=True):
            assert isinstance(value, str), f"{entry!r}: {field} is not a string"
            assert value.strip(), f"{entry!r}: {field} is empty"


# (c) slugs unique, lowercase, well-formed -----------------------------------
def test_slugs_unique_lowercase_and_wellformed():
    slugs = [e[0] for e in tb.BRANDS]
    assert len(set(slugs)) == len(slugs), "duplicate slug in BRANDS"
    for slug in slugs:
        assert slug == slug.lower(), f"{slug}: not lowercase"
        assert SLUG_RE.match(slug), f"{slug}: does not match ^[a-z0-9][a-z0-9-]*$"


# (d) no slug or name collides with the existing generator library -----------
def test_no_collision_with_existing_generator_brands():
    from tools import gen_templates as gt
    # BASE_SITES, not SITES: SITES is the merged result, so comparing against it
    # would compare the batch with itself.
    existing_slugs = {s[0] for s in gt.BASE_SITES}
    existing_names = {s[1] for s in gt.BASE_SITES}
    for slug, name, *_rest in tb.BRANDS:
        assert slug not in existing_slugs, f"slug {slug!r} already in gen_templates.SITES"
        assert name not in existing_names, f"name {name!r} already in gen_templates.SITES"


# (e) colours are valid 6-digit hex ------------------------------------------
def test_colours_are_valid_hex():
    for slug, _name, brand, accent, *_rest in tb.BRANDS:
        assert HEX_RE.match(brand), f"{slug}: bad brand colour {brand!r}"
        assert HEX_RE.match(accent), f"{slug}: bad accent colour {accent!r}"


# (f) every text value is ASCII-only -----------------------------------------
def test_all_text_values_are_ascii():
    for entry in tb.BRANDS:
        for value in entry:
            assert value.isascii(), f"{entry!r}: non-ASCII value {value!r}"
            value.encode("ascii")  # belt and braces: raises on any non-ASCII


# (g) each entry names a password-ish (credential login) field ---------------
def test_each_entry_names_a_password_ish_field():
    for entry in tb.BRANDS:
        login_field = entry[4]
        assert login_field in PASSWORDISH_LOGIN_FIELDS, \
            f"{entry[0]}: login field {login_field!r} is not a credential field"


# extra: the requested verticals are all present and populated ---------------
def test_requested_categories_are_covered():
    missing = REQUESTED_CATEGORIES - set(tb.CATEGORIES)
    assert not missing, f"missing categories: {sorted(missing)}"
    for cat in REQUESTED_CATEGORIES:
        assert tb.CATEGORIES[cat], f"category {cat} is empty"
    # every entry is mapped to exactly one category
    assert set(tb.CATEGORY_OF) == {e[0] for e in tb.BRANDS}

"""The operator-facing fixes: what the tool reports must match what it does.

Each test names the defect it pins: a false alarm in `doctor`, a database path no
campaign writes, a brand leak in the interstitial, an identity that was invisible to
reuse detection, and a panic path that only existed on Telegram.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

# integration: the operator surface is driven through the CLI in a subprocess
pytestmark = pytest.mark.integration

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import capture as cap  # noqa: E402
from core import challenge as chal  # noqa: E402


class TestDoctorDoesNotCryWolf:

    def test_every_registered_template_is_found(self):
        # the check resolved each manifest "dir" against the cwd and reported all 670
        # as missing files whenever the operator ran it from anywhere else
        out = subprocess.run([sys.executable, os.path.join(HERE, "tools", "doctor.py")],
                             capture_output=True, text=True, timeout=120, cwd=HERE).stdout
        line = [ln for ln in out.splitlines() if "templates" in ln]
        assert line, out
        assert "0 missing files" in line[0], line[0]


class TestTheDatabasePath:

    def test_lab_check_uses_the_products_own_default(self, monkeypatch, tmp_path):
        # it reported and created data/campaigns.db while the CLI writes
        # data/bytephisher.db (DEFAULT_DB), so the check described a file nobody uses
        monkeypatch.setenv("BYTEPHISHER_HOME", str(tmp_path))
        sys.path.insert(0, os.path.join(HERE, "tools"))
        import importlib

        import lab_check
        importlib.reload(lab_check)
        res = lab_check.check_db()
        detail = json.dumps(res, default=str)
        assert "bytephisher.db" in detail, detail
        assert str(tmp_path) in detail, detail


class TestTheInterstitialStaysNeutral:

    def test_no_brand_by_default(self):
        # the campaign name ("microsoft") was used as the title of the one page
        # whose whole purpose is to look brand-neutral
        page = chal.Challenge().page("/login")
        assert "<title>Just a moment</title>" in page, page[:400]

    def test_an_empty_brand_is_neutral_too(self):
        assert "<title>Just a moment</title>" in chal.Challenge(brand="").page("/login")

    def test_a_named_brand_is_honoured(self):
        assert "<title>Contoso</title>" in chal.Challenge(brand="Contoso").page("/login")

    def test_the_cli_does_not_pass_the_campaign_as_a_brand(self):
        src = open(os.path.join(HERE, "bytephisher.py"), encoding="utf-8").read()
        assert "brand=args.verify_brand" in src
        assert 'Challenge(ttl=args.verify_ttl, brand=args.campaign' not in src


class TestIdentityDetection:

    def _db(self):
        return cap.CaptureDB(os.path.join(tempfile.mkdtemp(prefix="bh_ops_"), "o.db"))

    def test_a_non_standard_identity_field_is_still_an_identity(self):
        # `loginfmt` (Microsoft) / `session_key` (LinkedIn) produced NO identity, so
        # credential reuse was invisible on those targets
        db = self._db()
        try:
            for ip in ("1.2.3.4", "1.2.3.5"):
                db.record("https://x.test/login", ip, "Pune", "IN", "ISP", "UA",
                          "desktop", {"loginfmt": "ravi@corp.test", "passwd": "S3cret"},
                          True, "c1", 0, "")
            st = db.reuse_stats()
            assert [i["identity"] for i in st["repeated_identities"]] == ["ravi@corp.test"]
            assert st["repeated_passwords"], "password reuse was not correlated"
        finally:
            db.close()

    def test_a_password_is_never_used_as_an_identity(self):
        db = self._db()
        try:
            for ip in ("1.2.3.4", "1.2.3.5"):
                db.record("https://x.test/login", ip, "Pune", "IN", "ISP", "UA",
                          "desktop", {"passwd": "only-a-secret"}, True, "c1", 0, "")
            st = db.reuse_stats()
            assert st["repeated_identities"] == []
        finally:
            db.close()


class TestTheConsolePanicPath:
    """`/panic` and `/kill` existed only on the control channel: a console operator had
    no panic path at all unless Telegram was configured."""

    def _run(self, *args, home):
        env = dict(os.environ, BYTEPHISHER_HOME=home)
        return subprocess.run([sys.executable, os.path.join(HERE, "bytephisher.py"), *args],
                              capture_output=True, text=True, timeout=180, cwd=HERE, env=env)

    def test_kill_refuses_without_confirmation(self, tmp_path):
        home = str(tmp_path)
        r = self._run("--kill", home=home)
        assert "--yes" in r.stdout, r.stdout + r.stderr

    def test_kill_wipes_the_store(self, tmp_path):
        home = str(tmp_path)
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        db.record("https://x.test/", "1.2.3.4", "Pune", "IN", "ISP", "UA", "d",
                  {"user": "a", "password": "b"}, True, "c", 0, "")
        db.close()
        r = self._run("--kill", "--yes", home=home)
        assert "wiped" in r.stdout, r.stdout + r.stderr
        db = cap.CaptureDB(os.path.join(home, "data", "bytephisher.db"))
        try:
            assert db.all(limit=10) == [], "the store survived --kill --yes"
        finally:
            db.close()

    def test_verify_brand_is_offered(self, tmp_path):
        r = self._run("--help", home=str(tmp_path))
        assert "--verify-brand" in r.stdout
        assert "--panic" in r.stdout


class TestTheVerifyFirstHonesty:
    """`--verify-first` is not a no-op in static mode any more: the CLI builds the
    challenge for both servers, so there is no mode where the flag is silently ignored."""

    def test_the_static_server_receives_a_challenge(self):
        src = open(os.path.join(HERE, "bytephisher.py"), encoding="utf-8").read()
        assert "challenge=static_challenge" in src, "the static server gets no challenge"
        assert "proxy-only" not in src, "the CLI still claims the challenge is proxy-only"

    def test_campaign_sh_turns_it_on(self):
        sh = open(os.path.join(HERE, "tools", "campaign.sh"), encoding="utf-8").read()
        assert 'CAMPAIGN_VERIFY:=1' in sh

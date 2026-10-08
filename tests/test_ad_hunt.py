"""The directory hunt: what AD gives away, and the two attributes worth writing.

Every read is labelled: CONFIRMED means the value came back from the attribute, SUSPECTED means
it is present but needs another step (a DPAPI key, a KDS key, a human reading a description),
and FAILED means an attempt that did not work. A hunt that labels a DPAPI blob as "recovered"
is worse than no hunt.
"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ad_hunt as H  # noqa: E402
from core import aes  # noqa: E402

pytestmark = pytest.mark.unit


def row(**attrs):
    return {"dn": f"CN={attrs.get('cn', ['x'])[0]},DC=x", "attrs": attrs}


class TestLaps:

    def test_a_legacy_laps_password_comes_back_confirmed(self):
        found = H.laps([row(cn=["WS01"], dNSHostName=["ws01.x.test"], **{"ms-Mcs-AdmPwd": ["P@ss!"]})])
        assert found and found[0]["password"] == "P@ss!" and found[0]["verdict"] == "CONFIRMED"

    def test_a_windows_laps_json_blob_is_unwrapped(self):
        found = H.laps([row(cn=["WS02"], **{"msLAPS-Password": ['{"n":"Administrator","p":"Xy9!"}']})])
        assert found[0]["password"] == "Xy9!" and found[0]["attribute"] == "msLAPS-Password"

    def test_an_encrypted_blob_is_reported_present_not_recovered(self):
        found = H.laps([row(cn=["WS03"], **{"msLAPS-EncryptedPassword": ["AQAA..."]})],
                       include_encrypted=True)
        assert found[0]["verdict"] == "SUSPECTED" and found[0]["password"] == ""
        assert "DPAPI" in found[0]["why"]

    def test_a_host_without_laps_is_not_reported(self):
        assert H.laps([row(cn=["WS04"])]) == []


class TestGpp:

    def _cpassword(self, secret="Local*P4ssword"):
        blob = aes.cbc_encrypt(aes.GPP_KEY, secret.encode("utf-16-le"), iv=bytes(16))
        return base64.b64encode(blob).decode()

    def test_a_cpassword_decrypts_with_the_published_key(self):
        found = H.gpp([row(cn=["Default Domain Policy"],
                           gpcUserSettings=[f'cpassword="{self._cpassword()}"'])])
        assert found[0]["password"] == "Local*P4ssword" and found[0]["verdict"] == "CONFIRMED"
        assert "MS14-025" in found[0]["why"]

    def test_a_broken_cpassword_is_reported_failed_not_guessed(self):
        found = H.gpp([row(cn=["GPO"], gpcUserSettings=['cpassword="not-base64!!!"'])])
        assert found[0]["verdict"] == "FAILED" and found[0]["password"] == ""

    def test_a_gpo_without_a_cpassword_is_not_reported(self):
        assert H.gpp([row(cn=["GPO"], gpcUserSettings=["nothing here"])]) == []


class TestDelegation:

    def test_unconstrained_delegation_is_flagged(self):
        found = H.delegation([row(cn=["DC01"], userAccountControl=["532480"])])
        assert any(f["kind"] == "TRUSTED_FOR_DELEGATION" for f in found)
        assert "usable TGS" in found[0]["next"]

    def test_a_normal_host_is_not_flagged(self):
        assert H.delegation([row(cn=["WS01"], userAccountControl=["4096"])]) == []

    def test_constrained_delegation_names_its_targets(self):
        found = H.delegation([row(cn=["APP01"], userAccountControl=["4096"],
                                  **{"msDS-AllowedToDelegateTo": ["cifs/srv.x",
                                                                  "http/srv.x"]})])
        assert found[0]["kind"] == "CONSTRAINED" and "cifs/srv.x" in found[0]["why"]

    def test_an_existing_rbcd_configuration_is_reported(self):
        found = H.delegation([row(cn=["SRV01"], userAccountControl=["4096"],
                                  **{"msDS-AllowedToActOnBehalfOfOtherIdentity": ["\x01\x00"]})])
        assert found[0]["kind"] == "RBCD"


class TestTextHunt:

    def test_a_password_in_a_description_is_suspected_with_the_text(self):
        found = H.password_hunt([row(sAMAccountName=["svc"], description=["password: Summer!"])])
        assert found[0]["verdict"] == "SUSPECTED" and "Summer" in found[0]["value"]

    def test_a_password_attribute_is_confirmed(self):
        found = H.password_hunt([row(sAMAccountName=["u"], userPassword=["plaintext!"])])
        assert found[0]["verdict"] == "CONFIRMED"

    def test_a_harmless_description_is_not_reported(self):
        assert H.password_hunt([row(sAMAccountName=["u"], description=["Finance team lead"])]) == []


class TestTheWrites:

    def test_the_rbcd_descriptor_is_a_single_ace_dacl(self):
        sd = H.rbcd_value("S-1-5-21-1-2-3-1105")
        assert sd[:4] == b"\x01\x00\x04\x80", "revision, control with a DACL"
        assert len(sd) == 58, "20-byte header + 8-byte DACL header + 30-byte ACE"
        assert b"\x05\x15" in sd, "the SID revision and sub-authority count are in there"

    def test_setting_rbcd_uses_a_replace_and_clearing_uses_a_delete(self):
        calls = []

        class C:
            def modify(self, dn, changes, operation=2):
                calls.append((dn, list(changes), operation))
                return True

        H.rbcd_set(C(), "CN=srv,DC=x", "S-1-5-21-1-2-3-1105")
        H.rbcd_set(C(), "CN=srv,DC=x", "S-1-5-21-1-2-3-1105", remove=True)
        assert [c[2] for c in calls] == [2, 1]
        assert calls[0][1] == ["msDS-AllowedToActOnBehalfOfOtherIdentity"]

    def test_a_dns_record_is_built_with_the_address_in_the_rdata(self):
        payload = H.dns_record("wpad", "10.0.0.5", "DC=x.test")
        assert payload["dn"] == "DC=wpad,DC=x.test"
        assert payload["attrs"]["dnsRecord"][0].endswith(bytes([10, 0, 0, 5]))

    def test_a_bad_name_or_address_is_refused(self):
        with pytest.raises(ValueError):
            H.dns_record("", "10.0.0.5", "DC=x")
        with pytest.raises(ValueError):
            H.dns_record("wpad", "999.1.1.1", "DC=x")
        with pytest.raises(ValueError):
            H.dns_record("wpad", "10.0.0.5", "DC=x", record_type="AAAA")


class TestTheReport:

    def test_every_finding_is_labelled_and_counted(self):
        rep = H.report(laps_rows=[row(cn=["W"], **{"ms-Mcs-AdmPwd": ["p"]})],
                       delegation_rows=[row(cn=["D"], userAccountControl=["532480"])])
        assert rep["confirmed"] == 2 and rep["suspected"] == 0 and rep["failed"] == 0
        assert rep["total"] == 2

    def test_an_empty_hunt_says_nothing_found_not_success(self):
        rep = H.report()
        assert rep["total"] == 0
        assert "0 finding(s)" in H.describe(rep)

    def test_the_next_steps_name_what_to_do_with_each_kind(self):
        rep = H.report()
        joined = " ".join(rep["next"])
        assert "local administrator" in joined and "TGS" in joined and "DNS" in joined

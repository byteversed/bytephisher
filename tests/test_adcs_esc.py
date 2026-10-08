"""ESC conditions decided from directory attributes.

Every finding is labelled CONFIRMED (read from an attribute) or SUSPECTED (implied, needs a
check), because the difference between "this flag is set" and "a low-privileged principal can
actually enrol" is a security descriptor nobody should guess at.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import adcs_esc as E  # noqa: E402

pytestmark = pytest.mark.unit


def template(cn, name_flag=0, enroll_flag=0, ekus=(), **extra):
    attrs = {"cn": [cn], "msPKI-Certificate-Name-Flag": [str(name_flag)],
             "msPKI-Enrollment-Flag": [str(enroll_flag)],
             "pKIExtendedKeyUsage": list(ekus)}
    attrs.update(extra)
    return {"dn": f"CN={cn},CN=Certificate Templates,DC=x", "attrs": attrs}


class TestTemplates:

    def test_esc1_needs_the_flag_the_missing_approval_and_a_client_auth_eku(self):
        rows = [template("User", name_flag=0x1, enroll_flag=0,
                         ekus=["1.3.6.1.5.5.7.3.2"])]
        findings = E.analyse_templates(rows)
        esc1 = [f for f in findings if f["esc"] == "ESC1"]
        assert esc1 and esc1[0]["verdict"] == "CONFIRMED"
        assert "ENROLLEE_SUPPLIES_SUBJECT" in esc1[0]["why"]
        assert "nTSecurityDescriptor" in esc1[0]["needs"]

    def test_manager_approval_downgrades_esc1_to_suspected(self):
        rows = [template("User", name_flag=0x1, enroll_flag=0x2,
                         ekus=["1.3.6.1.5.5.7.3.2"])]
        esc1 = [f for f in E.analyse_templates(rows) if f["esc"] == "ESC1"]
        assert esc1 and esc1[0]["verdict"] == "SUSPECTED"
        assert "approval" in esc1[0]["why"]

    def test_a_server_auth_only_template_is_not_esc1(self):
        rows = [template("Web", name_flag=0x1, enroll_flag=0, ekus=["1.3.6.1.5.5.7.3.1"])]
        assert not [f for f in E.analyse_templates(rows) if f["esc"] == "ESC1"]

    def test_an_any_purpose_eku_is_esc2(self):
        rows = [template("Any", name_flag=0x1, ekus=["2.5.29.37.0"])]
        assert any(f["esc"] == "ESC2" and f["verdict"] == "CONFIRMED"
                   for f in E.analyse_templates(rows))

    def test_the_agent_eku_is_esc3(self):
        rows = [template("Agent", ekus=["1.3.6.1.4.1.311.20.2.1"])]
        esc3 = [f for f in E.analyse_templates(rows) if f["esc"] == "ESC3"]
        assert esc3 and "on behalf of another user" in esc3[0]["why"]

    def test_a_template_with_no_eku_is_suspected_esc2(self):
        rows = [template("Bare", ekus=[])]
        assert any(f["esc"] == "ESC2" and f["verdict"] == "SUSPECTED"
                   for f in E.analyse_templates(rows))

    def test_the_application_policy_attribute_counts_as_an_eku(self):
        rows = [{"dn": "CN=X", "attrs": {"cn": ["X"], "msPKI-Certificate-Name-Flag": ["1"],
                                         "msPKI-Enrollment-Flag": ["0"],
                                         "msPKI-Certificate-Application-Policy":
                                             ["1.3.6.1.5.5.7.3.2"]}}]
        assert any(f["esc"] == "ESC1" for f in E.analyse_templates(rows))

    def test_an_empty_directory_gives_no_findings(self):
        assert E.analyse_templates([]) == []


class TestTheCa:

    def test_the_editf_flag_is_esc6(self):
        rows = [{"dn": "CN=CA", "attrs": {"cn": ["CONTOSO-CA"], "flags": ["262144"]}}]
        esc6 = [f for f in E.analyse_ca(rows) if f["esc"] == "ESC6"]
        assert esc6 and esc6[0]["verdict"] == "CONFIRMED"
        assert "0x40000" in esc6[0]["why"]

    def test_a_published_ca_is_a_suspected_esc8_until_the_probe_says_otherwise(self):
        rows = [{"dn": "CN=CA", "attrs": {"cn": ["CONTOSO-CA"], "flags": ["0"]}}]
        esc8 = [f for f in E.analyse_ca(rows) if f["esc"] == "ESC8"]
        assert esc8 and esc8[0]["verdict"] == "SUSPECTED"
        assert "probe" in esc8[0]["needs"]

    def test_a_ca_without_the_flag_is_not_esc6(self):
        rows = [{"dn": "CN=CA", "attrs": {"cn": ["X"], "flags": ["0"]}}]
        assert not [f for f in E.analyse_ca(rows) if f["esc"] == "ESC6"]


class TestTheReport:

    def test_the_report_counts_confirmed_and_suspected_separately(self):
        rows = [template("User", name_flag=0x1, ekus=["1.3.6.1.5.5.7.3.2"]),
                template("Web", ekus=["1.3.6.1.5.5.7.3.1"])]
        rep = E.report(rows)
        assert rep["confirmed"] >= 1
        assert rep["confirmed"] + rep["suspected"] == len(rep["findings"])

    def test_the_next_steps_chain_the_relay_and_the_certificate(self):
        rows = [template("User", name_flag=0x1, ekus=["1.3.6.1.5.5.7.3.2"])]
        rep = E.report(rows, probe={"ntlm_offered": True})
        joined = " ".join(rep["next"])
        assert "core.relay.Relay" in joined and "PKINIT" in joined
        assert "krbtgt" in joined

    def test_a_hardened_ca_says_so_instead_of_inventing_a_path(self):
        rep = E.report([], [], probe={})
        assert rep["confirmed"] == 0
        assert "nothing confirmed" in rep["next"][0]

    def test_the_description_labels_every_finding(self):
        rep = E.report([template("User", name_flag=0x1, ekus=["1.3.6.1.5.5.7.3.2"])])
        text = E.describe(rep)
        assert "[CONFIRMED]" in text and "next:" in text

    def test_the_sddl_reader_names_the_principals(self):
        sids = E.sddl_principals("D:(A;;RPWP;;;S-1-5-21-1-2-3-512)(A;;RPLCLORC;;;S-1-5-21-1-2-3-513)")
        assert sids == ["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-513"]
        assert E.sddl_principals("") == []
        assert E.sddl_principals("D:(A;;;;;)") == [], "an empty ACE names nobody"

    def test_the_eku_table_names_the_esc_ekus(self):
        assert "ESC2" in E.EKU["2.5.29.37.0"]
        assert "ESC3" in E.EKU["1.3.6.1.4.1.311.20.2.1"]
        assert E.EKU["1.3.6.1.5.5.7.3.2"] == "Client Authentication"

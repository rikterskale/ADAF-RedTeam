"""Tests for the discovery/inventory capabilities:
acl-write-rights-inventory, privileged-group-inventory, trust-inventory,
sidhistory-inventory, machine-account-quota-check.

Analyzer tests are pure. End-to-end tests run the CLI against a fixture and
assert the bridged validation-result.json.
"""

from __future__ import annotations

import json

from adaf_redteam.__main__ import main
from adaf_redteam.capabilities.discovery import (
    acl_write_rights,
    machine_account_quota,
    privileged_group_membership,
    sidhistory,
    trust_inventory,
)
from adaf_redteam.directory.acl import Ace

T = "S-1-5-21-1-2-3-1000"
DOMAIN = "corp.contoso.test"
DOMAIN_DN = "DC=corp,DC=contoso,DC=test"


# --- analyzer: acl_write_rights -----------------------------------------

def test_acl_write_rights_confirmed_with_generic_all():
    aces = [Ace(T, "GenericAll")]
    res = acl_write_rights.analyze(T, "CN=Alice," + DOMAIN_DN, aces)
    assert res.verdict == "Confirmed"
    assert "GenericAll" in res.redacted_refs["takeoverRightsHeld"]


def test_acl_write_rights_confirmed_with_force_change_password():
    aces = [Ace(T, "User-Force-Change-Password",
                object_type="User-Force-Change-Password")]
    res = acl_write_rights.analyze(T, "CN=Alice," + DOMAIN_DN, aces)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["takeoverRightsHeld"] == ["User-Force-Change-Password"]


def test_acl_write_rights_confirmed_with_write_dacl():
    aces = [Ace(T, "WriteDACL")]
    assert (acl_write_rights.analyze(T, "CN=X," + DOMAIN_DN, aces).verdict
            == "Confirmed")


def test_acl_write_rights_not_exploitable_with_only_read():
    aces = [Ace(T, "ReadProperty")]
    res = acl_write_rights.analyze(T, "CN=X," + DOMAIN_DN, aces)
    assert res.verdict == "NotExploitable"
    assert res.redacted_refs["takeoverRightsHeld"] == []


def test_acl_write_rights_deny_cancels_allow():
    aces = [Ace(T, "GenericAll", effect="Allow"),
            Ace(T, "GenericAll", effect="Deny")]
    assert (acl_write_rights.analyze(T, "CN=X," + DOMAIN_DN, aces).verdict
            == "NotExploitable")


# --- analyzer: privileged_group_membership ------------------------------

def test_privileged_group_confirmed_when_non_empty():
    members = [
        {"dn": "CN=Alice," + DOMAIN_DN, "class": "user"},
        {"dn": "CN=DC01," + DOMAIN_DN, "class": "computer"},
        {"dn": "CN=NestedGroup," + DOMAIN_DN, "class": "group"},
    ]
    res = privileged_group_membership.analyze("CN=Domain Admins," + DOMAIN_DN, members)
    assert res.verdict == "Confirmed"
    refs = res.redacted_refs
    assert refs["memberCountTotal"] == 3
    assert refs["memberCountUsers"] == 1
    assert refs["memberCountComputers"] == 1
    assert refs["memberCountNestedGroups"] == 1
    assert refs["memberUsers"] == ["CN=Alice," + DOMAIN_DN]
    assert refs["memberComputers"] == ["CN=DC01," + DOMAIN_DN]
    assert refs["memberNestedGroups"] == ["CN=NestedGroup," + DOMAIN_DN]


def test_privileged_group_not_exploitable_when_empty():
    res = privileged_group_membership.analyze("CN=Empty," + DOMAIN_DN, [])
    assert res.verdict == "NotExploitable"


# --- analyzer: trust_inventory ------------------------------------------

def test_trust_inventory_flags_unfiltered_inbound():
    trusts = [
        # inbound, no SID filter -> the flagged case
        {"trustPartner": "child.corp.test", "trustDirection": 2,
         "trustType": 2, "trustAttributes": 0},
        # bidirectional, SID-filter enabled -> counted but not flagged
        {"trustPartner": "partner.example", "trustDirection": 6,
         "trustType": 2, "trustAttributes": 0x4},
        # outbound only
        {"trustPartner": "outbound.example", "trustDirection": 4,
         "trustType": 2, "trustAttributes": 0},
    ]
    res = trust_inventory.analyze(DOMAIN, trusts)
    assert res.verdict == "Confirmed"
    refs = res.redacted_refs
    assert refs["trustCount"] == 3
    assert refs["unfilteredInboundCount"] == 1
    # trusts is a list of pipe-separated summary strings; check the flagged partner.
    assert refs["unfilteredInboundPartners"] == ["child.corp.test"]
    assert any("dir=inbound" in s for s in refs["trusts"])
    assert any("sid-filter" in s for s in refs["trusts"])


def test_trust_inventory_no_trusts():
    res = trust_inventory.analyze(DOMAIN, [])
    assert res.verdict == "NotExploitable"


# --- analyzer: sidhistory -----------------------------------------------

def test_sidhistory_flags_privileged_rid():
    accts = [
        {"dn": "CN=Alice," + DOMAIN_DN,
         "sidHistory": ["S-1-5-21-9-9-9-1104"]},
        {"dn": "CN=Bob," + DOMAIN_DN,
         "sidHistory": ["S-1-5-21-9-9-9-512"]},  # Domain Admins RID
    ]
    res = sidhistory.analyze(DOMAIN, accts)
    assert res.verdict == "Confirmed"
    refs = res.redacted_refs
    assert refs["sidHistoryAccountCount"] == 2
    assert refs["privilegedFlaggedCount"] == 1
    assert refs["flaggedAccounts"] == ["CN=Bob," + DOMAIN_DN]


def test_sidhistory_flags_builtin_admins():
    accts = [{"dn": "CN=Carol," + DOMAIN_DN, "sidHistory": ["S-1-5-32-544"]}]
    res = sidhistory.analyze(DOMAIN, accts)
    assert res.redacted_refs["privilegedFlaggedCount"] == 1


def test_sidhistory_none_present():
    res = sidhistory.analyze(DOMAIN, [])
    assert res.verdict == "NotExploitable"


# --- analyzer: machine_account_quota ------------------------------------

def test_machine_account_quota_default_is_confirmed():
    res = machine_account_quota.analyze(DOMAIN, 10)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["machineAccountQuota"] == 10
    assert res.redacted_refs["quotaIsDefault"] == "yes"


def test_machine_account_quota_zero_is_safe():
    res = machine_account_quota.analyze(DOMAIN, 0)
    assert res.verdict == "NotExploitable"
    assert res.proof_class == "machine-account-quota-zero"


def test_machine_account_quota_low_but_nonzero_still_exploitable():
    res = machine_account_quota.analyze(DOMAIN, 1)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["quotaIsDefault"] == "no"


# --- CLI end-to-end (fixture-backed) ------------------------------------

def _eng(tmp_path, cap_id, target, technique):
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-DISC",
        "authorizedDomains": [DOMAIN], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z",
        "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@x"], "stopConditions": ["stop"],
        "capabilities": {cap_id: {
            "approved": True, "targets": [target], "attackTechnique": technique,
            "maximumActions": 1}},
    }
    p = tmp_path / f"{cap_id}.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return str(p)


def _fix(tmp_path, data):
    p = tmp_path / "fix.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _run(eng, cap_id, target, out, fix, control="ADAF-DISC"):
    return main([
        "run", "--engagement", eng, "--capability", cap_id,
        "--source-address", "192.0.2.25", "--target", target,
        "--finding-id", "F-0123456789ABCDEF", "--control-id", control,
        "--fixture", fix, "--out", str(out),
    ])


def test_acl_write_rights_cli_end_to_end(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "acl-write-rights-inventory", "CN=Alice," + DOMAIN_DN, "T1098")
    # Fixture: object_acl returns a single WriteDACL Ace for source-address (192.0.2.25).
    fix = _fix(tmp_path, {"object_acl":
                          [{"trustee": "192.0.2.25", "right": "WriteDACL"}]})
    assert _run(eng, "acl-write-rights-inventory", "CN=Alice," + DOMAIN_DN, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["takeoverRightsHeld"] == ["WriteDACL"]


def test_privileged_group_cli_end_to_end(tmp_path):
    out = tmp_path / "o"
    group_dn = "CN=Domain Admins,CN=Users," + DOMAIN_DN
    eng = _eng(tmp_path, "privileged-group-inventory", group_dn, "T1069.002")
    fix = _fix(tmp_path, {"group_members": {group_dn: [
        {"dn": "CN=Alice," + DOMAIN_DN, "class": "user"},
        {"dn": "CN=Bob," + DOMAIN_DN, "class": "user"},
    ]}})
    assert _run(eng, "privileged-group-inventory", group_dn, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["memberCountTotal"] == 2


def test_trust_inventory_cli_end_to_end(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "trust-inventory", DOMAIN, "T1482")
    fix = _fix(tmp_path, {"trusts": {DOMAIN: [
        {"trustPartner": "child.corp.test", "trustDirection": 2,
         "trustType": 2, "trustAttributes": 0},
    ]}})
    assert _run(eng, "trust-inventory", DOMAIN, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["trustCount"] == 1
    assert doc["proof"]["redactedRefs"]["unfilteredInboundCount"] == 1


def test_sidhistory_cli_end_to_end(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "sidhistory-inventory", DOMAIN, "T1134.005")
    fix = _fix(tmp_path, {"sidhistory": {DOMAIN: [
        {"dn": "CN=Migrated," + DOMAIN_DN, "sidHistory": ["S-1-5-21-old-512"]},
    ]}})
    assert _run(eng, "sidhistory-inventory", DOMAIN, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["privilegedFlaggedCount"] == 1


def test_machine_account_quota_cli_end_to_end_default(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "machine-account-quota-check", DOMAIN, "T1136.002")
    fix = _fix(tmp_path, {})  # default = 10 (exploitable)
    assert _run(eng, "machine-account-quota-check", DOMAIN, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["machineAccountQuota"] == 10


def test_machine_account_quota_cli_end_to_end_zero(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "machine-account-quota-check", DOMAIN, "T1136.002")
    fix = _fix(tmp_path, {"machine_account_quota": {DOMAIN: 0}})
    assert _run(eng, "machine-account-quota-check", DOMAIN, out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "NotExploitable"

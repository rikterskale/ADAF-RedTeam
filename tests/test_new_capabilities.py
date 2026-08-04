"""Tests for ESC6/ESC7/ESC8, delegation read + S4U proof, and NTDS/DPAPI read proof."""

import json

from adaf_redteam.__main__ import main
from adaf_redteam.capabilities.adcs import esc6_esc7
from adaf_redteam.capabilities.kerberos import delegation_rights
from adaf_redteam.directory.acl import Ace
from adaf_redteam.statechange import is_latched

FAKE_PFX = "FIXTURE-FAKE-PFX-CONTENT"
FAKE_NTDS = "FIXTURE-FAKE-NTDS-SAMPLE-BYTES"
FAKE_DPAPI = "FIXTURE-FAKE-DPAPI-BACKUP-KEY"

T = "S-1-5-21-TARGET"


# --- pure analyzers -----------------------------------------------------

def test_esc6_confirmed_when_flag_present():
    res = esc6_esc7.analyze_esc6("CN=CA01", ["EDITF_ATTRIBUTESUBJECTALTNAME2", "OTHER_FLAG"])
    assert res.verdict == "Confirmed"
    assert res.proof_class == "adcs-esc6-editf-attributesubjectaltname2-set"
    assert res.redacted_refs["editfAttributeSubjectAltName2"] == "yes"


def test_esc6_not_exploitable_when_flag_absent():
    res = esc6_esc7.analyze_esc6("CN=CA01", ["OTHER_FLAG"])
    assert res.verdict == "NotExploitable"
    assert "does not have" in " ".join(res.assertions)


def test_esc7_confirmed_with_manageca():
    aces = [Ace(T, "ManageCA")]
    res = esc6_esc7.analyze_esc7(T, "CN=CA01", aces)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["esc7RightsHeld"] == ["ManageCA"]


def test_esc7_confirmed_with_managecertificates():
    aces = [Ace(T, "ManageCertificates")]
    res = esc6_esc7.analyze_esc7(T, "CN=CA01", aces)
    assert res.verdict == "Confirmed"


def test_esc7_deny_overrides_allow():
    aces = [Ace(T, "ManageCA", effect="Allow"), Ace(T, "ManageCA", effect="Deny")]
    res = esc6_esc7.analyze_esc7(T, "CN=CA01", aces)
    assert res.verdict == "NotExploitable"


def test_esc7_ignores_unrelated_principal():
    aces = [Ace("S-1-5-21-OTHER", "ManageCA")]
    res = esc6_esc7.analyze_esc7(T, "CN=CA01", aces)
    assert res.verdict == "NotExploitable"


def test_delegation_unconstrained_wins_over_constrained():
    res = delegation_rights.analyze("HOST$", {
        "unconstrained": True, "protocol_transition": False,
        "allowed_to_delegate_to": ["cifs/x.corp"],
    })
    assert res.verdict == "Confirmed"
    assert res.proof_class == "delegation-unconstrained-configured"


def test_delegation_constrained_with_protocol_transition_labels_correctly():
    res = delegation_rights.analyze("HOST$", {
        "unconstrained": False, "protocol_transition": True,
        "allowed_to_delegate_to": ["cifs/x.corp"],
    })
    assert res.verdict == "Confirmed"
    assert res.proof_class == "delegation-constrained-with-protocol-transition"


def test_delegation_not_configured_is_not_exploitable():
    res = delegation_rights.analyze("HOST$", {"unconstrained": False,
                                              "protocol_transition": False,
                                              "allowed_to_delegate_to": []})
    assert res.verdict == "NotExploitable"


# --- end-to-end (CLI, fixture-backed) -----------------------------------

def _eng(tmp_path, cap_id, target, technique, state_changing=False):
    cap = {"approved": True, "targets": [target], "attackTechnique": technique,
           "maximumActions": 1}
    if state_changing:
        cap.update({"stateChangingApproved": True, "riskAccepted": True,
                    "riskAcceptanceReference": "RA-LAB", "cleanupRequired": True,
                    "labContainmentRequired": True})
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-NEW",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop"],
        "labAddressRanges": ["10.10.0.0/16"], "labResolvedAddresses": ["10.10.0.5"],
        "capabilities": {cap_id: cap},
    }
    p = tmp_path / f"{cap_id}.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return str(p)


def _fix(tmp_path, data):
    p = tmp_path / "fix.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _run(eng, cap_id, target, out, fix, control="ADAF-X"):
    return main([
        "run", "--engagement", eng, "--capability", cap_id,
        "--source-address", "192.0.2.25", "--target", target,
        "--finding-id", "F-0123456789ABCDEF", "--control-id", control,
        "--fixture", fix, "--out", str(out),
    ])


def test_esc6_end_to_end_via_cli(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc6-editf-check", "CN=CA01", "T1649")
    fix = _fix(tmp_path, {"esc6": {"CN=CA01": {"flags": ["EDITF_ATTRIBUTESUBJECTALTNAME2"]}}})
    assert _run(eng, "adcs-esc6-editf-check", "CN=CA01", out, fix, control="ADAF-ESC6") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"


def test_esc7_end_to_end_via_cli_uses_object_acl(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc7-manage-rights", T, "T1649")
    fix = _fix(tmp_path, {"object_acl": [{"trustee": T, "right": "ManageCertificates"}]})
    assert _run(eng, "adcs-esc7-manage-rights", T, out, fix, control="ADAF-ESC7") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["esc7RightsHeld"] == ["ManageCertificates"]


def test_esc8_confirmed_pfx_never_leaks_and_durable_residue(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc8-relay-web-enrollment", "WIN-LAB01$",
               "T1649", state_changing=True)
    fix = _fix(tmp_path, {"esc8": {"WIN-LAB01$": {"coerced": True, "relayed": True,
        "issued": True, "authenticated": True, "revoke_ok": True,
        "serial": "AABBCCDD1234", "ca": "http://ca01/certsrv/"}}})
    rc = _run(eng, "adcs-esc8-relay-web-enrollment", "WIN-LAB01$", out, fix,
              control="ADAF-ESC8")
    assert rc == 0
    text = (out / "validation-result.json").read_text()
    doc = json.loads(text)
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["proofClass"] == "relayed-machine-auth-to-web-enrollment"
    # Revocation succeeded -> verified True, but issuance is durable -> residue present.
    assert doc["cleanup"]["verified"] is True
    assert any("durable" in r.lower() for r in doc["cleanup"]["durableResidue"])
    refs = doc["proof"]["redactedRefs"]
    assert refs["issuedSerialLast4"] == "1234"
    assert refs["secretHandles"][0].startswith("pfx#redacted")
    assert len(refs["certificateSha256"]) == 64
    assert FAKE_PFX not in text
    assert not is_latched(out)


def test_esc8_failed_revocation_latches(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc8-relay-web-enrollment", "WIN-LAB01$",
               "T1649", state_changing=True)
    fix = _fix(tmp_path, {"esc8": {"WIN-LAB01$": {"coerced": True, "relayed": True,
        "issued": True, "authenticated": True, "revoke_ok": False,
        "serial": "AABBCCDD1234", "ca": "http://ca01/certsrv/"}}})
    assert _run(eng, "adcs-esc8-relay-web-enrollment", "WIN-LAB01$", out, fix,
                control="ADAF-ESC8") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["cleanup"]["verified"] is False
    assert any("NOT revoked" in r for r in doc["cleanup"]["durableResidue"])
    assert is_latched(out)


def test_delegation_rights_confirmed_end_to_end(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "delegation-rights-validation", "HOST$", "T1558")
    fix = _fix(tmp_path, {"delegation": {"HOST$": {"unconstrained": True,
        "protocol_transition": False, "allowed_to_delegate_to": []}}})
    assert _run(eng, "delegation-rights-validation", "HOST$", out, fix,
                control="ADAF-DEL") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["proofClass"] == "delegation-unconstrained-configured"


def test_delegation_s4u_confirmed_no_ticket_exported(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "delegation-s4u2proxy-proof", "svc$", "T1558",
               state_changing=False)
    fix = _fix(tmp_path, {"s4u": {"svc$": {"s4u2self_ok": True, "s4u2proxy_ok": True,
                                            "authenticated": True}}})
    assert _run(eng, "delegation-s4u2proxy-proof", "svc$", out, fix,
                control="ADAF-S4U") == 0
    text = (out / "validation-result.json").read_text()
    doc = json.loads(text)
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["proofClass"] == "delegation-s4u2proxy-confirmed"
    # Boolean-only: no ticket bytes anywhere.
    for bad in ("ticket-bytes", "TGT-BYTES", "TICKET_BYTES"):
        assert bad.lower() not in text.lower() or "no ticket" in text.lower()
    # No secret handles ever created — the proof is boolean.
    assert "secretHandles" not in doc["proof"]["redactedRefs"]


def test_delegation_s4u_not_exploitable_when_s4u2proxy_fails(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "delegation-s4u2proxy-proof", "svc$", "T1558")
    fix = _fix(tmp_path, {"s4u": {"svc$": {"s4u2self_ok": True, "s4u2proxy_ok": False,
                                            "authenticated": False}}})
    assert _run(eng, "delegation-s4u2proxy-proof", "svc$", out, fix,
                control="ADAF-S4U") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "NotExploitable"


def test_ntds_dpapi_confirmed_bytes_never_leak(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "ntds-dpapi-read-proof", "DC01", "T1003.003",
               state_changing=False)
    fix = _fix(tmp_path, {"ntds": {"DC01": {"ntds_readable": True,
        "account_count": 4321, "dpapi_readable": True}}})
    rc = _run(eng, "ntds-dpapi-read-proof", "DC01", out, fix, control="ADAF-NTDS")
    assert rc == 0
    text = (out / "validation-result.json").read_text()
    doc = json.loads(text)
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["proofClass"] == "ntds-dpapi-readable-not-exported"
    refs = doc["proof"]["redactedRefs"]
    assert refs["accountCount"] == 4321
    assert refs["ntdsReadable"] == "yes" and refs["dpapiBackupKeyReadable"] == "yes"
    assert len(refs["ntdsSampleSha256"]) == 64
    assert len(refs["dpapiBackupKeySha256"]) == 64
    handles = refs["secretHandles"]
    assert any(h.startswith("ntds-dit-sample#redacted") for h in handles)
    assert any(h.startswith("dpapi-backup-key#redacted") for h in handles)
    # Neither the NTDS sample nor the DPAPI key value ever appears in the output.
    assert FAKE_NTDS not in text
    assert FAKE_DPAPI not in text
    journal_text = (out / "transaction-journal.jsonl").read_text()
    assert FAKE_NTDS not in journal_text and FAKE_DPAPI not in journal_text


def test_ntds_dpapi_not_readable_reports_not_exploitable(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "ntds-dpapi-read-proof", "DC01", "T1003.003")
    fix = _fix(tmp_path, {"ntds": {"DC01": {"ntds_readable": False,
        "dpapi_readable": False}}})
    assert _run(eng, "ntds-dpapi-read-proof", "DC01", out, fix,
                control="ADAF-NTDS") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "NotExploitable"
    assert doc["proof"]["redactedRefs"]["secretHandles"] == []


# --- live-primitive raises without fixture ------------------------------

def test_esc6_live_primitive_raises_without_fixture(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc6-editf-check", "CN=CA01", "T1649")
    rc = main(["run", "--engagement", eng, "--capability", "adcs-esc6-editf-check",
               "--source-address", "192.0.2.25", "--target", "CN=CA01",
               "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-ESC6",
               "--out", str(out)])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err


def test_esc8_live_primitive_raises_without_fixture(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adcs-esc8-relay-web-enrollment", "WIN-LAB01$", "T1649",
               state_changing=True)
    rc = main(["run", "--engagement", eng, "--capability",
               "adcs-esc8-relay-web-enrollment", "--source-address", "192.0.2.25",
               "--target", "WIN-LAB01$", "--finding-id", "F-0123456789ABCDEF",
               "--control-id", "ADAF-ESC8", "--out", str(out)])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err


def test_delegation_s4u_live_primitive_raises_without_fixture(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "delegation-s4u2proxy-proof", "svc$", "T1558")
    rc = main(["run", "--engagement", eng, "--capability", "delegation-s4u2proxy-proof",
               "--source-address", "192.0.2.25", "--target", "svc$",
               "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-S4U",
               "--out", str(out)])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err


def test_ntds_dpapi_live_primitive_raises_without_fixture(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "ntds-dpapi-read-proof", "DC01", "T1003.003")
    rc = main(["run", "--engagement", eng, "--capability", "ntds-dpapi-read-proof",
               "--source-address", "192.0.2.25", "--target", "DC01",
               "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-NTDS",
               "--out", str(out)])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err

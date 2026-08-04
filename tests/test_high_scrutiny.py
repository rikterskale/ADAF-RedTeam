"""Phase 2 inc 3: exec / forgery / coercion / relay / evasion / reliability.

All wired as gated scaffolds; live primitives raise; orchestration exercised via
fixtures. Secret material (forged tickets, relay keys) must never leak."""

import json

from adaf_redteam.__main__ import main

SECRETS = ("FIXTURE-FAKE-TICKET-BYTES", "FIXTURE-FAKE-RELAY-KEY")


def _eng(tmp_path, cap_id, target, technique, notify=None):
    cap = {"approved": True, "targets": [target], "attackTechnique": technique,
           "maximumActions": 1, "stateChangingApproved": True, "riskAccepted": True,
           "riskAcceptanceReference": "RA", "cleanupRequired": True, "labContainmentRequired": True}
    if notify:
        cap["detectionNotification"] = notify
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-INC3",
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


def _run(eng, cap_id, target, out, fix=None, control="ADAF-X"):
    argv = ["run", "--engagement", eng, "--capability", cap_id, "--source-address", "192.0.2.25",
            "--target", target, "--finding-id", "F-0123456789ABCDEF", "--control-id", control,
            "--out", str(out)]
    if fix:
        argv += ["--fixture", fix]
    return main(argv)


def _no_secret(out):
    text = (out / "validation-result.json").read_text()
    for s in SECRETS:
        assert s not in text
    return json.loads(text)


def test_exec_proof_confirmed_and_cleans_up(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "exec-proof-svcctl", "WIN-LAB01", "T1569.002")
    fix = _fix(tmp_path, {"exec": {"WIN-LAB01": {"marker_echoed": True, "exit_code": 0}}})
    assert _run(eng, "exec-proof-svcctl", "WIN-LAB01", out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed" and doc["cleanup"]["verified"] is True


def test_golden_ticket_confirmed_secret_redacted(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "golden-silver-ticket", "krbtgt", "T1558.001")
    fix = _fix(tmp_path, {"forge": {"krbtgt": {"auth_ok": True}}})
    assert _run(eng, "golden-silver-ticket", "krbtgt", out, fix) == 0
    doc = _no_secret(out)
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["secretHandles"][0].startswith("kerberos-ticket#redacted")


def test_coercion_confirmed(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "coercion-petitpotam", "DC01", "T1187")
    fix = _fix(tmp_path, {"coercion": {"DC01": {"callback_observed": True}}})
    assert _run(eng, "coercion-petitpotam", "DC01", out, fix) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"


def test_relay_confirmed_secret_redacted_and_restored(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "smb-ldap-relay-shadowcred", "WIN-LAB01$", "T1557.001")
    fix = _fix(tmp_path, {"relay": {"WIN-LAB01$": {"relayed": True, "written": True, "restore_ok": True}}})
    assert _run(eng, "smb-ldap-relay-shadowcred", "WIN-LAB01$", out, fix) == 0
    doc = _no_secret(out)
    assert doc["verdict"] == "Confirmed"
    assert doc["cleanup"]["verified"] is True
    assert doc["proof"]["redactedRefs"]["secretHandles"][0].startswith("relay-shadowcred-privkey#redacted")


def test_evasion_emits_detection_block_and_gap_verdict(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adversary-emulation-evasion", "WIN-LAB01", "T1562",
               notify="Notify SOC lead before window")
    fix = _fix(tmp_path, {"evasion": {"WIN-LAB01":
              {"detected": ["EDR-rule-1"], "not_detected": ["amsi-bypass"], "controls": ["EDR"]}}})
    assert _run(eng, "adversary-emulation-evasion", "WIN-LAB01", out, fix, control="ADAF-EVA") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"  # a detection gap exists
    det = doc["proof"]["detection"]
    assert det["notDetected"] == ["amsi-bypass"] and det["detectedBy"] == ["EDR-rule-1"]


def test_evasion_blocked_without_detection_notification(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "adversary-emulation-evasion", "WIN-LAB01", "T1562")  # no notify
    fix = _fix(tmp_path, {"evasion": {"WIN-LAB01": {"detected": [], "not_detected": ["x"]}}})
    rc = _run(eng, "adversary-emulation-evasion", "WIN-LAB01", out, fix, control="ADAF-EVA")
    assert rc == 3
    assert "detectionNotification" in capsys.readouterr().err


def test_reliability_confirmed_with_detection(tmp_path):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "payload-reliability-labtest", "WIN-LAB01", "T1550",
               notify="Notify SOC lead")
    fix = _fix(tmp_path, {"reliability": {"WIN-LAB01": {"attempts": 10, "successes": 7, "detected": ["siem-1"]}}})
    assert _run(eng, "payload-reliability-labtest", "WIN-LAB01", out, fix, control="ADAF-REL") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["proof"]["redactedRefs"]["reliabilityPct"] == 70


def test_live_primitives_raise_without_fixture(tmp_path, capsys):
    out = tmp_path / "o"
    eng = _eng(tmp_path, "coercion-petitpotam", "DC01", "T1187")
    rc = _run(eng, "coercion-petitpotam", "DC01", out)  # no fixture -> live -> raises
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err

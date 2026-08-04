"""RBCD state-changing capability: containment gate, mutate->restore, cleanup latch."""

import json

from adaf_redteam.__main__ import main
from adaf_redteam.statechange import is_latched


def _engagement(tmp_path, *, lab_ranges=None, lab_addresses=None):
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-RBCD",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop"],
        "labAddressRanges": lab_ranges if lab_ranges is not None else ["10.10.0.0/16"],
        "labResolvedAddresses": lab_addresses if lab_addresses is not None else ["10.10.0.5"],
        "capabilities": {"rbcd-write-validation": {
            "approved": True, "targets": ["WIN-LAB01$"], "attackTechnique": "T1558",
            "maximumActions": 1, "stateChangingApproved": True, "riskAccepted": True,
            "riskAcceptanceReference": "RA-LAB-RBCD", "cleanupRequired": True,
            "labContainmentRequired": True}},
    }
    p = tmp_path / "eng.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return str(p)


def _fixture(tmp_path, **rbcd):
    data = {"rbcd": {"WIN-LAB01$": {"current": None, "s4u_ok": True, **rbcd}}}
    p = tmp_path / "fix.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _run(tmp_path, eng, fix, out):
    return main([
        "run", "--engagement", eng, "--capability", "rbcd-write-validation",
        "--source-address", "192.0.2.25", "--target", "WIN-LAB01$",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-RBCD",
        "--fixture", fix, "--out", str(out),
    ])


def test_rbcd_confirmed_with_restore_verified(tmp_path):
    out = tmp_path / "out"
    rc = _run(tmp_path, _engagement(tmp_path), _fixture(tmp_path), out)
    assert rc == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["stateChanging"] is True
    assert doc["containment"]["verified"] is True
    assert doc["cleanup"]["verified"] is True
    assert doc["cleanup"]["durableResidue"] == []
    # journal was written and is secret-free
    journal = (out / "transaction-journal.jsonl").read_text()
    assert "write-rbcd" in journal and "restore" in journal
    assert "password" not in json.dumps(doc).lower()
    assert not is_latched(out)


def test_rbcd_blocked_when_address_out_of_lab_range(tmp_path):
    out = tmp_path / "out"
    eng = _engagement(tmp_path, lab_addresses=["192.0.2.99"])  # outside 10.10/16
    rc = _run(tmp_path, eng, _fixture(tmp_path), out)
    assert rc == 3
    assert not (out / "validation-result.json").exists()


def test_rbcd_failed_restore_latches(tmp_path, capsys):
    out = tmp_path / "out"
    rc = _run(tmp_path, _engagement(tmp_path), _fixture(tmp_path, restore_fails=True), out)
    assert rc == 0  # the run completes, but...
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["cleanup"]["verified"] is False
    assert doc["cleanup"]["durableResidue"]  # residue noted
    assert is_latched(out)  # latch set

    # A subsequent state-changing run in the same out dir is refused.
    rc2 = _run(tmp_path, _engagement(tmp_path), _fixture(tmp_path), out)
    assert rc2 == 3
    assert "BLOCKED BY LATCH" in capsys.readouterr().err


def test_rbcd_live_writer_not_certified(tmp_path, capsys):
    # No --fixture -> live writer -> NotImplementedError path (after containment passes).
    out = tmp_path / "out"
    rc = main([
        "run", "--engagement", _engagement(tmp_path), "--capability", "rbcd-write-validation",
        "--source-address", "192.0.2.25", "--target", "WIN-LAB01$",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-RBCD", "--out", str(out),
    ])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err

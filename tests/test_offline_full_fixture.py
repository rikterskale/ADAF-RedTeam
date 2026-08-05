"""Smoke the expanded offline fixture through the real CLI path."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_redteam.__main__ import main

FIX = Path(__file__).resolve().parents[1] / "examples" / "offline-full-fixture.example.json"


def _engagement(tmp_path, capability_id: str, target: str, technique: str, **extra) -> str:
    eng = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-OFFLINE-FULL",
        "authorizedDomains": ["corp.contoso.test"],
        "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z",
        "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"],
        "stopConditions": ["stop"],
        "labAddressRanges": ["10.10.0.0/16"],
        "labResolvedAddresses": ["10.10.0.5"],
        "capabilities": {
            capability_id: {
                "approved": True,
                "targets": [target],
                "attackTechnique": technique,
                "maximumActions": 1,
                **extra,
            }
        },
    }
    path = tmp_path / "eng.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def _run(tmp_path, capability_id: str, target: str, technique: str, **extra) -> dict:
    out = tmp_path / f"out-{capability_id}"
    rc = main([
        "run",
        "--engagement", _engagement(tmp_path, capability_id, target, technique, **extra),
        "--capability", capability_id,
        "--source-address", "192.0.2.25",
        "--target", target,
        "--finding-id", "F-0FF1CE0000000000",
        "--control-id", "ADAF-OFFLINE",
        "--fixture", str(FIX),
        "--out", str(out),
    ])
    assert rc == 0, f"{capability_id} offline run failed: rc={rc}"
    return json.loads((out / "validation-result.json").read_text(encoding="utf-8"))


def test_offline_asrep_confirmed(tmp_path):
    doc = _run(tmp_path, "asrep-roast-validation", "svc-asrep01", "T1558.004")
    assert doc["verdict"] == "Confirmed"


def test_offline_kerberoast_confirmed(tmp_path):
    doc = _run(tmp_path, "kerberoast-validation", "MSSQLSvc/db01.corp.contoso.test", "T1558.003")
    assert doc["verdict"] == "Confirmed"


def test_offline_zerologon_confirmed(tmp_path):
    doc = _run(tmp_path, "zerologon-detection", "DC01", "T1210")
    assert doc["verdict"] == "Confirmed"


def test_offline_dcsync_rights(tmp_path):
    doc = _run(tmp_path, "dcsync-rights-validation", "S-1-5-21-EXAMPLE-512", "T1003.006")
    assert doc["verdict"] == "Confirmed"


def test_offline_rbcd_with_restore(tmp_path):
    doc = _run(
        tmp_path,
        "rbcd-write-validation",
        "WIN-LAB01$",
        "T1558",
        stateChangingApproved=True,
        riskAccepted=True,
        riskAcceptanceReference="RA-OFFLINE",
        cleanupRequired=True,
        labContainmentRequired=True,
    )
    assert doc["verdict"] == "Confirmed"
    assert doc["cleanup"]["verified"] is True

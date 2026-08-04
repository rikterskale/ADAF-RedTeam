"""Phase 1 dispatch: execute -> analyze -> bridge, driven offline by a fixture."""

import json
from pathlib import Path

from adaf_redteam.__main__ import main

ENG = "examples/engagement.example.json"
ROOT = Path(__file__).resolve().parents[1]


def _write_fixture(tmp_path, **over):
    data = {
        "domain_acl": [
            {"trustee": "svc-asrep01", "right": "DS-Replication-Get-Changes"},
            {"trustee": "svc-asrep01", "right": "DS-Replication-Get-Changes-All"},
        ],
    }
    data.update(over)
    p = tmp_path / "acl.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_execute_dcsync_produces_validation_result(tmp_path, capsys):
    # Reuse the example engagement's asrep target as the DCSync principal under test.
    # Add dcsync-rights-validation authz by pointing --target at an authorized value.
    fixture = _write_fixture(tmp_path)
    rc = main([
        "run", "--engagement", ENG, "--capability", "dcsync-rights-validation",
        "--source-address", "192.0.2.25", "--target", "svc-asrep01",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-DCSYNC",
        "--fixture", fixture, "--out", str(tmp_path / "out"),
    ])
    # dcsync-rights-validation is not in the example engagement -> gate blocks (rc 3).
    assert rc == 3
    assert "not listed" in capsys.readouterr().err


def test_execute_with_authorized_capability(tmp_path, capsys):
    # Build a minimal engagement that authorizes dcsync-rights-validation.
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-002",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop on request"],
        "capabilities": {
            "dcsync-rights-validation": {
                "approved": True, "targets": ["svc-asrep01"], "attackTechnique": "T1003.006",
                "maximumActions": 1,
            }
        },
    }
    eng_path = tmp_path / "eng.json"
    eng_path.write_text(json.dumps(eng), encoding="utf-8")
    fixture = _write_fixture(tmp_path)

    rc = main([
        "run", "--engagement", str(eng_path), "--capability", "dcsync-rights-validation",
        "--source-address", "192.0.2.25", "--target", "svc-asrep01",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-DCSYNC",
        "--fixture", fixture, "--out", str(tmp_path / "out"),
    ])
    assert rc == 0
    doc = json.loads((tmp_path / "out" / "validation-result.json").read_text())
    assert doc["verdict"] == "Confirmed"
    assert doc["readinessUsed"] == "Executable"
    assert doc["stateChanging"] is False
    # Unvalidated caveat is present because lab_certified=False.
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])
    # No secret material anywhere in the emitted result.
    blob = json.dumps(doc).lower()
    assert "password" not in blob and "krbtgt" not in blob


def test_live_collector_reports_not_certified(tmp_path, capsys):
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-003",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop"],
        "capabilities": {"dcsync-rights-validation": {
            "approved": True, "targets": ["svc-asrep01"], "attackTechnique": "T1003.006",
            "maximumActions": 1}},
    }
    eng_path = tmp_path / "eng.json"
    eng_path.write_text(json.dumps(eng), encoding="utf-8")
    # No --fixture -> live collector -> NotImplementedError path.
    rc = main([
        "run", "--engagement", str(eng_path), "--capability", "dcsync-rights-validation",
        "--source-address", "192.0.2.25", "--target", "svc-asrep01",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-DCSYNC",
        "--out", str(tmp_path / "out"),
    ])
    assert rc == 4
    assert "NOT CERTIFIED" in capsys.readouterr().err

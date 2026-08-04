"""Schema validity + bridge invariants."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.mark.parametrize("name", [p.name for p in SCHEMA_DIR.glob("*.json")])
def test_schema_is_valid_draft202012(name):
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_example_engagement_matches_schema():
    schema = json.loads((SCHEMA_DIR / "engagement.schema.json").read_text(encoding="utf-8"))
    data = json.loads((EXAMPLES / "engagement.example.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(data)


def _result_schema():
    return json.loads((SCHEMA_DIR / "validation-result.schema.json").read_text(encoding="utf-8"))


def _minimal_result(**over):
    doc = {
        "schemaVersion": "1.0",
        "resultId": "VR-0123456789ABCDEF",
        "engagementId": "ENG-LAB-001",
        "producedByUtc": "2026-08-04T00:00:00Z",
        "producer": {"tool": "ADAF-RedTeam", "version": "0.1.0"},
        "correlatesTo": {"FindingId": "F-0123456789ABCDEF", "ControlId": "ADAF-ADCS-ESC1"},
        "capabilityId": "adcs-esc1-validation",
        "attackTechnique": "T1649",
        "target": {"domain": "corp.contoso.test"},
        "verdict": "Confirmed",
        "readinessUsed": "LabExecutable",
        "stateChanging": False,
        "proof": {"proofClass": "enrolled-certificate", "assertions": ["ok"]},
        "authorization": {"authorizedSourceAddress": "192.0.2.25", "operatorContact": "x@y.test"},
        "integrity": {"resultSha256": "a" * 64},
    }
    doc.update(over)
    return doc


def test_state_changing_requires_containment_and_cleanup():
    schema = _result_schema()
    bad = _minimal_result(stateChanging=True)  # missing containment + cleanup
    assert list(Draft202012Validator(schema).iter_errors(bad)), "must reject state-change w/o containment"

    good = _minimal_result(
        stateChanging=True,
        containment={"verified": True, "environment": "disposable-lab"},
        cleanup={"required": True, "performed": True, "verified": True, "durableResidue": []},
    )
    Draft202012Validator(schema).validate(good)


def test_executable_cannot_be_state_changing():
    schema = _result_schema()
    bad = _minimal_result(readinessUsed="Executable", stateChanging=True,
                          containment={"verified": True, "environment": "authorized-production"},
                          cleanup={"required": True, "performed": True, "verified": True})
    assert list(Draft202012Validator(schema).iter_errors(bad))


def test_no_additional_top_level_properties():
    schema = _result_schema()
    bad = _minimal_result(loot="should-not-be-allowed")
    assert list(Draft202012Validator(schema).iter_errors(bad))

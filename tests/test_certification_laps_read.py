"""Lab-gated certification test for laps-read-authorization.

Reads the computer object's LAPS attribute ACL only — never the password value.

Required env vars when running:
  ADAF_RT_LAB=1
  ADAF_RT_LAB_DOMAIN
  ADAF_RT_LAB_DC
  ADAF_RT_LAB_SOURCE_ADDR
  ADAF_RT_LAB_BIND_USER
  ADAF_RT_LAB_TARGET_PRINCIPAL     principal SID/DN under test
  ADAF_RT_LAB_LAPS_COMPUTER_DN     computer object DN whose ACL is read
  ADAF_RT_LAB_EXPECTED             Confirmed | NotExploitable
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("ldap3")
pytest.importorskip("impacket")

from adaf_redteam.__main__ import main

REQUIRED_ENV = (
    "ADAF_RT_LAB",
    "ADAF_RT_LAB_DOMAIN",
    "ADAF_RT_LAB_DC",
    "ADAF_RT_LAB_SOURCE_ADDR",
    "ADAF_RT_LAB_BIND_USER",
    "ADAF_RT_LAB_TARGET_PRINCIPAL",
    "ADAF_RT_LAB_LAPS_COMPUTER_DN",
    "ADAF_RT_LAB_EXPECTED",
)

missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
pytestmark = pytest.mark.skipif(
    bool(missing) or os.environ.get("ADAF_RT_LAB") != "1",
    reason=f"lab-gated certification test; missing env: {missing or ['ADAF_RT_LAB!=1']}",
)


def _engagement(tmp_path) -> str:
    domain = os.environ["ADAF_RT_LAB_DOMAIN"]
    source_addr = os.environ["ADAF_RT_LAB_SOURCE_ADDR"]
    dc = os.environ["ADAF_RT_LAB_DC"]
    # Engagement target is the principal under test (authorized target list).
    target = os.environ["ADAF_RT_LAB_TARGET_PRINCIPAL"]
    eng = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-CERT-LAPS",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {"laps-read-authorization": {
            "approved": True, "targets": [target],
            "attackTechnique": "T1552", "maximumActions": 1,
        }},
    }
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def test_laps_read_certification_lab_run(tmp_path, capsys):
    expected = os.environ["ADAF_RT_LAB_EXPECTED"]
    assert expected in {"Confirmed", "NotExploitable"}

    out = tmp_path / "out"
    target = os.environ["ADAF_RT_LAB_TARGET_PRINCIPAL"]
    rc = main([
        "run", "--engagement", _engagement(tmp_path),
        "--capability", "laps-read-authorization",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", target,
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-LAPS000000",
        "--control-id", "ADAF-CERT-LAPS",
        "--out", str(out),
    ])
    assert rc == 0, f"live run failed: rc={rc}, stderr={capsys.readouterr().err}"

    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected

    lower = result_text.lower()
    for bad in ("ms-mcs-admpwd:", "password value", "-----begin", "nthash", "cleartext"):
        assert bad not in lower, f"redaction leak: {bad!r}"

    assert any("NOT retrieved" in a for a in doc["proof"]["assertions"])
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])

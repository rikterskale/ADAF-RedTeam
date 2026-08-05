"""Lab-gated certification test for zerologon-detection.

Runs the FULL live pipeline against a disposable-lab DC:
  bound zero-challenge Netlogon auth attempts -> analyzer -> bridge ->
  validation-result.json

The probe MUST stop before NetrServerPasswordSet2. This test asserts the
result shape and redaction; the operator must also confirm via packet capture
/ DC audit that no password-set call occurred (see docs/certifications/).

Skipped unless the operator opts in with `ADAF_RT_LAB=1` and supplies the
required env vars. Never runs in normal CI.

Required env vars when running:
  ADAF_RT_LAB=1                          opt-in acknowledging disposable-lab work
  ADAF_RT_LAB_DOMAIN                     lab AD domain
  ADAF_RT_LAB_DC                         lab DC hostname / IP
  ADAF_RT_LAB_SOURCE_ADDR                operator's authorized source address
  ADAF_RT_LAB_ZEROLOGON_TARGET           DC machine name or hostname under test
  ADAF_RT_LAB_EXPECTED                   "Confirmed" or "NotExploitable"
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("impacket")

from adaf_redteam.__main__ import main

REQUIRED_ENV = (
    "ADAF_RT_LAB",
    "ADAF_RT_LAB_DOMAIN",
    "ADAF_RT_LAB_DC",
    "ADAF_RT_LAB_SOURCE_ADDR",
    "ADAF_RT_LAB_ZEROLOGON_TARGET",
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
    target = os.environ["ADAF_RT_LAB_ZEROLOGON_TARGET"]
    eng = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-CERT-ZEROLOGON",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {"zerologon-detection": {
            "approved": True, "targets": [target],
            "attackTechnique": "T1210", "maximumActions": 1,
        }},
    }
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def test_zerologon_detection_certification_lab_run(tmp_path, capsys):
    expected = os.environ["ADAF_RT_LAB_EXPECTED"]
    assert expected in {"Confirmed", "NotExploitable"}

    out = tmp_path / "out"
    target = os.environ["ADAF_RT_LAB_ZEROLOGON_TARGET"]
    rc = main([
        "run", "--engagement", _engagement(tmp_path),
        "--capability", "zerologon-detection",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", target,
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-ZEROLOGON0",
        "--control-id", "ADAF-CERT-ZEROLOG",
        "--out", str(out),
    ])
    assert rc == 0, f"live run failed: rc={rc}, stderr={capsys.readouterr().err}"

    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected

    lower = result_text.lower()
    for bad in ("passwordset", "netrserverpasswordset", "nthash", "-----begin",
                "machine account password"):
        assert bad not in lower, f"redaction / scope leak: {bad!r}"

    # Detection-only assertion must be present.
    assert any("NetrServerPasswordSet2 was NOT called" in a for a in doc["proof"]["assertions"])

    # Flag still False; UNVALIDATED stamp required until promotion PR.
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])

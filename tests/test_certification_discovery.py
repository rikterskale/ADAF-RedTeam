"""Lab-gated certification tests for Tier-A discovery capabilities.

Covers:
  - machine-account-quota-check
  - privileged-group-inventory

Required shared env:
  ADAF_RT_LAB=1
  ADAF_RT_LAB_DOMAIN
  ADAF_RT_LAB_DC
  ADAF_RT_LAB_SOURCE_ADDR
  ADAF_RT_LAB_BIND_USER

Quota-specific:
  ADAF_RT_LAB_QUOTA_EXPECTED   Confirmed | NotExploitable

Privileged-group-specific:
  ADAF_RT_LAB_PRIV_GROUP_DN    group DN to enumerate
  ADAF_RT_LAB_PRIV_EXPECTED    Confirmed | NotExploitable
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("ldap3")
pytest.importorskip("impacket")

from adaf_redteam.__main__ import main

SHARED = (
    "ADAF_RT_LAB",
    "ADAF_RT_LAB_DOMAIN",
    "ADAF_RT_LAB_DC",
    "ADAF_RT_LAB_SOURCE_ADDR",
    "ADAF_RT_LAB_BIND_USER",
)

shared_missing = [k for k in SHARED if not os.environ.get(k)]
base_skip = bool(shared_missing) or os.environ.get("ADAF_RT_LAB") != "1"


def _engagement(tmp_path, capability_id: str, target: str, technique: str) -> str:
    domain = os.environ["ADAF_RT_LAB_DOMAIN"]
    source_addr = os.environ["ADAF_RT_LAB_SOURCE_ADDR"]
    dc = os.environ["ADAF_RT_LAB_DC"]
    eng = {
        "schemaVersion": "1.0",
        "engagementId": f"ENG-CERT-{capability_id.upper()[:12]}",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {capability_id: {
            "approved": True, "targets": [target],
            "attackTechnique": technique, "maximumActions": 1,
        }},
    }
    path = tmp_path / f"eng-{capability_id}.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def _assert_clean_and_unvalidated(result_text: str, doc: dict) -> None:
    lower = result_text.lower()
    for bad in ("password", "nthash", "-----begin", "krbtgt:"):
        assert bad not in lower, f"redaction leak: {bad!r}"
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])


@pytest.mark.skipif(
    base_skip or not os.environ.get("ADAF_RT_LAB_QUOTA_EXPECTED"),
    reason="lab-gated; need shared env + ADAF_RT_LAB_QUOTA_EXPECTED",
)
def test_machine_account_quota_certification(tmp_path, capsys):
    expected = os.environ["ADAF_RT_LAB_QUOTA_EXPECTED"]
    assert expected in {"Confirmed", "NotExploitable"}
    domain = os.environ["ADAF_RT_LAB_DOMAIN"]
    out = tmp_path / "out-quota"
    rc = main([
        "run", "--engagement", _engagement(
            tmp_path, "machine-account-quota-check", domain, "T1136.002"),
        "--capability", "machine-account-quota-check",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", domain,
        "--domain", domain,
        "--finding-id", "F-CERT-QUOTA00000",
        "--control-id", "ADAF-CERT-QUOTA",
        "--out", str(out),
    ])
    assert rc == 0, f"quota live run failed: rc={rc}, stderr={capsys.readouterr().err}"
    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected
    assert "machineAccountQuota" in doc["proof"]["redactedRefs"]
    _assert_clean_and_unvalidated(result_text, doc)


@pytest.mark.skipif(
    base_skip or not os.environ.get("ADAF_RT_LAB_PRIV_GROUP_DN")
    or not os.environ.get("ADAF_RT_LAB_PRIV_EXPECTED"),
    reason="lab-gated; need shared env + PRIV_GROUP_DN + PRIV_EXPECTED",
)
def test_privileged_group_certification(tmp_path, capsys):
    expected = os.environ["ADAF_RT_LAB_PRIV_EXPECTED"]
    assert expected in {"Confirmed", "NotExploitable"}
    group_dn = os.environ["ADAF_RT_LAB_PRIV_GROUP_DN"]
    out = tmp_path / "out-priv"
    rc = main([
        "run", "--engagement", _engagement(
            tmp_path, "privileged-group-inventory", group_dn, "T1069.002"),
        "--capability", "privileged-group-inventory",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", group_dn,
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-PRIVGRP000",
        "--control-id", "ADAF-CERT-PRIVGRP",
        "--out", str(out),
    ])
    assert rc == 0, f"priv-group live run failed: rc={rc}, stderr={capsys.readouterr().err}"
    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected
    assert any("Read-only enumeration" in a for a in doc["proof"]["assertions"])
    _assert_clean_and_unvalidated(result_text, doc)

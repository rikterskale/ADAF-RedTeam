"""Lab-gated certification test for kerberoast-validation.

Runs the FULL live pipeline against a disposable-lab DC:
  load TGT from KRB5CCNAME -> one TGS-REQ for the target SPN -> parse ->
  analyzer -> bridge -> validation-result.json

Requires TWO SPNs in the lab:
  - a registered service account SPN (expected Confirmed)
  - a made-up SPN that does not exist (expected NotExploitable)

Skipped unless the operator opts in with `ADAF_RT_LAB=1` and supplies the
required env vars, including a valid `KRB5CCNAME` pointing to a ccache with a
TGT for the lab realm. Never runs in normal CI.

Required env vars when running:
  ADAF_RT_LAB=1                          opt-in acknowledging disposable-lab work
  ADAF_RT_LAB_DOMAIN                     lab AD domain (e.g. corp.contoso.test)
  ADAF_RT_LAB_DC                         lab DC hostname / IP (port 88)
  ADAF_RT_LAB_SOURCE_ADDR                operator's authorized source address
  ADAF_RT_LAB_KERBEROAST_SPN             a registered SPN (e.g. http/host.corp)
  ADAF_RT_LAB_KERBEROAST_MISSING_SPN     an SPN that is NOT registered
  KRB5CCNAME                             path to a ccache with a valid TGT
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
    "ADAF_RT_LAB_KERBEROAST_SPN",
    "ADAF_RT_LAB_KERBEROAST_MISSING_SPN",
    "KRB5CCNAME",
)

missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
pytestmark = pytest.mark.skipif(
    bool(missing) or os.environ.get("ADAF_RT_LAB") != "1",
    reason=f"lab-gated certification test; missing env: {missing or ['ADAF_RT_LAB!=1']}",
)


def _engagement(tmp_path, targets: list[str]) -> str:
    domain = os.environ["ADAF_RT_LAB_DOMAIN"]
    source_addr = os.environ["ADAF_RT_LAB_SOURCE_ADDR"]
    dc = os.environ["ADAF_RT_LAB_DC"]
    eng = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-CERT-KERBEROAST",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {"kerberoast-validation": {
            "approved": True, "targets": targets,
            "attackTechnique": "T1558.003", "maximumActions": 1,
        }},
    }
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def _run_and_check(tmp_path, capsys, spn: str, expected: str) -> dict:
    out = tmp_path / f"out-{spn.replace('/', '_')}"
    rc = main([
        "run", "--engagement", _engagement(tmp_path, [spn]),
        "--capability", "kerberoast-validation",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", spn,
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-KERBEROAS0",
        "--control-id", "ADAF-CERT-KERBRST",
        "--out", str(out),
    ])
    assert rc == 0, f"live run failed for {spn}: rc={rc}, stderr={capsys.readouterr().err}"

    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected, \
        f"expected {expected} for {spn}, got {doc['verdict']}"

    # Cert-doc §1.3: no crackable service-ticket bytes anywhere.
    lower = result_text.lower()
    for bad in ("crackable", "$krb5tgs$", "ticket-bytes", "-----begin",
                "cipher:", "password", "krbtgt:", "nthash", "ntlm"):
        assert bad not in lower, f"redaction leak in {spn} result: {bad!r}"

    # Tier A: flag still False; the UNVALIDATED stamp MUST be present.
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])
    return doc


def test_kerberoast_certification_existing_spn(tmp_path, capsys):
    """§5 mechanical promotion: live run against a registered SPN."""
    doc = _run_and_check(tmp_path, capsys,
                         os.environ["ADAF_RT_LAB_KERBEROAST_SPN"],
                         expected="Confirmed")
    assert doc["proof"]["proofClass"] == "kerberoast-service-ticket-obtained"
    assert doc["proof"]["redactedRefs"]["etype"]


def test_kerberoast_certification_missing_spn(tmp_path, capsys):
    """Negative case: an SPN that doesn't exist is NotExploitable.

    Proves the analyzer isn't returning Confirmed for every SPN.
    """
    doc = _run_and_check(tmp_path, capsys,
                         os.environ["ADAF_RT_LAB_KERBEROAST_MISSING_SPN"],
                         expected="NotExploitable")
    assert doc["proof"]["proofClass"] == "kerberoast-no-ticket"

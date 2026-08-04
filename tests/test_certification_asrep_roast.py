"""Lab-gated certification test for asrep-roast-validation.

Runs the FULL live pipeline against a disposable-lab DC:
  build padata-free AS-REQ -> KDC on port 88 -> parse response ->
  analyzer -> bridge -> validation-result.json

Requires TWO lab accounts:
  - a known DONT_REQUIRE_PREAUTH account (expected Confirmed)
  - a normal preauth-required account (expected NotExploitable)

Skipped unless the operator opts in with `ADAF_RT_LAB=1` and supplies the
required env vars. Never runs in normal CI.

Required env vars when running:
  ADAF_RT_LAB=1                          opt-in acknowledging disposable-lab work
  ADAF_RT_LAB_DOMAIN                     lab AD domain (e.g. corp.contoso.test)
  ADAF_RT_LAB_DC                         lab DC hostname / IP (port 88)
  ADAF_RT_LAB_SOURCE_ADDR                operator's authorized source address
  ADAF_RT_LAB_ASREP_ROASTABLE_USER       account with DONT_REQUIRE_PREAUTH set
  ADAF_RT_LAB_ASREP_PREAUTH_USER         normal account (preauth required)
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
    "ADAF_RT_LAB_ASREP_ROASTABLE_USER",
    "ADAF_RT_LAB_ASREP_PREAUTH_USER",
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
        "engagementId": "ENG-CERT-ASREP",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {"asrep-roast-validation": {
            "approved": True, "targets": targets,
            "attackTechnique": "T1558.004", "maximumActions": 1,
        }},
    }
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def _run_and_check(tmp_path, capsys, target: str, expected: str) -> dict:
    out = tmp_path / f"out-{target}"
    rc = main([
        "run", "--engagement", _engagement(tmp_path, [target]),
        "--capability", "asrep-roast-validation",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", target,
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-ASREP00000",
        "--control-id", "ADAF-CERT-ASREP",
        "--out", str(out),
    ])
    assert rc == 0, f"live run failed for {target}: rc={rc}, stderr={capsys.readouterr().err}"

    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected, \
        f"expected {expected} for {target}, got {doc['verdict']}"

    # Cert-doc §1.3: no crackable AS-REP cipher bytes anywhere.
    lower = result_text.lower()
    for bad in ("crackable", "asrep-hash", "-----begin", "cipher:", "$krb5asrep$",
                "password", "krbtgt:", "nthash", "ntlm"):
        assert bad not in lower, f"redaction leak in {target} result: {bad!r}"

    # Tier A: the flag is still False; the UNVALIDATED stamp MUST be present
    # until the promotion PR flips it.
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])
    return doc


def test_asrep_roast_certification_roastable_user(tmp_path, capsys):
    """§5 mechanical promotion: live run against a DONT_REQUIRE_PREAUTH account."""
    doc = _run_and_check(tmp_path, capsys,
                         os.environ["ADAF_RT_LAB_ASREP_ROASTABLE_USER"],
                         expected="Confirmed")
    assert doc["proof"]["proofClass"] == "asrep-roastable-no-preauth"
    # The analyzer must record an etype string (whatever the KDC returned).
    assert doc["proof"]["redactedRefs"]["etype"]


def test_asrep_roast_certification_normal_user(tmp_path, capsys):
    """The negative case: a normal preauth-required account is NotExploitable.

    Proves the analyzer isn't returning Confirmed for every account.
    """
    doc = _run_and_check(tmp_path, capsys,
                         os.environ["ADAF_RT_LAB_ASREP_PREAUTH_USER"],
                         expected="NotExploitable")
    assert doc["proof"]["proofClass"] == "asrep-preauth-required"

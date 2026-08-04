"""Lab-gated certification test for dcsync-rights-validation.

Runs the FULL live pipeline against a disposable-lab DC:
  bind (LDAPS, Kerberos or SIMPLE) -> read nTSecurityDescriptor (DACL only) ->
  parse -> analyzer -> bridge -> validation-result.json

Skipped unless the operator opts in explicitly with `ADAF_RT_LAB=1` and supplies
lab connection env vars. It never runs in normal CI. See docs/CERTIFICATION.md
for the full evidence package this test contributes to.

Required env vars when running:
  ADAF_RT_LAB=1                     opt-in acknowledging disposable-lab work
  ADAF_RT_LAB_DOMAIN                the lab AD domain (e.g. corp.contoso.test)
  ADAF_RT_LAB_DC                    the lab DC host / IP for the LDAPS bind
  ADAF_RT_LAB_BIND_USER             UPN or DOMAIN\\user for the bind
  ADAF_RT_LAB_TARGET_PRINCIPAL      the SID under test (expected DCSync holder,
                                    e.g. Domain Admins S-1-5-21-...-512)
  ADAF_RT_LAB_EXPECTED              "Confirmed" or "NotExploitable"
  ADAF_RT_LAB_SOURCE_ADDR           the operator's authorized source address
  ADAF_RT_LAB_BIND_PASSWORD         (optional) SIMPLE bind password; omit to use
                                    the Kerberos ccache
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
    "ADAF_RT_LAB_BIND_USER",
    "ADAF_RT_LAB_TARGET_PRINCIPAL",
    "ADAF_RT_LAB_EXPECTED",
    "ADAF_RT_LAB_SOURCE_ADDR",
)

missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
pytestmark = pytest.mark.skipif(
    bool(missing) or os.environ.get("ADAF_RT_LAB") != "1",
    reason=f"lab-gated certification test; missing env: {missing or ['ADAF_RT_LAB!=1']}",
)


def _engagement(tmp_path) -> str:
    domain = os.environ["ADAF_RT_LAB_DOMAIN"]
    target = os.environ["ADAF_RT_LAB_TARGET_PRINCIPAL"]
    source_addr = os.environ["ADAF_RT_LAB_SOURCE_ADDR"]
    dc = os.environ["ADAF_RT_LAB_DC"]
    # The engagement must name the exact lab DC as the sole containment target
    # and the exact source address the operator is running from.
    eng = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-CERT-DCSYNC",
        "authorizedDomains": [domain],
        "authorizedSourceAddresses": [source_addr],
        "windowStartUtc": "2026-01-01T00:00:00Z",
        "windowEndUtc": "2030-01-01T00:00:00Z",
        "operatorContacts": ["cert@lab.local"],
        "stopConditions": ["stop"],
        "labAddressRanges": [],
        "labResolvedAddresses": [dc],
        "capabilities": {"dcsync-rights-validation": {
            "approved": True, "targets": [target],
            "attackTechnique": "T1003.006", "maximumActions": 1,
        }},
    }
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(eng), encoding="utf-8")
    return str(path)


def test_dcsync_rights_certification_lab_run(tmp_path, capsys):
    """§5 mechanical promotion: live run against the lab DC.

    Asserts: verdict matches lab expectation, output contains the UNVALIDATED
    stamp (flag still False here), no secret substrings, no DRSUAPI reference,
    and the transaction journal is either absent or clean.
    """
    expected = os.environ["ADAF_RT_LAB_EXPECTED"]
    assert expected in {"Confirmed", "NotExploitable"}, \
        "ADAF_RT_LAB_EXPECTED must be 'Confirmed' or 'NotExploitable'"

    out = tmp_path / "out"
    rc = main([
        "run", "--engagement", _engagement(tmp_path),
        "--capability", "dcsync-rights-validation",
        "--source-address", os.environ["ADAF_RT_LAB_SOURCE_ADDR"],
        "--target", os.environ["ADAF_RT_LAB_TARGET_PRINCIPAL"],
        "--domain", os.environ["ADAF_RT_LAB_DOMAIN"],
        "--finding-id", "F-CERT-DCSYNC000",
        "--control-id", "ADAF-CERT-DCSYNC",
        "--out", str(out),
    ])
    assert rc == 0, f"live run failed: rc={rc}, stderr={capsys.readouterr().err}"

    result_text = (out / "validation-result.json").read_text(encoding="utf-8")
    doc = json.loads(result_text)
    assert doc["verdict"] == expected

    # Cert-doc §1.3: redaction proven. No secret substrings anywhere.
    lower = result_text.lower()
    for bad in ("password", "krbtgt", "nthash", "ntlm", "aes256-cts", "aes128-cts",
                "-----begin", "hash:", "ticket-bytes"):
        assert bad not in lower, f"redaction leak: {bad!r} in result"

    # Cert-doc §2 Tier A: proof that DRSUAPI was not called. This is a read-side
    # collector; the analyzer's own assertions promise it, and nothing in the
    # output should reference DRS.
    assert "drsuapi" not in lower and "drs replication" not in lower

    # Flag is still False in the shipped registry; the UNVALIDATED stamp MUST be
    # present until this test's evidence is complete and the flag is flipped.
    # (Once the flag flips in a later PR, delete this assertion.)
    assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])

    # Transaction journal (if the capability keeps one) must also be clean.
    journal = out / "transaction-journal.jsonl"
    if journal.exists():
        jtext = journal.read_text(encoding="utf-8").lower()
        for bad in ("password", "krbtgt", "-----begin"):
            assert bad not in jtext, f"journal leak: {bad!r}"

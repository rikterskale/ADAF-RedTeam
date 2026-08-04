"""Bridge build + ADAF ingest round trip."""

import importlib.util
import json
from pathlib import Path

from adaf_redteam.bridge import build_result, write_result
from adaf_redteam.capabilities.base import CapabilityResult
from adaf_redteam.capabilities.registry import get_descriptor

ROOT = Path(__file__).resolve().parents[1]


def _load_ingest():
    spec = importlib.util.spec_from_file_location("adaf_ingest", ROOT / "bridge" / "adaf_ingest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_result():
    d = get_descriptor("adcs-esc1-validation")
    result = CapabilityResult(
        verdict="Confirmed",
        proof_class="enrolled-certificate-for-arbitrary-san",
        assertions=["Enrollment request accepted", "Certificate chains to root"],
        redacted_refs={"certificateSha256": "b1946ac9" + "0" * 56, "secretHandles": ["pfx#redacted-01"]},
        cleanup={"required": True, "performed": True, "verified": True, "durableResidue": ["AD CS issuance record"]},
    )
    return build_result(
        engagement_id="ENG-LAB-001", descriptor=d,
        finding_id="F-0123456789ABCDEF", control_id="ADAF-ADCS-ESC1",
        domain="corp.contoso.test", principal="CN=CA01",
        result=result, readiness_used="LabExecutable", state_changing=True,
        source_address="192.0.2.25", operator_contact="purple@contoso.test",
        risk_ref="RA-LAB-EXAMPLE",
        containment={"verified": True, "environment": "disposable-lab"},
        budget={"actionsAuthorized": 3, "actionsUsed": 1, "minIntervalMs": 5000},
    )


def test_build_result_validates_and_hashes():
    doc = _make_result()
    assert doc["resultId"].startswith("VR-")
    assert len(doc["integrity"]["resultSha256"]) == 64
    # no secret material shapes present
    assert "pfx#redacted-01" in doc["proof"]["redactedRefs"]["secretHandles"]


def test_ingest_round_trip(tmp_path):
    doc = _make_result()
    out = write_result(doc, tmp_path / "out")

    # Fake an ADAF run dir containing the finding id in a findings.csv
    adaf_run = tmp_path / "ADAF-Run" / "corp.contoso.test"
    adaf_run.mkdir(parents=True)
    (adaf_run / "findings.csv").write_text("FindingId,Title\nF-0123456789ABCDEF,ESC1\n", encoding="utf-8")

    ingest = _load_ingest()
    rc = ingest.main(["--result", str(out), "--adaf-run", str(tmp_path / "ADAF-Run")])
    assert rc == 0
    linkage = json.loads((tmp_path / "ADAF-Run" / "validation-linkage.json").read_text())
    assert linkage[0]["confidenceUpgrade"] == "HIGH"


def test_ingest_refuses_forbidden_keys(tmp_path):
    doc = _make_result()
    doc["proof"]["redactedRefs"]["password"] = "leak"  # inject a forbidden key
    (tmp_path / "bad.json").write_text(json.dumps(doc), encoding="utf-8")
    adaf_run = tmp_path / "run"
    adaf_run.mkdir()
    ingest = _load_ingest()
    rc = ingest.main(["--result", str(tmp_path / "bad.json"), "--adaf-run", str(adaf_run)])
    assert rc in (3, 4)  # schema (additionalProperties) or forbidden-key refusal

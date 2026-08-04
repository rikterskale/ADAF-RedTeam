"""Phase 2 increment 2: shadow-credential-write (reversible + secret) and ESC1
(durable residue + PFX never leaks)."""

import json

from adaf_redteam.__main__ import main
from adaf_redteam.statechange import is_latched

# The exact fake secret bytes the fixtures use; must never appear in any output.
FAKE_KEY = "FIXTURE-FAKE-PRIVATE-KEY-BYTES"
FAKE_PFX = "FIXTURE-FAKE-PFX-CONTENT"


def _eng(tmp_path, cap_id, target, extra=None):
    cap = {"approved": True, "targets": [target], "maximumActions": 1,
           "stateChangingApproved": True, "riskAccepted": True,
           "riskAcceptanceReference": "RA-LAB", "cleanupRequired": True,
           "labContainmentRequired": True}
    cap["attackTechnique"] = {"shadow-credential-write": "T1556",
                              "adcs-esc1-validation": "T1649"}[cap_id]
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-INC2",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop"],
        "labAddressRanges": ["10.10.0.0/16"], "labResolvedAddresses": ["10.10.0.5"],
        "capabilities": {cap_id: cap},
    }
    p = tmp_path / "eng.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return str(p)


def _fixture(tmp_path, data):
    p = tmp_path / "fix.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _run(eng, cap_id, target, fix, out, control="ADAF-X"):
    return main([
        "run", "--engagement", eng, "--capability", cap_id,
        "--source-address", "192.0.2.25", "--target", target,
        "--finding-id", "F-0123456789ABCDEF", "--control-id", control,
        "--fixture", fix, "--out", str(out),
    ])


# --- Shadow Credentials --------------------------------------------------

def test_shadowcred_confirmed_reversible_secret_never_leaks(tmp_path):
    out = tmp_path / "out"
    eng = _eng(tmp_path, "shadow-credential-write", "WIN-LAB01$")
    fix = _fixture(tmp_path, {"shadowcred": {"WIN-LAB01$": {"links": [], "pkinit_ok": True}}})
    rc = _run(eng, "shadow-credential-write", "WIN-LAB01$", fix, out)
    assert rc == 0
    result_text = (out / "validation-result.json").read_text()
    doc = json.loads(result_text)
    assert doc["verdict"] == "Confirmed"
    assert doc["cleanup"]["verified"] is True and doc["cleanup"]["durableResidue"] == []
    # A redacted handle is recorded, but the secret bytes never appear anywhere.
    assert doc["proof"]["redactedRefs"]["secretHandles"][0].startswith("shadowcred-privkey#redacted")
    assert FAKE_KEY not in result_text
    assert FAKE_KEY not in (out / "transaction-journal.jsonl").read_text()
    assert not is_latched(out)


def test_shadowcred_failed_restore_latches(tmp_path):
    out = tmp_path / "out"
    eng = _eng(tmp_path, "shadow-credential-write", "WIN-LAB01$")
    fix = _fixture(tmp_path, {"shadowcred": {"WIN-LAB01$":
                  {"links": [], "pkinit_ok": True, "restore_fails": True}}})
    assert _run(eng, "shadow-credential-write", "WIN-LAB01$", fix, out) == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["cleanup"]["verified"] is False
    assert is_latched(out)


# --- ESC1 (durable) ------------------------------------------------------

def test_esc1_confirmed_durable_residue_pfx_never_leaks(tmp_path):
    out = tmp_path / "out"
    eng = _eng(tmp_path, "adcs-esc1-validation", "CN=CA01")
    fix = _fixture(tmp_path, {"esc1": {"CN=CA01":
                  {"issued": True, "authenticated": True, "revoke_ok": True, "serial": "AABBCCDD8F2A"}}})
    rc = _run(eng, "adcs-esc1-validation", "CN=CA01", fix, out, control="ADAF-ESC1")
    assert rc == 0
    result_text = (out / "validation-result.json").read_text()
    doc = json.loads(result_text)
    assert doc["verdict"] == "Confirmed"
    # Revocation succeeded -> verified True, but issuance is durable -> residue present.
    assert doc["cleanup"]["verified"] is True
    assert any("durable" in r.lower() for r in doc["cleanup"]["durableResidue"])
    refs = doc["proof"]["redactedRefs"]
    assert refs["issuedSerialLast4"] == "8F2A"
    assert refs["secretHandles"][0].startswith("pfx#redacted")
    assert len(refs["certificateSha256"]) == 64
    assert FAKE_PFX not in result_text  # PFX never exported
    assert not is_latched(out)  # revocation succeeded -> no latch despite durable residue


def test_esc1_failed_revocation_latches(tmp_path, capsys):
    out = tmp_path / "out"
    eng = _eng(tmp_path, "adcs-esc1-validation", "CN=CA01")
    fix = _fixture(tmp_path, {"esc1": {"CN=CA01":
                  {"issued": True, "authenticated": True, "revoke_ok": False, "serial": "AABBCCDD8F2A"}}})
    assert _run(eng, "adcs-esc1-validation", "CN=CA01", fix, out, control="ADAF-ESC1") == 0
    doc = json.loads((out / "validation-result.json").read_text())
    assert doc["cleanup"]["verified"] is False
    assert any("NOT revoked" in r for r in doc["cleanup"]["durableResidue"])
    assert is_latched(out)

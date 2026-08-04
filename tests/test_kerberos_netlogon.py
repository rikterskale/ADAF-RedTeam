"""Phase 1 increment 2 analyzers + Zerologon reset gating."""

import json

from adaf_redteam.__main__ import main
from adaf_redteam.capabilities.kerberos import asrep_roast, kerberoast
from adaf_redteam.capabilities.netlogon import zerologon

# --- AS-REP roast --------------------------------------------------------

def test_asrep_confirmed_when_no_preauth():
    res = asrep_roast.analyze("svc01", {"preauth_required": False, "etype": 23})
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["weakEtype"] == "yes"
    assert any("NOT returned or exported" in a for a in res.assertions)


def test_asrep_not_exploitable_when_preauth_required():
    res = asrep_roast.analyze("svc01", {"preauth_required": True})
    assert res.verdict == "NotExploitable"


# --- Kerberoast ----------------------------------------------------------

def test_kerberoast_confirmed_and_flags_rc4():
    res = kerberoast.analyze("MSSQLSvc/db01", {"obtained": True, "etype": 23})
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["etype"] == "rc4-hmac"
    assert res.redacted_refs["weakEtype"] == "yes"


def test_kerberoast_aes_not_flagged_weak():
    res = kerberoast.analyze("MSSQLSvc/db01", {"obtained": True, "etype": 18})
    assert res.redacted_refs["weakEtype"] == "no"


# --- Zerologon detection (safe) -----------------------------------------

def test_zerologon_detect_vulnerable():
    res = zerologon.analyze_detection("DC01", {"accepted_zero_auth": True, "attempts_used": 42})
    assert res.verdict == "Confirmed"
    assert any("NOT called" in a for a in res.assertions)  # no password set


def test_zerologon_detect_patched():
    res = zerologon.analyze_detection("DC01", {"accepted_zero_auth": False, "attempts_used": 2000})
    assert res.verdict == "NotExploitable"


# --- Zerologon reset: destructive, gated, primitive absent ---------------

def test_reset_execute_raises_not_implemented():
    from adaf_redteam.authz.gates import AuthorizedAction
    from adaf_redteam.redaction import SecretVault
    action = AuthorizedAction("zerologon-reset", "DC01", "T1210", "192.0.2.25",
                              state_changing=True, production=False, max_actions=1, min_interval_ms=0)
    cap = zerologon.ZerologonResetCapability(action, SecretVault(), domain="corp.contoso.test")
    try:
        cap.execute()
        assert False, "reset must not be executable"
    except NotImplementedError as e:
        assert "intentionally NOT implemented" in str(e)


def _reset_engagement(tmp_path):
    eng = {
        "schemaVersion": "1.0", "engagementId": "ENG-LAB-RESET",
        "authorizedDomains": ["corp.contoso.test"], "authorizedSourceAddresses": ["192.0.2.25"],
        "windowStartUtc": "2026-08-01T00:00:00Z", "windowEndUtc": "2026-09-01T00:00:00Z",
        "operatorContacts": ["op@contoso.test"], "stopConditions": ["stop"],
        "capabilities": {"zerologon-reset": {
            "approved": True, "targets": ["DC01"], "attackTechnique": "T1210", "maximumActions": 1,
            "stateChangingApproved": True, "riskAccepted": True,
            "riskAcceptanceReference": "RA-LAB-RESET", "cleanupRequired": True,
            "labContainmentRequired": True}},
    }
    p = tmp_path / "eng.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return str(p)


def test_reset_execute_blocked_by_containment(tmp_path, capsys):
    # Phase 1 containment live-checks are unimplemented -> probe not verified ->
    # state-changing execution is refused before execute() is ever reached.
    rc = main([
        "run", "--engagement", _reset_engagement(tmp_path), "--capability", "zerologon-reset",
        "--source-address", "192.0.2.25", "--target", "DC01",
        "--finding-id", "F-0123456789ABCDEF", "--control-id", "ADAF-ZEROLOGON",
        "--out", str(tmp_path / "out"),
    ])
    assert rc == 3
    assert "containment not verified" in capsys.readouterr().err


def test_reset_plan_only_is_allowed(tmp_path, capsys):
    rc = main([
        "run", "--engagement", _reset_engagement(tmp_path), "--capability", "zerologon-reset",
        "--source-address", "192.0.2.25", "--target", "DC01", "--plan-only",
        "--out", str(tmp_path / "out"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Most destructive" in out
    assert "intentionally NOT implemented" in out

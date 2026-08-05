"""Offline unit tests for zerologon-detection analyzer."""

from __future__ import annotations

from adaf_redteam.capabilities.netlogon.zerologon import analyze_detection


def test_zerologon_analyze_vulnerable():
    result = analyze_detection("DC01", {"accepted_zero_auth": True, "attempts_used": 42})
    assert result.verdict == "Confirmed"
    assert result.proof_class == "zerologon-vulnerable-detected"
    assert result.redacted_refs["vulnerable"] == "yes"
    assert result.redacted_refs["attemptsUsed"] == 42
    assert any("NetrServerPasswordSet2 was NOT called" in a for a in result.assertions)


def test_zerologon_analyze_patched():
    result = analyze_detection("DC01", {"accepted_zero_auth": False, "attempts_used": 2000})
    assert result.verdict == "NotExploitable"
    assert result.proof_class == "zerologon-patched"
    assert result.redacted_refs["vulnerable"] == "no"

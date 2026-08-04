"""Offline unit tests for the AS-REP metadata probe helpers.

Builds AS-REQ / AS-REP / KRB_ERROR bytes in-process with impacket and asserts
that:
  - `build_asrep_probe_request` produces a well-formed padata-free AS-REQ that
    advertises AES256, AES128, RC4 (in that order) and names the correct realm
    and client principal.
  - `extract_asrep_metadata` returns only {preauth_required, etype} — the
    crackable `enc-part.cipher` bytes NEVER appear in the returned dict, even
    when they are present in the response.
No network. Skipped only if impacket / pyasn1 aren't installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("impacket")

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, AS_REQ, KRB_ERROR, seq_set
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import Principal
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

from adaf_redteam.capabilities.kerberos.asrep_roast import analyze
from adaf_redteam.probes.kerberos import (
    build_asrep_probe_request,
    extract_asrep_metadata,
)

CRACKABLE = b"CRACKABLE-ASREP-BYTES-MUST-NEVER-APPEAR"


# --- request builder ----------------------------------------------------

def test_request_is_a_valid_as_req_for_user_and_realm():
    data = build_asrep_probe_request("svcnopreauth", "corp.contoso.test", nonce=1234)
    decoded, _ = der_decode(data, asn1Spec=AS_REQ())
    assert int(decoded["msg-type"]) == int(constants.ApplicationTagNumbers.AS_REQ.value)
    # Client principal name components.
    cname_parts = [str(x) for x in decoded["req-body"]["cname"]["name-string"]]
    assert cname_parts == ["svcnopreauth"]
    assert str(decoded["req-body"]["realm"]) == "CORP.CONTOSO.TEST"
    # Advertised etypes in strong-to-weak order (AES256, AES128, RC4).
    etypes = [int(e) for e in decoded["req-body"]["etype"]]
    assert etypes == [18, 17, 23]
    # No padata is present — critical for the roastability observation.
    padata_field = decoded.getComponentByName("padata")
    # noValue -> either absent or empty
    assert not padata_field.hasValue() or len(padata_field) == 0


def test_request_rejects_empty_inputs():
    with pytest.raises(ValueError):
        build_asrep_probe_request("", "corp.test")
    with pytest.raises(ValueError):
        build_asrep_probe_request("svc", "")


# --- response parser ----------------------------------------------------

def _build_asrep(etype: int) -> bytes:
    """Build a fake AS-REP that includes a crackable-looking cipher field."""
    rep = AS_REP()
    rep["pvno"] = 5
    rep["msg-type"] = int(constants.ApplicationTagNumbers.AS_REP.value)
    rep["crealm"] = "CORP.TEST"
    cname = Principal("svcnopreauth", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(rep, "cname", cname.components_to_asn1)
    ticket = seq_set(rep, "ticket")
    ticket["tkt-vno"] = 5
    ticket["realm"] = "CORP.TEST"
    tsname = Principal("krbtgt/CORP.TEST",
                       type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(ticket, "sname", tsname.components_to_asn1)
    tenc = seq_set(ticket, "enc-part")
    tenc["etype"] = etype
    tenc["cipher"] = CRACKABLE
    enc = seq_set(rep, "enc-part")
    enc["etype"] = etype
    enc["cipher"] = CRACKABLE
    return der_encode(rep)


def test_extract_returns_only_metadata_no_cipher_leak():
    meta = extract_asrep_metadata(_build_asrep(etype=23))
    assert meta == {"preauth_required": False, "etype": 23}
    # Prove the returned dict does not carry the crackable material anywhere.
    serialized = repr(meta).encode()
    assert CRACKABLE not in serialized


def test_extract_reports_aes_etype_when_kdc_used_aes():
    meta = extract_asrep_metadata(_build_asrep(etype=18))
    assert meta == {"preauth_required": False, "etype": 18}


# --- end-to-end through the analyzer ------------------------------------

def test_analyzer_confirms_roastable_with_weak_etype():
    meta = extract_asrep_metadata(_build_asrep(etype=23))
    res = analyze("svcnopreauth", meta)
    assert res.verdict == "Confirmed"
    assert res.proof_class == "asrep-roastable-no-preauth"
    assert res.redacted_refs["weakEtype"] == "yes"
    # The result must never carry the crackable bytes.
    assert CRACKABLE not in repr(res).encode()


def test_analyzer_confirms_roastable_but_flags_strong_etype():
    meta = extract_asrep_metadata(_build_asrep(etype=18))
    res = analyze("svcnopreauth", meta)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["weakEtype"] == "no"


def test_analyzer_not_exploitable_when_preauth_required():
    # This is the shape the live probe returns when it catches
    # KDC_ERR_PREAUTH_REQUIRED — no AS-REP is ever parsed.
    res = analyze("normaluser", {"preauth_required": True, "etype": None})
    assert res.verdict == "NotExploitable"
    assert res.proof_class == "asrep-preauth-required"


# --- KRB_ERROR round-trip (mirrors the live catch path) -----------------

def test_kerberos_error_preauth_required_has_expected_code():
    err = KRB_ERROR()
    err["pvno"] = 5
    err["msg-type"] = int(constants.ApplicationTagNumbers.KRB_ERROR.value)
    err["stime"] = "20260101000000Z"
    err["susec"] = 0
    err["error-code"] = int(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value)
    err["realm"] = "CORP.TEST"
    sname = Principal("krbtgt/CORP.TEST",
                      type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(err, "sname", sname.components_to_asn1)
    encoded = der_encode(err)
    decoded, _ = der_decode(encoded, asn1Spec=KRB_ERROR())
    assert (int(decoded["error-code"])
            == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value)
    # Confirm this is the constant the live probe compares against.
    assert constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value == 25


def test_kerberos_error_class_is_importable_for_live_catch():
    # Sanity: the live probe imports KerberosError from impacket.krb5.kerberosv5
    # to catch KDC_ERR_PREAUTH_REQUIRED. If that class ever moves, the live
    # path silently breaks — this test fails loudly instead.
    assert isinstance(KerberosError, type)
    exc = KerberosError(error=25)
    assert exc.getErrorCode() == 25

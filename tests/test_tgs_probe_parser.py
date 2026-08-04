"""Offline unit tests for the TGS metadata probe helper.

Builds synthetic TGS-REP bytes in-process with impacket and asserts that
`extract_tgs_metadata` returns only {obtained, etype} — the crackable
`ticket.enc-part.cipher` bytes NEVER appear in the returned dict, even when
they are present in the response.
No network. Skipped only if impacket / pyasn1 aren't installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("impacket")

from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, seq_set
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import Principal
from pyasn1.codec.der.encoder import encode as der_encode

from adaf_redteam.capabilities.kerberos.kerberoast import analyze
from adaf_redteam.probes.kerberos import extract_tgs_metadata

CRACKABLE_TICKET = b"CRACKABLE-SERVICE-TICKET-MUST-NEVER-APPEAR"
CRACKABLE_OUTER = b"CRACKABLE-TGS-OUTER-CIPHER-MUST-NEVER-APPEAR"


def _build_tgs_rep(*, ticket_etype: int, spn: str = "http/host.corp.test") -> bytes:
    """Build a fake TGS-REP whose service ticket carries a crackable cipher."""
    rep = TGS_REP()
    rep["pvno"] = 5
    rep["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REP.value)
    rep["crealm"] = "CORP.TEST"
    cname = Principal("labtest", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(rep, "cname", cname.components_to_asn1)
    ticket = seq_set(rep, "ticket")
    ticket["tkt-vno"] = 5
    ticket["realm"] = "CORP.TEST"
    tsname = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(ticket, "sname", tsname.components_to_asn1)
    tenc = seq_set(ticket, "enc-part")
    tenc["etype"] = ticket_etype
    tenc["cipher"] = CRACKABLE_TICKET
    enc = seq_set(rep, "enc-part")
    enc["etype"] = ticket_etype
    enc["cipher"] = CRACKABLE_OUTER
    return der_encode(rep)


# --- extractor -----------------------------------------------------------

def test_extractor_returns_only_metadata_no_cipher_leak():
    meta = extract_tgs_metadata(_build_tgs_rep(ticket_etype=23))
    assert meta == {"obtained": True, "etype": 23}
    serialized = repr(meta).encode()
    # Neither the ticket cipher nor the outer cipher may appear anywhere.
    assert CRACKABLE_TICKET not in serialized
    assert CRACKABLE_OUTER not in serialized


def test_extractor_reads_ticket_etype_not_outer_etype():
    # If a fake response carried different etypes for ticket vs outer, we want
    # the TICKET etype — that's the one determining roastability.
    rep = TGS_REP()
    rep["pvno"] = 5
    rep["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REP.value)
    rep["crealm"] = "CORP.TEST"
    cname = Principal("labtest", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(rep, "cname", cname.components_to_asn1)
    ticket = seq_set(rep, "ticket")
    ticket["tkt-vno"] = 5
    ticket["realm"] = "CORP.TEST"
    tsname = Principal("http/host.corp.test",
                       type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(ticket, "sname", tsname.components_to_asn1)
    tenc = seq_set(ticket, "enc-part")
    tenc["etype"] = 23  # ticket = RC4 (roastable)
    tenc["cipher"] = CRACKABLE_TICKET
    enc = seq_set(rep, "enc-part")
    enc["etype"] = 18  # outer = AES256 (misleading)
    enc["cipher"] = CRACKABLE_OUTER
    meta = extract_tgs_metadata(der_encode(rep))
    assert meta["etype"] == 23


# --- end-to-end through the analyzer ------------------------------------

def test_analyzer_confirms_roastable_with_weak_ticket_etype():
    meta = extract_tgs_metadata(_build_tgs_rep(ticket_etype=23))
    res = analyze("http/host.corp.test", meta)
    assert res.verdict == "Confirmed"
    assert res.proof_class == "kerberoast-service-ticket-obtained"
    assert res.redacted_refs["weakEtype"] == "yes"
    assert CRACKABLE_TICKET not in repr(res).encode()


def test_analyzer_confirms_but_flags_aes_ticket_etype():
    meta = extract_tgs_metadata(_build_tgs_rep(ticket_etype=18))
    res = analyze("http/host.corp.test", meta)
    assert res.verdict == "Confirmed"
    assert res.redacted_refs["weakEtype"] == "no"


def test_analyzer_not_exploitable_when_spn_unknown():
    # Shape returned by the live probe when it catches KDC_ERR_S_PRINCIPAL_UNKNOWN.
    res = analyze("http/nothere.corp.test", {"obtained": False, "etype": None})
    assert res.verdict == "NotExploitable"
    assert res.proof_class == "kerberoast-no-ticket"


# --- KerberosError round-trip (mirrors the live catch path) --------------

def test_kerberos_error_s_principal_unknown_code():
    exc = KerberosError(error=constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value)
    assert exc.getErrorCode() == 7
    assert constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value == 7

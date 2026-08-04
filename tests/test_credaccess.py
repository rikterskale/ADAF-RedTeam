"""Phase 1 credential-access analyzers — pure security-decision logic."""

from adaf_redteam.capabilities.credaccess import dcsync_rights, gmsa_read, laps_read
from adaf_redteam.directory.acl import Ace, effective_rights

T = "S-1-5-21-TARGET"


# --- effective_rights model ---------------------------------------------

def test_deny_overrides_allow():
    aces = [Ace(T, "ReadProperty", effect="Allow"), Ace(T, "ReadProperty", effect="Deny")]
    assert "ReadProperty" not in effective_rights(aces, T)


def test_generic_all_implies_dcsync_and_read():
    aces = [Ace(T, "GenericAll")]
    r = effective_rights(aces, T)
    assert {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "ReadProperty"} <= r


# --- DCSync rights -------------------------------------------------------

def test_dcsync_confirmed_when_both_rights_held():
    aces = [Ace(T, "DS-Replication-Get-Changes"), Ace(T, "DS-Replication-Get-Changes-All")]
    res = dcsync_rights.analyze(T, aces)
    assert res.verdict == "Confirmed"
    assert res.proof_class == "dcsync-replication-rights-held"
    assert sorted(res.redacted_refs["dcsyncRightsHeld"]) == [
        "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"]


def test_dcsync_not_exploitable_with_only_one_right():
    aces = [Ace(T, "DS-Replication-Get-Changes")]
    res = dcsync_rights.analyze(T, aces)
    assert res.verdict == "NotExploitable"


def test_dcsync_result_never_contains_secret_fields():
    aces = [Ace(T, "DS-Replication-Get-Changes"), Ace(T, "DS-Replication-Get-Changes-All")]
    res = dcsync_rights.analyze(T, aces)
    blob = str(res.redacted_refs) + " ".join(res.assertions)
    for bad in ("hash", "password", "krbtgt", "aes"):
        assert bad not in blob.lower() or "no drsuapi" in blob.lower()


# --- gMSA read -----------------------------------------------------------

def test_gmsa_confirmed_when_target_in_readers():
    res = gmsa_read.analyze(T, "CN=gmsa01", [T, "S-1-5-21-OTHER"])
    assert res.verdict == "Confirmed"
    assert "NOT retrieved" in " ".join(res.assertions)


def test_gmsa_denied_when_absent():
    res = gmsa_read.analyze(T, "CN=gmsa01", ["S-1-5-21-OTHER"])
    assert res.verdict == "NotExploitable"


# --- LAPS read -----------------------------------------------------------

def test_laps_confirmed_with_readproperty_on_attr():
    aces = [Ace(T, "ReadProperty", object_type="ms-Mcs-AdmPwd")]
    res = laps_read.analyze(T, "CN=PC1", "ms-Mcs-AdmPwd", aces)
    assert res.verdict == "Confirmed"


def test_laps_ignores_rights_scoped_to_other_attribute():
    aces = [Ace(T, "ReadProperty", object_type="description")]
    res = laps_read.analyze(T, "CN=PC1", "ms-Mcs-AdmPwd", aces)
    assert res.verdict == "NotExploitable"


def test_laps_denied_when_no_read_right():
    aces = [Ace(T, "WriteProperty", object_type="ms-Mcs-AdmPwd")]
    res = laps_read.analyze(T, "CN=PC1", "ms-Mcs-AdmPwd", aces)
    assert res.verdict == "NotExploitable"

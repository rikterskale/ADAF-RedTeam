"""Offline unit tests for the SD binary → Ace parser used by LdapDirectorySource.

Builds synthetic security descriptors in-process with impacket and asserts that
`parse_sd_to_aces` maps them to the normalized Ace form the analyzers consume.
No network. Skipped only if impacket / ldap3 aren't installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("ldap3")
pytest.importorskip("impacket")

from impacket.ldap import ldaptypes as lt

from adaf_redteam.capabilities.credaccess.dcsync_rights import analyze
from adaf_redteam.directory.ldap_source import (
    _trustees_from_sd,
    parse_sd_to_aces,
)

DCSYNC_1 = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes
DCSYNC_2 = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All

CTRL_ACCESS = 0x00000100
READ_PROP = 0x00000010
GENERIC_ALL = 0x10000000


def _sid(canonical: str):
    s = lt.LDAP_SID()
    s.fromCanonical(canonical)
    return s


def _guid_bytes(guid_str: str) -> bytes:
    p = guid_str.split("-")
    return (bytes.fromhex(p[0])[::-1] + bytes.fromhex(p[1])[::-1]
            + bytes.fromhex(p[2])[::-1] + bytes.fromhex(p[3])
            + bytes.fromhex(p[4]))


def _ace(ace_type: int, trustee_sid: str, mask: int, *, obj_guid: bytes | None = None):
    ace = lt.ACE()
    ace["AceType"] = ace_type
    ace["AceFlags"] = 0
    body = lt.ACE_TYPE_MAP[ace_type]()
    m = lt.ACCESS_MASK()
    m["Mask"] = mask
    body["Mask"] = m
    body["Sid"] = _sid(trustee_sid)
    if ace_type in (0x05, 0x06):
        body["Flags"] = 0x01 if obj_guid is not None else 0
        body["ObjectType"] = obj_guid if obj_guid is not None else b""
        body["InheritedObjectType"] = b""
    ace["Ace"] = body
    return ace


def _sd(aces: list) -> bytes:
    sd = lt.SR_SECURITY_DESCRIPTOR()
    dacl = lt.ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = aces
    sd["Dacl"] = dacl
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = _sid("S-1-5-32-544")
    sd["GroupSid"] = _sid("S-1-5-32-544")
    sd["Sacl"] = b""
    return sd.getData()


# --- parser round-trip ---------------------------------------------------

def test_parser_maps_two_extended_right_aces_to_named_rights():
    trust = "S-1-5-21-1-2-3-1000"
    raw = _sd([
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_1)),
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_2)),
    ])
    aces = parse_sd_to_aces(raw)
    rights = {a.right for a in aces}
    assert rights == {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"}
    assert all(a.trustee == trust and a.effect == "Allow" for a in aces)


def test_parser_analyzer_end_to_end_confirms_dcsync():
    trust = "S-1-5-21-1-2-3-1000"
    raw = _sd([
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_1)),
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_2)),
    ])
    res = analyze(trust, parse_sd_to_aces(raw))
    assert res.verdict == "Confirmed"
    assert res.proof_class == "dcsync-replication-rights-held"


def test_parser_generic_all_produces_generic_all_right():
    trust = "S-1-5-21-1-2-3-1000"
    raw = _sd([_ace(0x00, trust, GENERIC_ALL)])
    aces = parse_sd_to_aces(raw)
    assert any(a.right == "GenericAll" and a.effect == "Allow" for a in aces)
    # And the analyzer expands GenericAll to the DCSync rights.
    assert analyze(trust, aces).verdict == "Confirmed"


def test_parser_deny_ace_is_labeled_deny():
    trust = "S-1-5-21-1-2-3-1000"
    raw = _sd([
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_1)),
        _ace(0x05, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_2)),
        _ace(0x06, trust, CTRL_ACCESS, obj_guid=_guid_bytes(DCSYNC_1)),
    ])
    aces = parse_sd_to_aces(raw)
    denies = [a for a in aces if a.effect == "Deny"]
    assert len(denies) == 1 and denies[0].right == "DS-Replication-Get-Changes"
    # Deny of one right leaves only the other -> DCSync no longer complete.
    assert analyze(trust, aces).verdict == "NotExploitable"


def test_parser_attribute_filter_keeps_scoped_and_unscoped_only():
    trust = "S-1-5-21-1-2-3-1000"
    # An unscoped ReadProperty (applies broadly), a scoped one on our attr, and a
    # scoped one on a different attr — the filter must keep the first two.
    other_guid = _guid_bytes("00000000-0000-0000-0000-000000000042")
    laps_guid = _guid_bytes("00000000-0000-0000-0000-0000000000ff")
    raw = _sd([
        _ace(0x00, trust, READ_PROP),                              # unscoped Allow
        _ace(0x05, trust, READ_PROP, obj_guid=laps_guid),          # scoped to laps_guid
        _ace(0x05, trust, READ_PROP, obj_guid=other_guid),         # scoped elsewhere
    ])
    laps_guid_str = "00000000-0000-0000-0000-0000000000ff"
    kept = parse_sd_to_aces(raw, attribute_filter=laps_guid_str)
    # Two ACEs kept: the unscoped one (object_type=None) and the scoped-to-laps one.
    scopes = sorted(a.object_type or "" for a in kept)
    assert scopes == ["", laps_guid_str]


def test_parser_ignores_audit_aces():
    # SACL ACE type 0x02 (SYSTEM_AUDIT_ACE) — we don't request the SACL and must
    # not emit an Ace for it if a server ever returns one anyway.
    trust = "S-1-5-21-1-2-3-1000"
    audit_ace = lt.ACE()
    audit_ace["AceType"] = 0x02
    audit_ace["AceFlags"] = 0
    body = lt.ACE_TYPE_MAP[0x02]()
    m = lt.ACCESS_MASK(); m["Mask"] = CTRL_ACCESS
    body["Mask"] = m
    body["Sid"] = _sid(trust)
    audit_ace["Ace"] = body
    raw = _sd([audit_ace])
    assert parse_sd_to_aces(raw) == []


# --- gMSA trustee extraction --------------------------------------------

def test_trustees_from_sd_returns_allow_control_access_and_generic_all_only():
    reader = "S-1-5-21-1-2-3-2000"
    other = "S-1-5-21-1-2-3-3000"
    denied = "S-1-5-21-1-2-3-4000"
    raw = _sd([
        _ace(0x00, reader, CTRL_ACCESS),
        _ace(0x00, other, GENERIC_ALL),
        _ace(0x00, "S-1-5-21-1-2-3-5000", READ_PROP),  # only ReadProperty -> not a reader
        _ace(0x01, denied, CTRL_ACCESS),               # deny -> excluded
    ])
    trustees = _trustees_from_sd(raw)
    assert sorted(trustees) == sorted([reader, other])

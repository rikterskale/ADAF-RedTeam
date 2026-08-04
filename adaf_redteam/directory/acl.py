"""Normalized ACL model and the DirectorySource protocol.

The binary nTSecurityDescriptor from LDAP is parsed by the *collector* into this
normalized Ace form. The capability analyzers only ever see Ace objects, so their
security logic is testable with plain fixtures and never depends on live LDAP or
binary SD parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Well-known control-access-right / extended-right GUIDs (lowercase).
EXTENDED_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",  # member attribute self-add
}

# The two rights whose combination grants full DCSync.
DCSYNC_RIGHTS = frozenset({"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"})

# Rights on an object that let a trustee take it over (change its password,
# grant themselves any right, alter its DACL/owner, etc.). Used by
# acl-write-rights-inventory.
TAKEOVER_RIGHTS = frozenset({
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "User-Force-Change-Password",
    "Self-Membership",
})


@dataclass(frozen=True)
class Ace:
    """One normalized access control entry.

    trustee: the principal the ACE applies to (SID, or resolved DN/name).
    right:   a normalized right name, e.g. an extended-right name from
             EXTENDED_RIGHTS, or "ReadProperty" / "ControlAccess" / "GenericAll".
    object_type: the attribute or extended-right the ACE is scoped to, if any
             (e.g. "ms-Mcs-AdmPwd"); None means the ACE is not object-scoped.
    effect:  "Allow" or "Deny".
    """

    trustee: str
    right: str
    object_type: str | None = None
    effect: str = "Allow"


def effective_rights(aces: list[Ace], trustee: str) -> set[str]:
    """Rights a trustee effectively holds: Allow rights minus matching Deny rights.

    This is a deliberately simple model — it does not resolve group nesting or ACE
    ordering nuances. The live collector is responsible for expanding the trustee
    set it asks about; this function answers "for this exact trustee string, what
    is granted net of denies."
    """
    allow = {a.right for a in aces if a.trustee == trustee and a.effect == "Allow"}
    deny = {a.right for a in aces if a.trustee == trustee and a.effect == "Deny"}
    # GenericAll / full control implies the object-specific rights we test for.
    if "GenericAll" in allow:
        allow |= DCSYNC_RIGHTS | {"ReadProperty", "ControlAccess"}
    return allow - deny


@runtime_checkable
class DirectorySource(Protocol):
    """Read-only directory access the capabilities depend on.

    The live implementation (LdapDirectorySource) uses ldap3 + impacket to read
    and parse security descriptors. Tests inject a fake implementing this Protocol
    so analyzers and dispatch run fully offline.
    """

    def domain_acl(self, domain: str) -> list[Ace]:
        """ACEs on the domain naming-context head (for DCSync-rights analysis)."""
        ...

    def object_acl(self, dn: str, *, attribute: str | None = None) -> list[Ace]:
        """ACEs on an object, optionally filtered to an attribute (for LAPS)."""
        ...

    def gmsa_readers(self, dn: str) -> list[str]:
        """Trustees in msDS-GroupMSAMembership (who may retrieve the password)."""
        ...

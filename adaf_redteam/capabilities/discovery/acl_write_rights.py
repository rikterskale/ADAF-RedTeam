"""ACL object-takeover rights inventory (Executable, secret-free).

For a target object (user, computer, group, OU, or the domain head), reports
which of the takeover-class rights a target principal effectively holds:

  GenericAll                    total control
  GenericWrite / WriteProperty  write any attribute (chain to shadow-cred, RBCD, etc.)
  WriteDACL                     rewrite the DACL to grant self anything
  WriteOwner                    take ownership, then grant self anything
  User-Force-Change-Password    reset the target's password without knowing it
  Self-Membership               add self to the object (group.member self-write)

Read-only: parses the object's nTSecurityDescriptor DACL via the same reader
that backs dcsync-rights-validation. No writes, no password resets, no group
manipulation. Feeds attack-path analysis (BloodHound-shaped questions) without
performing any of the abuses it reports on.
"""

from __future__ import annotations

from ...directory.acl import TAKEOVER_RIGHTS, Ace, effective_rights
from ..base import Capability, CapabilityResult


def analyze(target_principal: str, target_object_dn: str,
            aces: list[Ace]) -> CapabilityResult:
    """Pure decision: which takeover rights does `target_principal` hold on the object?"""
    rights = effective_rights(aces, target_principal)
    held = TAKEOVER_RIGHTS & rights
    confirmed = bool(held)
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="acl-takeover-rights-held" if confirmed
        else "acl-takeover-rights-absent",
        assertions=[
            (f"Target principal holds: {sorted(held) or 'none'} of the "
             "takeover-class rights on the object."),
            "Read-only ACL check: no password reset, no ACL modification, no membership change.",
        ],
        redacted_refs={
            "targetPrincipal": target_principal,
            "targetObject": target_object_dn,
            "takeoverRightsHeld": sorted(held),
            "objectAceCount": len(aces),
        },
    )


class AclWriteRightsCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "acl-write-rights-inventory",
            "reads": "nTSecurityDescriptor DACL of the target object",
            "does_not": ["reset a password", "modify a DACL", "change group membership",
                         "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        # action.target is the object under test. The target principal (whose
        # rights we're inventorying) is passed alongside via source_address by
        # convention here, since a discovery cap has no "attacker" — the caller
        # picks which principal to inspect. In fixtures/tests this is a SID.
        principal = getattr(self, "_principal_under_test", self.action.source_address)
        aces = source.object_acl(self.action.target)
        return analyze(principal, self.action.target, aces)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)

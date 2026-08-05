"""DCSync replication-rights exposure.

Proves whether a target principal holds the two replication rights that together
grant DCSync (DS-Replication-Get-Changes + -All) on the domain head. This reads
the domain object's ACL only; it performs no DRSUAPI replication and extracts no
hashes. Mirrors ADAF's "effective rights only; no DRS proof" contract.
"""

from __future__ import annotations

from ...directory.acl import DCSYNC_RIGHTS, Ace, effective_rights
from ...lab_env import lab_bind_password, lab_bind_user, lab_dc
from ..base import Capability, CapabilityResult


def analyze(target: str, domain_aces: list[Ace]) -> CapabilityResult:
    """Pure decision: does `target` effectively hold both DCSync rights?"""
    rights = effective_rights(domain_aces, target)
    held = DCSYNC_RIGHTS & rights
    confirmed = held == DCSYNC_RIGHTS
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="dcsync-replication-rights-held" if confirmed
        else "dcsync-replication-rights-absent",
        assertions=[
            f"Target holds: {sorted(held) or 'none'} of the DCSync rights on the domain head",
            "No DRSUAPI replication performed; no hashes requested or extracted.",
        ],
        redacted_refs={
            "targetPrincipal": target,
            "dcsyncRightsHeld": sorted(held),
            "domainAceCount": len(domain_aces),
        },
    )


class DcsyncRightsCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "dcsync-rights-validation",
            "reads": "nTSecurityDescriptor of the domain naming context",
            "does_not": ["DRSUAPI replication", "hash extraction", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        aces = source.domain_acl(self.domain)
        return analyze(self.action.target, aces)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        # Certification path: explicit bind principal from lab env.
        # Normal path: prefer Kerberos ccache (user is still required by the
        # constructor for identity logging; the ccache provides the ticket).
        bind_user = lab_bind_user() or self.action.source_address
        server = lab_dc() or self.domain
        password = lab_bind_password()
        use_ccache = password is None
        return LdapDirectorySource(
            server,
            user=bind_user,
            use_kerberos_ccache=use_ccache,
            password=password,
        )

"""gMSA managed-password read exposure.

Proves whether a target principal is authorized to retrieve a gMSA's managed
password (via msDS-GroupMSAMembership), WITHOUT reading the password blob. The
proof is the authorization, not the secret.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


def analyze(target: str, gmsa_dn: str, readers: list[str]) -> CapabilityResult:
    confirmed = target in readers
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="gmsa-password-read-authorized" if confirmed
        else "gmsa-password-read-denied",
        assertions=[
            (f"Target is {'in' if confirmed else 'not in'} the gMSA's "
             "PrincipalsAllowedToRetrieveManagedPassword."),
            "The managed password value was NOT retrieved.",
        ],
        redacted_refs={
            "targetPrincipal": target,
            "gmsa": gmsa_dn,
            "authorizedReaderCount": len(readers),
        },
    )


class GmsaReadCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "gmsa-read-authorization",
            "reads": "msDS-GroupMSAMembership of the target gMSA",
            "does_not": ["retrieve msDS-ManagedPassword", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        # self.action.target is the principal; the gMSA DN is supplied as domain-scoped.
        readers = source.gmsa_readers(self._gmsa_dn())
        return analyze(self.action.target, self._gmsa_dn(), readers)

    def _gmsa_dn(self) -> str:
        # In this phase the engagement lists the gMSA DN as the capability target's
        # companion; for the exposure check we treat action.target as the principal
        # and expect the collector to resolve the gMSA under test. Kept explicit so
        # the live path is obvious at certification time.
        return getattr(self, "_gmsa_under_test", self.action.target)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)

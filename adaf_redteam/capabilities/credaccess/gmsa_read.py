"""gMSA managed-password read exposure.

Proves whether a target principal is authorized to retrieve a gMSA's managed
password (via msDS-GroupMSAMembership), WITHOUT reading the password blob. The
proof is the authorization, not the secret.
"""

from __future__ import annotations

from ...lab_env import (
    lab_bind_password,
    lab_bind_user,
    lab_dc,
    lab_gmsa_dn,
    lab_target_principal,
)
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
        principal, gmsa_dn = self._principal_and_gmsa()
        return {
            "capabilityId": "gmsa-read-authorization",
            "reads": "msDS-GroupMSAMembership of the target gMSA",
            "does_not": ["retrieve msDS-ManagedPassword", "any write"],
            "target": self.action.target,
            "principal": principal,
            "gmsa": gmsa_dn,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        principal, gmsa_dn = self._principal_and_gmsa()
        readers = source.gmsa_readers(gmsa_dn)
        return analyze(principal, gmsa_dn, readers)

    def _principal_and_gmsa(self) -> tuple[str, str]:
        principal = lab_target_principal() or self.action.target
        gmsa_dn = lab_gmsa_dn() or getattr(self, "_gmsa_under_test", self.action.target)
        return principal, gmsa_dn

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
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

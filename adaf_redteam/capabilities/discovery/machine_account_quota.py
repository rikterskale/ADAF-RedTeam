"""ms-DS-MachineAccountQuota check (Executable, secret-free).

Reads the domain object's ms-DS-MachineAccountQuota attribute. The Windows
default of 10 lets any authenticated user create up to 10 computer accounts —
the enabling primitive for many RBCD / shadow-cred / relay chains. Setting
the quota to 0 removes that primitive; join rights can then be delegated
explicitly where needed.

Read-only: one attribute read on the domain naming context. No account is
created; nothing is written.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult

# Windows default when the attribute is absent.
_DEFAULT_QUOTA = 10


def analyze(domain: str, quota: int) -> CapabilityResult:
    quota = int(quota)
    exploitable = quota > 0
    return CapabilityResult(
        # A non-zero quota is exploitable by any authenticated user; that's the
        # Confirmed case. Zero means the primitive is gone and this specific
        # abuse path is closed.
        verdict="Confirmed" if exploitable else "NotExploitable",
        proof_class="machine-account-quota-nonzero" if exploitable
        else "machine-account-quota-zero",
        assertions=[
            (f"ms-DS-MachineAccountQuota = {quota}: any authenticated user can "
             f"create up to {quota} computer account(s).") if exploitable
            else "ms-DS-MachineAccountQuota = 0: unprivileged users cannot create computer accounts.",
            "Read-only check: no computer account was created.",
        ],
        redacted_refs={
            "domain": domain,
            "machineAccountQuota": quota,
            "quotaIsDefault": "yes" if quota == _DEFAULT_QUOTA else "no",
        },
    )


class MachineAccountQuotaCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "machine-account-quota-check",
            "reads": "ms-DS-MachineAccountQuota attribute on the domain naming context",
            "does_not": ["create a computer account", "modify the attribute", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        return analyze(self.domain or self.action.target,
                       source.machine_account_quota(self.domain or self.action.target))

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)

"""SIDHistory inventory (Executable, secret-free).

Lists every account whose sIDHistory attribute is set. Any non-empty
sIDHistory grants the effective privileges of the additional SIDs — legitimate
during a domain migration, dangerous when left behind or when an attacker
injects a Tier 0 SID.

Read-only: LDAP filter `(sIDHistory=*)`. Reports the account DN and the SIDs
carried; no rights are exercised, no attribute is modified.
"""

from __future__ import annotations

from ...lab_env import lab_bind_password, lab_bind_user, lab_dc
from ..base import Capability, CapabilityResult


def _looks_privileged(sid: str) -> bool:
    """Best-effort flag for SIDs commonly abused via history injection."""
    if not sid:
        return False
    # Well-known privileged RIDs (in the account domain): 500 (Administrator),
    # 512 (Domain Admins), 518 (Schema Admins), 519 (Enterprise Admins),
    # 520 (Group Policy Creator Owners).
    tail = sid.rsplit("-", 1)[-1]
    if tail in {"500", "512", "518", "519", "520"}:
        return True
    # Built-in Administrators (S-1-5-32-544) and similar BUILTIN groups.
    return sid.startswith("S-1-5-32-")


def analyze(domain: str, accounts: list[dict]) -> CapabilityResult:
    """`accounts` is a list of {dn, sidHistory: [sid, ...]} dicts."""
    total = len(accounts)
    flagged = [a for a in accounts
               if any(_looks_privileged(s) for s in a.get("sidHistory", []))]
    confirmed = total > 0
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="sidhistory-accounts-found" if confirmed else "no-sidhistory-accounts",
        assertions=[
            f"{total} account(s) carry a non-empty sIDHistory.",
            (f"{len(flagged)} of those carry a well-known privileged SID "
             "(RID 500/512/518/519/520 or BUILTIN)."),
            "Read-only enumeration: no attribute modified, no rights exercised.",
        ],
        redacted_refs={
            "domain": domain,
            "sidHistoryAccountCount": total,
            "privilegedFlaggedCount": len(flagged),
            # One string per account: "DN|sid1,sid2,..." (schema requires
            # string values in redactedRefs).
            "accounts": [f"{a['dn']}|{','.join(a.get('sidHistory', []))}"
                         for a in accounts],
            "flaggedAccounts": [a["dn"] for a in flagged],
        },
    )


class SidHistoryInventoryCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "sidhistory-inventory",
            "reads": "LDAP (sIDHistory=*) filter over the domain naming context",
            "does_not": ["modify sIDHistory", "exercise the historical SIDs", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        return analyze(self.domain or self.action.target,
                       source.accounts_with_sidhistory(self.domain or self.action.target))

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

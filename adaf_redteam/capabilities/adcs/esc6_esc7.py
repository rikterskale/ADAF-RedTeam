"""AD CS ESC6 and ESC7 misconfiguration reads (Executable, secret-free).

ESC6: the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set, which lets any enrollee
supply an arbitrary SAN on the request — turning any usable template into an
ESC1-equivalent. Read the CA's edit-flags; no enrollment, no certificate issued.

ESC7: a non-admin principal holds ManageCA or ManageCertificates on the CA
object. Read the CA's ACL via the same directory/acl.py reader that backs
dcsync-rights-validation; no CA setting is toggled, no certificate is issued.
"""

from __future__ import annotations

from ...directory.acl import Ace, effective_rights
from ..base import Capability, CapabilityResult

EDITF_ATTRIBUTESUBJECTALTNAME2 = "EDITF_ATTRIBUTESUBJECTALTNAME2"
ESC7_RIGHTS = frozenset({"ManageCA", "ManageCertificates"})


# --- ESC6 ---------------------------------------------------------------

def analyze_esc6(ca: str, flags: list[str]) -> CapabilityResult:
    """Pure decision: is EDITF_ATTRIBUTESUBJECTALTNAME2 set on this CA?"""
    vulnerable = EDITF_ATTRIBUTESUBJECTALTNAME2 in set(flags)
    return CapabilityResult(
        verdict="Confirmed" if vulnerable else "NotExploitable",
        proof_class="adcs-esc6-editf-attributesubjectaltname2-set" if vulnerable
        else "adcs-esc6-editf-attributesubjectaltname2-unset",
        assertions=[
            f"CA {'has' if vulnerable else 'does not have'} EDITF_ATTRIBUTESUBJECTALTNAME2 set.",
            "Read-only check: no enrollment attempted, no certificate issued.",
        ],
        redacted_refs={
            "ca": ca,
            "editFlagsCount": len(flags),
            "editfAttributeSubjectAltName2": "yes" if vulnerable else "no",
        },
    )


class Esc6Capability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "adcs-esc6-editf-check",
            "reads": "CA edit-flags (msPKI-Enterprise-Oid / certutil GetConfig equivalent)",
            "does_not": ["enroll a certificate", "toggle any CA setting", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        return analyze_esc6(self.action.target, source.ca_edit_flags(self.action.target))

    def _live_source(self):
        from ...probes.adcs import LiveAdcsConfigReader
        return LiveAdcsConfigReader(self.domain)


# --- ESC7 ---------------------------------------------------------------

def analyze_esc7(target: str, ca: str, aces: list[Ace]) -> CapabilityResult:
    """Pure decision: does `target` effectively hold ManageCA or ManageCertificates?"""
    rights = effective_rights(aces, target)
    held = ESC7_RIGHTS & rights
    confirmed = bool(held)
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="adcs-esc7-manage-rights-held" if confirmed
        else "adcs-esc7-manage-rights-absent",
        assertions=[
            f"Target holds: {sorted(held) or 'none'} of the CA management rights.",
            "Read-only ACL check: no CA setting toggled, no certificate approved or issued.",
        ],
        redacted_refs={
            "targetPrincipal": target,
            "ca": ca,
            "esc7RightsHeld": sorted(held),
            "caAceCount": len(aces),
        },
    )


class Esc7Capability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "adcs-esc7-manage-rights",
            "reads": "nTSecurityDescriptor of the CA object",
            "does_not": ["toggle a CA setting", "approve a pending request", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        # action.target is the principal under test; the CA DN is passed via source.
        ca = getattr(self, "_ca_under_test", self.action.target)
        aces = source.object_acl(ca)
        return analyze_esc7(self.action.target, ca, aces)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)

"""Constrained / unconstrained delegation exposure (metadata only).

Reads the target's delegation-related attributes:
  - userAccountControl.TRUSTED_FOR_DELEGATION       (unconstrained delegation)
  - userAccountControl.TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition / S4U2Self)
  - msDS-AllowedToDelegateTo                        (constrained delegation SPN list)

Metadata proof only: no TGT, ST, or S4U ticket is requested. The S4U proof path
lives in delegation_s4u.py and is a separate LabExecutable capability.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


def analyze(target: str, meta: dict) -> CapabilityResult:
    unconstrained = bool(meta.get("unconstrained"))
    protocol_transition = bool(meta.get("protocol_transition"))
    allowed = list(meta.get("allowed_to_delegate_to") or [])
    constrained = bool(allowed)
    confirmed = unconstrained or constrained
    if unconstrained:
        proof_class = "delegation-unconstrained-configured"
    elif constrained:
        proof_class = ("delegation-constrained-with-protocol-transition"
                       if protocol_transition else "delegation-constrained-configured")
    else:
        proof_class = "delegation-not-configured"
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class=proof_class,
        assertions=[
            f"TRUSTED_FOR_DELEGATION (unconstrained) is {'set' if unconstrained else 'NOT set'}.",
            f"TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition / S4U2Self) is "
            f"{'set' if protocol_transition else 'NOT set'}.",
            f"msDS-AllowedToDelegateTo lists {len(allowed)} SPN(s).",
            "Metadata only: no TGT, ST, or S4U ticket was requested.",
        ],
        redacted_refs={
            "target": target,
            "unconstrained": "yes" if unconstrained else "no",
            "protocolTransition": "yes" if protocol_transition else "no",
            "allowedToDelegateToCount": len(allowed),
            "allowedToDelegateTo": allowed,
        },
    )


class DelegationRightsCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "delegation-rights-validation",
            "reads": [
                "userAccountControl (TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH_FOR_DELEGATION)",
                "msDS-AllowedToDelegateTo",
            ],
            "does_not": ["request a TGT/ST", "run S4U2Self or S4U2Proxy", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        return analyze(self.action.target, source.delegation_info(self.action.target))

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        return LdapDirectorySource(self.domain, user=self.action.source_address)

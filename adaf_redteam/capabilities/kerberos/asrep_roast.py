"""AS-REP roasting exposure (metadata only).

Proves an account has DONT_REQUIRE_PREAUTH (so an AS-REP is obtainable without
credentials) and records the encryption type. The crackable AS-REP blob is never
returned or written.
"""

from __future__ import annotations

from ...lab_env import lab_dc
from ...probes import ETYPE_NAMES, WEAK_ETYPES
from ..base import Capability, CapabilityResult


def analyze(user: str, meta: dict) -> CapabilityResult:
    roastable = meta.get("preauth_required") is False
    etype = meta.get("etype")
    weak = etype in WEAK_ETYPES
    return CapabilityResult(
        verdict="Confirmed" if roastable else "NotExploitable",
        proof_class="asrep-roastable-no-preauth" if roastable else "asrep-preauth-required",
        assertions=[
            f"Account {'does NOT require' if roastable else 'requires'} Kerberos pre-authentication.",
            f"AS-REP encryption type: {ETYPE_NAMES.get(etype, 'unknown')}"
            + (" (weak / crackable)" if weak else ""),
            "The crackable AS-REP blob was NOT returned or exported.",
        ],
        redacted_refs={
            "targetUser": user,
            "etype": ETYPE_NAMES.get(etype, str(etype)),
            "weakEtype": "yes" if weak else "no",
        },
    )


class AsrepRoastCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "asrep-roast-validation",
            "sends": "one AS-REQ without pre-authentication for the target user",
            "records": ["preauth_required", "etype"],
            "does_not": ["export the AS-REP blob", "crack anything", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        probe = self.source or self._live_probe()
        return analyze(self.action.target, probe.asrep(self.action.target))

    def _live_probe(self):
        from ...probes.kerberos import LiveKerberosProbe
        # Prefer the certification-lab DC when the operator has opted in;
        # otherwise fall back to domain (SRV) resolution.
        return LiveKerberosProbe(self.domain, dc=lab_dc())

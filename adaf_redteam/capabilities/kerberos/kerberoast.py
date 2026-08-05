"""Kerberoasting exposure (metadata only).

Proves a service ticket (TGS) is obtainable for a target SPN and records the
encryption type (RC4 is trivially roastable). The crackable TGS blob is never
returned or written.
"""

from __future__ import annotations

from ...lab_env import lab_dc
from ...probes import ETYPE_NAMES, WEAK_ETYPES
from ..base import Capability, CapabilityResult


def analyze(spn: str, meta: dict) -> CapabilityResult:
    obtained = bool(meta.get("obtained"))
    etype = meta.get("etype")
    weak = etype in WEAK_ETYPES
    return CapabilityResult(
        verdict="Confirmed" if obtained else "NotExploitable",
        proof_class="kerberoast-service-ticket-obtained" if obtained else "kerberoast-no-ticket",
        assertions=[
            f"A service ticket for the SPN was {'obtained' if obtained else 'not obtained'}.",
            f"TGS encryption type: {ETYPE_NAMES.get(etype, 'unknown')}"
            + (" (weak / crackable)" if weak else ""),
            "The crackable TGS blob was NOT returned or exported.",
        ],
        redacted_refs={
            "targetSpn": spn,
            "etype": ETYPE_NAMES.get(etype, str(etype)),
            "weakEtype": "yes" if weak else "no",
        },
    )


class KerberoastCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "kerberoast-validation",
            "sends": "one bounded TGS-REQ for the target SPN",
            "records": ["obtained", "etype"],
            "does_not": ["export the TGS blob", "crack anything", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        probe = self.source or self._live_probe()
        return analyze(self.action.target, probe.tgs(self.action.target))

    def _live_probe(self):
        from ...probes.kerberos import LiveKerberosProbe
        # Prefer the certification-lab DC when the operator has opted in;
        # otherwise fall back to domain (SRV) resolution.
        return LiveKerberosProbe(self.domain, dc=lab_dc())

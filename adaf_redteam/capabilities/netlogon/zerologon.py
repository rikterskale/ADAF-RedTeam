"""Zerologon (CVE-2020-1472) detection and (gated, unimplemented) reset."""

from __future__ import annotations

from ..base import Capability, CapabilityResult

# --- SAFE detection ------------------------------------------------------

def analyze_detection(dc: str, meta: dict) -> CapabilityResult:
    vulnerable = bool(meta.get("accepted_zero_auth"))
    attempts = meta.get("attempts_used")
    return CapabilityResult(
        verdict="Confirmed" if vulnerable else "NotExploitable",
        proof_class="zerologon-vulnerable-detected" if vulnerable else "zerologon-patched",
        assertions=[
            (f"DC {'ACCEPTED' if vulnerable else 'rejected'} a zero-challenge Netlogon "
             f"credential within {attempts} bounded attempts."),
            ("Detection only: NetrServerPasswordSet2 was NOT called; the machine "
             "account password was NOT modified."),
        ],
        redacted_refs={
            "domainController": dc,
            "attemptsUsed": int(attempts) if attempts is not None else 0,
            "vulnerable": "yes" if vulnerable else "no",
        },
    )


class ZerologonDetectionCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "zerologon-detection",
            "does": "bounded ComputeNetlogonCredential(zero-challenge) attempts against the DC",
            "does_not": ["call NetrServerPasswordSet2", "modify the machine account", "reset anything"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        probe = self.source or self._live_probe()
        return analyze_detection(self.action.target, probe.zerologon_detect(self.action.target))

    def _live_probe(self):
        from ...probes.netlogon import LiveNetlogonProbe
        return LiveNetlogonProbe(self.action.target)


# --- Destructive reset (gated; primitive intentionally NOT implemented) --

class ZerologonResetCapability(Capability):
    """The Zerologon exploit: reset the DC machine-account password.

    This is the most destructive capability in the toolkit — it breaks the DC's
    secure channel and replication. It is LabExecutable only (containment-gated),
    requires risk acceptance, and MANDATES restore of the original password. The
    destructive primitive is deliberately not shipped: execute() raises. The
    containment gate blocks it before execute() is ever reached outside a lab.
    """

    def plan(self) -> dict:
        return {
            "capabilityId": "zerologon-reset",
            "WARNING": "Most destructive capability. Zeroes the DC machine-account password.",
            "readiness": "LabExecutable (disposable lab only; containment-gated)",
            "requires": [
                "verified disposable-lab containment",
                "engagement risk acceptance + reference",
                "mandatory restore of the original machine-account password",
                "post-run DC replication/health verification",
            ],
            "sequence": [
                "confirm vulnerability (detection)",
                "reset DC machine-account password  [LAB ONLY]",
                "MANDATORY restore original password",
                "verify DC health; cleanup-latch blocks further actions on failure",
            ],
            "does_not": [
                "run against production (containment refuses)",
                "leave the account reset (restore is mandatory)",
            ],
            "note": "The destructive reset primitive is intentionally NOT implemented in this repo.",
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        raise NotImplementedError(
            "Zerologon reset primitive is intentionally NOT implemented. It bricks a DC; "
            "it is the lab-certification boundary and must reset-then-restore under verified "
            "containment with mandatory recovery. Not shipped as working code."
        )

    def cleanup(self) -> dict:
        return {
            "required": True,
            "performed": False,
            "verified": False,
            "durableResidue": [
                ("DC machine-account password reset MUST be restored from the pre-reset value; "
                 "verify secure channel and replication health before ending the run."),
            ],
        }

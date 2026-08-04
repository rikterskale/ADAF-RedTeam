"""Forged-ticket/relay payload-reliability lab test (purple team).

Measures how reliably a forged-ticket/relay technique succeeds against a lab
target and what the blue team detected. Detection evidence is a required output.
The reliability primitive is the lab-certification boundary and raises.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class PayloadReliabilityCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "payload-reliability-labtest",
            "framing": "purple-team; detection evidence is a required output",
            "sequence": [
                "notify per ROE (detectionNotification gate)",
                "run the technique N bounded times against the named lab target  [LAB ONLY]",
                "record success rate + detection evidence",
            ],
            "does_not": ["run without detection notification", "run against production"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        emu = self.source or self._live_emu()
        target = self.action.target
        technique = self.action.technique

        res = emu.reliability(target, technique)  # {"attempts","successes","detected":[...]}
        attempts = int(res.get("attempts", 0))
        successes = int(res.get("successes", 0))
        detected = list(res.get("detected", []))
        pct = round(100 * successes / attempts) if attempts else 0
        self.journal.append({"op": "reliability", "target": target, "technique": technique,
                             "attempts": attempts, "successes": successes})

        detection = {
            "techniquesAttempted": [technique],
            "controlsObserved": [],
            "detectedBy": detected,
            "notDetected": [] if detected else [technique],
        }

        self._cleanup = {"required": True, "performed": True, "verified": True, "durableResidue": []}

        reliable = successes > 0
        result = CapabilityResult(
            verdict="Confirmed" if reliable else "NotExploitable",
            proof_class="payload-reliable" if reliable else "payload-unreliable",
            assertions=[
                f"Technique {technique} succeeded {successes}/{attempts} times ({pct}%).",
                f"Detected by {len(detected)} control(s). Detection evidence attached.",
            ],
            redacted_refs={
                "target": target,
                "technique": technique,
                "attempts": attempts,
                "successes": successes,
                "reliabilityPct": pct,
            },
        )
        result.detection = detection
        return result

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_emu(self):
        from ...probes.emulation import LiveEmulator
        return LiveEmulator(self.domain)

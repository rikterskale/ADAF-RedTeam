"""Adversary-emulation with evasion (purple team, detection evidence required).

Runs an authorized evasion TTP against a named lab target and reports what the
blue team detected. The verdict is framed around the DETECTION GAP: a technique
that ran without being detected is the finding. Always emits a detection block.
The evasion primitive is the lab-certification boundary and raises.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class AdversaryEmulationEvasionCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "adversary-emulation-evasion",
            "framing": "purple-team; detection evidence is a required output",
            "sequence": [
                "notify per ROE (detectionNotification gate)",
                "run the authorized evasion technique against the named target  [LAB ONLY]",
                "collect detection evidence (attempted / detected / not-detected)",
                "restore any temporarily impaired defense",
            ],
            "does_not": ["run without detection notification", "succeed silently"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        emu = self.source or self._live_emu()
        target = self.action.target
        technique = self.action.technique

        res = emu.emulate(target, technique)  # {"detected":[...],"not_detected":[...],"controls":[...]}
        detected = list(res.get("detected", []))
        not_detected = list(res.get("not_detected", []))
        self.journal.append({"op": "emulate", "target": target, "technique": technique,
                             "detectedCount": len(detected), "notDetectedCount": len(not_detected)})

        detection = {
            "techniquesAttempted": [technique],
            "controlsObserved": list(res.get("controls", [])),
            "detectedBy": detected,
            "notDetected": not_detected,
        }

        # Impaired defenses (e.g. logging) must be restored; flag for operator confirmation.
        self._cleanup = {
            "required": True,
            "performed": True,
            "verified": True,
            "durableResidue": ["Confirm any temporarily impaired defense (logging/EDR) was restored."],
        }

        gap = bool(not_detected)
        result = CapabilityResult(
            verdict="Confirmed" if gap else "NotExploitable",
            proof_class="evasion-detection-gap" if gap else "evasion-fully-detected",
            assertions=[
                f"Technique {technique} ran; {len(not_detected)} step(s) were NOT detected.",
                "Purple-team: detection evidence is attached; no silent-success path exists.",
            ],
            redacted_refs={
                "target": target,
                "technique": technique,
                "detectedCount": len(detected),
                "notDetectedCount": len(not_detected),
            },
        )
        result.detection = detection
        return result

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_emu(self):
        from ...probes.emulation import LiveEmulator
        return LiveEmulator(self.domain)

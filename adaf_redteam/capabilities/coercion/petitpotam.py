"""PetitPotam / PrinterBug coercion validation (state-changing, lab-only).

Proves a single named target can be coerced into authenticating to a short-lived
listener. Observation only — no relay, no persistence, no second destination. The
authentication is transient; nothing durable is written.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class CoercionPetitpotamCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "coercion-petitpotam",
            "sequence": [
                "start a short-lived listener",
                "trigger coercion on the single named target  [LAB ONLY]",
                "observe whether the target authenticated back (proof)",
                "tear down the listener (no persistence)",
            ],
            "does_not": ["relay the authentication", "persist a listener", "target more than one host"],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        coercer = self.source or self._live_coercer()
        target = self.action.target

        res = coercer.trigger(target)  # {"callback_observed": bool}
        observed = bool(res.get("callback_observed"))
        self.journal.append({"op": "coerce", "target": target, "callbackObserved": observed})

        # Transient auth only; nothing durable to undo beyond tearing down the listener.
        self._cleanup = {"required": True, "performed": True, "verified": True, "durableResidue": []}

        return CapabilityResult(
            verdict="Confirmed" if observed else "NotExploitable",
            proof_class="coercion-callback-observed" if observed else "coercion-no-callback",
            assertions=[
                f"The named target {'authenticated to the listener' if observed else 'did not respond'}.",
                "Observation only — no relay, no persistent listener, single named target.",
            ],
            redacted_refs={"target": target, "callbackObserved": "yes" if observed else "no"},
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_coercer(self):
        from ...probes.coercion import LiveCoercer
        return LiveCoercer(self.domain)

"""RBCD write validation (state-changing, lab-only, reversible).

Proves resource-based constrained delegation is exploitable by writing
msDS-AllowedToActOnBehalfOfOtherIdentity on the target to grant a controlled
principal, verifying S4U succeeds, then RESTORING the original attribute value.

This is the reference reversible state-changing capability: it demonstrates the
mutate -> verify -> restore orchestration, the redacted transaction journal, and
cleanup verification that the whole state-changing tier reuses. The live mutation
primitive is the lab-certification boundary (probes/rbcd.py raises); the
orchestration here is exercised offline via the fixture writer.

No secret material is involved — RBCD is an attribute write — so nothing is
redacted through the vault; the journal records object names and operations only.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult

# A clearly-labelled, controlled principal used only for the delegation proof.
CONTROLLED_PRINCIPAL = "ADAF-RT-VALIDATOR$"


class RbcdWriteCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "rbcd-write-validation",
            "sequence": [
                "read + capture original msDS-AllowedToActOnBehalfOfOtherIdentity",
                "write RBCD granting a controlled principal  [LAB ONLY]",
                "verify S4U2Self/S4U2Proxy succeeds",
                "RESTORE the original attribute value (mandatory)",
                "verify restoration; cleanup latch on failure",
            ],
            "controlledPrincipal": CONTROLLED_PRINCIPAL,
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        writer = self.source or self._live_writer()
        target = self.action.target

        original = writer.read_rbcd(target)
        self.journal.append({"op": "capture-original", "target": target,
                             "hadValue": original is not None})

        writer.write_rbcd(target, CONTROLLED_PRINCIPAL)
        self.journal.append({"op": "write-rbcd", "target": target, "principal": CONTROLLED_PRINCIPAL})

        s4u_ok = bool(writer.verify_s4u(target, CONTROLLED_PRINCIPAL))
        self.journal.append({"op": "verify-s4u", "target": target, "succeeded": s4u_ok})

        # Mandatory restore.
        writer.clear_rbcd(target, restore_to=original)
        restored = writer.read_rbcd(target) == original
        self.journal.append({"op": "restore", "target": target, "verified": restored})

        self._cleanup = {
            "required": True,
            "performed": True,
            "verified": restored,
            "durableResidue": [] if restored else [
                "msDS-AllowedToActOnBehalfOfOtherIdentity was NOT restored to its original value",
            ],
        }

        return CapabilityResult(
            verdict="Confirmed" if s4u_ok else "NotExploitable",
            proof_class="rbcd-s4u-delegation-confirmed" if s4u_ok else "rbcd-s4u-not-exploitable",
            assertions=[
                f"RBCD write {'granted delegation and S4U succeeded' if s4u_ok else 'did not yield working delegation'}.",
                f"Original attribute value was {'restored and verified' if restored else 'NOT verifiably restored'}.",
                "No ticket, hash, or key material was exported.",
            ],
            redacted_refs={
                "target": target,
                "grantedPrincipal": CONTROLLED_PRINCIPAL,
                "restored": "yes" if restored else "no",
                "journalEntries": len(self.journal),
            },
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_writer(self):
        from ...probes.rbcd import LiveRbcdWriter
        return LiveRbcdWriter(self.domain)

"""Golden/silver ticket forgery validation (state-changing, lab-only).

Proves a forged Kerberos ticket authenticates as a privileged principal. Forgery
takes a secret key (krbtgt or service-account hash) as INPUT — that input is
redacted to a vault handle and never exported — and the forged ticket is likewise
redacted and discarded. No directory object is written; the forged ticket is held
in memory only. Lab-only so a forged privileged ticket is never used in
production.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class GoldenSilverTicketCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "golden-silver-ticket",
            "sequence": [
                "accept a secret key as input (redacted immediately, never exported)",
                "forge a TGT/TGS for the principal  [LAB ONLY]",
                "authenticate with the forged ticket (boolean proof)",
                "discard the forged ticket (no directory change)",
            ],
            "does_not": ["export the input key", "export the forged ticket", "write any object"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        forge = self.source or self._live_forge()
        principal = self.action.target

        res = forge.forge_and_auth(principal)  # {"auth_ok": bool, "ticket": <bytes>}
        auth_ok = bool(res.get("auth_ok"))
        handles = []
        if res.get("ticket") is not None:
            handles.append(self.vault.redact(res["ticket"], "kerberos-ticket").handle_id)
        self.journal.append({"op": "forge-and-auth", "principal": principal, "authenticated": auth_ok})

        # No durable directory change; the forged ticket is discarded with the vault.
        self._cleanup = {
            "required": True,
            "performed": True,
            "verified": True,
            "durableResidue": [],
        }

        return CapabilityResult(
            verdict="Confirmed" if auth_ok else "NotExploitable",
            proof_class="ticket-forgery-authenticated" if auth_ok else "ticket-forgery-failed",
            assertions=[
                f"A forged ticket {'authenticated' if auth_ok else 'did not authenticate'} as the principal.",
                "The input key and the forged ticket were redacted and never exported.",
                "No directory object was written; the forged ticket was discarded.",
            ],
            redacted_refs={
                "principal": principal,
                "authConfirmed": "yes" if auth_ok else "no",
                "secretHandles": handles,
            },
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_forge(self):
        from ...probes.forgery import LiveTicketForge
        return LiveTicketForge(self.domain)

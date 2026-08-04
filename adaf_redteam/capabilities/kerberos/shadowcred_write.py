"""Shadow Credentials write validation (state-changing, lab-only, reversible).

Proves an attacker who can write msDS-KeyCredentialLink can add a key credential,
authenticate via PKINIT, then REMOVE the credential to restore the object. The
key credential's private key is secret material: it is redacted to a handle the
instant it is obtained and discarded; it is never exported. PKINIT proof is a
boolean — no TGT, NT hash, or key is returned.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class ShadowCredWriteCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "shadow-credential-write",
            "sequence": [
                "read + capture original msDS-KeyCredentialLink",
                "add a key credential (private key redacted, never exported)  [LAB ONLY]",
                "verify PKINIT succeeds (boolean; no ticket exported)",
                "REMOVE the added key credential (mandatory restore)",
                "verify restoration; cleanup latch on failure",
            ],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        writer = self.source or self._live_writer()
        target = self.action.target

        original = writer.read_keycred(target)
        self.journal.append({"op": "capture-original", "target": target,
                             "existingLinks": len(original)})

        added = writer.add_keycred(target)  # {"key_id": ..., "private_key": <bytes>}
        # Secret material -> handle immediately; the value never leaves the vault.
        key_handle = self.vault.redact(added["private_key"], "shadowcred-privkey")
        key_id = added["key_id"]
        self.journal.append({"op": "add-keycred", "target": target, "keyId": key_id})

        pkinit_ok = bool(writer.verify_pkinit(target))
        self.journal.append({"op": "verify-pkinit", "target": target, "succeeded": pkinit_ok})

        writer.remove_keycred(target, key_id)
        restored = writer.read_keycred(target) == original
        self.journal.append({"op": "restore", "target": target, "verified": restored})

        self._cleanup = {
            "required": True,
            "performed": True,
            "verified": restored,
            "durableResidue": [] if restored else [
                "msDS-KeyCredentialLink was NOT restored to its original value",
            ],
        }

        return CapabilityResult(
            verdict="Confirmed" if pkinit_ok else "NotExploitable",
            proof_class="shadowcred-pkinit-confirmed" if pkinit_ok else "shadowcred-pkinit-failed",
            assertions=[
                f"Key credential written and PKINIT {'succeeded' if pkinit_ok else 'did not succeed'}.",
                f"Original msDS-KeyCredentialLink was {'restored and verified' if restored else 'NOT verifiably restored'}.",
                "The key-credential private key and any ticket were redacted and never exported.",
            ],
            redacted_refs={
                "target": target,
                "restored": "yes" if restored else "no",
                "secretHandles": [key_handle.handle_id],
                "journalEntries": len(self.journal),
            },
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_writer(self):
        from ...probes.shadowcred import LiveShadowCredWriter
        return LiveShadowCredWriter(self.domain)

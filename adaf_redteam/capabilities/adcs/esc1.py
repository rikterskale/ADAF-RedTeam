"""AD CS ESC1 enrollment validation (state-changing, lab-only, DURABLE residue).

Proves an ESC1-vulnerable template allows enrolling a certificate for an
arbitrary SAN (impersonating a privileged principal) and that the certificate
authenticates. Unlike RBCD / Shadow Credentials, certificate issuance is NOT
fully reversible: cleanup revokes the certificate (the reversible part) but the
AD CS issuance/revocation record is durable and cannot be undone. Cleanup reports
this honestly as durableResidue rather than claiming a clean restore.

The issued PFX (private key) is secret material: redacted to a handle the instant
it is obtained and discarded; only its hash and issuance metadata are recorded.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class Esc1Capability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def _requested_san(self) -> str:
        # The privileged identity the ESC1 misconfiguration would let us impersonate.
        return f"administrator@{self.domain}"

    def plan(self) -> dict:
        return {
            "capabilityId": "adcs-esc1-validation",
            "sequence": [
                "enroll a certificate for an arbitrary SAN via the ESC1 template  [LAB ONLY]",
                "verify the certificate authenticates (PKINIT)",
                "revoke the issued certificate (reversible part)",
                "record durable residue: issuance/revocation cannot be undone",
            ],
            "requestedSan": self._requested_san(),
            "reversible": False,
            "residue": "AD CS issuance record is durable even after revocation",
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        enroller = self.source or self._live_enroller()
        ca = self.action.target
        san = self._requested_san()

        issued = enroller.enroll(ca, requested_san=san)  # {"issued","authenticated","pfx","serial"}
        got_cert = bool(issued.get("issued"))
        authenticated = bool(issued.get("authenticated"))
        serial = str(issued.get("serial", ""))
        self.journal.append({"op": "enroll", "ca": ca, "issued": got_cert,
                             "serialLast4": serial[-4:]})

        refs = {"ca": ca, "requestedSan": san}
        if got_cert and issued.get("pfx") is not None:
            # Secret material -> handle immediately; the PFX never leaves the vault.
            pfx_handle = self.vault.redact(issued["pfx"], "pfx")
            refs["certificateSha256"] = self.vault.sha256_of(pfx_handle)
            refs["issuedSerialLast4"] = serial[-4:]
            refs["secretHandles"] = [pfx_handle.handle_id]

        # Cleanup: revoke (reversible part). Issuance record remains durable.
        revoked = bool(enroller.revoke(ca, serial)) if got_cert else True
        self.journal.append({"op": "revoke", "ca": ca, "revoked": revoked})

        residue = ["AD CS issuance record is durable; revocation is not full restoration."]
        if got_cert and not revoked:
            residue.append("Certificate was NOT revoked; revoke it manually.")
        self._cleanup = {
            "required": True,
            "performed": revoked,
            # verified == the reversible part (revocation) completed; residue notes
            # what is irreversible. If revocation failed, verified=False -> latch.
            "verified": revoked,
            "durableResidue": residue,
        }

        confirmed = got_cert and authenticated
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="adcs-esc1-arbitrary-san-cert-issued" if confirmed
            else "adcs-esc1-not-exploitable",
            assertions=[
                f"Certificate for an arbitrary SAN was {'issued' if got_cert else 'not issued'}.",
                f"The certificate {'authenticated' if authenticated else 'did not authenticate'}.",
                f"Certificate {'revoked' if revoked else 'NOT revoked'}; issuance record is durable.",
                "The PFX/private key was redacted and never exported.",
            ],
            redacted_refs=refs,
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_enroller(self):
        from ...probes.adcs import LiveAdcsEnroller
        return LiveAdcsEnroller(self.domain)

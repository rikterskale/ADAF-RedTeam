"""AD CS ESC8: NTLM relay to HTTP web enrollment (LabExecutable, durable residue).

Proves a coerced machine authentication can be relayed to the CA's HTTP/HTTPS
web-enrollment endpoint (certsrv) and issued a certificate for the coerced
machine account. Sibling to Esc1Capability: the certificate is real, so cleanup
revokes it (reversible part) but the AD CS issuance/revocation record is durable
and cannot be undone. Cleanup reports this honestly.

Reuses the coercion listener contract (single named target, short-lived listener,
no persistence, no second destination). The issued PFX is secret material:
redacted to a handle the instant it is obtained and discarded; only its hash and
issuance metadata are recorded. Proof class: relayed-machine-auth-to-web-enrollment.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class Esc8Capability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "adcs-esc8-relay-web-enrollment",
            "sequence": [
                "start a short-lived listener (no persistence)",
                "coerce the single named target machine to authenticate  [LAB ONLY]",
                "relay the NTLM authentication to the CA web-enrollment endpoint",
                "receive a certificate issued for the coerced machine account",
                "revoke the issued certificate (reversible part)",
                "record durable residue: issuance/revocation cannot be undone",
            ],
            "does_not": ["persist a listener", "use a second destination",
                         "export the PFX / private key"],
            "reversible": False,
            "residue": "AD CS issuance record is durable even after revocation",
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        relay = self.source or self._live_relay()
        target = self.action.target

        res = relay.esc8_relay(target)  # {"coerced","relayed","issued","authenticated","pfx","serial","ca"}
        coerced = bool(res.get("coerced"))
        relayed = bool(res.get("relayed"))
        issued = bool(res.get("issued"))
        authenticated = bool(res.get("authenticated"))
        serial = str(res.get("serial", ""))
        ca = str(res.get("ca", ""))
        self.journal.append({"op": "coerce-relay-enroll", "target": target, "ca": ca,
                             "coerced": coerced, "relayed": relayed, "issued": issued,
                             "serialLast4": serial[-4:] if serial else ""})

        refs: dict = {"target": target, "ca": ca,
                      "coerced": "yes" if coerced else "no",
                      "relayed": "yes" if relayed else "no"}
        if issued and res.get("pfx") is not None:
            # Secret material -> handle immediately; the PFX never leaves the vault.
            pfx_handle = self.vault.redact(res["pfx"], "pfx")
            refs["certificateSha256"] = self.vault.sha256_of(pfx_handle)
            refs["issuedSerialLast4"] = serial[-4:]
            refs["secretHandles"] = [pfx_handle.handle_id]

        # Cleanup: revoke (reversible part). Issuance record remains durable.
        revoked = bool(relay.esc8_revoke(ca, serial)) if issued else True
        self.journal.append({"op": "revoke", "ca": ca, "revoked": revoked})

        residue = ["AD CS issuance record is durable; revocation is not full restoration."]
        if issued and not revoked:
            residue.append("Certificate was NOT revoked; revoke it manually.")
        self._cleanup = {
            "required": True,
            "performed": revoked,
            # verified == the reversible part (revocation) completed; residue notes
            # what is irreversible. If revocation failed, verified=False -> latch.
            "verified": revoked,
            "durableResidue": residue,
        }

        confirmed = coerced and relayed and issued and authenticated
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="relayed-machine-auth-to-web-enrollment" if confirmed
            else "adcs-esc8-not-exploitable",
            assertions=[
                f"Coerced machine auth was {'relayed and a certificate issued' if confirmed else 'not successfully relayed to web enrollment'}.",
                f"The issued certificate {'authenticated' if authenticated else 'did not authenticate'}.",
                f"Certificate {'revoked' if revoked else 'NOT revoked'}; issuance record is durable.",
                "Single named target, no persistence; the PFX/private key was redacted and never exported.",
            ],
            redacted_refs=refs,
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_relay(self):
        from ...probes.adcs import LiveAdcsRelay
        return LiveAdcsRelay(self.domain)

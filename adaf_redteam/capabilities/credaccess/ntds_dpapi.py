"""NTDS.dit + domain DPAPI backup-key proof-of-access (LabExecutable).

Proves the operator's session can READ the NTDS.dit database file and the domain
DPAPI backup key WITHOUT exporting either. Bytes stream straight into
SecretVault handles the instant they leave the source, are hashed for the
result, and are discarded when the vault is zeroized. The result records only
readable=true and (for NTDS) an account count derived from the stream.

Fits the "we held it, value never left" pattern established by
shadow-credential-write (private key redacted, PKINIT proved as a boolean) and
adcs-esc1-validation (PFX redacted, certificate never exported).

Not state-changing: no ntdsutil snapshot is written, no DRSUAPI replication is
performed, no shadow copy is left behind on the DC. Live primitives are the
lab-certification boundary and raise; the orchestration is exercised via fixture.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class NtdsDpapiReadProofCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "ntds-dpapi-read-proof",
            "sequence": [
                "open a read-side stream to NTDS.dit on the target DC  [LAB ONLY]",
                "count accounts from the stream; redact the sample bytes to a vault handle",
                "open a read-side stream to the domain DPAPI backup key",
                "redact the key bytes to a vault handle",
                "discard both streams via vault zeroize on exit",
            ],
            "does_not": [
                "write, copy, or export NTDS.dit",
                "write, copy, or export the DPAPI backup key",
                "run DRSUAPI replication",
                "leave a shadow copy or ntdsutil snapshot on the DC",
            ],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        reader = self.source or self._live_reader()
        target = self.action.target
        refs: dict = {"target": target}
        handles: list[str] = []

        ntds = reader.read_ntds_stream(target)  # {"readable","account_count","sample"}
        ntds_readable = bool(ntds.get("readable"))
        account_count = int(ntds.get("account_count", 0)) if ntds_readable else 0
        if ntds_readable and ntds.get("sample") is not None:
            h = self.vault.redact(ntds["sample"], "ntds-dit-sample")
            handles.append(h.handle_id)
            refs["ntdsSampleSha256"] = self.vault.sha256_of(h)
        self.journal.append({"op": "read-ntds", "target": target,
                             "readable": ntds_readable, "accountCount": account_count})

        dpapi = reader.read_dpapi_backup_key(target)  # {"readable","key_bytes"}
        dpapi_readable = bool(dpapi.get("readable"))
        if dpapi_readable and dpapi.get("key_bytes") is not None:
            h = self.vault.redact(dpapi["key_bytes"], "dpapi-backup-key")
            handles.append(h.handle_id)
            refs["dpapiBackupKeySha256"] = self.vault.sha256_of(h)
        self.journal.append({"op": "read-dpapi-backup-key", "target": target,
                             "readable": dpapi_readable})

        refs.update({
            "ntdsReadable": "yes" if ntds_readable else "no",
            "accountCount": account_count,
            "dpapiBackupKeyReadable": "yes" if dpapi_readable else "no",
            "secretHandles": handles,
        })

        confirmed = ntds_readable and dpapi_readable
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="ntds-dpapi-readable-not-exported" if confirmed
            else "ntds-dpapi-not-readable",
            assertions=[
                f"NTDS.dit was {'readable' if ntds_readable else 'not readable'}"
                + (f" ({account_count} accounts)" if ntds_readable else "") + ".",
                f"Domain DPAPI backup key was {'readable' if dpapi_readable else 'not readable'}.",
                "No file was written or copied; bytes streamed into vault handles and were discarded.",
            ],
            redacted_refs=refs,
        )

    def _live_reader(self):
        from ...probes.credaccess import LiveNtdsDpapiReader
        return LiveNtdsDpapiReader(self.domain)

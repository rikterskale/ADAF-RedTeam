"""SVCCTL execution proof (state-changing, lab-only, reversible).

Proof-of-execution ONLY. It runs a single fixed benign marker (echo a random
nonce) via a temporary service, captures the exit code and echoed marker, then
REMOVES the service. It is not a shell and accepts no user-supplied command — the
point is to prove code execution is possible, not to provide it.
"""

from __future__ import annotations

import secrets

from ..base import Capability, CapabilityResult


class SvcctlExecProofCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "exec-proof-svcctl",
            "sequence": [
                "create a temporary service that echoes a random benign marker  [LAB ONLY]",
                "capture exit code + echoed marker (proof of execution)",
                "REMOVE the temporary service (mandatory)",
            ],
            "benignMarkerOnly": True,
            "does_not": ["run a user-supplied command", "provide a shell", "persist"],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        runner = self.source or self._live_exec()
        target = self.action.target
        marker = "ADAF-RT-" + secrets.token_hex(8)

        res = runner.run_marker(target, marker)
        echoed = bool(res.get("marker_echoed"))
        exit_code = res.get("exit_code")
        self.journal.append({"op": "run-marker", "target": target, "echoed": echoed,
                             "exitCode": exit_code})

        removed = bool(runner.remove_service(target))
        self.journal.append({"op": "remove-service", "target": target, "removed": removed})

        self._cleanup = {
            "required": True,
            "performed": removed,
            "verified": removed,
            "durableResidue": [] if removed else ["temporary service was NOT removed"],
        }

        confirmed = echoed and exit_code == 0
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="svcctl-execution-confirmed" if confirmed else "svcctl-execution-failed",
            assertions=[
                f"Benign marker {'echoed with exit 0' if confirmed else 'did not confirm execution'}.",
                "Only a fixed benign marker was run — no user command, no shell, no persistence.",
                f"Temporary service was {'removed' if removed else 'NOT removed'}.",
            ],
            redacted_refs={
                "target": target,
                "markerEchoed": "yes" if echoed else "no",
                "exitCode": int(exit_code) if isinstance(exit_code, int) else -1,
            },
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_exec(self):
        from ...probes.execution import LiveSvcctlExec
        return LiveSvcctlExec(self.domain)

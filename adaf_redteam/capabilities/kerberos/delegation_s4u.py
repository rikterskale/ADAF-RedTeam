"""S4U2Self -> S4U2Proxy delegation proof (LabExecutable, boolean proof only).

Given a principal with either unconstrained or constrained delegation configured,
proves the chain works end-to-end by running S4U2Self (get a ST to self as an
arbitrary user) then S4U2Proxy (forward that ST to a delegated SPN). The proof
is a single boolean — the requested/forwarded tickets are NEVER exported.

No mutation: msDS-AllowedToDelegateTo is not changed. Only Kerberos ticket
exchanges occur, all boolean-reported. Modeled on shadow-credential-write's
"PKINIT succeeded, no ticket exported" pattern.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class DelegationS4uProofCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "delegation-s4u2proxy-proof",
            "sequence": [
                "run S4U2Self on the source principal to obtain a ST to itself  [LAB ONLY]",
                "run S4U2Proxy to forward that ST to the delegated SPN",
                "record boolean success only (no ticket bytes exported)",
            ],
            "does_not": ["export any ticket", "modify msDS-AllowedToDelegateTo",
                         "modify UAC delegation flags"],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        prover = self.source or self._live_prover()
        source_principal = self.action.target
        # The delegated SPN under test is domain-scoped alongside the target; the
        # collector resolves it at certification time.
        target_spn = getattr(self, "_target_spn", source_principal)

        res = prover.s4u_chain(source_principal, target_spn)  # {"s4u2self_ok","s4u2proxy_ok","authenticated"}
        self_ok = bool(res.get("s4u2self_ok"))
        proxy_ok = bool(res.get("s4u2proxy_ok"))
        authenticated = bool(res.get("authenticated"))
        self.journal.append({"op": "s4u2self", "sourcePrincipal": source_principal, "succeeded": self_ok})
        self.journal.append({"op": "s4u2proxy", "targetSpn": target_spn, "succeeded": proxy_ok})
        self.journal.append({"op": "verify-auth", "targetSpn": target_spn, "authenticated": authenticated})

        confirmed = self_ok and proxy_ok and authenticated
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="delegation-s4u2proxy-confirmed" if confirmed
            else "delegation-s4u2proxy-failed",
            assertions=[
                f"S4U2Self {'succeeded' if self_ok else 'did not succeed'}.",
                f"S4U2Proxy {'forwarded to the delegated SPN' if proxy_ok else 'did not forward'}.",
                f"The forwarded ST {'authenticated to the target service' if authenticated else 'did not authenticate'}.",
                "Boolean proof only; no ticket bytes were exported.",
            ],
            redacted_refs={
                "sourcePrincipal": source_principal,
                "targetSpn": target_spn,
                "s4u2self": "yes" if self_ok else "no",
                "s4u2proxy": "yes" if proxy_ok else "no",
                "authenticated": "yes" if authenticated else "no",
                "journalEntries": len(self.journal),
            },
        )

    def _live_prover(self):
        from ...probes.kerberos import LiveDelegationProver
        return LiveDelegationProver(self.domain)

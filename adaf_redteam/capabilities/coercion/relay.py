"""SMB->LDAP relay to Shadow Credential validation (state-changing, lab-only).

Proves a coerced authentication can be relayed to LDAP to write a shadow
credential on the target, then REMOVES the shadow credential (reversible). Single
named target, short-lived listener, no persistence, no second destination. Any
key/credential material obtained is redacted to a handle and never exported.
"""

from __future__ import annotations

from ..base import Capability, CapabilityResult


class SmbLdapRelayCapability(Capability):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cleanup: dict | None = None
        self.journal: list[dict] = []

    def plan(self) -> dict:
        return {
            "capabilityId": "smb-ldap-relay-shadowcred",
            "sequence": [
                "coerce the single named target and relay SMB->LDAP  [LAB ONLY]",
                "write a shadow credential via the relayed session",
                "verify the write, redact any obtained key material",
                "REMOVE the shadow credential (mandatory restore)",
            ],
            "does_not": ["persist a listener", "use a second destination", "export key material"],
            "reversible": True,
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        relay = self.source or self._live_relay()
        target = self.action.target

        res = relay.coerce_and_relay(target)  # {"relayed","written","privkey"?}
        relayed = bool(res.get("relayed"))
        written = bool(res.get("written"))
        handles = []
        if res.get("privkey") is not None:
            handles.append(self.vault.redact(res["privkey"], "relay-shadowcred-privkey").handle_id)
        self.journal.append({"op": "coerce-relay", "target": target, "relayed": relayed,
                             "shadowcredWritten": written})

        removed = bool(relay.remove_shadowcred(target)) if written else True
        self.journal.append({"op": "remove-shadowcred", "target": target, "removed": removed})

        self._cleanup = {
            "required": True,
            "performed": removed,
            "verified": removed,
            "durableResidue": [] if removed else ["relayed shadow credential was NOT removed"],
        }

        confirmed = relayed and written
        return CapabilityResult(
            verdict="Confirmed" if confirmed else "NotExploitable",
            proof_class="relay-shadowcred-written" if confirmed else "relay-not-exploitable",
            assertions=[
                f"Coerced auth was {'relayed to LDAP and a shadow credential written' if confirmed else 'not successfully relayed'}.",
                f"Shadow credential was {'removed' if removed else 'NOT removed'}.",
                "Single named target, no persistence; any key material was redacted and never exported.",
            ],
            redacted_refs={
                "target": target,
                "relayed": "yes" if relayed else "no",
                "shadowcredWritten": "yes" if written else "no",
                "removed": "yes" if removed else "no",
                "secretHandles": handles,
            },
        )

    def cleanup(self) -> dict:
        return self._cleanup or super().cleanup()

    def _live_relay(self):
        from ...probes.coercion import LiveRelay
        return LiveRelay(self.domain)

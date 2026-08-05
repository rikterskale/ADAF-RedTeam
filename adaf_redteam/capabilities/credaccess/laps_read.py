"""LAPS password read exposure.

Proves whether a target principal can read a computer's LAPS password attribute
(legacy ms-Mcs-AdmPwd or Windows LAPS ms-LAPS-* attributes) via ReadProperty /
ControlAccess on that attribute — WITHOUT reading the password value.
"""

from __future__ import annotations

from ...directory.acl import Ace, effective_rights
from ...lab_env import lab_bind_password, lab_bind_user, lab_dc
from ..base import Capability, CapabilityResult

LAPS_ATTRIBUTES = ("ms-Mcs-AdmPwd", "ms-LAPS-Password", "ms-LAPS-EncryptedPassword")
_READ_RIGHTS = {"ReadProperty", "ControlAccess"}


def analyze(target: str, computer_dn: str, attribute: str, aces: list[Ace]) -> CapabilityResult:
    # Only ACEs scoped to the LAPS attribute (or unscoped full-control) count.
    scoped = [a for a in aces if a.object_type in (attribute, None)]
    rights = effective_rights(scoped, target)
    confirmed = bool(rights & _READ_RIGHTS)
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="laps-password-read-authorized" if confirmed
        else "laps-password-read-denied",
        assertions=[
            f"Target {'can' if confirmed else 'cannot'} read {attribute} on the computer object.",
            "The LAPS password value was NOT retrieved.",
        ],
        redacted_refs={
            "targetPrincipal": target,
            "computer": computer_dn,
            "lapsAttribute": attribute,
            "readRightsHeld": sorted(rights & _READ_RIGHTS),
        },
    )


class LapsReadCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "laps-read-authorization",
            "reads": f"ACL for one of {LAPS_ATTRIBUTES} on the target computer",
            "does_not": ["read the LAPS password value", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        attribute = LAPS_ATTRIBUTES[0]
        aces = source.object_acl(self.action.target, attribute=attribute)
        return analyze(self.action.target, self.action.target, attribute, aces)

    def _live_source(self):
        from ...directory.ldap_source import LdapDirectorySource
        bind_user = lab_bind_user() or self.action.source_address
        server = lab_dc() or self.domain
        password = lab_bind_password()
        use_ccache = password is None
        return LdapDirectorySource(
            server,
            user=bind_user,
            use_kerberos_ccache=use_ccache,
            password=password,
        )

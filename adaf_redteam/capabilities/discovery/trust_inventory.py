"""AD trust inventory (Executable, secret-free).

Reads (objectClass=trustedDomain) under the domain and reports each trust:
partner name, direction (inbound / outbound / bidirectional), type (Windows
domain / MIT / cross-forest), whether SID-filter quarantining is enabled, and
whether the trust is transitive. This is the input other analyses need to
answer "can compromise here spread beyond this domain?" — it does not itself
attempt any cross-trust operation.

trustDirection bits (per MS-ADTS):
  0x1  DISABLED     0x2  INBOUND    0x4  OUTBOUND    0x6 = 0x2|0x4  BIDIRECTIONAL

trustAttributes bits we surface:
  0x1  NON_TRANSITIVE                 0x4  QUARANTINED_DOMAIN (SID filter)
  0x8  FOREST_TRANSITIVE              0x40 TREAT_AS_EXTERNAL

Read-only: no cross-domain authentication is attempted, no trust is created
or modified.
"""

from __future__ import annotations

from ...lab_env import lab_bind_password, lab_bind_user, lab_dc
from ..base import Capability, CapabilityResult

_DIRECTION = {0: "disabled", 1: "disabled", 2: "inbound", 4: "outbound", 6: "bidirectional"}

_ATTR_NON_TRANSITIVE = 0x00000001
_ATTR_QUARANTINED = 0x00000004
_ATTR_FOREST_TRANSITIVE = 0x00000008
_ATTR_TREAT_AS_EXTERNAL = 0x00000040


def _describe_trust(t: dict) -> dict:
    """Compute the interpreted view of a trust (used internally for flagging)."""
    direction = _DIRECTION.get(int(t.get("trustDirection", 0)), "unknown")
    attrs = int(t.get("trustAttributes", 0))
    return {
        "partner": str(t.get("trustPartner", "")),
        "type": int(t.get("trustType", 0)),
        "direction": direction,
        "transitive": not bool(attrs & _ATTR_NON_TRANSITIVE),
        "forestTransitive": bool(attrs & _ATTR_FOREST_TRANSITIVE),
        "quarantined": bool(attrs & _ATTR_QUARANTINED),
        "treatAsExternal": bool(attrs & _ATTR_TREAT_AS_EXTERNAL),
    }


def _serialize_trust(t: dict) -> str:
    """One trust as a pipe-separated string (schema requires string values)."""
    flags: list[str] = []
    if t["transitive"]:
        flags.append("transitive")
    if t["forestTransitive"]:
        flags.append("forest-transitive")
    if t["quarantined"]:
        flags.append("sid-filter")
    if t["treatAsExternal"]:
        flags.append("treat-as-external")
    return f"{t['partner']}|dir={t['direction']}|type={t['type']}|{','.join(flags) or '-'}"


def analyze(domain: str, trusts: list[dict]) -> CapabilityResult:
    described = [_describe_trust(t) for t in trusts]
    # A trust without SID filter that is inbound or bidirectional is the
    # attention-grabbing case — it lets SIDHistory from the other side inject
    # privileges here. We flag but do not fail: the operator decides.
    unfiltered_inbound = [t for t in described
                          if t["direction"] in ("inbound", "bidirectional")
                          and not t["quarantined"]]
    confirmed = len(trusts) > 0
    return CapabilityResult(
        verdict="Confirmed" if confirmed else "NotExploitable",
        proof_class="trusts-enumerated" if confirmed else "no-trusts",
        assertions=[
            f"Domain has {len(trusts)} trust(s).",
            (f"{len(unfiltered_inbound)} of those are inbound/bidirectional "
             "WITHOUT SID-filter quarantining "
             "(potential SIDHistory injection path)."),
            "Read-only enumeration: no cross-trust authentication attempted.",
        ],
        redacted_refs={
            "domain": domain,
            "trustCount": len(trusts),
            "unfilteredInboundCount": len(unfiltered_inbound),
            "trusts": [_serialize_trust(t) for t in described],
            "unfilteredInboundPartners": [t["partner"] for t in unfiltered_inbound],
        },
    )


class TrustInventoryCapability(Capability):
    def plan(self) -> dict:
        return {
            "capabilityId": "trust-inventory",
            "reads": "(objectClass=trustedDomain) under System container",
            "does_not": ["attempt cross-trust authentication", "modify a trust", "any write"],
            "target": self.action.target,
            "domain": self.domain,
        }

    def execute(self) -> CapabilityResult:
        source = self.source or self._live_source()
        return analyze(self.domain or self.action.target,
                       source.list_trusts(self.domain or self.action.target))

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

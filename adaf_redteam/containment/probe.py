"""Containment probe.

Before any state-changing action, confirm the target is a disposable lab. Phase 0
ships the record shape and the engagement-declaration check only; the live
network checks (address range, DC install date, object count) are TODOs wired in
Phase 2, and are marked as not-yet-implemented so a run cannot silently pass.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ContainmentProbe:
    domain: str
    verified: bool
    environment: str  # disposable-lab | authorized-production | unknown
    checks: list[dict] = field(default_factory=list)
    probe_id: str = ""
    probed_at_utc: str = ""

    def to_record(self) -> dict:
        return {
            "probeId": self.probe_id,
            "probedAtUtc": self.probed_at_utc,
            "domain": self.domain,
            "verified": self.verified,
            "environment": self.environment,
            "checks": self.checks,
        }


def _probe_id() -> str:
    return "CP-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16].upper()


def probe_domain(domain: str, *, engagement_declares_lab: bool) -> ContainmentProbe:
    """Phase 0 containment: conservative. Passes only when the engagement declares
    a disposable lab AND the live checks are implemented. Live checks are not yet
    implemented, so `verified` is False by design — state-changing execution
    stays blocked until Phase 2 wires them.
    """
    checks = [
        {
            "name": "engagement-declares-disposable-lab",
            "passed": bool(engagement_declares_lab),
            "detail": "labContainmentRequired flag in engagement capability authz",
        },
        {
            "name": "live-address-range-check",
            "passed": False,
            "detail": "NOT IMPLEMENTED (Phase 2): resolve target, confirm lab address range",
        },
        {
            "name": "live-production-heuristics",
            "passed": False,
            "detail": "NOT IMPLEMENTED (Phase 2): DC install date / object-count sanity",
        },
    ]
    verified = all(c["passed"] for c in checks)
    return ContainmentProbe(
        domain=domain,
        verified=verified,
        environment="disposable-lab" if verified else "unknown",
        checks=checks,
        probe_id=_probe_id(),
        probed_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

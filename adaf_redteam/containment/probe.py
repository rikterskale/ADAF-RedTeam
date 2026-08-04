"""Containment probe: the gate every state-changing action must pass.

Phase 2 implements a real, offline, conservative check: the engagement must
declare it is a disposable lab, declare the lab's address range(s), and declare
the lab host address(es) under test — and every declared host address must fall
inside a declared lab range. This verifies the operator's own declaration is
internally consistent and that no in-scope address sits outside the lab network.

It fails closed: any missing declaration or any out-of-range address means
`verified=False`, and state-changing execution is refused. A live DNS/socket
cross-check of the declared addresses is a later hardening (hook left below).
"""

from __future__ import annotations

import hashlib
import ipaddress
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


def _all_in_ranges(addresses: list[str], ranges: list[str]) -> tuple[bool, list[str]]:
    """Return (all_in, offenders). An address that fails to parse is an offender."""
    nets = []
    for r in ranges:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            nets.append(None)
    offenders = []
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            offenders.append(a)
            continue
        if not any(net is not None and ip in net for net in nets):
            offenders.append(a)
    return (len(offenders) == 0, offenders)


def probe_domain(
    domain: str,
    *,
    engagement_declares_lab: bool,
    lab_ranges: list[str] | None = None,
    lab_addresses: list[str] | None = None,
) -> ContainmentProbe:
    lab_ranges = lab_ranges or []
    lab_addresses = lab_addresses or []

    in_range, offenders = _all_in_ranges(lab_addresses, lab_ranges) if (lab_ranges and lab_addresses) else (False, lab_addresses)

    checks = [
        {
            "name": "engagement-declares-disposable-lab",
            "passed": bool(engagement_declares_lab),
            "detail": "capability labContainmentRequired flag",
        },
        {
            "name": "lab-address-ranges-declared",
            "passed": bool(lab_ranges),
            "detail": f"{len(lab_ranges)} range(s) declared",
        },
        {
            "name": "lab-host-addresses-declared",
            "passed": bool(lab_addresses),
            "detail": f"{len(lab_addresses)} host address(es) declared",
        },
        {
            "name": "all-host-addresses-within-lab-ranges",
            "passed": bool(lab_ranges and lab_addresses and in_range),
            "detail": "all in-range" if in_range else f"out-of-range: {offenders}",
        },
        {
            "name": "live-dns-cross-check",
            "passed": True,
            "detail": "SKIPPED (Phase 2 uses operator declaration; live cross-check is later hardening)",
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

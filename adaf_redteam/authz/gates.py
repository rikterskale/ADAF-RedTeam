"""The runtime authorization gate.

A capability may run only when every check here passes. This is a safety floor,
not a license: it cannot know whether your engagement letter is genuine, only
whether the file is internally consistent and names the action you are about to
take.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .engagement import Engagement

if TYPE_CHECKING:
    from ..capabilities.registry import CapabilityDescriptor


class GateError(Exception):
    """Raised when authorization is refused, with a stable operator-facing code."""

    def __init__(self, code: str, message: str, remedy: str) -> None:
        super().__init__(message)
        self.code = code
        self.remedy = remedy


@dataclass(frozen=True)
class AuthorizedAction:
    capability_id: str
    target: str
    technique: str
    source_address: str
    state_changing: bool
    production: bool
    max_actions: int
    min_interval_ms: int


def authorize(
    engagement: Engagement,
    descriptor: CapabilityDescriptor,
    *,
    target: str,
    source_address: str,
    plan_only: bool,
) -> AuthorizedAction:
    cid = descriptor.capability_id
    authz = engagement.capability_authz(cid)
    if authz is None:
        raise GateError("ADAF-RT-E100", f"capability '{cid}' is not listed in the engagement file",
                        "Ask the engagement owner to add and approve the exact capability.")
    if not authz.get("approved", False):
        raise GateError("ADAF-RT-E101", f"capability '{cid}' is present but not approved",
                        "Do not bypass this gate; obtain written approval in the engagement file.")

    if source_address not in engagement.authorized_source_addresses:
        raise GateError("ADAF-RT-E102", f"source address '{source_address}' is not authorized",
                        "Use an approved operator host or have the engagement owner correct the scope.")

    if target not in authz.get("targets", []):
        raise GateError("ADAF-RT-E103", f"target '{target}' is not in the authorized target list for '{cid}'",
                        "Use the exact approved target; do not broaden the target list yourself.")

    technique = authz.get("attackTechnique", "")
    if descriptor.required_technique and technique != descriptor.required_technique:
        raise GateError("ADAF-RT-E104",
                        f"capability '{cid}' requires technique {descriptor.required_technique}, "
                        f"engagement authorizes {technique or '(none)'}",
                        "Have the engagement owner authorize the exact ATT&CK technique.")

    state_changing = bool(authz.get("stateChangingApproved", False)) and descriptor.state_changing
    production = bool(authz.get("productionAuthorized", False))

    # Plan-only never executes, so the state-changing / containment gates do not apply.
    if not plan_only:
        if descriptor.state_changing and not authz.get("stateChangingApproved", False):
            raise GateError("ADAF-RT-E105", f"capability '{cid}' is state-changing but not approved for state change",
                            "State-changing work requires explicit approval; use --plan-only until it exists.")
        if state_changing:
            for field in ("riskAccepted", "cleanupRequired", "labContainmentRequired"):
                if not authz.get(field, False):
                    raise GateError("ADAF-RT-E106", f"state-changing '{cid}' requires '{field}: true'",
                                    "Complete the engagement's risk, cleanup, and lab-containment approvals.")
            if not authz.get("riskAcceptanceReference"):
                raise GateError("ADAF-RT-E107", f"state-changing '{cid}' requires a riskAcceptanceReference",
                                "Record the approved risk-acceptance reference before retrying.")
        if descriptor.requires_detection_notification and not authz.get("detectionNotification"):
            raise GateError("ADAF-RT-E108",
                            f"adversary-emulation capability '{cid}' requires a detectionNotification "
                            "(ROE-defined) before it may run",
                            "Add the ROE-defined blue-team notification before retrying.")
        if production and descriptor.state_changing and not authz.get("labContainmentRequired", False):
            raise GateError("ADAF-RT-E109",
                            f"'{cid}' is state-changing; production runs still require lab-containment proof",
                            "State-changing work must remain containment-verified in a disposable lab.")

    return AuthorizedAction(
        capability_id=cid,
        target=target,
        technique=technique,
        source_address=source_address,
        state_changing=state_changing,
        production=production,
        max_actions=int(authz.get("maximumActions", 1)),
        min_interval_ms=int(authz.get("minimumIntervalMilliseconds", 0)),
    )

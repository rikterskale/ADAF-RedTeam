"""Declarative capability registry.

Phase 0: descriptors only. `adapter` is None for every entry, so `run` without
`--plan-only` reports that no executable adapter exists. Descriptors carry the
readiness state, required ATT&CK technique, and safety flags the gate enforces.

Readiness (see DESIGN.md §3):
  PlanOnly       - emits a plan; never touches the network.
  LabExecutable  - may execute only under verified lab containment.
  Executable     - may execute against an authorized (incl. production) target,
                   read/metadata proof classes only; never state-changing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityDescriptor:
    capability_id: str
    title: str
    group: str
    readiness: str  # PlanOnly | LabExecutable | Executable
    required_technique: str
    state_changing: bool = False
    requires_detection_notification: bool = False
    adapter: type | None = None  # None until a real adapter lands in a later phase


# NOTE: every entry is PlanOnly in Phase 0. Readiness listed as the *target*
# state a capability is intended to reach once its adapter passes review.
_DESCRIPTORS: tuple[CapabilityDescriptor, ...] = (
    # --- credential access (target: Executable, read/rights proof only) ---
    CapabilityDescriptor("dcsync-rights-validation", "DCSync replication-rights check",
                         "credential-access", "PlanOnly", "T1003.006"),
    CapabilityDescriptor("laps-read-authorization", "LAPS read authorization check",
                         "credential-access", "PlanOnly", "T1552"),
    CapabilityDescriptor("gmsa-read-authorization", "gMSA read authorization check",
                         "credential-access", "PlanOnly", "T1552"),
    # --- kerberos (mixed) ---
    CapabilityDescriptor("asrep-roast-validation", "AS-REP roasting metadata",
                         "kerberos", "PlanOnly", "T1558.004"),
    CapabilityDescriptor("kerberoast-validation", "Kerberoasting metadata",
                         "kerberos", "PlanOnly", "T1558.003"),
    CapabilityDescriptor("shadow-credential-write", "Shadow Credentials + PKINIT (lab)",
                         "kerberos", "PlanOnly", "T1556", state_changing=True),
    CapabilityDescriptor("rbcd-write-validation", "RBCD S4U write (lab)",
                         "kerberos", "PlanOnly", "T1558", state_changing=True),
    CapabilityDescriptor("golden-silver-ticket", "Golden/silver ticket forgery (lab)",
                         "kerberos", "PlanOnly", "T1558.001", state_changing=True),
    # --- ADCS ---
    CapabilityDescriptor("adcs-esc1-validation", "AD CS ESC1 enrollment (lab)",
                         "adcs", "PlanOnly", "T1649", state_changing=True),
    # --- coercion / relay (highest scrutiny; lab-only) ---
    CapabilityDescriptor("coercion-petitpotam", "PetitPotam/PrinterBug coercion (lab)",
                         "coercion-relay", "PlanOnly", "T1187", state_changing=True),
    CapabilityDescriptor("smb-ldap-relay-shadowcred", "SMB->LDAP relay to Shadow Cred (lab)",
                         "coercion-relay", "PlanOnly", "T1557.001", state_changing=True),
    # --- lateral / execution proof ---
    CapabilityDescriptor("exec-proof-svcctl", "SVCCTL exec proof (benign marker)",
                         "lateral", "PlanOnly", "T1569.002", state_changing=True),
    # --- detection / adversary-emulation (purple team; detection evidence required) ---
    CapabilityDescriptor("adversary-emulation-evasion", "Adversary-emulation TTPs w/ evasion (purple team)",
                         "detection", "PlanOnly", "T1562",
                         state_changing=True, requires_detection_notification=True),
    CapabilityDescriptor("payload-reliability-labtest", "Forged-ticket/relay reliability lab test",
                         "detection", "PlanOnly", "T1550",
                         state_changing=True, requires_detection_notification=True),
    # --- detection ---
    CapabilityDescriptor("zerologon-detection", "Zerologon detection (safe)",
                         "detection", "PlanOnly", "T1210"),
)

_BY_ID = {d.capability_id: d for d in _DESCRIPTORS}


def list_descriptors() -> list[CapabilityDescriptor]:
    return list(_DESCRIPTORS)


def get_descriptor(capability_id: str) -> CapabilityDescriptor:
    if capability_id not in _BY_ID:
        raise KeyError(f"unknown capability id: {capability_id}")
    return _BY_ID[capability_id]

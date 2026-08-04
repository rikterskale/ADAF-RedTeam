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
    lab_certified: bool = False  # True only after a disposable-lab test certifies the live path


# Phase 1 wires read-only, secret-free adapters for the credential-access group.
# Their live collector is NOT lab-certified yet (lab_certified=False), so the CLI
# flags any real run as unvalidated. Analyzers are unit-tested; the collector is
# the remaining certification boundary. Everything else remains PlanOnly.
from .credaccess import (
    DcsyncRightsCapability,
    GmsaReadCapability,
    LapsReadCapability,
)

_DESCRIPTORS: tuple[CapabilityDescriptor, ...] = (
    # --- credential access (Executable target; read/rights proof, no secret export) ---
    CapabilityDescriptor("dcsync-rights-validation", "DCSync replication-rights check",
                         "credential-access", "Executable", "T1003.006",
                         adapter=DcsyncRightsCapability, lab_certified=False),
    CapabilityDescriptor("laps-read-authorization", "LAPS read authorization check",
                         "credential-access", "Executable", "T1552",
                         adapter=LapsReadCapability, lab_certified=False),
    CapabilityDescriptor("gmsa-read-authorization", "gMSA read authorization check",
                         "credential-access", "Executable", "T1552",
                         adapter=GmsaReadCapability, lab_certified=False),
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

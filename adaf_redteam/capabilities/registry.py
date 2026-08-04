"""Declarative capability registry.

Descriptors carry the readiness state, required ATT&CK technique, and safety flags
the gate enforces. A capability with `adapter=None` is PlanOnly (run without
`--plan-only` reports no adapter). Wired adapters ship `lab_certified=False` until
a disposable-lab test certifies their live primitive; their live path raises, so
real runs are stamped UNVALIDATED and exercised offline via `--fixture`. No
state-changing capability ships a working live mutation primitive.

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
from .adcs import Esc1Capability
from .credaccess import (
    DcsyncRightsCapability,
    GmsaReadCapability,
    LapsReadCapability,
)
from .kerberos import (
    AsrepRoastCapability,
    KerberoastCapability,
    RbcdWriteCapability,
    ShadowCredWriteCapability,
)
from .netlogon import ZerologonDetectionCapability, ZerologonResetCapability

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
    # --- kerberos (metadata proof; Executable, no blob export) ---
    CapabilityDescriptor("asrep-roast-validation", "AS-REP roasting metadata",
                         "kerberos", "Executable", "T1558.004",
                         adapter=AsrepRoastCapability, lab_certified=False),
    CapabilityDescriptor("kerberoast-validation", "Kerberoasting metadata",
                         "kerberos", "Executable", "T1558.003",
                         adapter=KerberoastCapability, lab_certified=False),
    CapabilityDescriptor("shadow-credential-write", "Shadow Credentials + PKINIT (lab, reversible)",
                         "kerberos", "LabExecutable", "T1556", state_changing=True,
                         adapter=ShadowCredWriteCapability, lab_certified=False),
    CapabilityDescriptor("rbcd-write-validation", "RBCD S4U write (lab, reversible)",
                         "kerberos", "LabExecutable", "T1558", state_changing=True,
                         adapter=RbcdWriteCapability, lab_certified=False),
    CapabilityDescriptor("golden-silver-ticket", "Golden/silver ticket forgery (lab)",
                         "kerberos", "PlanOnly", "T1558.001", state_changing=True),
    # --- ADCS (durable residue: issuance is not fully reversible) ---
    CapabilityDescriptor("adcs-esc1-validation", "AD CS ESC1 enrollment (lab, durable)",
                         "adcs", "LabExecutable", "T1649", state_changing=True,
                         adapter=Esc1Capability, lab_certified=False),
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
    # --- netlogon / zerologon ---
    CapabilityDescriptor("zerologon-detection", "Zerologon detection (safe)",
                         "detection", "Executable", "T1210",
                         adapter=ZerologonDetectionCapability, lab_certified=False),
    # Destructive exploit: reset the DC machine-account password. Lab-only,
    # containment-gated, reset-then-restore. Primitive intentionally unimplemented.
    CapabilityDescriptor("zerologon-reset", "Zerologon DC account reset (LAB ONLY, destructive)",
                         "netlogon", "LabExecutable", "T1210",
                         state_changing=True,
                         adapter=ZerologonResetCapability, lab_certified=False),
)

_BY_ID = {d.capability_id: d for d in _DESCRIPTORS}


def list_descriptors() -> list[CapabilityDescriptor]:
    return list(_DESCRIPTORS)


def get_descriptor(capability_id: str) -> CapabilityDescriptor:
    if capability_id not in _BY_ID:
        raise KeyError(f"unknown capability id: {capability_id}")
    return _BY_ID[capability_id]

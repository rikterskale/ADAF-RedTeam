"""Build, validate, and write the redacted validation-result (the ADAF bridge).

This is the only artifact that crosses back into ADAF. It is validated against
schemas/validation-result.schema.json before it is written, so a malformed or
secret-bearing shape cannot leave the tool.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..capabilities.base import CapabilityResult
from ..capabilities.registry import CapabilityDescriptor
from ..schemas import load_schema, validate

__version__ = "0.1.0"


def _result_id() -> str:
    return "VR-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16].upper()


def build_result(
    *,
    engagement_id: str,
    descriptor: CapabilityDescriptor,
    finding_id: str,
    control_id: str,
    domain: str,
    principal: str | None,
    result: CapabilityResult,
    readiness_used: str,
    state_changing: bool,
    source_address: str,
    operator_contact: str,
    risk_ref: str | None = None,
    containment: dict | None = None,
    budget: dict | None = None,
) -> dict:
    proof: dict = {"proofClass": result.proof_class, "assertions": result.assertions}
    if result.redacted_refs:
        proof["redactedRefs"] = result.redacted_refs
    if result.detection:
        proof["detection"] = result.detection

    doc: dict = {
        "schemaVersion": "1.0",
        "resultId": _result_id(),
        "engagementId": engagement_id,
        "producedByUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {"tool": "ADAF-RedTeam", "version": __version__},
        "correlatesTo": {"FindingId": finding_id, "ControlId": control_id},
        "capabilityId": descriptor.capability_id,
        "attackTechnique": descriptor.required_technique,
        "target": {"domain": domain},
        "verdict": result.verdict,
        "readinessUsed": readiness_used,
        "stateChanging": state_changing,
        "proof": proof,
        "authorization": {
            "authorizedSourceAddress": source_address,
            "operatorContact": operator_contact,
        },
    }
    if principal:
        doc["target"]["principal"] = principal
    if risk_ref:
        doc["authorization"]["riskAcceptanceReference"] = risk_ref
    if containment:
        doc["containment"] = containment
    if budget:
        doc["budget"] = budget
    if result.cleanup:
        doc["cleanup"] = result.cleanup

    # Integrity over the document body (integrity field excluded from the hash).
    body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    doc["integrity"] = {"resultSha256": hashlib.sha256(body).hexdigest()}

    validate(doc, load_schema("validation-result.schema.json"))
    return doc


def write_result(doc: dict, out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "validation-result.json"
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path

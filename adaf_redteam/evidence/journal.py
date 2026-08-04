"""Redacted plan and journal writers.

These only ever receive already-redacted data (handles, hashes, counts, DNs).
The redaction test suite greps their output for secret shapes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_plan(plan: dict, out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "plan.json"
    payload = {"producedByUtc": _now(), "planOnly": True, "plan": plan}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_journal(entries: list[dict], out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "transaction-journal.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps({"ts": _now(), **entry}) + "\n")
    return path


def write_manifest(out_dir: str | Path, *, mode: str, capability_id: str) -> Path:
    """Write a secret-free inventory of the known evidence artifacts in *out_dir*."""
    out_dir = Path(out_dir)
    allowed = ("plan.json", "validation-result.json", "transaction-journal.jsonl", ".state-change-latch")
    artifacts = []
    for name in allowed:
        path = out_dir / name
        if path.is_file():
            raw = path.read_bytes()
            artifacts.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    manifest = {
        "producedByUtc": _now(), "schemaVersion": "1.0", "redacted": True,
        "mode": mode, "capabilityId": capability_id, "artifacts": artifacts,
        "retention": "Contains only artifact names, sizes, and checksums; retain under the engagement policy.",
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path

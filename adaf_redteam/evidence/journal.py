"""Redacted plan and journal writers.

These only ever receive already-redacted data (handles, hashes, counts, DNs).
The redaction test suite greps their output for secret shapes.
"""

from __future__ import annotations

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

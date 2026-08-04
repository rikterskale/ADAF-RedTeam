"""Cleanup latch. A verified-clean state change leaves no latch; a failed cleanup
latches the output directory against further state-changing actions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

LATCH_FILENAME = ".state-change-latch"


def _path(out_dir: str | Path) -> Path:
    return Path(out_dir) / LATCH_FILENAME


def is_latched(out_dir: str | Path) -> bool:
    return _path(out_dir).exists()


def set_latch(out_dir: str | Path, reason: str, *, capability_id: str = "", target: str = "") -> Path:
    p = _path(out_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({
            "latchedAtUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason": reason,
            "capabilityId": capability_id,
            "target": target,
            "clearedBy": "manual operator action required after verifying cleanup",
        }, indent=2),
        encoding="utf-8",
    )
    return p


def clear_latch(out_dir: str | Path) -> bool:
    p = _path(out_dir)
    if p.exists():
        p.unlink()
        return True
    return False

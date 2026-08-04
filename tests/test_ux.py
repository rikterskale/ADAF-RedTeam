"""Operator-experience contracts: references, guides, and safe manifests."""

import json
import subprocess
import sys
from pathlib import Path

from adaf_redteam.__main__ import main


def test_plan_manifest_is_secret_free_inventory(tmp_path):
    rc = main([
        "run", "--engagement", "examples/engagement.example.json",
        "--capability", "asrep-roast-validation", "--source-address", "192.0.2.25",
        "--plan-only", "--out", str(tmp_path),
    ])
    assert rc == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["redacted"] is True
    assert manifest["mode"] == "plan-only"
    assert manifest["artifacts"][0]["path"] == "plan.json"
    assert len(manifest["artifacts"][0]["sha256"]) == 64


def test_generated_reference_and_guides_are_current():
    root = Path(__file__).resolve().parents[1]
    for script in ("scripts/generate_capability_reference.py", "scripts/validate_novice_guides.py"):
        result = subprocess.run([sys.executable, script, "--check"] if "generate" in script
                                else [sys.executable, script], cwd=root, text=True, capture_output=True,
                                check=False)
        assert result.returncode == 0, result.stdout + result.stderr

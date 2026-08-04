#!/usr/bin/env python3
"""ADAF-side ingest for an ADAF-RedTeam validation-result.

Run this from the ADAF host. It validates a redacted validation-result against
the bridge schema, confirms the correlated finding exists in the target ADAF run,
and writes a redacted `validation-linkage.json` next to findings.csv. It imports
nothing executable from ADAF-RedTeam — only JSON crosses the boundary.

This is intentionally standalone (stdlib + jsonschema) so it can live in the ADAF
repo without depending on the offensive package.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("error: pip install jsonschema", file=sys.stderr)
    raise SystemExit(2)

_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "validation-result.schema.json"

# Fields that must never appear anywhere in an ingested result.
_FORBIDDEN_KEYS = {"password", "hash", "ntlm", "nthash", "aeskey", "ticket", "krbtgt",
                   "pfx", "privatekey", "private_key", "secret", "lapsvalue", "plaintext"}


def _scan_forbidden(node, path="") -> list[str]:
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower().replace("_", "") in _FORBIDDEN_KEYS:
                hits.append(f"{path}/{k}")
            hits += _scan_forbidden(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += _scan_forbidden(v, f"{path}[{i}]")
    return hits


def _find_finding_row(adaf_run: Path, finding_id: str) -> bool:
    for csv_path in adaf_run.rglob("findings.csv"):
        text = csv_path.read_text(encoding="utf-8", errors="replace")
        if finding_id in text:
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ingest an ADAF-RedTeam validation result into an ADAF run.")
    ap.add_argument("--result", required=True, help="path to validation-result.json")
    ap.add_argument("--adaf-run", required=True, help="path to the ADAF run directory")
    args = ap.parse_args(argv)

    doc = json.loads(Path(args.result).read_text(encoding="utf-8"))
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))

    errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        for e in errors:
            print(f"SCHEMA ERROR {'/'.join(str(p) for p in e.path)}: {e.message}", file=sys.stderr)
        return 3

    forbidden = _scan_forbidden(doc)
    if forbidden:
        print("REFUSED: result contains forbidden secret-shaped keys:", file=sys.stderr)
        for f in forbidden:
            print(f"  {f}", file=sys.stderr)
        return 4

    finding_id = doc["correlatesTo"]["FindingId"]
    adaf_run = Path(args.adaf_run)
    if not _find_finding_row(adaf_run, finding_id):
        print(f"REFUSED: finding {finding_id} not found under {adaf_run}", file=sys.stderr)
        return 5

    linkage = {
        "findingId": finding_id,
        "controlId": doc["correlatesTo"]["ControlId"],
        "resultId": doc["resultId"],
        "verdict": doc["verdict"],
        "proofClass": doc["proof"]["proofClass"],
        "readinessUsed": doc["readinessUsed"],
        "stateChanging": doc["stateChanging"],
        "engagementId": doc["engagementId"],
        "resultSha256": doc["integrity"]["resultSha256"],
        "confidenceUpgrade": "HIGH" if doc["verdict"] == "Confirmed" else None,
    }
    out = adaf_run / "validation-linkage.json"
    existing = json.loads(out.read_text(encoding="utf-8")) if out.exists() else []
    existing.append(linkage)
    out.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"linked {finding_id} <- {doc['resultId']} ({doc['verdict']}); wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

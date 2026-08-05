"""Copy only redaction-clean certification result files into local evidence storage."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

PATTERN = re.compile(
    r"password|nthash|ntlm|krbtgt:|-----BEGIN|cipher:|\$krb5asrep\$|\$krb5tgs\$|"
    r"crackable|asrep-hash|ms-mcs-admpwd:|managedpassword|cleartext", re.IGNORECASE
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect redaction-clean certification evidence")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-path")
    source.add_argument("--test-output-root")
    parser.add_argument("--capability", required=True)
    parser.add_argument("--ticket", required=True)
    parser.add_argument("--destination-root", default="certification-evidence")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]+", args.capability):
        parser.error("--capability may contain only lowercase letters, numbers, and hyphens")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.ticket):
        parser.error("--ticket may contain only letters, numbers, period, underscore, and hyphen")

    if args.test_output_root:
        root = Path(args.test_output_root)
        results = list(root.rglob("validation-result.json")) if root.is_dir() else []
        if len(results) != 1:
            print(f"FAIL  Expected exactly one validation-result.json beneath TestOutputRoot; found {len(results)}.")
            print("STOP: Run one capability at a time in a new certification-work folder.")
            return 1
        source_dir = results[0].parent
    else:
        source_dir = Path(args.source_path)

    result = source_dir / "validation-result.json"
    if not result.is_file():
        print("FAIL  validation-result.json was not found.")
        print("STOP: Preserve the test log and ask the lab administrator to investigate.")
        return 1
    candidates = [result, *source_dir.glob("transaction-journal*.jsonl")]
    dirty: list[str] = []
    for file in candidates:
        if PATTERN.search(file.read_text(encoding="utf-8", errors="replace")):
            dirty.append(file.name)
    if dirty:
        print(f"FAIL  Redaction scan found possible secret material in: {', '.join(dirty)}")
        print("STOP: Nothing was copied. Restrict access to the source folder and give this output to the security owner.")
        return 1

    destination = Path(args.destination_root) / args.ticket / args.capability
    destination.mkdir(parents=True, exist_ok=True)
    for file in candidates:
        shutil.copy2(file, destination / file.name)
    log = destination / "collection-log.txt"
    hashes = [f"  {file.name}  {sha256(file)}" for file in destination.iterdir() if file.is_file() and file.name != log.name]
    log.write_text("\n".join([
        f"CollectedUtc: {datetime.now(UTC).isoformat()}", f"Capability: {args.capability}",
        f"Ticket: {args.ticket}", "RedactionScan: CLEAN", "Files:", *hashes,
        "Packet captures were not copied by this script. Record their SHA-256 hash in the evidence template.", "",
    ]), encoding="utf-8")
    print("PASS  Redaction scan: CLEAN")
    print(f"PASS  Evidence saved to: {destination}")
    print("NEXT  Attach the copied files and collection-log.txt to the certification ticket. Do not commit this folder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

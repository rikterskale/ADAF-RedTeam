"""Generate or verify the checked-in capability reference."""

from __future__ import annotations

import argparse
from pathlib import Path

from adaf_redteam.reference import render_capability_reference


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the checked-in reference is stale")
    args = parser.parse_args()
    path = Path("docs/CAPABILITY_REFERENCE.md")
    expected = render_capability_reference()
    if args.check:
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            print("Capability reference is stale. Run: python scripts/generate_capability_reference.py")
            return 1
        print("Capability reference is current.")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

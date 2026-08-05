"""Validate repository Markdown links and heading anchors without network access."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", ".pytest_cache", ".ruff_cache", "__pycache__", "review-output"}
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
NON_FILE_TARGET = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED_PARTS for part in path.parts)
    )


def slug(value: str) -> str:
    value = re.sub(r"[`*_]", "", unquote(value)).strip().lower()
    value = re.sub(r"\s+", "-", value)
    return re.sub(r"[^\w-]", "", value)


def anchors(path: Path) -> set[str]:
    result: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING.match(line)
        if match:
            result.add(slug(match.group(1)))
    return result


def main() -> int:
    errors: list[str] = []
    files = markdown_files()
    for source in files:
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            for match in LINK.finditer(line):
                target = unquote(match.group(1))
                if NON_FILE_TARGET.match(target):
                    continue
                path_part, separator, fragment = target.partition("#")
                destination = (
                    source
                    if not path_part
                    else (
                        ROOT / path_part.lstrip("/")
                        if path_part.startswith("/")
                        else source.parent / path_part
                    )
                )
                if not destination.exists():
                    errors.append(
                        f"{source.relative_to(ROOT)}:{number}: missing link target {target!r}"
                    )
                    continue
                if (
                    separator
                    and fragment
                    and destination.is_file()
                    and destination.suffix.lower() == ".md"
                    and slug(fragment) not in anchors(destination)
                ):
                    errors.append(
                        f"{source.relative_to(ROOT)}:{number}: missing heading anchor {target!r}"
                    )
    if errors:
        print("Markdown validation failed:\n- " + "\n- ".join(errors))
        return 1
    print(f"Validated relative links and anchors in {len(files)} Markdown files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

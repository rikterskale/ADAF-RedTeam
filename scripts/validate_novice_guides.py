"""Fail closed if the canonical novice guides become undiscoverable or unsafe."""

from __future__ import annotations

from pathlib import Path

GUIDES = (
    Path("docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md"),
    Path("docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md"),
    Path("docs/guides/DOCKER_USABILITY_GUIDE.md"),
)
REQUIRED = ("# ADAF-RedTeam", "doctor", "--plan-only", "ADAF-RT-E202")
VALIDATION_STATUS = {
    Path("docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md"): "PARTIALLY VERIFIED",
    Path("docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md"): "statically verified only",
    Path("docs/guides/DOCKER_USABILITY_GUIDE.md"): "CI-verified container build and offline plan-only smoke test",
}


def main() -> int:
    errors = []
    readme = Path("README.md").read_text(encoding="utf-8")
    for guide in GUIDES:
        if not guide.is_file():
            errors.append(f"missing guide: {guide}")
            continue
        text = guide.read_text(encoding="utf-8")
        for value in REQUIRED:
            if value not in text:
                errors.append(f"{guide}: missing required text {value!r}")
        status = VALIDATION_STATUS[guide]
        if status not in text:
            errors.append(f"{guide}: missing validation status {status!r}")
        if str(guide).replace("\\", "/") not in readme:
            errors.append(f"README.md does not link {guide}")
    if errors:
        print("Novice-guide validation failed:\n- " + "\n- ".join(errors))
        return 1
    print("Novice guides are present, linked, and include safe first-run boundaries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

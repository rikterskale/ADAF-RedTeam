"""Generated, source-of-truth capability documentation."""

from __future__ import annotations

from .capabilities.registry import list_descriptors


def availability(descriptor) -> str:
    if descriptor.lab_certified:
        return "Lab-certified live primitive"
    return "Uncertified: fixture/orchestration only; live use is unavailable"


def render_capability_reference() -> str:
    lines = [
        "# ADAF-RedTeam Capability Reference",
        "",
        "<!-- GENERATED: python scripts/generate_capability_reference.py -->",
        "",
        ("This reference is generated from `adaf_redteam/capabilities/registry.py`. "
         "`Executable` is a target authorization class, **not** proof of live availability."),
        "",
        "| Capability | Group | Target class | State changing | Required ATT&CK | Availability |",
        "|---|---|---|---|---|---|",
    ]
    for d in sorted(list_descriptors(), key=lambda item: item.capability_id):
        lines.append(
            f"| `{d.capability_id}` | {d.group} | {d.readiness} | "
            f"{'Yes' if d.state_changing else 'No'} | `{d.required_technique}` | {availability(d)} |")
    lines += [
        "",
        "## Stable operator error codes",
        "",
        "| Code range | Meaning |",
        "|---|---|",
        "| `ADAF-RT-E100`–`E109` | Engagement scope or safety gate refusal. Read the remediation printed with the error; do not bypass it. |",
        "| `ADAF-RT-E200` | Unknown capability. Use `list-capabilities` or this reference. |",
        "| `ADAF-RT-E201` | An executable result needs bridge correlation IDs. Supply `--finding-id` and `--control-id`. |",
        "| `ADAF-RT-E202` | Live collector is unavailable or not certified. Use a fixture or `--plan-only`. |",
        "| `ADAF-RT-E203` | A cleanup latch blocks a state-changing run. Verify recovery before manual clearance. |",
        "| `ADAF-RT-E204` | A required base runtime dependency is unavailable. Run `doctor` after installing project dependencies. |",
        "",
        "## Safe first use",
        "",
        ("Run `adaf-redteam doctor`, then `adaf-redteam list-capabilities`, then a committed-example `run --plan-only`. "
         "See the Windows and Linux novice guides for the platform-specific safe path."),
        "",
    ]
    return "\n".join(lines)

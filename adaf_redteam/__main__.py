"""ADAF-RedTeam CLI.

Commands:
  list-capabilities         Show the registry with readiness and technique.
  run --plan-only           Emit the exact plan for a capability. No side effects.
  run                       Execute (Phase 0: reports no adapter present).
"""

from __future__ import annotations

import argparse
import json
import sys

from .authz import GateError, authorize, load_engagement
from .capabilities.registry import get_descriptor, list_descriptors
from .evidence import write_plan


def _cmd_list(_args: argparse.Namespace) -> int:
    rows = list_descriptors()
    width = max(len(d.capability_id) for d in rows)
    print(f"{'CAPABILITY'.ljust(width)}  READINESS      TECH       FLAGS")
    for d in sorted(rows, key=lambda x: (x.group, x.capability_id)):
        flags = []
        if d.state_changing:
            flags.append("state-changing")
        if d.requires_detection_notification:
            flags.append("detection-notify")
        if d.adapter is None:
            flags.append("no-adapter")
        print(f"{d.capability_id.ljust(width)}  {d.readiness.ljust(13)}  {d.required_technique.ljust(9)}  {', '.join(flags)}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        descriptor = get_descriptor(args.capability)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    engagement = load_engagement(args.engagement)
    authz = engagement.capability_authz(args.capability) or {}
    target = args.target or (authz.get("targets") or [None])[0]
    if not target:
        print("error: no target given and none authorized in engagement", file=sys.stderr)
        return 2

    try:
        action = authorize(
            engagement,
            descriptor,
            target=target,
            source_address=args.source_address,
            plan_only=args.plan_only,
        )
    except GateError as exc:
        print(f"BLOCKED BY GATE: {exc}", file=sys.stderr)
        return 3

    if args.plan_only:
        plan = {
            "capabilityId": descriptor.capability_id,
            "title": descriptor.title,
            "readinessTarget": descriptor.readiness,
            "attackTechnique": action.technique,
            "target": action.target,
            "sourceAddress": action.source_address,
            "stateChanging": action.state_changing,
            "production": action.production,
            "maxActions": action.max_actions,
            "minIntervalMs": action.min_interval_ms,
            "wouldExecute": [
                "Phase 0: no adapter — this plan describes intent only.",
                "No network, authentication, KDC, mutation, or outbound activity performed.",
            ],
        }
        path = write_plan(plan, args.out)
        print(json.dumps(plan, indent=2))
        print(f"\nplan written: {path}")
        return 0

    if descriptor.adapter is None:
        print(
            f"NO EXECUTABLE ADAPTER: '{descriptor.capability_id}' is PlanOnly in this build "
            "(Phase 0). Re-run with --plan-only, or wait for the capability's adapter phase.",
            file=sys.stderr,
        )
        return 4

    # Unreachable in Phase 0; the adapter dispatch lands with the first capability.
    print("error: adapter dispatch not implemented in Phase 0", file=sys.stderr)
    return 4


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adaf-redteam", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list-capabilities", help="list the capability registry").set_defaults(func=_cmd_list)

    run = sub.add_parser("run", help="plan or execute a capability")
    run.add_argument("--engagement", required=True, help="path to engagement file")
    run.add_argument("--capability", required=True, help="capability id")
    run.add_argument("--source-address", required=True, help="this host's authorized source address")
    run.add_argument("--target", help="exact target (default: first authorized target)")
    run.add_argument("--plan-only", action="store_true", help="emit plan; perform no action")
    run.add_argument("--out", default="./out", help="output directory (default ./out)")
    run.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

"""ADAF-RedTeam CLI.

Commands:
  list-capabilities         Show the registry with readiness and technique.
  reference                 Print the generated capability reference to stdout.
  doctor                    Check local prerequisites without contacting a target.
  run --plan-only           Emit the exact plan for a capability. No side effects.
  run                       Execute an adapter-backed capability (or report none).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .capabilities.registry import get_descriptor, list_descriptors
from .evidence import write_manifest, write_plan
from .reference import availability, render_capability_reference

try:
    from .authz import GateError, authorize, load_engagement
    _AUTHZ_IMPORT_ERROR = None
except ImportError as exc:  # Let `doctor` explain a missing base dependency.
    GateError = Exception
    authorize = None
    load_engagement = None
    _AUTHZ_IMPORT_ERROR = exc


def _error(code: str, message: str, remedy: str) -> None:
    print(f"ERROR [{code}]: {message}\nREMEDY: {remedy}", file=sys.stderr)


def _decision_trace(descriptor, action) -> list[dict]:
    """Safe, non-secret explanation of the authorization decisions for a plan."""
    return [
        {"check": "capability-listed-and-approved", "passed": True},
        {"check": "source-address-authorized", "passed": True, "sourceAddress": action.source_address},
        {"check": "exact-target-authorized", "passed": True, "target": action.target},
        {"check": "attack-technique-authorized", "passed": True, "technique": action.technique},
        {"check": "execution-mode", "passed": True,
         "detail": "plan-only: no network, authentication, KDC, mutation, or outbound activity"},
        {"check": "live-availability", "passed": descriptor.lab_certified,
         "detail": availability(descriptor)},
    ]


def _cmd_list(_args: argparse.Namespace) -> int:
    rows = list_descriptors()
    width = max(len(d.capability_id) for d in rows)
    print(f"{'CAPABILITY'.ljust(width)}  TARGET CLASS   TECH       FLAGS  AVAILABILITY")
    for d in sorted(rows, key=lambda x: (x.group, x.capability_id)):
        flags = []
        if d.state_changing:
            flags.append("state-changing")
        if d.requires_detection_notification:
            flags.append("detection-notify")
        if d.adapter is None:
            flags.append("no-adapter")
        print(f"{d.capability_id.ljust(width)}  {d.readiness.ljust(13)}  {d.required_technique.ljust(9)}  "
              f"{', '.join(flags) or '-'}  {availability(d)}")
    return 0


def _cmd_reference(_args: argparse.Namespace) -> int:
    print(render_capability_reference(), end="")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    checks = []
    checks.append({"check": "python-version", "passed": sys.version_info >= (3, 10),
                   "detail": sys.version.split()[0]})
    try:
        import jsonschema  # noqa: F401
        checks.append({"check": "jsonschema-installed", "passed": True, "detail": "available"})
    except ImportError:
        checks.append({"check": "jsonschema-installed", "passed": False,
                       "detail": "run: python -m pip install -e '.[dev]'"})
    checks.append({"check": "project-metadata", "passed": Path("pyproject.toml").is_file(),
                   "detail": "pyproject.toml"})
    checks.append({"check": "example-engagement", "passed": Path("examples/engagement.example.json").is_file(),
                   "detail": "examples/engagement.example.json"})
    guides = (Path("docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md"),
              Path("docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md"))
    checks.append({"check": "novice-guides", "passed": all(path.is_file() for path in guides),
                   "detail": "both platform guides must be present"})
    out_dir = Path(args.out)
    output_parent = out_dir if out_dir.exists() else out_dir.parent
    checks.append({"check": "output-directory", "passed": output_parent.is_dir() and os.access(output_parent, os.W_OK),
                   "detail": str(out_dir)})
    doc = {"tool": "ADAF-RedTeam", "safe": True, "checks": checks,
           "next": "Run list-capabilities, then a committed-example --plan-only command. Do not remove --plan-only."}
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        print("ADAF-RedTeam doctor (no target contact)")
        for check in checks:
            print(f"{'PASS' if check['passed'] else 'FAIL'}  {check['check']}: {check['detail']}")
        print(doc["next"])
    return 0 if all(check["passed"] for check in checks) else 1


def _cmd_run(args: argparse.Namespace) -> int:
    if load_engagement is None or authorize is None:
        _error("ADAF-RT-E204", f"required runtime dependency is unavailable: {_AUTHZ_IMPORT_ERROR}",
               "Install the base project dependencies, then rerun 'adaf-redteam doctor'.")
        return 2
    try:
        descriptor = get_descriptor(args.capability)
    except KeyError:
        _error("ADAF-RT-E200", f"unknown capability '{args.capability}'",
               "Run 'adaf-redteam list-capabilities' and use an exact capability ID.")
        return 2

    engagement = load_engagement(args.engagement)
    authz = engagement.capability_authz(args.capability) or {}
    target = args.target or (authz.get("targets") or [None])[0]
    if not target:
        _error("ADAF-RT-E100", "no target was given and the engagement has no target for this capability",
               "Supply an exact authorized --target or ask the engagement owner to add one.")
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
        _error(exc.code, f"BLOCKED BY GATE: {exc}", exc.remedy)
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
            "hasAdapter": descriptor.adapter is not None,
            "labCertified": descriptor.lab_certified,
            "availability": availability(descriptor),
            "decisionTrace": _decision_trace(descriptor, action),
            "wouldExecute": [
                "Plan only — no network, authentication, KDC, mutation, or outbound activity.",
            ],
        }
        if descriptor.adapter is not None:
            from .redaction import SecretVault
            plan_domain = args.domain or (engagement.authorized_domains or [None])[0]
            with SecretVault() as _v:
                # plan() is contractually side-effect-free.
                plan["capabilityPlan"] = descriptor.adapter(action, _v, domain=plan_domain).plan()
        path = write_plan(plan, args.out)
        manifest = write_manifest(args.out, mode="plan-only", capability_id=descriptor.capability_id)
        print(json.dumps(plan, indent=2))
        print(f"\nplan written: {path}")
        print(f"safe output manifest: {manifest}")
        return 0

    if descriptor.adapter is None:
        _error("ADAF-RT-E202", f"'{descriptor.capability_id}' has no executable adapter",
               "Re-run with --plan-only, or wait for a certified adapter phase.")
        return 4

    return _dispatch_execute(args, engagement, descriptor, action, target)


def _dispatch_execute(args, engagement, descriptor, action, target) -> int:
    domain = args.domain or (engagement.authorized_domains or [None])[0]
    if not (args.finding_id and args.control_id):
        _error("ADAF-RT-E201", "--finding-id and --control-id are required to execute",
               "Supply the ADAF correlation identifiers, or use --plan-only.")
        return 2

    # Optional offline fixture source; live collector is only exercised when the
    # capability is lab-certified (or the operator explicitly opts in for cert dev).
    source = None
    if args.fixture:
        from .directory.fixture_source import FixtureDirectorySource
        source = FixtureDirectorySource.from_file(args.fixture)

    authz = engagement.capability_authz(descriptor.capability_id) or {}

    # State-changing capabilities: honor the cleanup latch, then verify containment.
    # Containment is the primary authorization control and must fire before the
    # lab-cert gate below — a misdeclared engagement should be refused with the
    # containment error, not a "not certified" message.
    containment = None
    if action.state_changing:
        from .containment import probe_domain
        from .statechange import is_latched
        if is_latched(args.out):
            _error("ADAF-RT-E203", "BLOCKED BY LATCH: a prior state-changing cleanup did not verify",
                   f"Verify cleanup before manually clearing the latch in {args.out}.")
            return 3
        probe = probe_domain(
            domain,
            engagement_declares_lab=authz.get("labContainmentRequired", False),
            lab_ranges=engagement.raw.get("labAddressRanges", []),
            lab_addresses=engagement.raw.get("labResolvedAddresses", []),
        )
        if not probe.verified:
            failed = [c["name"] for c in probe.checks if not c["passed"]]
            _error("ADAF-RT-E106", f"containment not verified for {domain} (failed: {', '.join(failed)})",
                   "Correct the lab declaration and independently verify the lab before retrying.")
            return 3
        containment = {"verified": True, "probeId": probe.probe_id, "environment": probe.environment}

    # Lab-certification gate: uncertified capabilities may not touch the network
    # unless the operator sets ADAF_RT_LAB=1 to acknowledge disposable-lab
    # certification-dev work (per docs/CERTIFICATION.md).
    import os as _os
    lab_dev_opt_in = _os.environ.get("ADAF_RT_LAB") == "1"
    if source is None and not descriptor.lab_certified and not lab_dev_opt_in:
        _error("ADAF-RT-E202",
               f"LIVE COLLECTOR NOT CERTIFIED: '{descriptor.capability_id}' has "
               "lab_certified=False and no --fixture was provided",
               "Provide --fixture to exercise the pipeline offline, use --plan-only, "
               "or set ADAF_RT_LAB=1 to acknowledge certification-dev work in a "
               "disposable lab (see docs/CERTIFICATION.md).")
        return 4

    if not descriptor.lab_certified:
        print(f"WARNING: '{descriptor.capability_id}' adapter is NOT lab-certified "
              "(lab_certified=False). Result is UNVALIDATED; certify in a disposable lab "
              "before relying on it.", file=sys.stderr)

    from .bridge import build_result, write_result
    from .redaction import SecretVault

    with SecretVault() as vault:
        cap = descriptor.adapter(action, vault, domain=domain, source=source)
        try:
            result = cap.execute()
        except (NotImplementedError, ImportError) as exc:
            _error("ADAF-RT-E202", f"LIVE COLLECTOR NOT CERTIFIED / UNAVAILABLE: {exc}",
                   "Provide --fixture to exercise the pipeline offline, or use --plan-only.")
            return 4
        if action.state_changing:
            result.cleanup = cap.cleanup()
        if not descriptor.lab_certified:
            result.assertions.insert(0, "UNVALIDATED: adapter not lab-certified; "
                                     "verify in a disposable lab before relying on this result.")
        doc = build_result(
            engagement_id=engagement.engagement_id,
            descriptor=descriptor,
            finding_id=args.finding_id,
            control_id=args.control_id,
            domain=domain,
            principal=action.target,
            result=result,
            readiness_used=descriptor.readiness,
            state_changing=action.state_changing,
            source_address=action.source_address,
            operator_contact=(engagement.raw.get("operatorContacts") or ["unknown"])[0],
            risk_ref=authz.get("riskAcceptanceReference"),
            containment=containment,
            budget={"actionsAuthorized": action.max_actions, "actionsUsed": 1,
                    "minIntervalMs": action.min_interval_ms},
        )
        # Persist the redacted transaction journal, if the capability kept one.
        journal = getattr(cap, "journal", None)
        if journal:
            from .evidence import write_journal
            write_journal(journal, args.out)
        # Latch the output dir if a state change was not verifiably cleaned up.
        if result.cleanup and not result.cleanup.get("verified", False):
            from .statechange import set_latch
            set_latch(args.out, "cleanup did not verify", capability_id=descriptor.capability_id,
                      target=action.target)
            print("LATCHED: cleanup did not verify; further state-changing runs in this "
                  "output dir are blocked until the latch is cleared.", file=sys.stderr)
        path = write_result(doc, args.out)
        manifest = write_manifest(args.out, mode="execute", capability_id=descriptor.capability_id)

    print(json.dumps(doc, indent=2))
    print(f"\nverdict: {doc['verdict']}  ({'LAB-CERTIFIED' if descriptor.lab_certified else 'UNVALIDATED'})")
    print(f"result written: {path}")
    print(f"safe output manifest: {manifest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adaf-redteam", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list-capabilities", help="list the capability registry").set_defaults(func=_cmd_list)
    sub.add_parser("reference", help="print the generated capability reference").set_defaults(func=_cmd_reference)
    doctor = sub.add_parser("doctor", help="check local prerequisites without contacting a target")
    doctor.add_argument("--out", default="./out", help="output directory to inspect (not created)")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable diagnostic output")
    doctor.set_defaults(func=_cmd_doctor)

    run = sub.add_parser("run", help="plan or execute a capability")
    run.add_argument("--engagement", required=True, help="path to engagement file")
    run.add_argument("--capability", required=True, help="capability id")
    run.add_argument("--source-address", required=True, help="this host's authorized source address")
    run.add_argument("--target", help="exact target (default: first authorized target)")
    run.add_argument("--plan-only", action="store_true", help="emit plan; perform no action")
    run.add_argument("--domain", help="authorized domain (default: engagement's first)")
    run.add_argument("--finding-id", help="ADAF FindingId to correlate (required to execute)")
    run.add_argument("--control-id", help="ADAF ControlId to correlate (required to execute)")
    run.add_argument("--fixture", help="offline ACE fixture JSON (bypasses the live collector)")
    run.add_argument("--out", default="./out", help="output directory (default ./out)")
    run.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

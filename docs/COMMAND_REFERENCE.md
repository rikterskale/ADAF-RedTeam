# Command Reference

This is the complete command-line reference for the current ADAF-RedTeam
release. All examples use `adaf-redteam`; `python -m adaf_redteam` is an
equivalent invocation after the package is installed. Run commands only under a
written, exact engagement. The current registry has no lab-certified live
primitive, so the safe supported paths are `doctor`, `list-capabilities`,
`reference`, `run --plan-only`, and approved offline fixture execution.

## Synopsis

```text
adaf-redteam [-h] {list-capabilities,reference,doctor,run} ...
```

`-h` or `--help` displays argparse help for the program or a subcommand. It
does not contact a target or write an output artifact.

| Command | Purpose | Target contact | Writes output |
|---|---|---:|---:|
| `list-capabilities` | Display the registered capability IDs, target classes, ATT&CK techniques, flags, and availability. | No | No |
| `reference` | Print the generated capability reference as Markdown to standard output. | No | No |
| `doctor` | Check local prerequisites and output-directory writability. | No | No |
| `run --plan-only` | Authorize then write an exact no-network plan and manifest. | No | Yes |
| `run --fixture` | Run an adapter against offline fixture data and emit a redacted, UNVALIDATED result. | No live collector | Yes |
| `run` without a fixture | Reserved for a certified live primitive or explicit certification-development work in a disposable lab. | Potentially | Yes |

`Executable` in the capability listing is a target authorization class, not a
claim that live execution is currently available. See
[CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) for the registry and
[CERTIFICATION.md](CERTIFICATION.md) for promotion requirements.

## `list-capabilities`

```text
adaf-redteam list-capabilities
```

Prints one row for each registry descriptor. The columns are:

| Column | Meaning |
|---|---|
| `CAPABILITY` | Exact value accepted by `run --capability`. |
| `TARGET CLASS` | `Executable` or `LabExecutable` authorization class. |
| `TECH` | ATT&CK technique that must exactly match the engagement entry. |
| `FLAGS` | `state-changing`, `detection-notify`, or `no-adapter` where applicable. |
| `AVAILABILITY` | Whether the live primitive is lab-certified. All current entries are uncertified. |

Use the exact ID printed here; an unknown ID returns `ADAF-RT-E200`.

## `reference`

```text
adaf-redteam reference
```

Prints the same generated capability data maintained in
`docs/CAPABILITY_REFERENCE.md`, including stable operator error-code summaries.
Redirecting standard output is optional and is an operator-local action; it does
not produce a tool-managed evidence artifact.

## `doctor`

```text
adaf-redteam doctor [--out OUTPUT_DIRECTORY] [--json]
```

`doctor` is always local and safe. It checks Python version, `jsonschema`,
`pyproject.toml`, the committed example engagement, novice-guide presence, and
whether the parent of the requested output location is writable. It does not
create the output directory.

| Option | Default | Meaning |
|---|---|---|
| `--out OUTPUT_DIRECTORY` | `./out` | Output location to inspect for writability. |
| `--json` | Off | Emit the diagnostic document as JSON instead of human-readable lines. |

Exit status is `0` only when every check passes; it is `1` when one or more
checks fail. A missing base dependency is typically reported as a failed
`jsonschema-installed` check. Use the project installation process rather than
disabling validation.

## `run`

```text
adaf-redteam run --engagement FILE --capability ID --source-address ADDRESS \
  [--target TARGET] [--plan-only] [--domain DOMAIN] \
  [--finding-id FINDING_ID --control-id CONTROL_ID] [--fixture FILE] [--out DIRECTORY]
```

Three arguments are required in every mode:

| Option | Required | Meaning |
|---|---:|---|
| `--engagement FILE` | Yes | Path to the schema-valid engagement JSON. It must contain authorization for the exact capability. |
| `--capability ID` | Yes | Exact ID from `list-capabilities` or the capability reference. |
| `--source-address ADDRESS` | Yes | The operator host's exact authorized source address. |

The remaining options are:

| Option | Default | Meaning |
|---|---|---|
| `--target TARGET` | First authorized target for the capability | Exact target. If omitted, the first target in the matching engagement entry is used. It must still be authorized exactly. |
| `--plan-only` | Off | Writes a no-network plan and does not run an adapter's `execute()` method. This is the required first execution mode. |
| `--domain DOMAIN` | First `authorizedDomains` entry | Domain recorded in the plan or result and supplied to the adapter. |
| `--finding-id FINDING_ID` | None | ADAF correlation ID. Required for non-plan execution; must match `F-` followed by 16 uppercase hexadecimal characters for a result to validate. |
| `--control-id CONTROL_ID` | None | ADAF correlation ID. Required for non-plan execution; must match the result schema's `ADAF-` identifier pattern. |
| `--fixture FILE` | None | Offline directory/ACE fixture JSON. It bypasses the live collector but does not bypass authorization, containment, cleanup, or output safeguards. |
| `--out DIRECTORY` | `./out` | Directory for tool-managed evidence artifacts. Use a fresh, approved directory per run. |

### Plan-only mode

```text
adaf-redteam run --engagement examples/engagement.example.json \
  --capability adcs-esc1-validation --source-address 192.0.2.25 \
  --plan-only --out ./out
```

Plan-only first loads the engagement and checks the capability, approval flag,
source address, exact target, and ATT&CK technique. It then writes:

| Artifact | Contents |
|---|---|
| `plan.json` | Timestamped redacted plan, including selected target, action budget, availability, decision trace, and adapter plan. |
| `manifest.json` | Redacted inventory of known artifacts with sizes and SHA-256 checksums. |

The plan decision trace explicitly records that there is no network,
authentication, KDC, mutation, or outbound activity. A successful plan is not
evidence that the target is safe to contact, containment is verified, or the
capability is certified.

### Offline fixture mode

```text
adaf-redteam run --engagement APPROVED_ENGAGEMENT.json \
  --capability APPROVED_CAPABILITY --source-address APPROVED_SOURCE_ADDRESS \
  --finding-id F-0123456789ABCDEF --control-id ADAF-EXAMPLE \
  --fixture OFFLINE_FIXTURE.json --out ./approved-output
```

Replace every uppercase placeholder only with engagement-approved values. A
fixture run exercises result construction and redaction without invoking a live
collector. It may write `validation-result.json`, `manifest.json`, and a
state-changing adapter's `transaction-journal.jsonl`. Results remain
**UNVALIDATED** until the exact capability is promoted through certification.

For state-changing descriptors, a fixture run still enforces the explicit
state-change approval, risk acceptance, cleanup requirement, containment
declaration, and cleanup-latch checks. A failed or unverified cleanup creates
`.state-change-latch`; see [STATE_CHANGE_RECOVERY.md](STATE_CHANGE_RECOVERY.md).

### Live and certification-development boundary

Without `--fixture`, an uncertified descriptor is refused with `ADAF-RT-E202`.
`ADAF_RT_LAB=1` is an explicit certification-development opt-in for a disposable
lab; it is not an operating shortcut and must not be set for routine use. It does
not bypass engagement authorization, containment, cleanup, or redaction. Follow
[CERTIFICATION.md](CERTIFICATION.md) rather than attempting a live command from
this reference.

## Authorization and exit statuses

`run` produces an error message and remedy on standard error for a controlled
refusal. The common return statuses are:

| Exit status | Meaning |
|---:|---|
| `0` | Command completed successfully. A non-plan fixture result can still be UNVALIDATED. |
| `2` | Invalid command input, missing correlation ID, unknown capability, missing target, or unavailable base dependency. |
| `3` | Authorization, scope, containment, or cleanup-latch gate refused the run. |
| `4` | Adapter has no executable path or the live collector is unavailable or uncertified. |
| argparse-defined nonzero | Invalid command-line syntax or missing required command arguments. |

Stable error IDs give the more precise reason:

| Code | Refusal |
|---|---|
| `ADAF-RT-E100` | Capability is not listed in the engagement, or no target can be selected. |
| `ADAF-RT-E101` | Capability is present but not approved. |
| `ADAF-RT-E102` | Source address is not authorized. |
| `ADAF-RT-E103` | Target is not in the exact approved target list. |
| `ADAF-RT-E104` | Engagement technique does not match the capability's required technique. |
| `ADAF-RT-E105` | State-changing capability lacks explicit state-change approval. |
| `ADAF-RT-E106` | Required state-change control or containment verification failed. |
| `ADAF-RT-E107` | State-changing risk-acceptance reference is missing. |
| `ADAF-RT-E108` | Purple-team notification instruction is missing. |
| `ADAF-RT-E109` | State-changing work lacks required lab-containment protection. |
| `ADAF-RT-E200` | Capability ID is unknown. |
| `ADAF-RT-E201` | Non-plan execution lacks ADAF correlation IDs. |
| `ADAF-RT-E202` | Live collector or executable adapter is unavailable or uncertified. |
| `ADAF-RT-E203` | Output directory is latched after unverified state-changing cleanup. |
| `ADAF-RT-E204` | Required base runtime dependency is unavailable. |

Correct the written authorization or environment with its owner; do not change
scope merely to make a command pass.

## ADAF bridge command

The bridge is a separate, standard-library-plus-`jsonschema` script intended to
run with the ADAF result store:

```text
python bridge/adaf_ingest.py --result VALIDATION_RESULT.json --adaf-run ADAF_RUN_DIRECTORY
```

| Option | Required | Meaning |
|---|---:|---|
| `--result VALIDATION_RESULT.json` | Yes | Redacted result produced by a non-plan run. |
| `--adaf-run ADAF_RUN_DIRECTORY` | Yes | ADAF run directory that contains a matching `findings.csv`. |

The bridge validates the result schema, refuses known secret-shaped keys, finds
the correlated finding, and appends a record to `validation-linkage.json` in the
ADAF run directory. Its exit statuses are `2` for a missing dependency, `3` for
a schema failure, `4` for forbidden secret-shaped keys, and `5` when the finding
cannot be found. A successful repeat appends another linkage record; check for
an existing `resultId` before retrying. See
[ADAF_BRIDGE_INTEGRATION.md](ADAF_BRIDGE_INTEGRATION.md) for review and handoff
requirements.

## Command safety checklist

Before a `run` command, verify the written ROE, exact source and target,
capability/technique match, output directory, stop conditions, and current
certification status. For a state-changing descriptor, also verify disposable-lab
addresses, risk acceptance, cleanup owner, recovery process, and blue-team
notification where required. Start with plan-only and preserve the plan for
review.

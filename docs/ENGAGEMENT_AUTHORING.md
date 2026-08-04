# Engagement Authoring Guide

An engagement file is the runtime scope for one ADAF-RedTeam engagement. It is
not a substitute for a signed rules of engagement (ROE), customer approval, or
operator judgment. A schema-valid file only proves the file is internally well
formed; the authorization gate cannot verify the underlying agreement.

Start from [examples/engagement.example.json](../examples/engagement.example.json).
Keep real engagement files outside the repository: `.gitignore` excludes
`engagement*.json` to reduce accidental disclosure.

## Authoring principles

- Use exact capability IDs from [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md).
- Use exact targets. Wildcards are rejected; do not simulate them with broad lists.
- Match the capability's required ATT&CK technique exactly.
- Treat `--plan-only` as a review artifact, not proof that live execution is
  approved, available, or safe.
- State-changing work is disposable-lab-only. A production authorization flag
  never makes a state-changing capability eligible for production work.
- Never put passwords, hashes, tickets, keys, PFX files, or other secrets in an
  engagement file.

## File-level fields

| Field | Required | What to provide |
|---|---:|---|
| `schemaVersion` | Yes | Exactly `"1.0"`. |
| `engagementId` | Yes | A stable ID matching `ENG-` followed by uppercase letters, digits, or hyphens. |
| `customer` | No | A non-secret customer or lab label. |
| `authorizedDomains` | Yes | One or more domains covered by the written ROE. The CLI uses the first unless `--domain` is supplied. |
| `authorizedSourceAddresses` | Yes | Exact approved operator-host source addresses. `--source-address` must match one exactly. |
| `windowStartUtc`, `windowEndUtc` | Yes | UTC RFC 3339 timestamps. Confirm the timezone conversion with the engagement owner. |
| `operatorContacts` | Yes | Responsible contacts suitable for the result record. |
| `stopConditions` | Yes | Concrete stop triggers, such as customer direction or observed production impact. |
| `prohibitedActions` | No | ROE context for review. The gate does not interpret free-text exclusions. |
| `labAddressRanges` | Conditional | Disposable-lab CIDR ranges; required for a state-changing execution. |
| `labResolvedAddresses` | Conditional | Every in-scope lab-host IP; every address must be inside a declared CIDR. |
| `capabilities` | Yes | Map of exact capability IDs to their per-capability authorization. |

The containment probe validates the internal consistency of declared lab ranges
and addresses, and fails closed when a declaration is missing or out of range.
Its live DNS cross-check is not implemented. An independent infrastructure
review of the actual lab boundary is still required before state-changing work.

## Per-capability authorization

Every capability entry requires these fields.

| Field | Required | Gate behavior |
|---|---:|---|
| `approved` | Yes | Must be `true`; otherwise `ADAF-RT-E101` is returned. |
| `targets` | Yes | Exact targets. The requested target must be present exactly. |
| `attackTechnique` | Yes | Must equal the capability's reference technique. |
| `maximumActions` | Yes | Positive approved budget, recorded in output. |
| `minimumIntervalMilliseconds` | No | Non-negative pacing value; set it explicitly when the ROE requires pacing. |
| `timeoutMilliseconds` | No | Positive timeout statement for the engagement. Retain it as ROE control even where an adapter does not yet consume it. |
| `productionAuthorized` | No | Applies only to non-state-changing capability classes. |

For a registry entry marked state changing, non-plan execution also requires all
of the following to be present and true:

| Field | Purpose |
|---|---|
| `stateChangingApproved` | Explicitly approves this state-changing class. |
| `riskAccepted` | Records explicit risk acceptance. |
| `riskAcceptanceReference` | Identifies the approval or ticket accepting the risk. |
| `cleanupRequired` | Requires verified cleanup; it does not promise cleanup will succeed. |
| `labContainmentRequired` | Declares work is restricted to a disposable lab. |

Purple-team capabilities also require a non-empty `detectionNotification` with
the ROE-defined coordination instruction. The tool records detection evidence;
it is not a mechanism for silently modifying security controls.

## Safe authoring workflow

1. Obtain the written ROE, named owner, exact targets, time window, and stop
   conditions before creating the file.
2. Copy the committed example to protected operator-controlled storage.
3. Add only currently approved capability entries. Do not retain broad or
   previously approved scope "just in case."
4. Compare every ID and technique against the generated reference.
5. For state-changing work, require a second reviewer to verify lab CIDRs, all
   listed addresses, the recovery owner, durable-residue handling, and risk
   acceptance reference.
6. Run `--plan-only`, review `plan.json`, and preserve the approved plan. The
   plan makes no target contact.
7. Store the approved file under the engagement evidence policy; never commit it.

## Review checklist and refusals

Confirm the ID, contacts, time window, source address, exact targets, technique,
action budget, pacing, and stop conditions match the ROE. For state-changing
work, confirm all five required controls, a named recovery owner, and a complete
lab declaration. For purple-team work, confirm blue-team notification.

`ADAF-RT-E100` through `E109` are safety or authorization refusals. Correct the
written authorization with its owner; do not change values merely to make a
command pass. `E102`, `E103`, and `E104` identify an unapproved source, target,
or technique. `E105` through `E109` identify missing state-change, containment,
risk, or notification controls.

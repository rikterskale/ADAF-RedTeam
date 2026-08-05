# Operator Lifecycle Guide

This guide connects the CLI, schemas, evidence writers, containment guard,
cleanup latch, and ADAF bridge into a safe operating lifecycle. It does not turn
an engagement into permission: only written authorization does that.

## Roles and handoffs

| Role | Accountable for |
|---|---|
| Engagement owner | Written scope, exact targets, window, risk acceptance, stop conditions, and recovery authority. |
| Operator | Uses only the approved engagement and source host; stops and escalates on any refusal or impact. |
| Recovery owner | Independently verifies restoration after state-changing work. |
| Blue-team contact | Receives ROE notification and preserves detection evidence for purple-team work. |
| ADAF owner | Confirms correlation and decides how evidence affects the ADAF finding. |
| Certification owner/reviewer | Prove each live primitive is bounded before promotion. |

## Lifecycle

### 1. Authorize and prepare

Collect the signed ROE, exact source address and targets, technique, time window,
budget, and stop conditions. State-changing work also requires risk acceptance,
cleanup requirements, lab CIDRs and host addresses, a recovery owner, and any
blue-team notification. Create the engagement using
[ENGAGEMENT_AUTHORING.md](ENGAGEMENT_AUTHORING.md), then protect it as evidence.

### 2. Local preflight

On the approved operator host, run `adaf-redteam doctor`, then
`adaf-redteam list-capabilities`. Doctor checks local dependencies, project
metadata, the example, platform guides, and output-directory writability without
contacting a target. Correct local failures through the approved process; do not
weaken the engagement or validation to compensate.

### 3. Plan review

Run the approved capability with `--plan-only` and a dedicated output directory.
Plan-only validates capability, source, target, and technique but makes no
network, authentication, KDC, mutation, or outbound activity. Review `plan.json`
for target, state-change flag, budget, and decision trace; retain `manifest.json`
as the redacted inventory. A plan does not certify a live primitive or prove lab
containment.

### 4. Offline pipeline validation

Where an approved fixture exists, `--fixture` exercises the adapter pipeline
without a live collector. It is useful for authorization, result construction,
redaction, and evidence handling. It is not a live test: results are
**UNVALIDATED** while `lab_certified=False`. Non-plan execution also requires
`--finding-id` and `--control-id`. Use a unique output directory for every run.

### 5. Certification boundary

Do not move from plans or fixtures to live work until the exact capability is
certified under [CERTIFICATION.md](CERTIFICATION.md). Certification is per
capability and does not transfer to a related operation or environment. The
current release has no lab-certified live primitive. Future certification does
not remove the engagement gate, containment check, recorded action budget,
redaction vault, cleanup process, or stop-condition obligation. The dispatcher
does not enforce the recorded action budget or pacing; certification evidence must
demonstrate any capability-specific bounds.

### 6. Execute, observe, and stop

Operate only within scope and the independently verified approved window. The
runtime does not compare the current time with the engagement window. Treat any
gate refusal as stop-and-correct, not an obstacle. Pause on a stop condition, unexpected behavior, suspected
production contact, redaction concern, or cleanup concern. Preserve artifacts
and notify the engagement owner. Purple-team work must follow its notification
plan and preserve truthful detection evidence.

### 7. Validate outputs and recover

Review `validation-result.json` for authorized target, technique, verdict,
redacted proof, authorization, budget, and, where applicable, containment and
cleanup. `manifest.json` inventories known artifacts; state-changing adapters may
write a transaction journal. If cleanup is unverified or a latch appears, stop
and follow [STATE_CHANGE_RECOVERY.md](STATE_CHANGE_RECOVERY.md). Never bypass a
latch by changing output directories.

### 8. Hand off to ADAF and close

Only redacted `validation-result.json` crosses into ADAF. Follow
[ADAF_BRIDGE_INTEGRATION.md](ADAF_BRIDGE_INTEGRATION.md) to review it, link it to
the correct finding, and avoid duplicates. Close by documenting recovery status,
durable residue, delivered results, and evidence retention; do not delete
customer evidence merely to clean a workspace.

## Output map

| Artifact | Meaning |
|---|---|
| `plan.json` | Redacted no-network execution plan. |
| `validation-result.json` | Only result intended to cross to ADAF. |
| `transaction-journal.jsonl` | Redacted activity and cleanup evidence, when present. |
| `manifest.json` | Redacted inventory of known artifact names, sizes, and checksums. |
| `.state-change-latch` | Local block on later state-changing runs after unverified cleanup. |
| `validation-linkage.json` | ADAF-side linkage list; it requires duplicate review. |

Escalate without retrying when a safety gate refuses work, cleanup cannot be
verified, evidence may contain a secret, a result cannot be correlated, a stop
condition is met, or unexpected production impact is suspected.

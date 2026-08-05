# Certification Standard and Maintainer Checklist

This technical reference is for certification owners, lab administrators, and
independent reviewers. It does not teach a novice to run a lab test.

For the only novice workflow, use the
[First Certification Session](guides/CERTIFICATION_NOVICE_COACH_PLAYBOOK.md).
That guide is Windows PowerShell only, coach-monitored, and starts with
`asrep-roast-validation`.

The authoritative policy is [CERTIFICATION.md](CERTIFICATION.md). This checklist
organizes decisions but never relaxes authorization, containment, cleanup, or
redaction controls.

## Core rule

Promote one capability only after its disposable-lab live primitive is proven
bounded, correctly redacted, and independently reviewed. Until then,
`lab_certified=False` is correct and expected. Certification is never production
authorization.

## Roles

| Role | Required action |
|---|---|
| Certification owner | Coordinates validation, assembles evidence, and owns the ticket and PR. |
| Coach / lab administrator | Prepares the isolated lab and lab objects; may also be owner. |
| Independent reviewer | Did not write the primitive; verifies evidence, live bounds, tests, and sign-off. |
| Second approver | Required for Tier E destructive certification. |

The reviewer must not be the certification owner.

## Preconditions

All must be true:

- Lab is isolated from production, has no shared trust, and can be restored or rebuilt.
- Written engagement authorizes the exact capability, targets, source, and lab containment addresses.
- Ticket names owner and independent reviewer.
- Capability has a reviewed evidence template.
- Offline tests are green before a live test.
- Zerologon work has capture and verification of no password-set call.

If any prerequisite fails, stop. Do not weaken a gate or substitute a
non-disposable environment.

## GOAD acceptance gate

GOAD may supply the disposable Tier A lab, but its intentional vulnerabilities
are not certification evidence. The certification owner records the GOAD
revision, provider, actual AD DNS root, VM inventory, isolated network design,
and clean snapshot/rebuild identifier in the ticket.

Use [GOAD Certification Profile](GOAD_CERTIFICATION_PROFILE.md) to create
dedicated `ADAF-Cert-*` fixtures. Do not use pre-existing GOAD training accounts
for positive or negative assertions: unrelated vulnerabilities make the result
ambiguous. The profile's base objects are suitable for AS-REP, Kerberoast, gMSA,
and inventory setup. Its DCSync and LAPS ACL flags require a separate snapshot,
explicit review, and evidence of the exact ACL change.

Before a live run, the reviewer confirms:

1. The actual GOAD domain equals the profile script's `-ExpectedDomain` value.
2. The `ADAF-Cert-*` object names, SIDs, DNs, and SPN were independently checked.
3. The generated profile contains no secret and reviewed values—not the generated file itself—populate `.env.lab.ps1`.
4. Expected verdicts are set per capability; a GOAD vulnerability alone never establishes `Confirmed`.
5. Zerologon has no profile mutation; its verdict and zero-password-set proof come from the captured run.

The profile is limited to Tier A. It does not authorize or prepare Tier B–E
state-changing work.

## Certification tiers

| Tier | Scope | Additional proof |
|---|---|---|
| A | Read/metadata | No state change and no secret export; wire/audit evidence as appropriate. |
| B | Reversible write | Exact restoration and forced-failure cleanup latch. |
| C | Durable change | Honest durable residue, revocation proof, and lab rebuild plan. |
| D | Purple team/evasion | Blue-team telemetry matches the detection block; restored defenses. |
| E | Destructive | Reset-then-restore, lab rebuild, containment refusal outside lab, and two-person approval. |

Use [CERTIFICATION.md](CERTIFICATION.md) for complete tier requirements.

## Tier A capability map

| Capability | Lab test | Evidence template |
|---|---|---|
| `asrep-roast-validation` | `tests/test_certification_asrep_roast.py` | `docs/certifications/asrep-roast-validation.md` |
| `kerberoast-validation` | `tests/test_certification_kerberoast.py` | `docs/certifications/kerberoast-validation.md` |
| `dcsync-rights-validation` | `tests/test_certification_dcsync_rights.py` | `docs/certifications/dcsync-rights-validation.md` |
| `zerologon-detection` | `tests/test_certification_zerologon.py` | `docs/certifications/zerologon-detection.md` |
| `laps-read-authorization` | `tests/test_certification_laps_read.py` | `docs/certifications/laps-read-authorization.md` |
| `gmsa-read-authorization` | `tests/test_certification_gmsa_read.py` | `docs/certifications/gmsa-read-authorization.md` |

`machine-account-quota-check` and `privileged-group-inventory` are not eligible
for novice certification until reviewed evidence templates exist.

## Evidence and review gate

Each package contains:

1. Redacted engagement and containment record, including refusal outside lab.
2. Tier-appropriate attestation: read-only for A; before/after state for B/C/E.
3. Clean redaction-scan result.
4. `validation-result.json` and any transaction journal.
5. Green offline-test record and matching lab-test record.
6. Required tier evidence: cleanup latch, blue-team telemetry, or packet capture.
7. Owner/reviewer sign-off; second approver for Tier E.

The reviewer verifies that observed behavior matches `plan()`, is bounded, and
makes no extra requests or state changes. Evidence gaps, redaction matches,
unexplained latch behavior, or reviewer/owner overlap block promotion.

## Promotion PR — maintainer only

After sign-off, create one PR for one capability:

1. Set only that descriptor's `lab_certified=True` in `adaf_redteam/capabilities/registry.py`.
2. Update its certification test's pre-promotion `UNVALIDATED` expectation.
3. Commit the completed redacted evidence template and reference ticket, owner, reviewer, and evidence in the PR.
4. Confirm offline CI is green, obtain review, then merge.

Never bulk-promote. The novice operator does not perform these steps.

## De-certification

Set the affected capability back to `lab_certified=False` when its live
primitive, bounds, `plan()`, cleanup behavior, dependencies, or lab
representativeness changes; when restoration is unexplained; or when a redaction
leak is found. Preserve evidence and re-certify after resolving the issue.

## Related documents

| Need | Document |
|---|---|
| Authoritative policy and tier detail | [CERTIFICATION.md](CERTIFICATION.md) |
| Coach-and-operator execution | [First Certification Session](guides/CERTIFICATION_NOVICE_COACH_PLAYBOOK.md) |
| Dedicated GOAD Tier A fixture objects | [GOAD Certification Profile](GOAD_CERTIFICATION_PROFILE.md) |
| Test inventory/run order | [CERTIFICATION_RUNBOOK.md](CERTIFICATION_RUNBOOK.md) |
| Capability-specific evidence | [certifications/](certifications/) |

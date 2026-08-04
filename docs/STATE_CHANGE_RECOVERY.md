# State-Change Recovery Runbook

Use this runbook when a state-changing capability reports cleanup as unverified,
when the CLI reports `ADAF-RT-E203`, or when an output directory contains
`.state-change-latch`. The latch is a safety control, not a transient error. It
blocks later state-changing runs in that output directory until recovery is
verified.

## Immediate response

1. Stop state-changing activity. Do not retry into a different output directory
   to bypass the latch.
2. Notify the engagement owner and named recovery owner. For purple-team work,
   notify the blue-team contact in `detectionNotification`.
3. Preserve the output directory, including `validation-result.json`, any
   `transaction-journal.jsonl`, `manifest.json`, and `.state-change-latch`.
   Do not edit these files in place.
4. Record time, target, capability, operator host, observed impact, and
   risk-acceptance reference in the engagement record.
5. Use the customer-approved recovery procedure. Tool artifacts are evidence
   aids, not authority to change systems outside the ROE.

## Understand the latch

The latch is `<out>/.state-change-latch`. It records its time, reason,
capability, target, and the instruction that manual operator action is required
after cleanup verification. Removing it before recovery only removes a local
guard; it does not prove the target was restored. Preserve a copy of the
original output before recovery. The manifest inventories known artifacts and
their checksums when it was written.

## Recovery decision path

| Situation | Required action | Exit criterion |
|---|---|---|
| Restore was attempted but verification is inconclusive | Independently inspect target state with the approved customer procedure; retain failed-run evidence. | A qualified reviewer can show the original state is restored. |
| A reversible change remains | Restore only the explicitly recorded original state under the ROE and recovery owner. | Before/after evidence shows the controlled change is absent and the original state is present. |
| Durable AD CS residue exists | Complete reversible cleanup, document residue, and rebuild or reset the disposable lab as required. | Revocation is verified and the rebuild plan is completed or owned. |
| Destructive or infrastructure impact is suspected | Escalate to customer incident and infrastructure owners; do not improvise a retry. | Customer recovery owner confirms directory and service health. |
| Output files are incomplete | Treat status as unknown and obtain target-side evidence. | Recovery owner supplies independent restoration evidence. |

## Verification focus

| Change family | Verify before any latch clear |
|---|---|
| RBCD | Target attribute equals its captured original value and no controlled delegation remains. |
| Shadow credentials and relay shadow credentials | Controlled key credential was removed and generated credential material is unavailable. |
| Temporary service proof | Temporary service is absent and no marker process or persistence remains. |
| Coercion/listener work | Listener stopped, no relay path remains, and no unintended destination changed. |
| AD CS enrollment | Certificate revoked as planned, residue documented, and lab teardown/rebuild owned. |
| Purple-team activity | Temporarily affected protections restored and detection evidence preserved. |
| Zerologon reset scaffold | Do not infer recovery from a plan or fixture; any future live incident needs customer-owned DC health verification. |

## Clearing the latch

There is intentionally no CLI command that clears a latch. The internal helper
only removes the local marker and cannot inspect the target. Clear one only after
the engagement or delegated recovery owner has approved closure, target
restoration is independently verified, durable residue is documented, required
stakeholders are notified, and the original evidence is retained.

Record the manual marker-clear action as an auditable event: who performed it,
when, why recovery was complete, and where supporting evidence is stored. If any
condition is unmet, leave the latch and escalate. A cleanup failure is also a
certification signal; apply the de-certification rules in
[CERTIFICATION.md](CERTIFICATION.md) when it changes expected bounds or restore
behavior.

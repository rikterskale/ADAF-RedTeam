# ADAF Bridge Integration Guide

The ADAF bridge transfers only a redacted `validation-result.json` from
ADAF-RedTeam into an ADAF run. It does not import executable code, credentials,
tickets, hashes, private keys, or raw protocol output. The standalone helper is
[bridge/adaf_ingest.py](../bridge/adaf_ingest.py).

## Preconditions

- The result came from an approved engagement and is retained under its evidence
  policy.
- The result includes the ADAF `FindingId` and `ControlId` supplied at execution.
- The target ADAF run contains a `findings.csv` with that `FindingId`.
- `jsonschema` is installed where the helper will run.
- The operator is authorized to write `validation-linkage.json` in the ADAF run.

Do not ingest a plan: `plan.json` is a review artifact, not a validation result.
Do not ingest a result from an unapproved target or one with unresolved cleanup.

## Result contract and safety checks

The bridge contract is [validation-result.schema.json](../schemas/validation-result.schema.json).
It includes a verdict, capability and ATT&CK identifiers, scoped target,
redacted proof assertions, authorization context, and integrity hash.
State-changing results also require containment and cleanup data. Opaque redacted
handles and safe metadata such as hashes, counts, names, or last-four values are
allowed; secret values are not.

The helper validates the schema, refuses known secret-shaped field names anywhere
in the document, and confirms that the correlated finding appears in a
`findings.csv` below the supplied ADAF run directory. These checks are important
but not complete evidence verification. The current helper does **not** recompute
`integrity.resultSha256`, verify a signature, validate an engagement signature,
or decide whether an UNVALIDATED result is certified. Review those facts in the
engagement record before ingesting.

## Procedure

From an environment with `jsonschema`, provide the result and ADAF run path:

```bash
python bridge/adaf_ingest.py --result /approved/path/validation-result.json --adaf-run /approved/path/ADAF-Run
```

The helper writes `<ADAF-Run>/validation-linkage.json`. A successful linkage
contains the finding and control IDs, result ID, verdict, proof class, readiness,
state-change flag, engagement ID, and result SHA-256. It sets
`confidenceUpgrade: "HIGH"` only when the result verdict is `Confirmed`.

After success, verify that the linkage identifies the expected finding, result,
and engagement. Retain the original redacted result where the evidence policy
requires it.

## Important operational behavior

- **Append-only, not idempotent:** every successful invocation appends a record.
  Check for the `resultId` before retrying, or the linkage list will contain a
  duplicate.
- **Whole-file write:** the helper reads the existing JSON list, appends one item,
  then writes the complete list. Back up or coordinate access if multiple
  operators may ingest concurrently.
- **Defense in depth:** a document with an allowed-shaped but sensitive value is
  not automatically safe. Redaction review and engagement controls remain primary.
- **No confidence override:** ADAF owners remain responsible for their evidence
  and risk decisions; the linkage value is not a remediation decision.

## Troubleshooting and handoff

| Outcome | Meaning and next action |
|---|---|
| `error: pip install jsonschema` | The bridge environment lacks its dependency. Use the approved package process, then retry. |
| `SCHEMA ERROR ...` | The result violates the contract. Preserve it and investigate the producer; do not hand-edit it to force ingestion. |
| `REFUSED: result contains forbidden secret-shaped keys` | Stop distribution, preserve the result securely, and follow the security process. |
| `REFUSED: finding ... not found` | Wrong ADAF run or finding ID. Verify both with the engagement owner. |
| Duplicate linkage | The helper has no deduplication. Correct it through the ADAF evidence-management process. |

Before handoff, match the finding, control, capability, domain, and engagement
IDs to the approved record. Confirm whether the result is `UNVALIDATED`; all
current capabilities are uncertified for live use. For state-changing work,
confirm verified containment and cleanup and understand any durable residue.
Finally, confirm redaction review and record the bridge outcome under the
engagement retention policy.

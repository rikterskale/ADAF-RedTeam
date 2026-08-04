# Capability Runbooks

This catalog translates the generated [capability reference](CAPABILITY_REFERENCE.md)
into operator boundaries. It intentionally is not a collection of exploit
instructions. The safe sequence for every capability is written authorization,
engagement review, plan review, offline fixture where appropriate, and live
certification before any live use.

## Current operating status

All 27 registered capabilities are adapter-backed and all currently have
`lab_certified=False`. Therefore, **no capability is currently available for live
use**. `--fixture` exercises orchestration with offline input and produces an
**UNVALIDATED** result. `--plan-only` produces a no-network review artifact.
`Executable` means a read/metadata target class after certification; it does not
mean a live primitive is available today.

Every run needs the exact capability, source address, target, and ATT&CK
technique in the engagement. Non-plan execution also needs `--finding-id` and
`--control-id` for ADAF correlation. State-changing entries require verified lab
containment and the additional approvals described in
[ENGAGEMENT_AUTHORING.md](ENGAGEMENT_AUTHORING.md).

## Catalog

| Capability | Target / change class | Intended redacted proof | Current safe path |
|---|---|---|---|
| `dcsync-rights-validation` | Executable / Read-metadata | Named principal's replication rights; no replication or hash extraction. | Plan or offline fixture. |
| `gmsa-read-authorization` | Executable / Read-metadata | Managed-password read authorization; never the password. | Plan or offline fixture. |
| `laps-read-authorization` | Executable / Read-metadata | LAPS attribute read authorization; never the LAPS value. | Plan or offline fixture. |
| `ntds-dpapi-read-proof` | LabExecutable / Read proof | Readability proof without exporting NTDS or DPAPI material. | Plan or offline fixture under approved lab scope. |
| `acl-write-rights-inventory` | Executable / Read-metadata | Object takeover-relevant ACL rights. | Plan or offline fixture. |
| `privileged-group-inventory` | Executable / Read-metadata | Transitive privileged-group membership facts. | Plan or offline fixture. |
| `trust-inventory` | Executable / Read-metadata | Trust relationships and SID-filter status. | Plan or offline fixture. |
| `sidhistory-inventory` | Executable / Read-metadata | Accounts with non-empty `sIDHistory`. | Plan or offline fixture. |
| `machine-account-quota-check` | Executable / Read-metadata | Configured machine-account quota. | Plan or offline fixture. |
| `asrep-roast-validation` | Executable / Read-metadata | Roastability and encryption metadata; no AS-REP blob export. | Plan or offline fixture. |
| `kerberoast-validation` | Executable / Read-metadata | Service roastability and encryption metadata; no TGS blob export. | Plan or offline fixture. |
| `delegation-rights-validation` | Executable / Read-metadata | Delegation configuration metadata. | Plan or offline fixture. |
| `delegation-s4u2proxy-proof` | LabExecutable / Read proof | Boolean S4U chain proof without ticket export. | Plan or offline fixture under approved lab scope. |
| `rbcd-write-validation` | LabExecutable / Reversible | Controlled RBCD write, verification, and restore journal. | Plan or offline fixture; recovery controls required. |
| `shadow-credential-write` | LabExecutable / Reversible | Controlled shadow-credential/PKINIT proof; secrets become vault handles. | Plan or offline fixture; recovery controls required. |
| `golden-silver-ticket` | LabExecutable / State-changing class | Redacted forgery proof; key and ticket stay vault-only. | Plan or offline fixture under approved lab scope. |
| `adcs-esc1-validation` | LabExecutable / Durable | Enrollment proof with revocation and declared durable issuance residue. | Plan or offline fixture; lab rebuild planning required. |
| `adcs-esc6-editf-check` | Executable / Read-metadata | ESC6 configuration state; no enrollment. | Plan or offline fixture. |
| `adcs-esc7-manage-rights` | Executable / Read-metadata | ESC7 management-rights state; no change. | Plan or offline fixture. |
| `adcs-esc8-relay-web-enrollment` | LabExecutable / Durable | Relay-to-enrollment outcome with truthful residue reporting. | Plan or offline fixture; lab rebuild planning required. |
| `coercion-petitpotam` | LabExecutable / Reversible | Bounded named-target coercion observation; no relay or persistence. | Plan or offline fixture; recovery controls required. |
| `smb-ldap-relay-shadowcred` | LabExecutable / Reversible | Bounded relay and removal of the controlled shadow credential. | Plan or offline fixture; recovery controls required. |
| `exec-proof-svcctl` | LabExecutable / Reversible | Fixed benign-marker proof and removal of the temporary service. | Plan or offline fixture; recovery controls required. |
| `adversary-emulation-evasion` | LabExecutable / Purple-team | Attempted, detected, and not-detected observations. | Plan or offline fixture; `detectionNotification` required. |
| `payload-reliability-labtest` | LabExecutable / Purple-team | Reliability and detection evidence without secret material. | Plan or offline fixture; `detectionNotification` required. |
| `zerologon-detection` | Executable / Read-metadata | Bounded safe detection that stops before account-password reset. | Plan or offline fixture. |
| `zerologon-reset` | LabExecutable / Destructive scaffold | Reset-and-restore plan only; no destructive primitive is shipped. | Plan or offline fixture; never treat as a live feature. |

## Output, cleanup, and certification

Plan-only writes `plan.json` and `manifest.json`. Offline execution may write
`validation-result.json`, `manifest.json`, and for state-changing adapters,
`transaction-journal.jsonl`. Failed or unverified cleanup creates
`.state-change-latch` and blocks later state-changing runs in that output
directory. Follow [STATE_CHANGE_RECOVERY.md](STATE_CHANGE_RECOVERY.md) before
considering a latch clear.

Promotion from this catalog's current offline-only status requires the evidence
and independent review in [CERTIFICATION.md](CERTIFICATION.md). Certification is
per capability, not per family or technique.

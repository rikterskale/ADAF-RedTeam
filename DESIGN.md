# ADAF-RedTeam — Architecture & Design Spec (v0.1)

> Status: implemented architecture with an evolving capability registry. The
> repository contains adapter-backed, offline-testable capability workflows, but
> every current live primitive is `lab_certified=False`. This document defines
> the scope, trust boundary, ADAF bridge contract, and implementation layout.
> Nothing here authorizes offensive action; non-plan execution is gated by a
> schema-valid engagement file at runtime.

## 1. Why this is a separate project

ADAF (Active-Directory-Assessment-Framework) is an **audit** tool. Its contract
promises, in writing, that it does *not* dump credentials, execute commands,
coerce authentication, run relays, or place secrets in evidence. Those promises
are load-bearing: they are what make ADAF safe to hand to a novice with a
"first safe read-only run" guide.

ADAF-RedTeam is the **execution** tool. Its whole job is the thing ADAF refuses
to do: actually prove exploitability against an authorized target. Keeping the
two in one repo would silently void every "does not do X" promise ADAF makes.
Separation keeps ADAF's identity and liability intact and gives the offensive
work an honest, authorization-first framing of its own.

The two meet at exactly one place: a **redacted result bridge**. ADAF finds and
prioritizes; RedTeam validates; a redacted, secret-free result flows back so
ADAF can mark a finding `Confirmed` without ever touching the proof material.

```
  ADAF (audit)                    ADAF-RedTeam (execution)
  ┌────────────────┐   finding    ┌───────────────────────────┐
  │ findings.csv   │  ─────────▶  │ authorization gate         │
  │ finding.schema │  (F-…,       │ capability adapters        │
  │ ADCS ESC1 =    │   ADAF-…)    │  ├ kerberos / adcs / relay │
  │  HIGH, Open    │              │  └ lab-containment guard   │
  └───────▲────────┘              └────────────┬──────────────┘
          │  redacted result                   │ redacted evidence
          │  (verdict + proof_class,           │ (no secrets, ever)
          │   NO secrets)                       ▼
  ┌───────┴────────┐   ingest     ┌───────────────────────────┐
  │ ADAF ingest    │  ◀─────────  │ validation-result.json     │
  │ marks Confirmed│              │ (bridge schema + hash)     │
  └────────────────┘              └───────────────────────────┘
```

## 2. Scope

### Historical intended scope (not the current feature list)

The following paragraph is retained as design history. It is not a claim that
every named technique is implemented or supported. For current capabilities,
consult the generated capability reference.
Credential access (DCSync, gMSA/LAPS read, offline secretsdump, PtH/OtH),
Kerberos (AS-REP/Kerberoast, RBCD S4U, Shadow Credentials + PKINIT, golden/silver,
PtT), lateral/execution (SVCCTL, WinRM, WMI/DCOM, TSCH), ADCS + coercion/relay
(ESC1, PetitPotam/PrinterBug, LLMNR/NBT-NS + SMB→LDAP relay), Zerologon detection.

### Hard non-goals (out of scope, permanently)
- **No mass targeting.** Every action names an exact principal/host. No wildcards,
  no "all vulnerable objects," no subtree sweeps, no auto-propagation.
- **No persistence or C2.** This proves access; it does not maintain it.
- **No live-use on-ramp.** The Windows, Linux, and Docker guides support only
  local setup, plan-only review, and approved offline fixtures. They do not
  authorize live validation or replace operator experience, a written ROE, or
  certification.
- **No secrets in any output.** Same rule as ADAF, applied to a tool that
  actually handles secrets in memory (see §6).
- **No silent-compromise mode.** Evasion is supported (see §2a) but only in a
  purple-team framing where detection evidence is a required output. There is no
  "succeed and report nothing" path.

### 2a. Detection-evasion / adversary emulation (in scope, most-gated tier)
Reversing the earlier draft's blanket exclusion: evasion and production-reliability
of forged-ticket/relay/coercion techniques are **in scope** because they are real
parts of authorized red-team and purple-team work — but only under an explicit
adversary-emulation contract. The gating that makes this defensible:

- **Purple-team framing, adapter-enforced.** These capabilities set
  `requires_detection_notification`; their adapters emit a `proof.detection`
  block (techniques attempted, controls observed, detected/not-detected). The
  generic result schema does not conditionally require that block by capability,
  so certification evidence and adapter tests must retain this invariant.
- **ATT&CK-allowlisted.** T1562 (Impair Defenses), T1070 (Indicator Removal),
  T1550 (Alternate Auth Material), T1558 (Kerberos). The engagement must authorize
  the exact technique.
- **ROE notification required.** The engagement's `detectionNotification` field
  must state how/when the blue team is informed; the gate refuses execution without
  it.
- **Production allowed, containment still required for state change.** Read/metadata
  emulation may run against authorized production; anything that writes objects or
  forges material still needs lab-containment proof first.
- **Novel evasion primitives stay research.** EDR/AV bypass and patched-KDC PAC
  forgery reliability remain `PlanOnly` until a lab-reproducible **detection test**
  (not just "it worked") promotes them. The tool ships the governance now; the
  primitives are earned per capability.

What stays out even here: turnkey stealth whose only product is an undetected
compromise with no detection/evidence value, and anything aimed at real third-party
targets outside the engagement.

## 3. Trust boundary & authorization model

The engagement-file model is compatible in purpose with ADAF's model, but this
repository's authoritative structure is `schemas/engagement.schema.json`. A
capability may run only when **all** of the following hold:

1. A schema-valid engagement file names the `engagementId`, `authorizedDomains`,
   `authorizedSourceAddresses`, time window, `stopConditions`, and `operatorContacts`.
2. The specific capability ID is listed under `capabilities` with exact
   `targets`, `maximumActions`, and the required ATT&CK technique.
3. The supplied `--source-address` exactly matches an entry in
   `authorizedSourceAddresses`; the CLI does not independently determine the
   host's address.
4. The target exactly matches the capability's `targets` entry. The selected
   domain is recorded from `authorizedDomains` (or `--domain`); the gate does
   not derive target-domain membership.
5. For anything state-changing: `stateChangingApproved: true`, `riskAccepted: true`
   with a `riskAcceptanceReference`, `cleanupRequired: true`, **and** a positive
   lab-containment probe (see §7).

Three readiness states, mirrored from ADAF, gate what a capability may do:

| State | Meaning | Example |
|---|---|---|
| `PlanOnly` | Emits the exact plan (targets, budgets, technique). No network, no auth, no KDC, no mutation. | Default for every capability on first landing. |
| `LabExecutable` | May execute only when the containment probe verifies the engagement's disposable-lab declaration. | golden-ticket, relay-write, ESC1 issuance. |
| `Executable` | May execute against an authorized production target (read-only proof classes only). | AS-REP metadata, DCSync *rights* check, Kerberoast ticket request. |

State-changing proof classes are **never** promoted to `Executable`. The most a
production run yields is read/metadata proof; anything that writes objects,
forges tickets, or issues certs stays lab-only.

## 4. Repo layout

```
ADAF-RedTeam/
├─ README.md                      # authorization-first entry point and safe local links
├─ LICENSE                        # proprietary license
├─ DESIGN.md                      # this file
├─ pyproject.toml                 # Python 3.10+; dependency floors and extras
├─ SECURITY.md  THREAT-MODEL.md   # operator threat model + disclosure
├─ schemas/
│  ├─ engagement.schema.json      # superset of ADAF's engagement file
│  └─ validation-result.schema.json   # THE BRIDGE (see §5)
├─ adaf_redteam/
│  ├─ __main__.py                 # CLI: run --engagement … --capability …
│  ├─ authz/                      # engagement parse, source-addr check, gates
│  ├─ containment/                # lab-containment probe + guard
│  ├─ redaction/                  # secret→handle redactor (single choke point)
│  ├─ bridge/                     # emit hashed validation results; ADAF-side ingest helper
│  ├─ evidence/                   # redacted journals, hashing, manifest
│  ├─ probes/                     # live-primitive boundaries (currently uncertified)
│  └─ capabilities/
│     ├─ base.py                  # Capability ABC: plan(), execute(), cleanup()
│     ├─ kerberos/ adcs/ credaccess/ discovery/ detection/ lateral/ coercion/ netlogon/
│     └─ registry.py              # id → class, readiness state, required technique
├─ bridge/
│  └─ adaf_ingest.py              # drop-in: reads validation-result.json into ADAF run dir
├─ tests/                         # plan-only golden tests + redaction unit tests + schema tests
└─ .github/workflows/ci.yml       # lint, tests, generated-reference, guide, and container checks
```

Optional heavy offensive deps (impacket, certipy-equivalents) live behind
`pyproject` extras so a plan-only install stays minimal and auditable.

## 5. The bridge contract (`validation-result.schema.json`)

This is the load-bearing artifact. It is the *only* thing that crosses back into
ADAF, and it is designed for secret-free evidence. It correlates to an ADAF
finding by `FindingId`/`ControlId`, states a verdict and a *class* of proof, and
carries redacted evidence only when adapters follow the redaction discipline.

```jsonc
{
  "schemaVersion": "1.0",
  "resultId": "VR-9F3A7C21D0B4E6A8",           // VR-[A-F0-9]{16}
  "engagementId": "ENG-PLAN-001",
  "producedByUtc": "2026-08-04T18:22:05Z",
  "producer": { "tool": "ADAF-RedTeam", "version": "0.1.0" },

  "correlatesTo": {                              // links to the ADAF finding
    "FindingId": "F-1A2B3C4D5E6F7081",           // ADAF finding.schema pattern
    "ControlId": "ADAF-ADCS-ESC1"
  },

  "capabilityId": "adcs-esc1-validation",
  "attackTechnique": "T1649",                    // ATT&CK id from engagement allowlist
  "target": { "domain": "corp.contoso.test", "principal": "CN=CA01,…" },

  "verdict": "Confirmed",                        // Confirmed | NotExploitable | Inconclusive | BlockedByGate
  "readinessUsed": "LabExecutable",              // PlanOnly | LabExecutable | Executable
  "stateChanging": true,

  "proof": {
    "proofClass": "enrolled-certificate-for-arbitrary-san",  // WHAT was proven, not the material
    "assertions": [                              // human-verifiable, secret-free
      "Enrollment request accepted by CA for requested SAN",
      "Issued certificate chains to the enterprise root"
    ],
    "redactedRefs": {                            // handles, never values
      "requestedSan": "administrator@corp.contoso.test",
      "certificateSha256": "b1946ac9…",          // hash of the cert, not the PFX
      "issuedSerialLast4": "…8F2A",
      "secretHandles": ["pfx#redacted-01"]       // proves we held it; value is discarded
    }
  },

  "authorization": {
    "authorizedSourceAddress": "192.0.2.25",
    "operatorContact": "purple-team@contoso.test",
    "riskAcceptanceReference": "RA-PLAN-EXAMPLE"
  },

  "containment": { "verified": true, "probeId": "CP-…", "environment": "disposable-lab" },

  "budget": { "actionsAuthorized": 3, "actionsUsed": 1, "minIntervalMs": 5000 },

  "cleanup": {
    "required": true,
    "performed": true,
    "verified": true,
    "durableResidue": ["AD CS issuance/revocation record is durable"]  // honest about what can't be undone
  },

  "integrity": { "resultSha256": "…" }
}
```

**Rules the schema and CI checks support:**
- The schema constrains the document's structural shape and selected identifiers.
  It accepts arbitrary strings in assertions and redacted references, so it cannot
  prove those values are non-secret. Adapter redaction discipline, artifact tests,
  certification evidence, and handoff review provide that assurance.
- `stateChanging: true` requires a containment block with `verified: true` and a
  cleanup block. The risk-acceptance reference is enforced by the runtime gate,
  not by this result schema.
- `durableResidue` is an optional cleanup field in the current schema. Durable
  capabilities must document it through their adapter and certification evidence.
- `readinessUsed: "Executable"` requires `stateChanging` to be `false`.

**ADAF ingest side** (`bridge/adaf_ingest.py`, run from ADAF): reads a
`validation-result.json`, validates it against the schema, confirms the
`FindingId` exists in the target ADAF run, and writes a redacted
`validation-linkage.json` next to `findings.csv`. It does not modify the ADAF
finding, its confidence, or its status; the linkage record has a
`confidenceUpgrade` hint for the ADAF owner to review. It imports nothing
executable from RedTeam — only the JSON crosses.

## 6. Redaction (the one rule that cannot leak)

RedTeam *does* hold secrets in memory (that's the point). The discipline is that
secrets never leave the process boundary:

- The `redaction/` module converts secrets to **handles** when adapters use it.
  Evidence, bridge, and logging code are intended to receive handles; this is an
  adapter discipline rather than a type-level restriction on arbitrary strings.
- Handle → value lives in one in-memory vault that is zeroized at run end and is
  never serialized. There is no "save loot" flag anywhere in the codebase.
- CI has a **redaction test suite** covering vault handles, zeroization, and the
  evidence writers, with selected capability fixture tests. It does not perform
  a universal high-entropy scan of every capability artifact; certification and
  handoff review must supplement those unit tests.
- Structured logs mirror ADAF: component, capability, target, technique,
  action count, timing — never secret material or full password-bearing command
  lines.

This is what lets an offensive tool honestly claim ADAF's evidence guarantee.

## 7. Lab containment guard

Implementation note: the containment probe currently validates the engagement's
`labContainmentRequired` control and the declared `labAddressRanges` /
`labResolvedAddresses` relationship. It fails closed when an address is missing
or lies outside the declared CIDRs. Its outcome is placed in a redacted result;
it does not write a separate `containment-probe.json` artifact or perform live
DNS, install-date, or object-count checks.

State-changing capabilities (golden/silver, RBCD/shadow-cred writes, ESC1
issuance, relay-writes) require a **positive containment probe** before the first
mutating action:

- Requires the engagement's `labContainmentRequired` control and a consistent
  declaration of lab CIDRs and addresses.
- Refuses when that declaration cannot demonstrate containment.
- Cleanup failure **latches**: once a cleanup verify fails, the guard blocks all
  further state-changing actions in the run. State-changing steps are never
  resumed from a checkpoint.

None of this is a substitute for operator judgment; it is a floor, not a ceiling.

## 8. Data flow (end to end)

1. Operator runs ADAF → `findings.csv` shows `ADAF-ADCS-ESC1`, HIGH, Open.
2. Operator authors/extends the engagement file: selects `adcs-esc1-validation`,
   sets exact `targets`, `stateChangingApproved`, `riskAccepted`, technique `T1649`.
3. `adaf-redteam run --engagement eng.json --capability adcs-esc1-validation
   --plan-only` → emits the plan; operator reviews.
4. After the exact capability has completed the certification process, an
   operator may drop `--plan-only` only in the approved lab; containment passes,
   the bounded workflow executes, secret material is handled and discarded, and
   cleanup runs and verifies.
5. RedTeam writes `validation-result.json` (verdict `Confirmed`, proofClass,
   redacted refs only). The CLI computes an integrity hash; a signature is
   optional in the schema and is not produced by the CLI.
6. `python bridge/adaf_ingest.py --result validation-result.json --adaf-run C:\ADAF-Run`
   → ADAF finding annotated, Confidence→HIGH, linkage recorded. Review the
   redacted result before handoff; the ingest helper does not independently prove
   that arbitrary string values are non-secret.

## 9. Phased build plan

Current status (authoritative): the Phase 0–2 safety controls and the current
adapter registry are implemented. All 27 descriptors are adapter-backed and
currently have `lab_certified=False`; supported operation is plan-only or an
engagement-approved offline fixture. The historical plan below is retained for
design context only and does not describe current live availability. The
generated `docs/CAPABILITY_REFERENCE.md` and `docs/CERTIFICATION.md` govern
registry status and certification promotion.

- **Phase 0 — skeleton (no capabilities).** Repo, CLI, engagement parser, authz
  gate, redaction choke point + its test suite, both schemas, `adaf_ingest.py`,
  CI. Everything below lands as `PlanOnly` first.
- **Phase 1 — read/metadata proof classes (`Executable` candidates).** AS-REP &
  Kerberoast ticket-request metadata, DCSync *rights* analysis (no DRS pull),
  gMSA/LAPS *read-authorization* check, Zerologon *detection*. These prove
  exposure without secret export.
- **Phase 2 — lab-only state-changing writes (`LabExecutable`).** Shadow
  Credentials / RBCD write + S4U, ESC1 issuance, golden/silver in-lab. Full
  containment guard + cleanup latch required before any of these merge.
- **Phase 3 — coercion/relay (`LabExecutable`, highest scrutiny).** PetitPotam/
  PrinterBug, LLMNR/NBT-NS + SMB→LDAP relay-to-shadow-cred. Lab-only, single
  named coercion target, no listener persistence.
- **Phase 4 — lateral/execution proof.** SVCCTL/WinRM/WMI as *proof-of-exec*
  (run a benign marker command, capture exit + redacted marker), not a shell.

Each phase is independently reviewable and ships behind its readiness state.
Nothing auto-promotes; promotion `PlanOnly → LabExecutable → Executable` is a
deliberate, tested, reviewed step per capability.

## 10. Open decisions for you

1. **License.** DECIDED: proprietary / all-rights-reserved (see LICENSE). No
   redistribution rights are granted; permitted use is conditioned on a written,
   scoped engagement. Revisit only if the repository is ever opened up.
2. **Repo visibility.** Private until Phase 1 is reviewed is the safer default.
3. **Claim verification.** The "custom PAC parser accepted by patched KDCs" /
   "Server 2025 paChecksum2" / "hand-rolled hive parser" claims should each get a
   lab-reproducible test before their capability leaves `PlanOnly`. The design
   treats them as unproven until a golden test says otherwise.
4. **How much of the golden/silver/relay code is yours to import.** If working
   code already exists elsewhere, the scaffold wraps it behind the Capability ABC;
   if not, Phase 2–3 are real research efforts, not integration.

---

*Next step: use `docs/CERTIFICATION.md` to evaluate a specific capability for
disposable-lab certification; do not infer live readiness from an adapter's
presence in the registry.*

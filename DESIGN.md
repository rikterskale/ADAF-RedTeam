# ADAF-RedTeam — Architecture & Design Spec (v0.1 draft)

> Status: design draft for review. No exploit code exists yet. This document
> defines scope, the trust boundary, the ADAF bridge contract, the repo layout,
> and a phased build plan. Nothing here authorizes offensive action; every
> capability is gated behind a signed engagement file at runtime.

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
  │ marks Confirmed│              │ (bridge schema, signed)    │
  └────────────────┘              └───────────────────────────┘
```

## 2. Scope

### In scope (the offensive surface you listed)
Credential access (DCSync, gMSA/LAPS read, offline secretsdump, PtH/OtH),
Kerberos (AS-REP/Kerberoast, RBCD S4U, Shadow Credentials + PKINIT, golden/silver,
PtT), lateral/execution (SVCCTL, WinRM, WMI/DCOM, TSCH), ADCS + coercion/relay
(ESC1, PetitPotam/PrinterBug, LLMNR/NBT-NS + SMB→LDAP relay), Zerologon detection.

### Hard non-goals (out of scope, permanently)
- **No mass targeting.** Every action names an exact principal/host. No wildcards,
  no "all vulnerable objects," no subtree sweeps, no auto-propagation.
- **No persistence or C2.** This proves access; it does not maintain it.
- **No "novice" on-ramp.** No beginner guide, no "safe first run" framing. The
  README's first section is authorization, not quick-start.
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

- **Purple-team framing, enforced.** These capabilities set
  `requires_detection_notification` and must emit a `proof.detection` block
  (techniques attempted, controls observed, detected/not-detected). A result with
  no detection evidence is schema-incomplete for this class.
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

Reuse ADAF's engagement-file model verbatim so operators learn one format. A
capability may run only when **all** of the following hold:

1. A schema-valid engagement file names the `engagementId`, `authorizedDomains`,
   `authorizedSourceAddresses`, time window, `stopConditions`, and `operatorContacts`.
2. The specific capability id is listed under `activeValidation.selected` with a
   per-capability `authorizations` block: exact `targets`, `maximumActions`,
   `minimumIntervalMilliseconds`, and the required ATT&CK technique.
3. The run's real source address is inside `authorizedSourceAddresses`.
4. The target is inside `authorizedDomains` **and** the capability's `targets`.
5. For anything state-changing: `stateChangingApproved: true`, `riskAccepted: true`
   with a `riskAcceptanceReference`, `cleanupRequired: true`, **and** a positive
   lab-containment probe (see §7).

Three readiness states, mirrored from ADAF, gate what a capability may do:

| State | Meaning | Example |
|---|---|---|
| `PlanOnly` | Emits the exact plan (targets, budgets, technique). No network, no auth, no KDC, no mutation. | Default for every capability on first landing. |
| `LabExecutable` | May execute, but only when the containment probe confirms a disposable lab. | golden-ticket, relay-write, ESC1 issuance. |
| `Executable` | May execute against an authorized production target (read-only proof classes only). | AS-REP metadata, DCSync *rights* check, Kerberoast ticket request. |

State-changing proof classes are **never** promoted to `Executable`. The most a
production run yields is read/metadata proof; anything that writes objects,
forges tickets, or issues certs stays lab-only.

## 4. Repo layout

```
ADAF-RedTeam/
├─ README.md                      # authorization-first; no beginner on-ramp
├─ LICENSE                        # decide: MIT vs. a use-restricted license (§10)
├─ DESIGN.md                      # this file
├─ pyproject.toml                 # Python 3.10+; pinned deps; extras per capability
├─ SECURITY.md  THREAT-MODEL.md   # operator threat model + disclosure
├─ schemas/
│  ├─ engagement.schema.json      # superset of ADAF's engagement file
│  ├─ validation-result.schema.json   # THE BRIDGE (see §5)
│  └─ containment-probe.schema.json
├─ adaf_redteam/
│  ├─ __main__.py                 # CLI: run --engagement … --capability …
│  ├─ authz/                      # engagement parse, source-addr check, gates
│  ├─ containment/                # lab-containment probe + guard
│  ├─ redaction/                  # secret→handle redactor (single choke point)
│  ├─ bridge/                     # emit/sign validation-result; ADAF-side ingest helper
│  ├─ evidence/                   # redacted journals, hashing, manifest
│  └─ capabilities/
│     ├─ base.py                  # Capability ABC: plan(), execute(), cleanup()
│     ├─ kerberos/  adcs/  credaccess/  lateral/  coercion_relay/
│     └─ registry.py              # id → class, readiness state, required technique
├─ bridge/
│  └─ adaf_ingest.py              # drop-in: reads validation-result.json into ADAF run dir
├─ labs/                          # disposable-lab build (Vagrant/terraform stubs)
├─ tests/                         # plan-only golden tests + redaction unit tests + schema tests
└─ .github/workflows/ci.yml       # ruff, schema-validate, pip-audit, redaction tests, SBOM
```

Optional heavy offensive deps (impacket, certipy-equivalents) live behind
`pyproject` extras so a plan-only install stays minimal and auditable.

## 5. The bridge contract (`validation-result.schema.json`)

This is the load-bearing artifact. It is the *only* thing that crosses back into
ADAF, and it is **secret-free by construction**. It correlates to an ADAF finding
by `FindingId`/`ControlId`, states a verdict and a *class* of proof, and carries
redacted evidence only.

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

  "integrity": { "resultSha256": "…", "signature": "…optional CMS…" }
}
```

**Rules the schema enforces (validated in CI):**
- No property may contain a password, hash, ticket, token, PFX blob, private key,
  LAPS value, or raw protocol blob. `redactedRefs` values are hashes, last-4s,
  DNs, counts, or opaque handles only. A test asserts the redactor is the single
  path that populates this object.
- `stateChanging: true` ⇒ `containment.verified: true` and a
  `authorization.riskAcceptanceReference` are required.
- `verdict: "Confirmed"` with `stateChanging: true` ⇒ `cleanup` block required;
  `durableResidue` must be present (may be an empty array only if truly none).
- `readinessUsed: "Executable"` ⇒ `stateChanging` must be `false`.

**ADAF ingest side** (`bridge/adaf_ingest.py`, run from ADAF): reads a
`validation-result.json`, validates it against the schema, confirms the
`FindingId` exists in the target ADAF run, and writes a redacted
`validation-linkage.json` next to `findings.csv`, flipping the finding's
`Confidence` to `HIGH` and annotating `Status`. It imports nothing executable
from RedTeam — only the JSON crosses.

## 6. Redaction (the one rule that cannot leak)

RedTeam *does* hold secrets in memory (that's the point). The discipline is that
secrets never leave the process boundary:

- A single `redaction/` module converts any secret into a **handle** the instant
  it is obtained. Downstream code (evidence, bridge, logs) can only see handles.
- Handle → value lives in one in-memory vault that is zeroized at run end and is
  never serialized. There is no "save loot" flag anywhere in the codebase.
- CI has a **redaction test suite**: it runs each capability in a mocked-lab mode
  and greps every produced artifact (journal, result, log, manifest) for
  high-entropy strings and known secret shapes; a hit fails the build.
- Structured logs mirror ADAF: component, capability, target, technique,
  action count, timing — never secret material or full password-bearing command
  lines.

This is what lets an offensive tool honestly claim ADAF's evidence guarantee.

## 7. Lab containment guard

State-changing capabilities (golden/silver, RBCD/shadow-cred writes, ESC1
issuance, relay-writes) require a **positive containment probe** before the first
mutating action, recorded as `containment-probe.json`:

- Confirms the target domain is flagged `disposable-lab` in the engagement file.
- Refuses to proceed if the target resolves to an address outside a lab range,
  or if the DC's install date / object count suggests production.
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
4. Drop `--plan-only`; containment probe passes; capability executes one bounded
   enrollment in the lab; secret is handled and discarded; cleanup runs & verifies.
5. RedTeam writes signed `validation-result.json` (verdict `Confirmed`,
   proofClass, redacted refs only).
6. `python bridge/adaf_ingest.py --result validation-result.json --adaf-run C:\ADAF-Run`
   → ADAF finding annotated, Confidence→HIGH, linkage recorded. No secret crossed.

## 9. Phased build plan

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

1. **License.** ADAF is MIT. A working offensive toolkit under MIT is a choice —
   consider a source-available / use-restricted license, or keep MIT and lean on
   the runtime authorization gate. (I'll default to a placeholder LICENSE +
   THREAT-MODEL until you decide.)
2. **Repo visibility.** Private until Phase 1 is reviewed is the safer default.
3. **Claim verification.** The "custom PAC parser accepted by patched KDCs" /
   "Server 2025 paChecksum2" / "hand-rolled hive parser" claims should each get a
   lab-reproducible test before their capability leaves `PlanOnly`. The design
   treats them as unproven until a golden test says otherwise.
4. **How much of the golden/silver/relay code is yours to import.** If working
   code already exists elsewhere, the scaffold wraps it behind the Capability ABC;
   if not, Phase 2–3 are real research efforts, not integration.

---

*Next step after your review: I can scaffold Phase 0 (skeleton + schemas +
redaction test harness + ADAF ingest bridge) with no capability code, so you have
something buildable to react to.*

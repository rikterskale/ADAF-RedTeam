# ADAF-RedTeam

**Authorization-first offensive validation for Active Directory. Not an audit
tool. The safe local guides cover setup and plan-only workflows; they do not
authorize or qualify an operator for live validation.**

ADAF-RedTeam proves exploitability of findings surfaced by
[ADAF](https://github.com/rikterskale/Active-Directory-Assessment-Framework) and
returns a **redacted, secret-free result** that ADAF can ingest. ADAF finds and
prioritizes; ADAF-RedTeam validates; only a redacted verdict crosses back.

> Run this only under a written, scoped engagement. Non-plan execution refuses
> to proceed without a schema-valid engagement file that
> names the domain, exact targets, source addresses, time window, stop
> conditions, allowed ATT&CK techniques, and (for anything that changes state)
> risk acceptance and lab containment. The documented safe first run is
> plan-only; there is no credential/loot export path anywhere in this codebase.

See [DESIGN.md](DESIGN.md) for the full architecture,
[THREAT-MODEL.md](THREAT-MODEL.md) for the operator threat model, and
[docs/CERTIFICATION.md](docs/CERTIFICATION.md) for how a capability is promoted
from `lab_certified=False` to `True`.

For operating documentation, see the [engagement authoring guide](docs/ENGAGEMENT_AUTHORING.md),
[capability runbooks](docs/CAPABILITY_RUNBOOKS.md),
[operator lifecycle guide](docs/OPERATOR_LIFECYCLE.md),
[state-change recovery runbook](docs/STATE_CHANGE_RECOVERY.md), and
[ADAF bridge integration guide](docs/ADAF_BRIDGE_INTEGRATION.md). The complete
CLI syntax is in the [command reference](docs/COMMAND_REFERENCE.md).

For safe local setup and a no-network plan-only first run, see the
[Windows guide](docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md),
[Linux guide](docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md), and the generated
[capability reference](docs/CAPABILITY_REFERENCE.md). Start with
`adaf-redteam doctor`; it checks local prerequisites without contacting a target.

The supported container workflow is documented in the
[Docker guide](docs/guides/DOCKER_USABILITY_GUIDE.md). It supports the same
offline, plan-only and fixture-backed workflows; it does not certify any live
capability.

Both Linux and Windows images include all capability adapters and optional Python
runtime dependencies; their separate host requirements and build commands are in
the [container platform support matrix](docs/CONTAINER_PLATFORM_SUPPORT.md).

## Status: Phase 2 (complete — all capabilities wired)

Phase 0 skeleton (CLI, authorization gate, redaction choke point, the three
schemas, ADAF ingest bridge) is complete. Phase 1 adds read/metadata **proof**
capabilities — all secret-free.

Increment 1 — pure LDAP reads (no offensive packet, no secret):

- `dcsync-rights-validation` — reads the domain ACL; proves DCSync rights held.
  No DRSUAPI replication, no hash extraction.
- `gmsa-read-authorization` — proves gMSA managed-password read authorization;
  never reads the value.
- `laps-read-authorization` — proves LAPS-attribute read authorization; never
  reads the value.

Increment 2 — live-protocol metadata + safe detection:

- `asrep-roast-validation` / `kerberoast-validation` — prove roastability and
  record the encryption type. The crackable AS-REP / TGS blob is never exported.
- `zerologon-detection` — SAFE. Detects vulnerability with bounded zero-challenge
  attempts and **stops before `NetrServerPasswordSet2`**; the machine account is
  never modified.

Each capability is a **pure `analyze()`** (unit-tested) plus a **thin live
collector/probe** that ships **`lab_certified=False`** — a real `run` prints an
UNVALIDATED warning and stamps the result until a disposable-lab test certifies
it. Use `--fixture examples/acl-fixture.example.json` to run the full
execute → analyze → bridge pipeline offline.

### `zerologon-reset` — destructive, lab-only, primitive not shipped

The Zerologon "account reset" (`NetrServerPasswordSet2`) is the destructive
exploit: it zeroes the DC machine-account password and breaks the domain
controller. It is registered as `state_changing`, **`LabExecutable`** (the
containment probe refuses non-lab targets), and requires risk acceptance +
mandatory restore + a cleanup latch. Its destructive primitive is **intentionally
not implemented** — `execute()` raises, and the containment gate blocks a real run
before `execute()` is ever reached. `--plan-only` shows the full reset-then-restore
plan and the warnings. This is the same posture as every other state-changing
capability (golden-ticket, ESC1, coercion, relay): gated scaffold, no working
exploit code.

### Phase 2 — lab-only state-changing writes (the containment tier)

Phase 2 builds the state-changing *safety machinery* and one reference reversible
write:

- **Containment guard** (`containment/probe.py`) now performs a real, offline,
  fail-closed check: the engagement must declare it is a disposable lab, declare
  the lab's `labAddressRanges` (CIDRs), and declare `labResolvedAddresses` — and
  every declared host address must fall inside a declared range. Any missing or
  out-of-range declaration refuses state-changing execution.
- **Cleanup latch** (`statechange/`): if a state change is not verifiably cleaned
  up, the output directory is latched and further state-changing runs are refused
  until an operator clears it.
- **`rbcd-write-validation`** — the reference reversible write. It captures the
  original `msDS-AllowedToActOnBehalfOfOtherIdentity`, writes RBCD granting a
  controlled principal, verifies S4U, then **restores** the original value and
  verifies the restore, emitting a redacted transaction journal. The live
  mutation primitive is the lab-certification boundary (`probes/rbcd.py` raises);
  the mutate → verify → restore orchestration, journal, and latch are exercised
  offline via the fixture writer.

Increment 2 adds two more state-changing writes on the same orchestration, with
the wrinkles that make them worth having:

- **`shadow-credential-write`** — reversible (add `msDS-KeyCredentialLink` →
  PKINIT → remove), *and* it handles **secret material**: the key credential's
  private key is redacted to a vault handle the instant it is obtained and
  discarded. Only the handle id is recorded; the key is never exported. PKINIT
  proof is a boolean — no ticket/hash returned.
- **`adcs-esc1-validation`** — the honest hard case. Certificate issuance is
  **durable**: cleanup revokes (the reversible part, which gates the latch) but
  reports the issuance as non-restorable `durableResidue` rather than claiming a
  clean restore. The issued **PFX/private key** is redacted to a handle; only its
  SHA-256 and serial-last-4 are recorded, never the key.

Both live primitives (`probes/shadowcred.py`, `probes/adcs.py`) raise; the
orchestration and secret handling are exercised offline via fixtures, and a test
asserts the fake secret bytes never appear in any emitted artifact.

### Phase 2 increment 3 — the highest-scrutiny scaffolds

The remaining state-changing capabilities are now wired as gated scaffolds
(orchestration + cleanup + fixture tests; live primitive raises):

- `exec-proof-svcctl` — proof-of-execution via a **fixed benign marker** (echo a
  nonce), then removes the temporary service. Not a shell; no user command.
- `golden-silver-ticket` — forgery; the input key and forged ticket are redacted
  to vault handles and never exported; no directory write.
- `coercion-petitpotam` — single named target, short-lived listener, **no relay,
  no persistence**; observation only.
- `smb-ldap-relay-shadowcred` — coerce → relay → write shadow cred → **remove it**
  (reversible); any key material redacted.
- `adversary-emulation-evasion` / `payload-reliability-labtest` — purple-team.
  Require an ROE `detectionNotification` (gate-enforced) and always emit a
  `proof.detection` block (attempted / detected / not-detected). No silent-success
  path.

All capabilities described above are adapter-backed and currently uncertified.
Some read-only collectors are implemented for certification development; an
operator must explicitly set `ADAF_RT_LAB=1` before the CLI will attempt an
uncertified live collector in a disposable lab. Other adapters remain scaffolds
whose live primitive raises. Neither path is a supported live-use feature: all
current descriptors have `lab_certified=False`. Use `--fixture` for the
supported offline workflow and see [docs/CERTIFICATION.md](docs/CERTIFICATION.md)
for the promotion gate.

The current generated registry contains **27 capabilities**: **14 Executable**
target-class capabilities and **13 LabExecutable** capabilities, with **0
PlanOnly** entries. This is an authorization classification, not live readiness:
all current entries have `lab_certified=False`. No capability is currently
available for live use; its orchestration can be exercised offline via
`--fixture` until a disposable-lab test certifies its live primitive. See the
generated [capability reference](docs/CAPABILITY_REFERENCE.md).

## Install (development)

```bash
python -m pip install -e ".[dev]"
```

## Plan-only run

```bash
adaf-redteam list-capabilities
adaf-redteam run --engagement examples/engagement.example.json \
  --capability adcs-esc1-validation --plan-only --out ./out
```

Plan-only performs no network, authentication, KDC, mutation, or outbound
activity. It writes the exact plan (targets, budgets, technique) for review.

## Container (supported offline workflow)

```bash
docker build --pull -t adaf-redteam:local .
mkdir -p out
docker run --rm --user "$(id -u):$(id -g)" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,source="$(pwd)/out",target=/out \
  adaf-redteam:local run --engagement examples/engagement.example.json \
  --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out /out
```

The image runs as an unprivileged user and requires an explicit writable output
mount. Keep `--network none` for plan-only and fixture workflows. See the Docker
guide for Windows PowerShell syntax and the support boundary.

## Feed a result back into ADAF

```bash
python bridge/adaf_ingest.py --result ./out/validation-result.json \
  --adaf-run /path/to/ADAF-Run
```

Only the redacted `validation-result.json` is intended to cross the boundary.
Supported adapters use the redaction vault and CI artifact checks, but the result
schema accepts arbitrary strings; review a result before handoff. Treat any
serialized secret, hash, ticket, PFX, or key as a security-critical defect.

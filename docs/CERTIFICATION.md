# Capability certification (`lab_certified: False → True`)

Every capability in ADAF-RedTeam ships with `lab_certified=False`. Some live
collectors are implemented only for certification development; other adapters
remain explicit `NotImplementedError` scaffolds. The CLI refuses an uncertified
live attempt unless the operator explicitly sets `ADAF_RT_LAB=1`, and it stamps
any such result *UNVALIDATED*. Certification is the deliberate, reviewed act of
proving one capability's live primitive is correct, bounded, and reversible in a
disposable lab, and then flipping its `lab_certified` flag to `True`. Every
current descriptor remains uncertified, and none is supported for routine live
use.

This document is the gate. It defines what an operator must implement and prove
before a capability may be trusted. It does not contain, and does not authorize,
any offensive primitive — writing and certifying those is the operator's lab work.

> Certification certifies a **capability against a lab**, never against a real
> engagement target. `lab_certified=True` means "the live primitive behaves as
> specified in a disposable lab." It never relaxes the runtime authorization gate,
> the containment probe, or the cleanup latch — those still apply on every run.

---

## 0. Non-negotiable preconditions

Certification work happens **only** in a disposable lab you can rebuild from
scratch. Before any live primitive is run even once:

- The lab is isolated (no route to production, no shared trust) and snapshot- or
  rebuild-capable.
- A certification engagement file authorizes the exact capability and target, with
  `labAddressRanges` / `labResolvedAddresses` that make the containment probe pass
  for the lab and **fail** for anything else.
- The work is logged against a certification ticket with a named owner.

If a primitive cannot be made safe and reversible in a disposable lab, it does not
get certified. It stays `False`.

---

## 1. Universal checklist (every capability)

A capability may be promoted only when **all** of the following are true and
evidenced:

1. **Live primitive implemented and reviewed** in its `probes/*.py` module, replacing the
   `NotImplementedError` — bounded to exactly what the capability's `plan()`
   describes and nothing more (no extra targets, no extra operations).
2. **Analyzer/orchestration unchanged in behavior.** The pure `analyze()` /
   orchestration is already unit-tested; certification adds the *live* path, it
   does not alter the decision logic. Existing tests still pass.
3. **Redaction proven.** Run the capability live in the lab and confirm — via the
   redaction test discipline (grep every produced artifact) — that no password,
   hash, ticket, key, PFX, or LAPS value appears in any result, journal, log, or
   manifest. Secret material must reach a `SecretVault` handle and nothing else.
4. **Authorization gate honored.** Live attempts outside the authorized
   source/target/technique are refused. Re-run the gate tests against the live
   build.
5. **Idempotent, bounded, and interval-respecting.** The primitive honors
   `maximumActions` and `minimumIntervalMilliseconds`; a second run does not
   compound state.
6. **Evidence package** (§7) is complete and attached to the certification ticket.
7. **Independent review** (§8) sign-off recorded.

Only then: set `lab_certified=True` for that one capability in
`adaf_redteam/capabilities/registry.py`, in the same PR as its certification test.

---

## 2. Tier-specific requirements

Capabilities fall into tiers by risk and reversibility. Each tier adds
requirements on top of §1.

### Tier A — read / metadata (Executable target)
`dcsync-rights-validation`, `laps-read-authorization`, `gmsa-read-authorization`,
`asrep-roast-validation`, `kerberoast-validation`, `zerologon-detection`

- **No state change, proven.** Demonstrate (packet capture / DC audit log) that the
  live run performs only reads / bounded metadata requests and writes nothing.
- **No secret export, proven.** For AS-REP/Kerberoast: confirm the crackable blob is
  discarded, never written. For DCSync: confirm no DRSUAPI replication is issued.
- **Zerologon-detection specifically:** prove the probe STOPS before
  `NetrServerPasswordSet2` — capture shows attempts only, and the DC machine
  account password is unchanged after the run.
- These are the only tier that may additionally be considered for production use
  under an engagement; certification still only certifies lab behavior.

### Tier B — reversible state change (lab only)
`rbcd-write-validation`, `shadow-credential-write`, `exec-proof-svcctl`,
`coercion-petitpotam`, `smb-ldap-relay-shadowcred`

- **Restore proven.** After the live run, the mutated object/service is
  byte-for-byte back to its captured original (attribute value, key credential
  list, service list). Show the before/after.
- **Cleanup latch proven.** Force a restore failure in the lab and confirm the run
  latches the output dir and the next state-changing run is refused.
- **Bounded blast radius.** `coercion-*` / relay: exactly one named target, a
  short-lived listener that is town down, no second destination, no persistence.
  `exec-proof-svcctl`: only the fixed benign marker runs — no user command, no
  shell — and the temporary service is removed.
- **Secret handling** (where applicable): relay/shadow-cred key material is redacted
  and discarded (Tier B inherits §1.3, called out because these hold secrets).

### Tier C — durable state change (not fully reversible)
`adcs-esc1-validation`

- **Honest residue.** Certification must confirm the capability reports
  `durableResidue` truthfully: the reversible part (revocation) is performed and
  `cleanup.verified` reflects only that, while the durable issuance/revocation
  record is documented, not hidden.
- **Revocation proven.** After the run, the issued certificate is revoked; a failed
  revocation must latch.
- **Lab teardown plan.** Because issuance is durable, the certification lab must be
  rebuilt (not just cleaned) between runs; document the rebuild step.

### Tier D — purple-team / evasion (detection evidence required)
`adversary-emulation-evasion`, `payload-reliability-labtest`

- **Detection block proven truthful.** The emitted `proof.detection`
  (attempted / detected / not-detected) matches what the lab's blue-team telemetry
  actually recorded. Certify against a lab SOC/EDR, not a mock.
- **Notification gate proven.** A live run without `detectionNotification` is
  refused.
- **Defenses restored.** Any temporarily impaired control (logging, EDR) is
  restored and verified; the residue note is not a substitute for actually
  restoring it.
- **No silent-success path.** Confirm there is no code path that completes without
  emitting the detection block.

### Tier E — destructive (extra bar)
`zerologon-reset`

- **Reset-then-restore, proven end to end.** The DC machine-account password is
  reset **and** restored from the captured pre-reset value, and DC secure-channel
  and replication health are verified green afterward. A run that cannot verify
  restoration must latch and leave a clear recovery record.
- **Two-person rule.** Certification (and any future authorized use) requires two
  named approvers, not one.
- **Rebuild, don't clean.** The lab DC is rebuilt from snapshot after every
  certification run.
- **Production is never in scope for certification.** The containment probe must be
  shown to refuse any non-lab address for this capability.

> If reset-then-restore cannot be proven fully reliable in the lab, this capability
> stays `lab_certified=False` indefinitely. That is an acceptable outcome.

---

## 3. Evidence package (attach to the certification ticket)

For each capability certified:

1. The certification engagement file (redacted) and the containment probe record
   showing it verified for the lab and refused a non-lab address.
2. Before/after state of the mutated object (Tier B/C/E) or a read-only attestation
   (Tier A).
3. A redaction scan result over all produced artifacts (must be clean).
4. The `validation-result.json` from the live run, plus its transaction journal.
5. For Tier B/C/E: a forced-failure run showing the cleanup latch engaging.
6. For Tier D: the blue-team telemetry corroborating the detection block.
7. The new/updated certification test (see §5) and a green CI run.
8. Reviewer sign-off (§8).

---

## 4. What certification is NOT

- It is **not** approval to run against production. Engagement authorization is a
  separate, per-run control.
- It does **not** disable any gate. `lab_certified=True` only removes the
  UNVALIDATED stamp; the authorization gate, containment probe, cleanup latch, and
  redaction vault all still run.
- It is **not** transferable. Certifying `rbcd-write-validation` says nothing about
  `shadow-credential-write`; each capability is certified on its own.
- It does **not** persist across a material change. Any edit to the live primitive,
  its bounds, or its cleanup **de-certifies** it (§6).

---

## 5. The mechanical promotion step

1. Implement the live primitive in `probes/<x>.py` (bounded to `plan()`).
2. Add a **certification test** that runs the live path against the disposable lab
   behind an explicit opt-in marker (e.g. an env var like `ADAF_RT_LAB=1`) so it
   never runs in normal CI, and asserts: correct verdict, clean redaction scan,
   verified restore (or honest durable residue), and latch-on-failure.
3. Attach the evidence package (§3).
4. Obtain review sign-off (§8).
5. In the **same PR**, set `lab_certified=True` for that one capability in
   `registry.py`. Never flip the flag in a PR that does not carry the evidence and
   the test.

CI keeps running the offline (`--fixture`) suite for every capability regardless
of certification state; the lab-gated certification test is additional.

---

## 6. De-certification

Set `lab_certified` back to `False` immediately when any of these occur:

- The live primitive, its bounds, `plan()`, or its cleanup changes.
- A run fails to restore and latches in a way not explained by the evidence.
- The lab it was certified against no longer represents the primitive's behavior
  (dependency/protocol change).
- Any redaction leak is found, anywhere, for any capability (audit them all).

De-certification is cheap and expected. Prefer it over debating edge cases.

---

## 7. Roles

- **Certification owner** — implements the primitive and assembles the evidence.
- **Independent reviewer** — did not write the primitive; verifies the evidence and
  the test, and confirms the bounds match `plan()`. Signs off.
- **Second approver** — required only for Tier E (destructive) capabilities.

No self-certification: the owner and the reviewer must be different people.

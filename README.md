# ADAF-RedTeam

**Authorization-first offensive validation for Active Directory. Not an audit
tool. Not for beginners.**

ADAF-RedTeam proves exploitability of findings surfaced by
[ADAF](https://github.com/rikterskale/Active-Directory-Assessment-Framework) and
returns a **redacted, secret-free result** that ADAF can ingest. ADAF finds and
prioritizes; ADAF-RedTeam validates; only a redacted verdict crosses back.

> Run this only under a written, scoped engagement. Every capability is disabled
> by default and refuses to execute without a schema-valid engagement file that
> names the domain, exact targets, source addresses, time window, stop
> conditions, allowed ATT&CK techniques, and (for anything that changes state)
> risk acceptance and lab containment. There is no "quick start" and no
> credential/loot export path anywhere in this codebase.

See [DESIGN.md](DESIGN.md) for the full architecture and
[THREAT-MODEL.md](THREAT-MODEL.md) for the operator threat model.

## Status: Phase 1 (complete)

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

Still `PlanOnly` (DESIGN.md §9): the lab-only state-changing writes (shadow-cred,
RBCD, ESC1, golden/silver), coercion/relay, exec-proof, and the adversary-
emulation/evasion capabilities.

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

## Feed a result back into ADAF

```bash
python bridge/adaf_ingest.py --result ./out/validation-result.json \
  --adaf-run /path/to/ADAF-Run
```

Only the redacted `validation-result.json` crosses the boundary. No secret,
hash, ticket, PFX, or key is ever written by this tool.

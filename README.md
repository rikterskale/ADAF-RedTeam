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

## Status: Phase 1 (increment 1)

Phase 0 skeleton (CLI, authorization gate, redaction choke point, the three
schemas, ADAF ingest bridge) is complete. Phase 1 increment 1 adds the first
**read-only, secret-free** capabilities:

- `dcsync-rights-validation` — reads the domain ACL; proves DCSync replication
  rights are held. No DRSUAPI replication, no hash extraction.
- `gmsa-read-authorization` — proves a principal may retrieve a gMSA password.
  The password value is never read.
- `laps-read-authorization` — proves a principal may read a LAPS attribute. The
  value is never read.

Each splits into a **pure `analyze()`** (unit-tested) and a **thin live
collector** (`directory/ldap_source.py`). The live collector is **not
lab-certified** (`lab_certified=False`): a real `run` prints an UNVALIDATED
warning and stamps the result until a disposable-lab test certifies it. Use
`--fixture examples/acl-fixture.example.json` to exercise the full
execute → analyze → bridge pipeline offline.

Everything else remains `PlanOnly`. Still to come (DESIGN.md §9): AS-REP/
Kerberoast metadata + Zerologon detection (Phase 1 increment 2), then the
lab-only state-changing and coercion/relay capabilities.

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

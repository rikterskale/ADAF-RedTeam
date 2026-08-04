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

## Status: Phase 0 (skeleton)

This repository currently contains the **skeleton only** — no working exploit
code. What exists:

- CLI (`adaf-redteam`) with `list-capabilities` and a `run --plan-only` path.
- The engagement authorization gate and source-address / target checks.
- The redaction choke point (secrets → handles) and its test suite.
- The three schemas: engagement, validation-result (the ADAF bridge),
  containment-probe.
- The ADAF ingest bridge (`bridge/adaf_ingest.py`).

Every capability is registered as `PlanOnly`. `run` without `--plan-only` will
report that no executable adapter is present. Capabilities land in later phases
(DESIGN.md §9), each behind its readiness state.

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

# ADAF-RedTeam Linux Guide

## Status

**PARTIALLY VERIFIED** on 2026-08-04 against source version 0.1.0. CI is configured for Ubuntu and Python 3.10/3.12; the safe `doctor`, `list-capabilities`, and `--plan-only` workflow was run with Python 3.12. A clean Linux installation and live capabilities remain unverified.

## Supported path and safety boundary

Use Bash with an organization-provided Python 3.10 or later. No distribution-specific install, container, root, or `sudo` path is committed. This is an authorized-operator guide, not permission to test a target. Use only committed examples for first use, and do not mistake `Executable` for a certified live capability.

## Install

Run these commands in Bash from a directory you own. `YOUR_REPOSITORY_URL` must be supplied by the maintainer.

```bash
python3 --version
git clone YOUR_REPOSITORY_URL ADAF-RedTeam
cd ADAF-RedTeam
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Success: the final command exits `0`. If Python or `venv` is absent, use the approved distribution process rather than guessing a `sudo` command. If pip is blocked, use the approved package mirror or offline-wheel process; do not disable TLS validation.

## Safe first workflow

Run all commands from the repository root. They do not contact an AD target.

```bash
.venv/bin/python -m adaf_redteam doctor
.venv/bin/python -m adaf_redteam list-capabilities
.venv/bin/python -m adaf_redteam run --engagement examples/engagement.example.json --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out ./out
```

Success: `doctor` prints only `PASS` lines, capability output labels every item as uncertified, and the final command writes `out/plan.json` plus `out/manifest.json`. The plan makes no network, authentication, KDC, mutation, or outbound activity. The manifest contains only artifact names, sizes, and checksums.

## Read results and recover safely

`ADAF-RT-E100` through `E109` are scope/safety-gate refusals; follow their printed remedy and do not bypass them. `ADAF-RT-E202` means live execution is unavailable; use `--plan-only` or an approved fixture. `ADAF-RT-E203` indicates a cleanup latch: stop, verify recovery with the engagement owner, and clear it only under an approved recovery procedure.

## Configuration, cleanup, and next steps

`examples/engagement.example.json` is not an authorization for a real environment. Do not commit engagements, credentials, tickets, keys, or result artifacts. Retain output according to the engagement, then delete only the confirmed local `out/` and `.venv/` directories. Before non-fixture work, read the [capability reference](../CAPABILITY_REFERENCE.md), [certification gate](../CERTIFICATION.md), and the rules of engagement.

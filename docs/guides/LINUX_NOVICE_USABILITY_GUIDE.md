---
guide_id: linux-novice-usability
guide_schema_version: 1
platform: linux
canonical_path: docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-RedTeam
target_release: "latest locally verifiable source version: 0.1.0"
target_commit: b67175ed4c232f32daa05cffc54674cfb65265dc
support_status: unverified
alternative_support_paths: []
validation_status: statically_verified_only
validated_on: 2026-08-04
validated_environments: []
primary_shells: ["Bash"]
maintainer_source_of_truth: "README.md, pyproject.toml, adaf_redteam/__main__.py"
known_limitations: ["No Linux host available for review", "All live capabilities are uncertified"]
---

# ADAF-RedTeam Linux Novice Usability Guide

## About This Guide

This is the repository-ready Bash guide for an authorized operator. It is **statically verified only** because no Linux environment was available. It is not authorization to test a target.

## What This Project Does

ADAF-RedTeam creates a gated AD validation plan or redacted ADAF result. The documented first run is plan-only and must make no target contact.

## Who Should Use It

Only operators with written, exact scope should use it. It is not a beginner AD scanner, a credential collector, or a way to export secrets.

## Safety, Authorization, and Data Handling

Use the committed example only. Never remove `--plan-only`, do not add a real credential, and do not commit engagement/result artifacts. Every current live capability is uncertified.

## Platform Support Status

Bash on a supported Linux distribution is inferred from the CI `ubuntu-latest` matrix, but no clean Linux install was executed. The project does not commit a distribution-specific package-install command. Use your approved distribution process for Python and Git.

## What You Will Accomplish

You will prepare an isolated environment, check local readiness, inspect capabilities, and create a no-network plan plus manifest under `out`.

## Before You Begin Checklist

Use an ordinary account, Bash, Python 3.10+, Git or approved ZIP source, a folder you own, and internet only for dependency installation. The project publishes no CPU/RAM/disk minimum, root/sudo requirement, container requirement, target credential requirement, or first-run network port requirement.

## Computer and Software Requirements

`pyproject.toml` requires Python `>=3.10`. `python3 -m venv` must work. If Python, venv, Git, or your package manager is absent, stop and follow organization-approved distribution documentation; do not copy an unverified `sudo` command.

## Terms and Concepts You Need to Know

An engagement is an authorization configuration; a capability is a named operation; plan-only is a dry run; artifacts are output files. `Executable` is a future authorization class, not a certified live operation.

## Choose the Correct Installation Path

Clone the maintainer-approved repository into a directory you own, then use `.venv`. An approved ZIP extraction is acceptable when Git is unavailable. This guide does not validate containers, WSL, or root installs.

## Open the Correct Terminal or Shell

Use Bash. Do not copy these commands into PowerShell, Command Prompt, or a shell with incompatible syntax.

## Check and Install Prerequisites

**Command ID:** LNX-CMD-001. **Purpose:** check Python. **Run in:** Bash. **Working directory:** any. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** statically verified.

```bash
python3 --version
```

Use Python 3.10 or newer. If missing, use your distribution’s approved process; do not disable package signature or TLS controls.

## Download or Clone the Repository

`YOUR_REPOSITORY_URL` is the maintainer-authorized Git URL. Example URL is not a credential and must still be approved.

**Command ID:** LNX-CMD-002. **Purpose:** clone source. **Run in:** Bash. **Working directory:** a folder you own. **Privilege:** ordinary user. **Internet:** required. **Safe to copy:** only after replacement. **Side effects:** creates project folder. **Validation:** statically verified.

```bash
git clone YOUR_REPOSITORY_URL ADAF-RedTeam
```

## Find and Enter the Repository Folder

**Command ID:** LNX-CMD-003. **Purpose:** choose project directory. **Run in:** Bash. **Working directory:** clone parent. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** statically verified.

```bash
cd ADAF-RedTeam
```

## Create an Isolated Environment

**Command ID:** LNX-CMD-004. **Purpose:** isolate Python packages. **Run in:** Bash. **Working directory:** repository root. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** creates `.venv`. **Validation:** statically verified.

```bash
python3 -m venv .venv
```

## Install Project Dependencies

**Command ID:** LNX-CMD-005. **Purpose:** install project/dev dependencies. **Run in:** Bash. **Working directory:** repository root. **Privilege:** ordinary user. **Internet:** required. **Safe to copy:** yes. **Replace:** none. **Side effects:** packages in `.venv`. **Validation:** statically verified.

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

Success is exit code 0. For an approved proxy or offline mirror, use the organization process; do not disable certificate validation.

## Build or Install the Project

The editable install above is the documented development install. There is no documented container, daemon, service, browser, database, or root build path.

## Verify the Installation

**Command ID:** LNX-CMD-006. **Purpose:** check local prerequisites. **Run in:** Bash. **Working directory:** repository root. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** statically verified.

```bash
.venv/bin/python -m adaf_redteam doctor
```

Success is PASS for Python, jsonschema, project metadata, example engagement, guides, and output directory. If `ADAF-RT-E204` appears, repeat LNX-CMD-005 after resolving your approved package source.

## Complete the First Safe Successful Run

**Command ID:** LNX-CMD-007. **Purpose:** view capability availability. **Run in:** Bash. **Working directory:** repository root. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** statically verified.

```bash
.venv/bin/python -m adaf_redteam list-capabilities
```

It lists every capability as currently unavailable for live use. Then run this command from the repository root:

**Command ID:** LNX-CMD-008. **Purpose:** write a safe plan. **Run in:** Bash. **Working directory:** repository root. **Privilege:** ordinary user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** writes plan and manifest. **Validation:** statically verified.

```bash
.venv/bin/python -m adaf_redteam run --engagement examples/engagement.example.json --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out ./out
```

It creates `out/plan.json` and `out/manifest.json`; it is statically verified only. The address is an example only, not a real authorization.

## Understand the Screen Output, Exit Status, and Result Files

Exit 0 and “plan written” show success. `plan.json` must say `planOnly: true`; the decision trace states no network, authentication, KDC, mutation, or outbound activity. `E100`–`E109` are scope/safety refusals; `E202` means unavailable live collector.

The full stable error identifier is `ADAF-RT-E202`; it indicates an unavailable live collector.

## Common Novice Workflows

`doctor` diagnoses prerequisites. `list-capabilities` shows current availability. `reference` prints the generated table. Fixture execution is advanced and requires engagement approval; do not begin with it.

## Configuration, Environment Variables, and Credentials

The example engagement is not a real scope. `ADAF_RT_LAB=1` is only for certification-development work; do not set it during first use. Do not put any secret in command history, environment, source, evidence, or issue text.

## How to Stop or Cancel Safely

The plan-only command exits itself. Ctrl+C stops a local command; inspect output and do not retry non-plan state changes without the engagement owner. This workflow starts no service, listener, or container.

## Cleanup, Uninstall, and Host Restoration

After approved retention, remove only the known local `.venv` and `out` paths through your normal file manager or approved process. Never use broad deletion commands against an unfamiliar path.

## Update, Upgrade, Downgrade, and Rollback

Ask the maintainer for an intended commit/tag, inspect it with Git, and rerun doctor/plan-only. No remote release/tag was verified in this review, so there is no supported upgrade version to infer.

## Troubleshooting Matrix

| Symptom | Likely cause | Confirm | Safe fix | Verify |
|---|---|---|---|---|
| `python3` missing | prerequisite absent | version command fails | approved distribution process | rerun LNX-CMD-001 |
| venv module missing | distribution split package | `python3 -m venv` fails | approved package process | rerun LNX-CMD-004 |
| `E204` | dependencies missing | doctor reports jsonschema fail | rerun LNX-CMD-005 | doctor passes |
| `E202` | live collector uncertified | error text | use plan-only | plan completes |

## Frequently Asked Questions

Can I use sudo? Not for this workflow. Can I remove plan-only? No. Does Executable mean live readiness? No. Is Linux verified? The commands are static only until a clean supported Linux run is recorded.

## Command Quick Reference

`doctor` validates local prerequisites; `list-capabilities` shows availability; `reference` prints docs; `run --plan-only` writes safe plan/manifest; `--fixture` is advanced offline testing.

## Glossary

Repository: project files; terminal: command window; shell: Bash command language; command: instruction; working directory: current folder; absolute/relative path: full/from-current location; runtime: Python; dependency: required package; package manager: pip; virtual environment: isolated packages; container: isolated runtime; environment variable: process setting; configuration file: engagement JSON; Administrator/root/sudo: elevated accounts; stdout/stderr: normal/error output; exit code: success/failure number; process: running program; service: background program; port/listener: network endpoint; log: diagnostic record; artifact/report: generated file; clone/pull/update/upgrade/downgrade/rollback/cleanup/uninstall: source and lifecycle operations.

## Validation Record, Known Limitations, and Support Boundaries

This guide is statically verified at `b67175e` on 2026-08-04. No Linux host, clean install, live target, fixture execution, cleanup recovery, or live capability was tested. It must be promoted only after a clean supported Linux CI/VM validation records the result.

---
guide_id: windows-novice-usability
guide_schema_version: 1
platform: windows
canonical_path: docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-RedTeam
target_release: "latest locally verifiable source version: 0.1.0"
target_commit: b67175ed4c232f32daa05cffc54674cfb65265dc
support_status: native_supported
alternative_support_paths: []
validation_status: partially_verified
validated_on: 2026-08-04
validated_environments: ["Windows review host; Python 3.12.13 disposable virtual environment"]
primary_shells: ["Windows Terminal PowerShell"]
maintainer_source_of_truth: "README.md, pyproject.toml, adaf_redteam/__main__.py"
known_limitations: ["No clean end-user install was run", "All live capabilities are uncertified"]
---

# ADAF-RedTeam Windows Novice Usability Guide

## About This Guide

This is a safe setup and plan-only guide for an authorized operator. It is not permission to test any system. The reviewed safe commands are PARTIALLY VERIFIED; live capability use is unavailable.

## What This Project Does

It produces an authorization-gated AD validation plan or a redacted ADAF result. A plan-only run makes no network, authentication, KDC, mutation, or outbound request.

## Who Should Use It

Use it only if your organization has given you a written scope. It is not a general AD scanner and is not a credential, ticket, or loot-export tool.

## Safety, Authorization, and Data Handling

Use only the committed example for this first run. A real engagement must name exact targets, approved source addresses, techniques, limits, and—in state-changing cases—risk/cleanup/lab approvals. Never commit real engagements, credentials, tickets, keys, or results. Do not remove `--plan-only` for this guide.

## Platform Support Status

Native Windows PowerShell is the documented path. This review ran the safe workflow on Windows with a disposable Python 3.12.13 environment. WSL, Git Bash, Docker, and live AD use are not validated by this guide.

## What You Will Accomplish

You will verify local prerequisites, view availability, and write a safe plan plus manifest under `out`. You will not contact a target.

## Before You Begin Checklist

You need a normal Windows user account, Windows Terminal/PowerShell, Python 3.10 or newer, Git or an approved ZIP source, write access to a folder you own, and internet access only for dependency installation. No Administrator rights, target credential, listener, service, or open port is needed for the first run.

## Computer and Software Requirements

The project states Python `>=3.10`; CPU, RAM, disk, and Windows edition minimums are not published. Reserve a few hundred MB for Python packages. Do not guess an installer command if Python, Git, or `venv` is missing—use your organization’s approved software process.

## Terms and Concepts You Need to Know

An **engagement** is the machine-readable scope; a **capability** is one named validation; **plan-only** is a dry run; an **artifact** is an output file. `Executable` is a target authorization class, not proof that a live operation is currently available.

## Choose the Correct Installation Path

Recommended: clone the approved repository into a folder you own and create `.venv`. If Git is unavailable, download an approved ZIP, extract it, and then start at “Find and Enter the Repository Folder.” Do not use a personal fork unless your maintainer approves it.

## Open the Correct Terminal or Shell

Open Windows Terminal and choose **PowerShell**. All commands below use PowerShell; do not paste them into Command Prompt or Git Bash.

## Check and Install Prerequisites

**Command ID:** WIN-CMD-001  
**Purpose:** confirm the Python launcher and version.  
**Run in:** PowerShell. **Working directory:** any. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** partially verified.

```powershell
py -3 --version
```

Success is Python 3.10 or later. If `py` is unavailable, stop and use your approved Python installation process; do not change execution policy or TLS settings.

## Download or Clone the Repository

`YOUR_REPOSITORY_URL` means the maintainer-provided URL; example: `https://github.com/rikterskale/ADAF-RedTeam.git` only when your access is approved.

**Command ID:** WIN-CMD-002  
**Purpose:** clone source. **Run in:** PowerShell. **Working directory:** folder you own. **Privilege:** standard user. **Internet:** required. **Safe to copy:** only after replacing URL. **Side effects:** creates folder. **Validation:** statically verified.

```powershell
git clone YOUR_REPOSITORY_URL ADAF-RedTeam
```

## Find and Enter the Repository Folder

**Command ID:** WIN-CMD-003  
**Purpose:** set the working directory. **Run in:** PowerShell. **Working directory:** clone parent. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** statically verified.

```powershell
Set-Location .\ADAF-RedTeam
```

## Create an Isolated Environment

**Command ID:** WIN-CMD-004  
**Purpose:** create project-local Python environment. **Run in:** PowerShell. **Working directory:** repository root. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** creates `.venv`. **Validation:** verified in disposable environment.

```powershell
py -3 -m venv .venv
```

## Install Project Dependencies

**Command ID:** WIN-CMD-005  
**Purpose:** install the project and development checks. **Run in:** PowerShell. **Working directory:** repository root. **Privilege:** standard user. **Internet:** required. **Safe to copy:** yes. **Replace:** none. **Side effects:** packages inside `.venv`. **Validation:** verified in disposable environment.

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Success is exit code 0. If an approved proxy or offline wheel process is required, use it; never disable certificate validation.

## Build or Install the Project

The preceding editable install is the supported development install. No separate build, service, container, or Administrator step is documented.

## Verify the Installation

**Command ID:** WIN-CMD-006. **Purpose:** check local prerequisites. **Run in:** PowerShell. **Working directory:** repository root. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** verified.

```powershell
.\.venv\Scripts\python.exe -m adaf_redteam doctor
```

Expected output: PASS for Python, jsonschema, project metadata, example engagement, guides, and output directory. `ADAF-RT-E204` means dependencies are missing; repeat WIN-CMD-005 in the repository root.

## Complete the First Safe Successful Run

**Command ID:** WIN-CMD-007. **Purpose:** view capability availability. **Run in:** PowerShell. **Working directory:** repository root. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** none. **Validation:** verified.

```powershell
.\.venv\Scripts\python.exe -m adaf_redteam list-capabilities
```

It lists every capability as currently unavailable for live use. Then run the following exact plan. It uses only the committed example and does not contact AD.

**Command ID:** WIN-CMD-008. **Purpose:** write a safe plan. **Run in:** PowerShell. **Working directory:** repository root. **Privilege:** standard user. **Internet:** not required. **Safe to copy:** yes. **Replace:** none. **Side effects:** writes plan and manifest. **Validation:** verified.

```powershell
.\.venv\Scripts\python.exe -m adaf_redteam run --engagement examples\engagement.example.json --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out .\out
```

This is the committed example only; it creates `out\plan.json` and `out\manifest.json` and was verified in this review. `192.0.2.25` is never a real authorization.

## Understand the Screen Output, Exit Status, and Result Files

Exit 0 and “plan written” mean success. The plan states `planOnly: true` and its decision trace says no network/authentication/KDC/mutation/outbound activity. `manifest.json` inventories output hashes. `ADAF-RT-E100`–`E109` are scope/safety refusals; follow the printed remedy rather than editing scope to bypass it. `E202` is an unavailable live collector.

## Common Novice Workflows

Use `doctor` before setup troubleshooting, `list-capabilities` to read availability, and `reference` to print the generated table. Fixture-backed execution is an advanced, engagement-approved workflow; it is not required for first success.

## Configuration, Environment Variables, and Credentials

`examples\engagement.example.json` is an example, not authorization. The project has an `ADAF_RT_LAB=1` certification-development opt-in; do not set it for routine use. Do not place secrets in environment variables, command history, commits, results, or issue reports.

## How to Stop or Cancel Safely

The plan-only command ends on its own. Press Ctrl+C only to stop a local command before completion; then inspect `out` and do not retry a non-plan state-changing operation without the engagement owner. No service/listener is started by this workflow.

## Cleanup, Uninstall, and Host Restoration

After your approved retention period, delete only the confirmed local `out` and `.venv` folders from the repository root using your organization’s normal file-management process. Do not delete an unknown path or any real engagement evidence before its retention owner approves.

## Update, Upgrade, Downgrade, and Rollback

Before changing source, preserve approved evidence, ask the maintainer for the intended commit/tag, use Git to inspect the change, then rerun `doctor` and plan-only. No released tag was verifiable during review, so do not infer an upgrade target.

## Troubleshooting Matrix

| Symptom | Most likely cause | Confirm | Exact safe fix | Verify |
|---|---|---|---|---|
| `py` not found | Python launcher absent | `py -3 --version` fails | approved Python install | rerun WIN-CMD-001 |
| `E204` | dependencies missing | `doctor` says jsonschema FAIL | rerun WIN-CMD-005 | `doctor` all PASS |
| `E100`–`E109` | scope gate refusal | read printed code/remedy | obtain corrected written scope; do not bypass | plan-only with approved example |
| `E202` | live collector uncertified | error text says unavailable | use plan-only; seek certification | plan completes |

## Frequently Asked Questions

**Can I remove `--plan-only`?** Not for first use. **Does Executable mean usable on production?** No. **Where are credentials?** This guide uses none. **Can I test a real domain?** Only under a separate written, exact, approved engagement and certification status.

## Command Quick Reference

`doctor` checks local readiness; `list-capabilities` lists target classes and unavailable status; `reference` prints capability docs; `run --plan-only` writes a safe plan; `run --fixture` is advanced offline testing.

## Glossary

Repository: project files; terminal: command window; shell: command language; command: instruction; working directory: current folder; absolute/relative path: full/from-current location; runtime: Python; dependency: required package; package manager: pip; virtual environment: isolated packages; container: isolated runtime; environment variable: process setting; configuration file: engagement JSON; Administrator/root/sudo: elevated accounts; stdout/stderr: normal/error messages; exit code: success/failure number; process: running program; service: background program; port/listener: network endpoint; log: diagnostic record; artifact/report: generated file; clone/pull/update/upgrade/downgrade/rollback/cleanup/uninstall: obtain/change/revert/remove software or files.

## Validation Record, Known Limitations, and Support Boundaries

This guide is PARTIALLY VERIFIED at `b67175e` on 2026-08-04. The safe Windows workflow and disposable install were run; clean end-user installation, real AD, fixture execution, cleanup latch recovery, and every live capability were not. Do not claim native live support from this guide.

# ADAF-RedTeam Windows Guide

## Status

**PARTIALLY VERIFIED** on 2026-08-04 against source version 0.1.0. The safe `doctor`, `list-capabilities`, and `--plan-only` workflow was run with Python 3.12. Native Windows installation and every live capability remain unverified. This is an authorized-operator guide, not permission to test a target.

## Supported path and safety boundary

Use Windows Terminal **PowerShell** with Python 3.10 or later. The repository does not claim WSL, Git Bash, Docker, or a live Active Directory path as supported. Do not use a real target, credential, or non-example engagement for first use. Every registered capability is currently uncertified; `Executable` is not a live-readiness claim.

## Install

Run these commands in PowerShell from a folder you own. `YOUR_REPOSITORY_URL` is a maintainer-authorized URL only.

```powershell
py -3 --version
git clone YOUR_REPOSITORY_URL ADAF-RedTeam
Set-Location .\ADAF-RedTeam
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Success: the final command exits `0`. If `py` is not found, use your organization’s approved Python installation process; do not alter execution policy or TLS checks. If pip is blocked, use the approved package mirror or offline-wheel process.

## Safe first workflow

Run all commands from the repository root. These commands do not contact an AD target.

```powershell
.\.venv\Scripts\python.exe -m adaf_redteam doctor
.\.venv\Scripts\python.exe -m adaf_redteam list-capabilities
.\.venv\Scripts\python.exe -m adaf_redteam run --engagement examples\engagement.example.json --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out .\out
```

Success: `doctor` prints only `PASS` lines, capability output explains each item is uncertified, and the last command writes `out\plan.json` and `out\manifest.json`. The plan contains no network, authentication, KDC, mutation, or outbound activity. The manifest contains only artifact names, sizes, and checksums.

## Read results and recover safely

`ADAF-RT-E100` through `E109` mean a scope or safety gate refused the action; follow its printed remedy and do not edit an engagement to bypass it. `ADAF-RT-E202` means the live collector is unavailable; use `--plan-only` or an approved fixture. `ADAF-RT-E203` means cleanup did not verify: stop, verify recovery with the engagement owner, then clear the latch only under the documented recovery process.

## Configuration, cleanup, and next steps

`examples\engagement.example.json` is an example scope file, not a reusable authorization. Do not commit real engagements, credentials, tickets, keys, or results. Keep output evidence under the engagement retention policy. After authorized retention, delete only the confirmed local `out` directory and `.venv` directory. Before any non-fixture activity, read the [capability reference](../CAPABILITY_REFERENCE.md), [certification gate](../CERTIFICATION.md), and engagement owner’s rules of engagement.

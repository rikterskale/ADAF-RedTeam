# First Certification Session (Coach and Operator)

Use this document for the first live certification session. It supports
**Windows Terminal using PowerShell** only. A senior red teamer (the **coach**)
must be present for every live-test step. Start with `asrep-roast-validation`
only.

This is a disposable-lab procedure. It is never permission to test production
or any network the coach has not named in the written engagement.

## One rule

If you are unsure, see `FAIL`, `SKIPPED`, or an unexpected name/address:
**stop and ask the coach. Do not guess or retry repeatedly.**

## Who does what

| Person | Responsibility |
|---|---|
| Operator | Follows commands, saves logs, and stops when instructed. |
| Coach / lab administrator | Confirms the lab, prepares accounts/settings, and fixes technical problems. |
| Certification owner | Owns evidence and promotion request; may also be coach. |
| Independent reviewer | Checks evidence and signs off; must not be the certification owner. |

The operator never edits `registry.py`, sets `lab_certified=True`, or approves
their own evidence.

## Before opening a terminal

The coach records these in the ticket: operator, coach, owner, reviewer, ticket
number, lab name, snapshot name/time, exact lab target, expected result, and
evidence template `docs/certifications/asrep-roast-validation.md`.

The coach confirms that the lab is isolated, disposable, and restorable. If any
item is unknown, the session does not start.

## 1. Open PowerShell in the project folder

Open **Windows Terminal**, select **PowerShell**, and use the exact project path
provided by the coach:

```powershell
Set-Location 'C:\Users\YOUR-NAME\Documents\GitHub\ADAF-RedTeam'
```

**Good result:** no message; the prompt ends in `ADAF-RedTeam>`.

**If it fails:** stop. The coach provides the correct path.

## 2. Confirm Python and run offline checks

```powershell
py -3 --version
```

**Good result:** `Python 3.10.x` or newer. If `py` is not recognized or the
version is older, stop. Do not download software or change security settings.
The coach follows the approved installation process.

If the coach says the local project environment is not ready, the coach runs:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[ldap,kerberos,dev]"
```

Then run the safe offline check. It does not contact the lab.

```powershell
.\.venv\Scripts\python.exe -m pytest -q 2>&1 | Tee-Object -FilePath offline-pytest-log.txt
```

**Good result:** final summary says tests `passed` and none says `FAILED`.

**If it fails:** stop. Leave `offline-pytest-log.txt` in place and give its name
to the coach. Do not run a live test.

## 3. Coach prepares and preflights lab settings

The coach creates the ignored local file `.env.lab.ps1` with approved lab values.
The operator does not invent, inspect, email, commit, or paste those values into
chat.

Run the local-only preflight:

```powershell
.\.venv\Scripts\python.exe .\scripts\certification_preflight.py --capability asrep-roast-validation
```

**Good result:** every check starts with `PASS`, ending with:

```text
PASS: Local preflight complete. This does not authorize or start a live test.
```

**If any check starts with `FAIL`:** stop. Copy the complete output into the
ticket without adding secret values. The coach fixes the named issue. Never edit
the preflight script to bypass a failure.

## 4. Coach confirms the lab objects

The coach confirms two lab-only accounts: one configured for the expected
positive result and one normal account for the expected negative result. The
operator does not change Active Directory settings. If the coach cannot confirm
both accounts and the lab snapshot, stop.

## 5. Run one live test

For the first AS-REP session, load approved settings and run exactly this test.
`--basetemp` keeps result files in an ignored local folder.

```powershell
. .\.env.lab.ps1
.\.venv\Scripts\python.exe -m pytest tests\test_certification_asrep_roast.py -v -rA --basetemp .\certification-work\asrep-roast-validation 2>&1 |
  Tee-Object -FilePath asrep-cert-log.txt
```

| What you see | Meaning | What you do |
|---|---|---|
| Two tests end in `PASSED`; summary says `2 passed` | Lab test completed | Continue to step 6. `UNVALIDATED` is expected before promotion. |
| `SKIPPED` | Setup/dependency missing; not a pass | Stop and give the skip reason to the coach. |
| `FAILED`, authorization/containment error, unexpected verdict, or redaction warning | Session needs review | Stop. Preserve `asrep-cert-log.txt`; do not retry or change target. |

## 6. Collect clean evidence

Run the collector only after a green test. It copies nothing if the redaction
scan finds a possible secret.

```powershell
.\.venv\Scripts\python.exe .\scripts\collect_certification_evidence.py `
  --test-output-root .\certification-work\asrep-roast-validation `
  --capability asrep-roast-validation `
  --ticket YOUR-CERTIFICATION-TICKET
```

**Good result:**

```text
PASS  Redaction scan: CLEAN
PASS  Evidence saved to: certification-evidence\YOUR-CERTIFICATION-TICKET\asrep-roast-validation
```

**If it reports `FAIL` or possible secret material:** stop. Do not open, email,
attach, or commit the source files. Restrict access to the source folder and
give the complete output to the security owner.

For a capability that requires packet capture, the coach records its hash and
approved storage location in the evidence form; raw captures never go in Git.

## 7. Hand off and end the session

Attach to the ticket:

- `offline-pytest-log.txt`
- `asrep-cert-log.txt`
- clean files and `collection-log.txt` under `certification-evidence/...`
- completed `docs/certifications/asrep-roast-validation.md`
- required lab/read-only attestation and packet-capture information

Then stop. The owner and reviewer use the
[Certification Standard and Maintainer Checklist](../ADAF-RedTeam_Capability_Certification_Howto.md).
The operator does not promote the capability.

## Say this to the coach

- “I am not sure this is the disposable lab, so I stopped.”
- “The offline tests failed; the log is `offline-pytest-log.txt`.”
- “The preflight failed; I copied the output to the ticket.”
- “The live test skipped; this is not a pass.”
- “The live test failed; the log is `asrep-cert-log.txt`.”
- “The redaction scan was not clean, so I stopped.”

## Further reading

| Need | Document |
|---|---|
| Policy, review, promotion, or de-certification | [Certification Standard and Maintainer Checklist](../ADAF-RedTeam_Capability_Certification_Howto.md) |
| Authoritative rules | [CERTIFICATION.md](../CERTIFICATION.md) |
| Capability-specific evidence | [certifications/](../certifications/) |
| Safe plan-only first use | [Windows novice guide](WINDOWS_NOVICE_USABILITY_GUIDE.md) |

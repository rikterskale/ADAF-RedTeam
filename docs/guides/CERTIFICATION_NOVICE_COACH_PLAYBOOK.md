# Certification Playbook for New Operators (Coach-Monitored)

**Project:** ADAF-RedTeam  
**Who this is for:** A person who is new to computers, terminals, and Active Directory  
**Who must sit with you:** A senior red teamer (your **coach**). You do not run lab tests alone.

---

## Read this first (60 seconds)

### What you are doing

You are helping **prove** that one safety-checked test works correctly against a **practice** Active Directory network (a **lab**). That proof is called **certification**.

You are **not**:

- Attacking a real company network
- Collecting real passwords
- "Hacking" anything without permission
- Allowed to change project settings that say a test is certified

### Two roles

| Role | What they do |
|------|----------------|
| **You (operator)** | Follow this list in order. Copy commands only when the coach says to. Save log files. Fill checkboxes. Say "stop" if anything looks wrong. |
| **Coach (senior red teamer)** | Provides all real names, addresses, and accounts. Watches every step. Fixes technical problems. Decides when it is safe to continue. |

**Rule:** If you do not understand a step, stop and ask the coach. Guessing is not allowed.

### Words you need (plain English)

| Word | Meaning |
|------|---------|
| **Terminal** | A text window where you type commands and press Enter |
| **Command** | One line of text you type or paste into the terminal |
| **Folder / directory** | A place that holds files (like a filing cabinet drawer) |
| **Repository / repo** | The project folder that contains ADAF-RedTeam |
| **Lab** | A practice network built only for testing; safe to break and rebuild |
| **Production** | The real work network. **Never** use these steps against production |
| **PASS** | The test succeeded |
| **FAIL** | The test failed — stop and show the coach |
| **SKIPPED** | The test did not run (usually missing settings) — not a pass |
| **Log file** | A text file that saves everything the terminal printed |
| **Evidence** | Files and filled forms that prove the test was done correctly |
| **Coach** | The senior red teamer watching you |

---

## Safety rules (non-negotiable)

1. **Coach present** for every command after "Open the terminal."
2. **Lab only.** If you are unsure whether a name or address is lab or real, **stop**.
3. **Do not invent** usernames, passwords, IP addresses, or domain names. Only use values the coach gives you.
4. **Do not type passwords into chat, email, or tickets** unless the coach explicitly directs an approved secret-handling process.
5. **Do not** set `lab_certified=True` or edit `registry.py`. That is a later maintainer step after evidence and review.
6. **Do not** run tests against any system the coach has not named as the disposable lab.
7. If the screen shows many lines of red errors and the coach is not looking, **say "stop" out loud**.

---

## Before you start — paper checklist

Fill this with the coach. Do not continue until every line has an answer.

| # | Item | Your notes |
|---|------|------------|
| 1 | Today's date | |
| 2 | Your name (operator) | |
| 3 | Coach's name | |
| 4 | Ticket / tracking number | |
| 5 | Lab name (plain words) | |
| 6 | Coach confirms: lab is disposable and not production | ☐ Yes |
| 7 | Capability for this session (start with AS-REP only) | `asrep-roast-validation` |
| 8 | Computer you will use (coach chooses) | ☐ Linux ☐ Other (coach leads) |

**First session goal:** Complete **only** the AS-REP certification test path below (or stop cleanly with logs). Do not start other capabilities the same day unless the coach says so.

---

## Part 0 — Finish the safe beginner guide first

If you have never run ADAF-RedTeam before:

1. Open `docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md` with the coach.
2. Complete **plan-only** steps only (no lab live tests).
3. Come back here when the coach says the safe first run worked.

If the coach already completed that with you, continue.

---

## Part 1 — Open the terminal and go to the project folder

### Step 1.1 — Open a terminal

**Coach shows you** how on your computer (for example: application named "Terminal").

You should see a blinking cursor and a short prompt, often ending in `$`.

**If you cannot find Terminal:** stop. Ask the coach. Do not download random software.

### Step 1.2 — Go to the project folder

The coach will give you the exact path. Example shape only:

```bash
cd /REPLACE_WITH_PATH_COACH_GIVES/ADAF-RedTeam
```

Press **Enter**.

**Check:**

```bash
pwd
ls
```

**You should see** folder names including something like:

```text
adaf_redteam
docs
tests
examples
```

**If you see** `No such file or directory`:

- You are in the wrong place.
- Ask the coach for the correct `cd` path.
- Do not continue.

**If you see** only unrelated files:

- Wrong folder. Stop. Coach fixes the path.

---

## Part 2 — Use the project’s Python (do not install random tools)

### Step 2.1 — Confirm Python in the project environment

Coach may have already created a virtual environment (a private toolbox) named `.venv`.

```bash
ls .venv/bin/python
```

**Success looks like:** the command prints a path and does not say "No such file".

**If missing:** coach runs the setup from the Linux novice guide (`python3 -m venv .venv` and install). You wait.

### Step 2.2 — Check version

```bash
.venv/bin/python --version
```

**Success example:**

```text
Python 3.12.3
```

Any **3.10 or newer** is OK.

**If command not found:** stop. Coach repairs the environment.

---

## Part 3 — Offline safety check (no lab required)

This proves the software’s basic tests pass on your machine **without** talking to the lab.

### Step 3.1 — Run offline tests and save a log

```bash
.venv/bin/python -m pytest -q 2>&1 | tee offline-pytest-log.txt
```

What this means in plain language:

- Run the automatic checks quietly
- Show the text on screen **and** save it into `offline-pytest-log.txt`

**Success (shape):** the last lines look like:

```text
.....                                                                  [100%]
42 passed in 3.10s
```

(The number of tests can differ. "passed" and no long FAIL block is what matters.)

**Failure:** you see `FAILED` in red or many traceback walls of text.

**What you do:**

1. Do not run lab tests.
2. Tell the coach: "Offline tests failed."
3. Leave `offline-pytest-log.txt` for the coach.

**Common coach fixes (you do not run these unless told):**

- Reinstall: `.venv/bin/python -m pip install -e ".[ldap,kerberos,dev]"`
- Wrong folder
- Broken virtual environment (recreate `.venv`)

### Step 3.2 — Confirm the log file exists

```bash
ls -la offline-pytest-log.txt
```

**Success:** a file size larger than zero.

---

## Part 4 — Lab settings (coach prepares; you only load)

### Step 4.1 — Coach creates `.env.lab`

The coach creates a file named `.env.lab` in the project folder with **real lab values**.

You must **not** copy example names like `corp.contoso.test` unless the coach says those are truly your lab.

**You never commit this file to Git.** The coach will ensure it stays private.

### Step 4.2 — Load the settings into this terminal

```bash
set -a && source .env.lab && set +a
```

**Expected:** usually no message (blank success is normal).

**If you see** `No such file or directory`:

- `.env.lab` is missing or you are in the wrong folder.
- Coach fixes it.

### Step 4.3 — Verify the important switches (safe to print)

```bash
echo "LAB_FLAG=$ADAF_RT_LAB"
echo "DOMAIN=$ADAF_RT_LAB_DOMAIN"
echo "DC=$ADAF_RT_LAB_DC"
echo "ASREP_USER=$ADAF_RT_LAB_ASREP_ROASTABLE_USER"
echo "ASREP_NORMAL=$ADAF_RT_LAB_ASREP_PREAUTH_USER"
```

**Success:**

```text
LAB_FLAG=1
DOMAIN=...something the coach recognizes...
DC=...something the coach recognizes...
ASREP_USER=...non-empty...
ASREP_NORMAL=...non-empty...
```

**If `LAB_FLAG` is empty or not `1`:**

- Stop. Lab mode is off.
- Coach reloads `.env.lab`.
- Run Step 4.2 and 4.3 again.

**If domain/DC look like the training examples and coach says "that is not our lab":**

- Stop immediately.

---

## Part 5 — First live certification path: AS-REP only

### What this test is (plain language)

It checks whether the lab correctly reports:

- One account that is configured in a special "no pre-authentication" way
- One normal account

It must **not** save password material into results.

### Step 5.1 — Coach confirms lab objects exist

You wait. Coach verifies lab users exist and are safe to test.

**You do not change Active Directory settings** unless the coach is driving and you are only watching.

### Step 5.2 — Run the AS-REP certification test with full logging

```bash
.venv/bin/python -m pytest tests/test_certification_asrep_roast.py -v -s 2>&1 | tee asrep-cert-log.txt
```

### Step 5.3 — Read the ending carefully

#### Outcome A — SKIPPED (most common if settings missing)

Example shape:

```text
SKIPPED [1] ... lab-gated certification test; missing env: [...]
```

**Meaning:** The test did not run. This is **not** a pass.

**Fix:** Coach checks `.env.lab` and required variable names. You reload (Part 4) and retry Step 5.2.

#### Outcome B — PASSED

Example shape:

```text
tests/test_certification_asrep_roast.py::... PASSED
tests/test_certification_asrep_roast.py::... PASSED
```

**Meaning:** This machine + lab settings produced the expected results for the automated checks.

**You still must** complete evidence steps below. Certification is not finished at PASS alone.

#### Outcome C — FAILED

Example shape:

```text
FAILED
AssertionError
```

or long Python tracebacks.

**Meaning:** Stop.

**What you do:**

1. Say "failed" to the coach.
2. Keep `asrep-cert-log.txt`.
3. Do not rerun in a loop without the coach changing something deliberate.
4. Do not try other capabilities "to see if they work."

### Step 5.4 — Common failure messages (coach + you)

| What you roughly see | Plain meaning | What happens next |
|----------------------|---------------|-------------------|
| Connection / timeout errors | Cannot reach the lab computer | Coach checks network/VPN/lab power |
| Principal unknown / no such user | Username not in lab | Coach fixes account names in `.env.lab` |
| Always wrong verdict | Lab account flags not set as expected | Coach fixes lab user configuration |
| Permission / bind errors | Lab login identity not accepted | Coach fixes bind user or Kerberos ticket |
| `NOT CERTIFIED` style refusal | Lab flag or gate blocked the run | Coach verifies `ADAF_RT_LAB=1` and engagement rules inside the test |

You do not need to memorize codes. You need to **save the log** and **stop**.

---

## Part 6 — Save evidence files (operator checklist)

Create a simple evidence folder (coach may choose the exact name):

```bash
mkdir -p evidence/asrep-roast-validation
cp offline-pytest-log.txt evidence/asrep-roast-validation/
cp asrep-cert-log.txt evidence/asrep-roast-validation/
ls -la evidence/asrep-roast-validation/
```

**Success:** both log files listed.

**Coach may also copy** a `validation-result.json` from a temporary output directory into this folder. You do not hunt for it alone if you cannot see it—ask.

### Redaction check (coach watches)

The coach will run a search that looks for secret-looking text. Example:

```bash
grep -Eri 'password|nthash|ntlm|krbtgt:|-----BEGIN|cipher:|\$krb5asrep\$' evidence/asrep-roast-validation/ || echo clean
```

**Success:**

```text
clean
```

**If any matching lines appear:**

- **STOP**
- Do not share the folder widely
- Do not commit files to Git
- Coach handles incident process for the **lab** if needed

---

## Part 7 — Fill the evidence form (together)

Open this file with the coach:

`docs/certifications/asrep-roast-validation.md`

For every blank (`__________`) or empty checkbox:

1. Coach provides the true fact
2. You type it or watch the coach type it
3. Do not mark complete items you did not actually do

Minimum items for a novice session:

- Date, lab name, ticket
- Operator name, coach name
- "Offline tests passed" with log filename
- "Live AS-REP test passed" with log filename
- Redaction result `clean`
- Notes of any SKIP/FAIL that required a fix

**Independent reviewer:** must be a different person from the operator who claims ownership of the technical implementation. Your coach will explain who signs.

---

## Part 8 — What you do **not** do after a green AS-REP run

1. Do not edit `adaf_redteam/capabilities/registry.py`
2. Do not set `lab_certified=True`
3. Do not open a "promote everything" request
4. Do not run Kerberoast, DCSync, LAPS, gMSA, Zerologon the same day unless the coach starts a **new** checklist for that capability

Promotion is a **maintainer** step after evidence + reviewer sign-off. It is intentionally separate.

---

## Part 9 — If the coach starts a second capability later

Repeat the same pattern:

1. Offline tests still green (`tee` a new log if the coach wants)
2. Load `.env.lab`
3. Run **one** matching file, for example:

```bash
.venv/bin/python -m pytest tests/test_certification_kerberoast.py -v -s 2>&1 | tee kerberoast-cert-log.txt
```

4. Save logs under `evidence/<capability-id>/`
5. Fill that capability's markdown template
6. Stop

Never change multiple capabilities' certification status in one unsupervised action.

---

## Part 10 — End-of-session shutdown

With the coach:

1. ☐ Logs saved under `evidence/...`
2. ☐ Evidence form updated
3. ☐ `.env.lab` not copied to USB/email/chat
4. ☐ Terminal can be closed
5. ☐ You know whether the result was PASS, FAIL, or STOP-WITH-LOGS

Optional (coach decides):

```bash
mkdir -p evidence/session-notes
echo "Session ended $(date -u)" | tee evidence/session-notes/end.txt
```

---

## Quick "what should I see?" card

| Step | Command idea | Good ending |
|------|--------------|-------------|
| Folder check | `ls` | See `tests` and `docs` |
| Offline tests | `pytest -q` via `.venv` + `tee` | `passed` summary |
| Load lab | `source .env.lab` | `LAB_FLAG=1` |
| AS-REP cert | `pytest tests/test_certification_asrep_roast.py -v -s` + `tee` | `PASSED` (or clear SKIPPED/FAIL handled by coach) |
| Redaction | `grep ... || echo clean` | `clean` |

---

## Troubleshooting for novices (say these sentences to the coach)

Use these exact phrases:

1. "I'm not in the project folder—can you give me the `cd` path again?"
2. "Offline tests failed; the log is `offline-pytest-log.txt`."
3. "Lab flag is not 1 after sourcing `.env.lab`."
4. "The AS-REP test skipped and listed missing env."
5. "The AS-REP test failed; log is `asrep-cert-log.txt`."
6. "The redaction check was not clean."
7. "I don't know if this name is lab or production, so I stopped."

---

## Appendix A — Why the coach is required

This project talks to Active Directory lab services when certification tests run. Mistakes can:

- Target the wrong network if addresses are wrong
- Leave confusing lab account changes if someone experiments
- Leak sensitive lab data into tickets or Git if files are copied carelessly

The process is designed so a monitored novice can still help with disciplined execution and evidence, without owning irreversible technical decisions.

## Appendix B — Maintainer-only reminder (not for the novice)

After evidence is complete and an independent reviewer signs:

- One capability ID only
- Same change sets `lab_certified=True` and updates the certification test's UNVALIDATED assertion
- Never mass-flip flags

See `docs/Capability_Certification_Howto.md` and `docs/CERTIFICATION.md`.

## Appendix C — Relationship to other docs

| Doc | Use |
|-----|-----|
| `docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md` | First safe plan-only install/run |
| **This playbook** | Coach-monitored first certification path |
| `docs/Capability_Certification_Howto.md` | Full technical certification process |
| `docs/CERTIFICATION_RUNBOOK.md` | Env matrix and test file list |
| `docs/CERTIFICATION.md` | Policy gate (authoritative rules) |
| `docs/certifications/*.md` | Per-capability evidence forms |

# Capability Certification How-To

**ADAF-RedTeam** — operator guide

Use `docs/CERTIFICATION_RUNBOOK.md` + a disposable lab → fill evidence templates → get independent reviewer sign-off → promote `lab_certified=True` **one capability at a time**.

> **Policy sources:** [`CERTIFICATION.md`](CERTIFICATION.md) (gate, tiers, evidence, promotion) · [`CERTIFICATION_RUNBOOK.md`](CERTIFICATION_RUNBOOK.md) (env + run order) · [`certifications/`](certifications/) (per-capability templates)

---

## What this is / is not

**Is:** Step-by-step process to prove a live primitive in a disposable lab and promote one registry flag with evidence.

**Is not:**

- Approval to run against production (engagement authorization stays separate)
- A relaxation of gates (authorization, containment, cleanup latch, redaction still run)
- Transferable across capabilities (each is certified alone)
- A blanket flag flip

---

## 1. Mental model

Every capability ships with `lab_certified=False`. Uncertified live runs are stamped **UNVALIDATED**.

`lab_certified=True` means only: the live primitive was proven correct, bounded, and (higher tiers) reversible **in a disposable lab**, with a complete evidence package and an independent reviewer who did **not** write the primitive.

It only removes the UNVALIDATED stamp. It does **not** disable runtime gates.

### 1.1 Roles (no self-certification)

| Role | Responsibility |
|------|----------------|
| Certification owner | Runs live path, assembles evidence, owns the ticket |
| Independent reviewer | Did not write the primitive; verifies evidence, tests, and `plan()` bounds; signs off |
| Second approver | Required only for Tier E (destructive), e.g. `zerologon-reset` |

### 1.2 Tiers (summary)

| Tier | Examples | Extra bar |
|------|----------|-----------|
| A — read/metadata | asrep, kerberoast, dcsync-rights, laps, gmsa, zerologon-detection | No write; no secret export; pcap proof |
| B — reversible write | rbcd-write, shadow-cred, exec-proof-svcctl | Restore + cleanup latch proven |
| C — durable | adcs-esc1 | Honest `durableResidue`; lab rebuild |
| D — purple team | adversary-emulation-evasion | Detection block matches real SOC/EDR |
| E — destructive | zerologon-reset | Reset-then-restore; two-person rule |

This guide focuses on **Tier A** (first wave). Higher tiers reuse the same process with the extra bars above.

---

## 2. Non-negotiable preconditions

**Stop if any of these are false.**

Certification happens **only** in a disposable lab you can rebuild from scratch. No route to production. No shared trust with production. If a primitive cannot be made safe/reversible there, it stays `lab_certified=False` indefinitely — that is acceptable.

- Lab isolated; snapshot- or rebuild-capable
- Certification engagement JSON authorizes exact capability + targets, with `labAddressRanges` / `labResolvedAddresses` that pass containment for the lab and fail otherwise
- Work logged on a certification ticket with a named owner
- Packet capture available (required for Zerologon "no password-set" proof)
- Install: `python -m pip install -e ".[ldap,kerberos,dev]"`

---

## 3. Lab inventory and `.env.lab`

Create a local, **untracked** file (never commit secrets, tickets, or validation results):

```bash
# .env.lab — example only; replace every value
export ADAF_RT_LAB=1
export ADAF_RT_LAB_DOMAIN=corp.contoso.test
export ADAF_RT_LAB_DC=dc01.corp.contoso.test
export ADAF_RT_LAB_SOURCE_ADDR=10.10.0.50
export ADAF_RT_LAB_BIND_USER='CORP\\certuser'
# export ADAF_RT_LAB_BIND_PASSWORD='...'   # only if not using Kerberos ccache

# AS-REP
export ADAF_RT_LAB_ASREP_ROASTABLE_USER=svc-nopreauth
export ADAF_RT_LAB_ASREP_PREAUTH_USER=normaluser

# Kerberoast
export ADAF_RT_LAB_KERBEROAST_SPN=MSSQLSvc/db01.corp.contoso.test
export ADAF_RT_LAB_KERBEROAST_MISSING_SPN=http/does-not-exist.corp.contoso.test
export KRB5CCNAME=/tmp/lab.ccache

# DCSync / LAPS / gMSA principal under test
export ADAF_RT_LAB_TARGET_PRINCIPAL='S-1-5-21-...-512'
export ADAF_RT_LAB_EXPECTED=Confirmed

# LAPS
export ADAF_RT_LAB_LAPS_COMPUTER_DN='CN=PC01,CN=Computers,DC=corp,DC=contoso,DC=test'

# gMSA
export ADAF_RT_LAB_GMSA_DN='CN=gmsa-web,CN=Managed Service Accounts,DC=corp,DC=contoso,DC=test'

# Zerologon
export ADAF_RT_LAB_ZEROLOGON_TARGET=DC01

# Discovery
export ADAF_RT_LAB_QUOTA_EXPECTED=Confirmed
export ADAF_RT_LAB_PRIV_GROUP_DN='CN=Domain Admins,CN=Users,DC=corp,DC=contoso,DC=test'
export ADAF_RT_LAB_PRIV_EXPECTED=Confirmed
```

Load:

```bash
set -a && source .env.lab && set +a
```

### 3.1 Lab object preparation (Tier A examples)

**AS-REP positive case:**

```powershell
Set-ADAccountControl -Identity svc-nopreauth -DoesNotRequirePreAuth $true
Get-ADUser svc-nopreauth -Properties DoesNotRequirePreAuth |
  Select-Object DoesNotRequirePreAuth
```

**Kerberoast TGT:**

```bash
kinit certuser@CORP.CONTOSO.TEST
export KRB5CCNAME=/tmp/lab.ccache
klist
```

**LAPS / gMSA:** configure ACLs/membership for reader vs non-reader principals. Never retrieve password values during certification.

---

## 4. Capability matrix (Tier A first wave)

| Capability ID | Cert test | Evidence template |
|---------------|-----------|-------------------|
| `asrep-roast-validation` | `tests/test_certification_asrep_roast.py` | `docs/certifications/asrep-roast-validation.md` |
| `kerberoast-validation` | `tests/test_certification_kerberoast.py` | `docs/certifications/kerberoast-validation.md` |
| `dcsync-rights-validation` | `tests/test_certification_dcsync_rights.py` | `docs/certifications/dcsync-rights-validation.md` |
| `zerologon-detection` | `tests/test_certification_zerologon.py` | `docs/certifications/zerologon-detection.md` |
| `laps-read-authorization` | `tests/test_certification_laps_read.py` | `docs/certifications/laps-read-authorization.md` |
| `gmsa-read-authorization` | `tests/test_certification_gmsa_read.py` | `docs/certifications/gmsa-read-authorization.md` |
| `machine-account-quota-check` | `tests/test_certification_discovery.py` | Fill after first lab run |
| `privileged-group-inventory` | `tests/test_certification_discovery.py` | Fill after first lab run |

---

## 5. Universal checklist (every capability)

Promote only when **all** are true and evidenced (`CERTIFICATION.md` §1):

1. **Live primitive implemented and reviewed** — bounded to exactly what `plan()` describes
2. **Analyzer/orchestration unchanged** — offline unit tests still pass
3. **Redaction proven** — grep every artifact; secrets only via SecretVault handles
4. **Authorization gate honored** — wrong source/target/technique refused
5. **Idempotent / bounded** — second run does not compound state
6. **Evidence package complete** — attached to the ticket
7. **Independent review** — owner ≠ reviewer

Only then: set `lab_certified=True` for **that one** capability in `adaf_redteam/capabilities/registry.py`, in the **same PR** as the evidence and cert-test assertion updates.

### 5.1 Tier A extra proofs

- **No state change:** pcap / DC audit shows only reads or bounded metadata
- **No secret export:** AS-REP/Kerberoast cipher never written; DCSync issues no DRSUAPI; LAPS/gMSA never read password attributes
- **Zerologon-detection:** stops before `NetrServerPasswordSet2`; zero password-set calls; machine-account password unchanged

---

## 6. Execution procedure

### 6.1 Baseline offline suite

```bash
pytest -q
```

Offline `--fixture` runs do **not** count as certification.

### 6.2 Recommended live run order

```bash
set -a && source .env.lab && set +a

pytest tests/test_certification_asrep_roast.py -v
pytest tests/test_certification_kerberoast.py -v
pytest tests/test_certification_dcsync_rights.py -v
pytest tests/test_certification_laps_read.py -v
pytest tests/test_certification_gmsa_read.py -v
pytest tests/test_certification_discovery.py -v
# start packet capture first for Zerologon
pytest tests/test_certification_zerologon.py -v
```

### 6.3 Per-capability loop (one at a time)

1. Confirm lab objects and env vars for this capability only
2. Start capture if required (Zerologon)
3. Run matching `tests/test_certification_*.py`
4. On green: copy `validation-result.json` (+ journal) into the evidence package
5. Run redaction grep (§7.2)
6. Fill every placeholder in `docs/certifications/<id>.md`
7. Independent reviewer sign-off (§8)
8. Promotion PR (§9) for **this capability only**
9. After merge → next capability

### 6.4 Gate negative tests (record in evidence)

- Wrong source → refused (`ADAF-RT-E102`)
- Target not on engagement list → refused (`ADAF-RT-E103`)
- Wrong technique → refused (`ADAF-RT-E104`)
- Live without `ADAF_RT_LAB=1` while uncertified → NOT CERTIFIED path
- Non-lab containment addresses must fail where applicable

---

## 7. Evidence package

Attach to the certification ticket for **each** capability (`CERTIFICATION.md` §3):

1. Redacted engagement file + containment probe record
2. Read-only attestation (Tier A) or before/after state (B/C/E)
3. Redaction scan result (must be clean)
4. `validation-result.json` + transaction journal if present
5. Tier B/C/E: forced-failure latch run
6. Tier D: blue-team telemetry
7. Cert test path + green offline CI
8. Reviewer sign-off (and second approver for Tier E)

### 7.2 Redaction scan commands

```bash
grep -Eri 'password|nthash|ntlm|krbtgt:|-----BEGIN|cipher:|\$krb5asrep\$|\$krb5tgs\$|crackable|asrep-hash' <out>/ || echo clean

# Zerologon
grep -Eri 'passwordset|netrserverpasswordset|nthash|-----BEGIN' <out>/ || echo clean

# LAPS / gMSA
grep -Eri 'ms-mcs-admpwd:|managedpassword|msds-managedpassword|cleartext' <out>/ || echo clean
```

### 7.3 Zerologon pcap expectations

- Netlogon challenge/authenticate only
- `NetrServerPasswordSet2` count = **0**
- DC machine-account password / secure channel unchanged
- Record pcap hash in `docs/certifications/zerologon-detection.md`

---

## 8. Independent reviewer sign-off

Reviewer ≠ owner. Verify:

- Evidence artifacts exist and match template claims
- Live bounds match `plan()`
- Redaction scan clean
- Gate negatives documented
- Tier A: no state change on the wire / audit log
- Cert test is lab-gated (`ADAF_RT_LAB=1`) and skipped in normal CI

Record name, date, and notes in the template sign-off table. **No completed sign-off → no promotion PR.**

---

## 9. Mechanical promotion PR (one capability)

**Same PR only:** set `lab_certified=True` for exactly one capability ID in `registry.py`, remove the UNVALIDATED assertion in that cert test, and commit completed evidence markdown (no secrets).

### 9.1 PR checklist

1. Branch e.g. `cert/asrep-roast-validation`
2. Edit only that descriptor in `adaf_redteam/capabilities/registry.py`
3. Remove UNVALIDATED assertion in matching `tests/test_certification_*.py`
4. Commit filled `docs/certifications/<id>.md`
5. PR description: ticket link, evidence list, owner, reviewer
6. Offline CI green
7. Merge after review

### 9.2 Illustrative registry change

```python
CapabilityDescriptor(
    "asrep-roast-validation",
    "AS-REP roasting metadata",
    "kerberos",
    "Executable",
    "T1558.004",
    adapter=AsrepRoastCapability,
    lab_certified=True,  # was False; only with evidence in this PR
),
```

### 9.3 Cert-test assertion

```python
# Remove once lab_certified=True for this capability:
# assert any("UNVALIDATED" in a for a in doc["proof"]["assertions"])
```

---

## 10. De-certification

Set `lab_certified` back to `False` immediately when:

- Live primitive, bounds, `plan()`, or cleanup changes
- Restore fails / unexplained latch
- Lab no longer represents the primitive (dependency/protocol change)
- Any redaction leak for any capability

De-certification is cheap and expected.

---

## 11. Worked example: `asrep-roast-validation`

1. Snapshot lab DC; create roastable + normal users; fill `.env.lab`; open ticket
2. `pytest -q` then `pytest tests/test_certification_asrep_roast.py -v`
3. Save both `validation-result.json` files; redaction grep → clean; pcap notes; gate negatives; complete evidence markdown; reviewer signs
4. Branch `cert/asrep-roast-validation` → flip only that flag → remove UNVALIDATED assert → PR → merge
5. Do not start the next capability until this PR is merged

---

## 12. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Cert test skipped | `ADAF_RT_LAB≠1` or missing env | Source `.env.lab`; check `REQUIRED_ENV` in test |
| LDAP bind failed | Wrong user / no ccache / not LDAPS | Set `BIND_USER`; `kinit`; port 636 |
| AS-REP always NotExploitable | Preauth still required | Verify `DoesNotRequirePreAuth` |
| Kerberoast fails TGT | `KRB5CCNAME` empty/expired | `kinit`; export; `klist` |
| UNVALIDATED missing after flip | Flag flipped without test edit | Never flip without assertion update in same PR |
| Redaction grep dirty | Secret leaked | Do not promote; fix probe |

---

## 13. Non-goals

- Do not set `lab_certified=True` from the runbook alone
- Do not run cert tests against production or non-disposable DCs
- Do not commit `.env.lab`, tickets, hashes, TGTs, or secret-bearing results
- Do not ship half-correct Tier B/C live writers just to flip a flag
- Do not treat certification as production authorization

---

## Appendix A — Repo paths

| Path | Role |
|------|------|
| `docs/CERTIFICATION.md` | Policy gate |
| `docs/CERTIFICATION_RUNBOOK.md` | Env + run order |
| `docs/certifications/*.md` | Evidence templates |
| `tests/test_certification_*.py` | Lab-gated tests |
| `adaf_redteam/capabilities/registry.py` | Sole place to flip `lab_certified` |
| `adaf_redteam/lab_env.py` | Lab DC / bind / object-DN helpers |

## Appendix B — Quick promote one capability

```text
1. Disposable lab ready + ticket open
2. source .env.lab   # ADAF_RT_LAB=1
3. pytest -q
4. pytest tests/test_certification_<capability>.py -v
5. Redaction grep → clean
6. Fill docs/certifications/<capability>.md
7. Independent reviewer signs
8. PR: registry lab_certified=True (one id) + remove UNVALIDATED assert + evidence
9. Merge → next capability
```

**Final rule:** If evidence is incomplete, reviewer == owner, or the PR flips more than one capability without per-id evidence — **do not merge**. Certification is slow on purpose.

# Certification Runbook — Tier A First Wave

This runbook drives the lab-gated certification tests for **read/metadata**
capabilities. It does **not** authorize production use and does **not** flip
`lab_certified` flags. Promotion still requires the evidence package +
independent reviewer sign-off in `docs/CERTIFICATION.md`.

**Full operator how-to (recommended):**
[`docs/ADAF-RedTeam_Capability_Certification_Howto.md`](ADAF-RedTeam_Capability_Certification_Howto.md)
— mental model, `.env.lab`, per-capability loop, evidence package, reviewer
sign-off, one-capability promotion PR, worked example, and troubleshooting.

**Using GOAD:** GOAD is an optional disposable Tier A lab, not a certification
result. A coach/lab administrator installs and isolates it, then follows the
[GOAD Certification Profile](GOAD_CERTIFICATION_PROFILE.md) to create dedicated
`ADAF-Cert-*` objects. Do not use GOAD's built-in vulnerable training accounts
as test fixtures.

## Capabilities covered

| Capability | Test file | Evidence template |
|---|---|---|
| `asrep-roast-validation` | `tests/test_certification_asrep_roast.py` | `docs/certifications/asrep-roast-validation.md` |
| `kerberoast-validation` | `tests/test_certification_kerberoast.py` | `docs/certifications/kerberoast-validation.md` |
| `dcsync-rights-validation` | `tests/test_certification_dcsync_rights.py` | `docs/certifications/dcsync-rights-validation.md` |
| `zerologon-detection` | `tests/test_certification_zerologon.py` | `docs/certifications/zerologon-detection.md` |
| `laps-read-authorization` | `tests/test_certification_laps_read.py` | `docs/certifications/laps-read-authorization.md` |
| `gmsa-read-authorization` | `tests/test_certification_gmsa_read.py` | `docs/certifications/gmsa-read-authorization.md` |
| `machine-account-quota-check` | `tests/test_certification_discovery.py` | (fill after first lab run) |
| `privileged-group-inventory` | `tests/test_certification_discovery.py` | (fill after first lab run) |

## Preconditions

1. Disposable lab you can rebuild from scratch (no route to production).
2. Editable install with extras: `python -m pip install -e ".[ldap,kerberos,dev]"`
3. A written certification engagement that names exact targets and lab addresses.
4. Packet capture capability on the operator host (required for Zerologon "no password-set" proof).

### GOAD-specific readiness (coach/lab administrator)

Before an operator loads lab settings, record in the ticket: GOAD revision,
provider, actual AD DNS root, VM names/IPs, isolated network design, snapshot or
rebuild identifier, and named operator/capture hosts. The GOAD VM network must
have no production route, bridge, shared trust, or public exposure.

On the GOAD DC or management host, run the profile in plan mode first:

```powershell
.\scripts\setup_goad_certification_profile.ps1 `
  -ExpectedDomain 'ACTUAL.GOAD.DOMAIN' `
  -IUnderstandThisIsAnIsolatedGOADLab
```

Expected result: `PLAN ONLY: No directory changes were made.` A domain mismatch,
missing ActiveDirectory module, blocked script, or absent snapshot is a stop
condition for the coach to resolve; the novice does not bypass it.

After review, the coach runs the same command with `-Apply`, verifies the
`PASS` messages, and reviews `certification-work/goad-profile.env.ps1`. That
file contains object hints only. It must contain no password and must not be
committed. Copy reviewed values, not blind defaults, into the local `.env.lab`
or `.env.lab.ps1` used by the operator platform.

## Shared environment file

Create a local, **untracked** file (never commit secrets):

```bash
# .env.lab  — example only; replace every value
export ADAF_RT_LAB=1
export ADAF_RT_LAB_DOMAIN=corp.contoso.test
export ADAF_RT_LAB_DC=dc01.corp.contoso.test
export ADAF_RT_LAB_SOURCE_ADDR=10.10.0.50
export ADAF_RT_LAB_BIND_USER='CORP\\certuser'
# export ADAF_RT_LAB_BIND_PASSWORD='...'   # only if not using Kerberos ccache

# AS-REP
export ADAF_RT_LAB_ASREP_ROASTABLE_USER=svc-nopreauth
export ADAF_RT_LAB_ASREP_PREAUTH_USER=normaluser

# Kerberoast (requires KRB5CCNAME with a TGT for the lab realm)
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

# Zerologon detection
export ADAF_RT_LAB_ZEROLOGON_TARGET=DC01

# Discovery
export ADAF_RT_LAB_QUOTA_EXPECTED=Confirmed
export ADAF_RT_LAB_PRIV_GROUP_DN='CN=Domain Admins,CN=Users,DC=corp,DC=contoso,DC=test'
export ADAF_RT_LAB_PRIV_EXPECTED=Confirmed
```

Load it:

```bash
set -a && source .env.lab && set +a
```

## Run order

```bash
# 1. Offline suite must stay green
pytest -q

# 2. Kerberos metadata
pytest tests/test_certification_asrep_roast.py -v
pytest tests/test_certification_kerberoast.py -v

# 3. LDAP rights / membership
pytest tests/test_certification_dcsync_rights.py -v
pytest tests/test_certification_laps_read.py -v
pytest tests/test_certification_gmsa_read.py -v

# 4. Discovery
pytest tests/test_certification_discovery.py -v

# 5. Zerologon detection (capture traffic in parallel)
pytest tests/test_certification_zerologon.py -v
```

### GOAD capability preparation matrix

Prepare and certify one row at a time. Restore/rebuild GOAD between ambiguous
or state-changing work; do not treat the profile as permission to run every
test in sequence.

| Capability | GOAD profile prerequisite | Expected value decision |
|---|---|---|
| AS-REP | Base profile users | Dedicated no-preauth user is `Confirmed`; normal user is `NotExploitable`. |
| Kerberoast | Base profile SPN | Registered profile SPN is `Confirmed`; nonexistent profile SPN is `NotExploitable`. |
| DCSync rights | `-IncludeDcsyncRights`, separately reviewed | Profile group is `Confirmed` only if both added rights are verified. |
| LAPS read | `-IncludeLapsAcl`, separately reviewed | Profile LAPS group is `Confirmed` only after ACL verification. |
| gMSA read | Base profile gMSA/group | Profile gMSA reader group is `Confirmed` after membership-ACL verification. |
| Machine quota | No profile change | Record actual GOAD domain quota; never alter it only to obtain a desired verdict. |
| Privileged-group inventory | Base profile inventory group | Enumerate the dedicated group; it is not Domain Admins. |
| Zerologon detection | No profile change; capture required | Use actual patched/vulnerable result and prove zero password-set calls. |

## After each green live run

1. Copy `validation-result.json` (and any journal) into the evidence package.
2. Run the redaction grep from the capability's evidence template.
3. For Zerologon: confirm the pcap contains **zero** `NetrServerPasswordSet2` calls.
4. Fill the corresponding `docs/certifications/*.md` checklist.
5. Obtain independent reviewer sign-off.
6. Only then open a promotion PR that sets `lab_certified=True` **and** removes
   the UNVALIDATED-stamp assertion in the same change.

## Offline alternative (no lab)

```bash
adaf-redteam run \
  --engagement examples/engagement.example.json \
  --capability asrep-roast-validation \
  --source-address 192.0.2.25 \
  --fixture examples/offline-full-fixture.example.json \
  --finding-id F-OFFLINE000000001 \
  --control-id ADAF-OFFLINE \
  --out ./out-offline
```

Offline runs exercise analyzers and the bridge; they do **not** count as certification.

## Non-goals

- Do not set `lab_certified=True` from this runbook alone.
- Do not run these tests against production or shared non-disposable DCs.
- Do not commit `.env.lab`, tickets, hashes, or validation results.

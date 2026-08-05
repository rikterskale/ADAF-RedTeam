# Certification Runbook — Tier A First Wave

This runbook drives the lab-gated certification tests for **read/metadata**
capabilities. It does **not** authorize production use and does **not** flip
`lab_certified` flags. Promotion still requires the evidence package +
independent reviewer sign-off in `docs/CERTIFICATION.md`.

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

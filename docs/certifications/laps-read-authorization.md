# Certification evidence: `laps-read-authorization`

> **Status:** IN PROGRESS — live LDAP path reads the LAPS attribute ACL only;
> `lab_certified` remains `False` until this file is complete and reviewer
> sign-off is recorded.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md).

---

## 0. Capability under certification

- **Capability id:** `laps-read-authorization`
- **Tier:** A — read / metadata
- **Adapter:** `adaf_redteam/capabilities/credaccess/laps_read.py`
- **Live primitive:** `LdapDirectorySource.object_acl` (DACL only, never password value)
- **Lab-gated cert test:** `tests/test_certification_laps_read.py`

---

## 1. Universal checklist

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ ACL read only |
| 2 | Analyzer offline tests pass | ✅ `tests/test_credaccess.py` |
| 3 | Redaction proven on live run | ⬜ TODO |
| 4 | Authorization gate honored | ⬜ TODO |
| 5 | Idempotent / bounded | ⬜ TODO |
| 6 | Evidence package complete | ⬜ TODO |
| 7 | Independent review sign-off | ⬜ TODO |

---

## 2. Lab inputs

- Principal under test (`ADAF_RT_LAB_TARGET_PRINCIPAL`): `__________`
- Computer DN (`ADAF_RT_LAB_LAPS_COMPUTER_DN`): `__________`
- Expected verdict: `__________`

## 3. Tier-A proofs

- Password value never requested (LDAP attributes list excludes password attrs): `__________`
- Grep of output dir for password material: `__________` (expect clean)

## 4. Sign-off

| Role | Name | Date |
|------|------|------|
| Certification owner | `__________` | `__________` |
| Independent reviewer | `__________` | `__________` |

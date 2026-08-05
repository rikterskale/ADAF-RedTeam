# Certification evidence: `gmsa-read-authorization`

> **Status:** IN PROGRESS — live path reads `msDS-GroupMSAMembership` only;
> never `msDS-ManagedPassword`. `lab_certified` remains `False` until complete.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md).

---

## 0. Capability under certification

- **Capability id:** `gmsa-read-authorization`
- **Tier:** A — read / metadata
- **Adapter:** `adaf_redteam/capabilities/credaccess/gmsa_read.py`
- **Live primitive:** `LdapDirectorySource.gmsa_readers`
- **Lab-gated cert test:** `tests/test_certification_gmsa_read.py`

---

## 1. Universal checklist

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ membership ACL only |
| 2 | Analyzer offline tests pass | ✅ `tests/test_credaccess.py` |
| 3 | Redaction proven on live run | ⬜ TODO |
| 4 | Authorization gate honored | ⬜ TODO |
| 5 | Idempotent / bounded | ⬜ TODO |
| 6 | Evidence package complete | ⬜ TODO |
| 7 | Independent review sign-off | ⬜ TODO |

---

## 2. Lab inputs

- Principal under test (`ADAF_RT_LAB_TARGET_PRINCIPAL`): `__________`
- gMSA DN (`ADAF_RT_LAB_GMSA_DN`): `__________`
- Expected verdict: `__________`

## 3. Tier-A proofs

- `msDS-ManagedPassword` never requested: `__________`
- Grep of output dir: `__________` (expect clean)

## 4. Sign-off

| Role | Name | Date |
|------|------|------|
| Certification owner | `__________` | `__________` |
| Independent reviewer | `__________` | `__________` |

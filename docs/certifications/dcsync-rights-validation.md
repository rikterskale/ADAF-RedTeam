# Certification evidence: `dcsync-rights-validation`

> **Status:** IN PROGRESS — the live primitive is implemented and offline-tested;
> the flag `lab_certified` remains `False` in `registry.py` until this file is
> complete and reviewer sign-off (§8) is recorded.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md). This file is the evidence
package (§3). The owner fills it in from a disposable-lab run; a second person
reviews and signs off (§7).

---

## 0. Capability under certification

- **Capability id:** `dcsync-rights-validation`
- **Tier:** A — read / metadata (Executable target)
- **Adapter:** [adaf_redteam/capabilities/credaccess/dcsync_rights.py](../../adaf_redteam/capabilities/credaccess/dcsync_rights.py)
- **Live primitive:** [adaf_redteam/directory/ldap_source.py](../../adaf_redteam/directory/ldap_source.py)
  - `LdapDirectorySource.domain_acl()` → `_read_raw_sd(base_dn, "nTSecurityDescriptor")`
  - Uses ldap3 SASL/GSSAPI (Kerberos ccache) or SIMPLE bind over LDAPS
  - Sends the SD_FLAGS control (`1.2.840.113556.1.4.801`) with
    `DACL_SECURITY_INFORMATION` only — SACL/Owner/Group are not returned
  - `parse_sd_to_aces()` maps the DACL to normalized `Ace` objects (unit-tested
    offline via [tests/test_ldap_source_parser.py](../../tests/test_ldap_source_parser.py))
- **Lab-gated cert test:** [tests/test_certification_dcsync_rights.py](../../tests/test_certification_dcsync_rights.py)

---

## 1. Universal checklist (docs/CERTIFICATION.md §1)

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ implemented, LDAPS-only, DACL-only, one attribute per search |
| 2 | Analyzer/orchestration behavior unchanged; offline tests pass | ✅ 103 offline tests pass |
| 3 | Redaction proven on live run | ⬜ TODO — run and paste grep result below |
| 4 | Authorization gate honored on live run | ⬜ TODO |
| 5 | Idempotent, bounded, interval-respecting | ⬜ TODO |
| 6 | Evidence package (this file) complete | ⬜ TODO |
| 7 | Independent review sign-off | ⬜ TODO |

---

## 2. Preconditions (docs/CERTIFICATION.md §0)

- Disposable lab identifier: `__________`
- Snapshot/rebuild capability: `__________`
- Certification ticket: `__________`
- Certification owner (implements + assembles evidence): `__________`
- Independent reviewer (verifies + signs off): `__________`

---

## 3. Tier-A specific proofs (docs/CERTIFICATION.md §2 Tier A)

### 3.1 No state change (packet capture / DC audit log)

Capture the live run. Confirm only LDAP search operations were issued (no
`Modify`, `Add`, `Delete`, or extended operations). Attach:

- `pcap` filename / hash: `__________`
- Server-side event ids observed: `__________` (expect only 1644/4662 read
  events on the naming-context head; no 4720/4724/5136 write events)

### 3.2 No secret export

- The capability's `redactedRefs` schema does not contain any secret field; the
  only outputs are the trustee, held rights, and ace count. Attestation from
  the live artifact:
  - `redactedRefs.dcsyncRightsHeld = __________`
  - `redactedRefs.domainAceCount = __________`

### 3.3 No DRSUAPI replication

Confirm via DC audit log / pcap that no DRSUAPI (DsBindWithSpn, DsGetNCChanges)
call was issued during the run. Attach:

- DC event log filter used: `__________`
- Result: `__________` (expect: no DRS events)

---

## 4. Universal proofs (docs/CERTIFICATION.md §1.3–§1.5)

### 4.1 Redaction scan over produced artifacts

Run the redaction scan over the run's output directory:

```bash
grep -Eri 'password|krbtgt|nthash|ntlm|aes256-cts|aes128-cts|-----BEGIN|hash:|ticket-bytes' <out>/ || echo 'clean'
```

- Result: `__________` (expect: `clean`)
- Artifacts scanned: `validation-result.json`, `transaction-journal.jsonl`
  (if present)

### 4.2 Authorization gate

- Ran with wrong source address → gate refused (rc=3): `__________`
- Ran with wrong technique → gate refused (rc=3): `__________`
- Ran outside window → gate refused (rc=3): `__________`

### 4.3 Idempotency / bounds

- Same run twice → identical `redactedRefs`, no state accumulated on the DC:
  `__________`
- `maximumActions=1` honored (second search refused): `__________`

---

## 5. Evidence package (docs/CERTIFICATION.md §3)

| Item | Location / attachment |
|------|----------------------|
| Redacted certification engagement file | `__________` |
| Containment probe record | `__________` |
| Read-only attestation (Tier A) | see §3.2 above |
| Redaction scan result | see §4.1 above |
| `validation-result.json` from live run | `__________` |
| Transaction journal (if any) | `__________` |
| Tier B/C/E force-fail run | N/A (Tier A) |
| Tier D blue-team telemetry | N/A (Tier A) |
| Cert test + green CI run link | [tests/test_certification_dcsync_rights.py](../../tests/test_certification_dcsync_rights.py); CI run: `__________` |
| Reviewer sign-off | see §6 |

---

## 6. Sign-off (docs/CERTIFICATION.md §7)

| Role | Name | Date | Notes |
|------|------|------|-------|
| Certification owner | `__________` | `__________` | |
| Independent reviewer | `__________` | `__________` | Confirms §3 & §4 evidence matches the artifact and the bounds in `plan()` are honored by the live primitive. |

**Once both signatures are recorded and the ⬜ boxes above are all ✅, open the
promotion PR:** set `lab_certified=True` for `dcsync-rights-validation` in
[adaf_redteam/capabilities/registry.py](../../adaf_redteam/capabilities/registry.py)
and delete the UNVALIDATED-stamp assertion at the bottom of
[tests/test_certification_dcsync_rights.py](../../tests/test_certification_dcsync_rights.py).

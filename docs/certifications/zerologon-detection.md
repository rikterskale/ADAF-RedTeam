# Certification evidence: `zerologon-detection`

> **Status:** IN PROGRESS — the live safe-detection primitive is implemented;
> `lab_certified` remains `False` until this file is complete and reviewer
> sign-off is recorded.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md). This file is the evidence
package (§3).

---

## 0. Capability under certification

- **Capability id:** `zerologon-detection`
- **Tier:** A — read / metadata (Executable target)
- **Adapter:** [adaf_redteam/capabilities/netlogon/zerologon.py](../../adaf_redteam/capabilities/netlogon/zerologon.py)
- **Live primitive:** [adaf_redteam/probes/netlogon.py](../../adaf_redteam/probes/netlogon.py)
  - `LiveNetlogonProbe.zerologon_detect()` — bounded zero-challenge Netlogon auth
  - Stops before `NetrServerPasswordSet2`; never modifies machine-account password
- **Lab-gated cert test:** [tests/test_certification_zerologon.py](../../tests/test_certification_zerologon.py)

---

## 1. Universal checklist (docs/CERTIFICATION.md §1)

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ bounded attempts; no password-set call |
| 2 | Analyzer/orchestration behavior unchanged; offline tests pass | ✅ `tests/test_zerologon_detection.py` |
| 3 | Redaction proven on live run | ⬜ TODO |
| 4 | Authorization gate honored on live run | ⬜ TODO |
| 5 | Idempotent, bounded, interval-respecting | ⬜ TODO |
| 6 | Evidence package (this file) complete | ⬜ TODO |
| 7 | Independent review sign-off | ⬜ TODO |

---

## 2. Preconditions

- Disposable lab identifier: `__________`
- Snapshot/rebuild capability: `__________`
- Certification ticket: `__________`
- Certification owner: `__________`
- Independent reviewer: `__________`

---

## 3. Tier-A specific proofs

### 3.1 No state change (packet capture / DC audit log)

- `pcap` filename / hash: `__________`
- Observed `NetrServerReqChallenge` / `NetrServerAuthenticate3` only: `__________`
- Observed `NetrServerPasswordSet2` count: `__________` (expect: **0**)
- DC machine-account password unchanged after run: `__________`

### 3.2 Analyzer decision matches DC behavior

- Vulnerable lab DC → `Confirmed` / `zerologon-vulnerable-detected`: `__________`
- Patched lab DC → `NotExploitable` / `zerologon-patched`: `__________`

---

## 4. Redaction scan

```bash
grep -Eri 'passwordset|netrserverpasswordset|nthash|-----BEGIN' <out>/ || echo clean
```

- Result: `__________` (expect: `clean`)

---

## 5. Sign-off

| Role | Name | Date | Notes |
|------|------|------|-------|
| Certification owner | `__________` | `__________` | |
| Independent reviewer | `__________` | `__________` | Confirms zero password-set calls and bounds match `plan()`. |

**Once both signatures are recorded and the ⬜ boxes are ✅, open the promotion
PR:** set `lab_certified=True` for `zerologon-detection` in `registry.py` and
delete the UNVALIDATED-stamp assertion in the certification test.

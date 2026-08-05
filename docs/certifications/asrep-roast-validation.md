# Certification evidence: `asrep-roast-validation`

> **Status:** IN PROGRESS — the live primitive is implemented and offline-tested;
> the flag `lab_certified` remains `False` in `registry.py` until this file is
> complete and reviewer sign-off (this file §6; `CERTIFICATION.md` §7) is recorded.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md). This file is the evidence
package (§3). The owner fills it in from a disposable-lab run; a second person
reviews and signs off (§7).

---

## 0. Capability under certification

- **Capability id:** `asrep-roast-validation`
- **Tier:** A — read / metadata (Executable target)
- **Adapter:** [adaf_redteam/capabilities/kerberos/asrep_roast.py](../../adaf_redteam/capabilities/kerberos/asrep_roast.py)
- **Live primitive:** [adaf_redteam/probes/kerberos.py](../../adaf_redteam/probes/kerberos.py)
  - `LiveKerberosProbe.asrep()` → `build_asrep_probe_request()` + `sendReceive()`
    + `extract_asrep_metadata()`
  - Sends exactly one padata-free AS-REQ for `user@REALM`, advertising AES256,
    AES128, RC4 (strong-to-weak order so an RC4 AS-REP is a deliberate signal)
  - Handles `KDC_ERR_PREAUTH_REQUIRED` (25) as the "normal account" branch;
    `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) raises `RuntimeError` to fail loudly
  - `extract_asrep_metadata()` reads ONLY `enc-part.etype`; the crackable
    `enc-part.cipher` bytes are never accessed, returned, logged, or written
  - Unit-tested offline via [tests/test_asrep_probe_parser.py](../../tests/test_asrep_probe_parser.py)
- **Lab-gated cert test:** [tests/test_certification_asrep_roast.py](../../tests/test_certification_asrep_roast.py)

---

## 1. Universal checklist (docs/CERTIFICATION.md §1)

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ implemented, one AS-REQ per call, no padata, no post-processing beyond etype |
| 2 | Analyzer/orchestration behavior unchanged; offline tests pass | ✅ 112 offline tests pass |
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

### 2.1 Lab accounts required

Two accounts in the lab domain:

| Purpose | sAMAccountName | DONT_REQUIRE_PREAUTH? | UPN |
|---|---|---|---|
| Roastable positive case | `__________` | Yes | `__________` |
| Preauth-required negative case | `__________` | No | `__________` |

Set the DONT_REQUIRE_PREAUTH bit on the positive-case account:

```powershell
Set-ADAccountControl -Identity <sam> -DoesNotRequirePreAuth $true
```

Confirm with:

```powershell
Get-ADUser <sam> -Properties DoesNotRequirePreAuth | Select DoesNotRequirePreAuth
```

---

## 3. Tier-A specific proofs (docs/CERTIFICATION.md §2 Tier A)

### 3.1 No state change (packet capture / DC audit log)

Capture the live runs. Confirm the only Kerberos traffic is exactly ONE AS-REQ
per capability run (no retries, no follow-on TGS-REQ). Attach:

- `pcap` filename / hash: `__________`
- Wireshark filter used: `kerberos.msg_type == 10` (AS-REQ) or `== 11` (AS-REP)
  or `== 30` (KRB-ERROR)
- Observed AS-REQs per run: `__________` (expect: 1)
- Observed follow-on TGS-REQs: `__________` (expect: 0)
- DC event ids observed: `__________` (expect: 4768 audit events on the KDC;
  no 4769 TGS events)

### 3.2 No secret export

The AS-REP for the roastable account contains the crackable `enc-part.cipher`
blob. Confirm it does not leave the vault:

- `redactedRefs` from the roastable run: `__________` (expect: only
  `targetUser`, `etype`, `weakEtype`)
- Grep the pcap for the cipher bytes → grep the output dir → confirm they
  never travel further than the wire: `__________`

### 3.3 Analyzer decision matches KDC behavior

- Roastable positive case → verdict `Confirmed`, proofClass
  `asrep-roastable-no-preauth`, `etype` recorded: `__________`
- Preauth-required negative case → verdict `NotExploitable`, proofClass
  `asrep-preauth-required`: `__________`
- (Optional) An unknown-principal call → CLI errors clearly (rc=4) with
  "unknown" in stderr; the run does NOT silently return `NotExploitable`:
  `__________`

---

## 4. Universal proofs (docs/CERTIFICATION.md §1.3–§1.5)

### 4.1 Redaction scan over produced artifacts

Run the redaction scan over each run's output directory:

```bash
grep -Eri 'crackable|asrep-hash|-----BEGIN|cipher:|\$krb5asrep\$|password|krbtgt:|nthash|ntlm' <out>/ \
  || echo 'clean'
```

- Roastable-case result: `__________` (expect: `clean`)
- Preauth-case result: `__________` (expect: `clean`)

### 4.2 Authorization gate

- Ran with wrong source address → gate refused (rc=3): `__________`
- Ran with wrong technique → gate refused (rc=3): `__________`
- The current gate does not enforce the engagement window; record the independent
  ROE/window review and reviewer attestation: `__________`
- Ran without `--fixture` and `ADAF_RT_LAB` unset → gate refused (rc=4)
  with NOT CERTIFIED message: `__________`

### 4.3 Idempotency / bounds

- Same run twice against the roastable account → identical `redactedRefs`,
  no state accumulated on the KDC (event log shows two audit entries and
  nothing else): `__________`
- `maximumActions=1` and pacing behavior evidenced by the certified primitive:
  `__________` (the current CLI records these values but does not enforce them)
- No retries on transient network failure (bounded to one AS-REQ per plan):
  `__________`

---

## 5. Evidence package (docs/CERTIFICATION.md §3)

| Item | Location / attachment |
|------|----------------------|
| Redacted certification engagement file | `__________` |
| Containment probe record | `__________` |
| Read-only attestation (Tier A) | see §3.1 and §3.2 above |
| Redaction scan result | see §4.1 above |
| `validation-result.json` from each live run | `__________` |
| Transaction journal (if any) | `__________` |
| Tier B/C/E force-fail run | N/A (Tier A) |
| Tier D blue-team telemetry | N/A (Tier A) |
| Cert test + green CI run link | [tests/test_certification_asrep_roast.py](../../tests/test_certification_asrep_roast.py); CI run: `__________` |
| Reviewer sign-off | see §6 |

---

## 6. Sign-off (docs/CERTIFICATION.md §7)

| Role | Name | Date | Notes |
|------|------|------|-------|
| Certification owner | `__________` | `__________` | |
| Independent reviewer | `__________` | `__________` | Confirms §3 & §4 evidence matches the artifact and the bounds in `plan()` are honored by the live primitive (one AS-REQ, no padata, cipher never read). |

**Once both signatures are recorded and the ⬜ boxes above are all ✅, open the
promotion PR:** set `lab_certified=True` for `asrep-roast-validation` in
[adaf_redteam/capabilities/registry.py](../../adaf_redteam/capabilities/registry.py)
and delete the UNVALIDATED-stamp assertion in
[tests/test_certification_asrep_roast.py](../../tests/test_certification_asrep_roast.py).

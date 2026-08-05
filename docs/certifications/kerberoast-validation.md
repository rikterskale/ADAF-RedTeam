# Certification evidence: `kerberoast-validation`

> **Status:** IN PROGRESS — the live primitive is implemented and offline-tested;
> the flag `lab_certified` remains `False` in `registry.py` until this file is
> complete and reviewer sign-off (this file §6; `CERTIFICATION.md` §7) is recorded.

Follow [docs/CERTIFICATION.md](../CERTIFICATION.md). This file is the evidence
package (§3). The owner fills it in from a disposable-lab run; a second person
reviews and signs off (§7).

---

## 0. Capability under certification

- **Capability id:** `kerberoast-validation`
- **Tier:** A — read / metadata (Executable target)
- **Adapter:** [adaf_redteam/capabilities/kerberos/kerberoast.py](../../adaf_redteam/capabilities/kerberos/kerberoast.py)
- **Live primitive:** [adaf_redteam/probes/kerberos.py](../../adaf_redteam/probes/kerberos.py)
  - `LiveKerberosProbe.tgs()` loads a TGT from `KRB5CCNAME`, sends exactly one
    TGS-REQ for the target SPN via `impacket.getKerberosTGS`, and reads only
    `ticket.enc-part.etype`
  - `KDC_ERR_S_PRINCIPAL_UNKNOWN` (7) → `{obtained: False}` (NotExploitable)
  - Any other Kerberos error raises `RuntimeError` — no silent NotExploitable
  - `extract_tgs_metadata()` reads ONLY `ticket.enc-part.etype`; the crackable
    `ticket.enc-part.cipher` bytes are never accessed, returned, logged, or
    written
  - Unit-tested offline via [tests/test_tgs_probe_parser.py](../../tests/test_tgs_probe_parser.py)
- **Lab-gated cert test:** [tests/test_certification_kerberoast.py](../../tests/test_certification_kerberoast.py)

---

## 1. Universal checklist (docs/CERTIFICATION.md §1)

| # | Requirement | Status |
|---|---|---|
| 1 | Live primitive implemented (bounded to `plan()`) | ✅ implemented, one TGS-REQ per call, only ticket etype read |
| 2 | Analyzer/orchestration behavior unchanged; offline tests pass | ✅ 118 offline tests pass |
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
- Certification owner: `__________`
- Independent reviewer: `__________`

### 2.1 Lab setup

The operator needs a valid TGT for the lab realm. On Linux:

```bash
kinit labtest@CORP.LAB.LOCAL
klist   # confirm a TGT is present
export KRB5CCNAME=/tmp/krb5cc_$UID
```

On Windows, use MIT Kerberos for Windows or Rubeus + `ktutil` to produce a
ccache file; point `KRB5CCNAME` at it.

Register a lab service SPN on a test service account:

```powershell
$sa = New-ADUser -SamAccountName svc-labtest -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PassThru
setspn -A http/labhost.corp.lab.local svc-labtest
# Confirm:
setspn -L svc-labtest
```

Pick a made-up SPN for the negative case (must NOT be registered):

```powershell
setspn -Q spn/does-not-exist.corp.lab.local
# should print: No SPNs registered.
```

### 2.2 Lab SPNs

| Purpose | SPN | Registered? |
|---|---|---|
| Kerberoastable positive case | `__________` | Yes |
| Missing-SPN negative case | `__________` | No |

---

## 3. Tier-A specific proofs (docs/CERTIFICATION.md §2 Tier A)

### 3.1 No state change (packet capture / DC audit log)

Confirm each capability run issues exactly ONE TGS-REQ (plus the AP-REQ inside
it). Attach:

- `pcap` filename / hash: `__________`
- Wireshark filter: `kerberos.msg_type == 12` (TGS-REQ) or `== 13` (TGS-REP)
  or `== 30` (KRB-ERROR)
- Observed TGS-REQs per run: `__________` (expect: 1)
- DC audit events observed: `__________` (expect: 4769 on the positive case;
  4771 or KRB-ERROR on the missing-SPN case; no writes)

### 3.2 No secret export

The TGS-REP for the registered SPN contains the crackable
`ticket.enc-part.cipher`. Confirm it doesn't leave the vault:

- `redactedRefs` from the positive-case run: `__________` (expect: only
  `targetSpn`, `etype`, `weakEtype`)
- Grep the pcap for the ticket cipher bytes → grep the output dir → confirm
  they never travel further than the wire: `__________`

### 3.3 Analyzer decision matches KDC behavior

- Positive case (registered SPN) → verdict `Confirmed`, proofClass
  `kerberoast-service-ticket-obtained`, `etype` recorded: `__________`
- Negative case (missing SPN) → verdict `NotExploitable`, proofClass
  `kerberoast-no-ticket`: `__________`

---

## 4. Universal proofs (docs/CERTIFICATION.md §1.3–§1.5)

### 4.1 Redaction scan over produced artifacts

```bash
grep -Eri 'crackable|\$krb5tgs\$|ticket-bytes|-----BEGIN|cipher:|password|krbtgt:|nthash|ntlm' <out>/ \
  || echo 'clean'
```

- Positive-case result: `__________` (expect: `clean`)
- Negative-case result: `__________` (expect: `clean`)

### 4.2 Authorization gate

- Ran with wrong source address → gate refused (rc=3): `__________`
- Ran with wrong technique → gate refused (rc=3): `__________`
- The current gate does not enforce the engagement window; record the independent
  ROE/window review and reviewer attestation: `__________`
- Ran without `--fixture` and `ADAF_RT_LAB` unset → gate refused (rc=4)
  with NOT CERTIFIED message: `__________`

### 4.3 Idempotency / bounds

- Same run twice against the registered SPN → identical `redactedRefs`;
  ccache is unchanged (only reads a TGT); KDC event log shows two 4769s
  and nothing else: `__________`
- `maximumActions=1` and pacing behavior evidenced by the certified primitive:
  `__________` (the current CLI records these values but does not enforce them)
- No retries on transient KerberosError (bounded to one TGS-REQ per plan):
  `__________`

### 4.4 KRB5CCNAME hygiene

- The TGT bytes never leave the vault: `__________`
- The ccache path is not embedded in `validation-result.json`: `__________`

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
| Cert test + green CI run link | [tests/test_certification_kerberoast.py](../../tests/test_certification_kerberoast.py); CI run: `__________` |
| Reviewer sign-off | see §6 |

---

## 6. Sign-off (docs/CERTIFICATION.md §7)

| Role | Name | Date | Notes |
|------|------|------|-------|
| Certification owner | `__________` | `__________` | |
| Independent reviewer | `__________` | `__________` | Confirms §3 & §4 evidence matches the artifact and the bounds in `plan()` are honored by the live primitive (one TGS-REQ, ticket.enc-part.cipher never read, no retries). |

**Once both signatures are recorded and the ⬜ boxes above are all ✅, open the
promotion PR:** set `lab_certified=True` for `kerberoast-validation` in
[adaf_redteam/capabilities/registry.py](../../adaf_redteam/capabilities/registry.py)
and delete the UNVALIDATED-stamp assertion in
[tests/test_certification_kerberoast.py](../../tests/test_certification_kerberoast.py).

# GOAD Certification Profile

Use this profile to create **new, dedicated** Active Directory objects for
ADAF-RedTeam Tier A certification in an isolated GOAD lab. It does not reuse or
modify GOAD training accounts. GOAD must have no production route, shared trust,
or internet exposure.

This is a coach/lab-administrator aid, not novice instructions. The operator
uses [First Certification Session](guides/CERTIFICATION_NOVICE_COACH_PLAYBOOK.md).

## Profile coverage

| Test | Dedicated object | Expected setup |
|---|---|---|
| AS-REP | Two `ADAF-Cert-*` users | One has preauthentication disabled; one remains normal. |
| Kerberoast | Dedicated service user and HTTP SPN | One registered SPN and one nonexistent SPN. |
| DCSync rights | Dedicated security group | Optional replication-control rights on the domain head. |
| LAPS authorization | Dedicated computer and reader group | Optional `GenericAll` only on the new computer object. |
| gMSA authorization | Dedicated reader group and gMSA | Group is the gMSA password-reader principal. |
| Machine quota | No new object | Read GOAD's existing value; do not change it. |
| Privileged-group inventory | Dedicated group with one member | Read-only enumeration; it is not Domain Admins. |
| Zerologon detection | No profile mutation | Use a GOAD DC, packet capture, and its actual patch-state verdict. |

The DCSync and LAPS options change ACLs. They are disabled by default and need
a snapshot plus reviewer acknowledgement.

## Safety gate

Run only on a GOAD DC or management host with the ActiveDirectory module and
domain-admin rights. The script requires the exact expected domain and makes no
changes unless `-Apply` is supplied.

```powershell
# Plan only; no directory change.
.\scripts\setup_goad_certification_profile.ps1 `
  -ExpectedDomain 'sevenkingdoms.local' `
  -IUnderstandThisIsAnIsolatedGOADLab
```

After the coach confirms the snapshot, create the base profile. The password is
entered securely and is never written to the generated profile.

```powershell
.\scripts\setup_goad_certification_profile.ps1 `
  -ExpectedDomain 'sevenkingdoms.local' `
  -IUnderstandThisIsAnIsolatedGOADLab `
  -Apply
```

To add the two high-impact dedicated-object ACL cases, use a separately
reviewed run:

```powershell
.\scripts\setup_goad_certification_profile.ps1 `
  -ExpectedDomain 'sevenkingdoms.local' `
  -IUnderstandThisIsAnIsolatedGOADLab `
  -Apply -IncludeDcsyncRights -IncludeLapsAcl
```

`-IncludeDcsyncRights` grants the two replication-control rights only to
`ADAF-Cert-DcsyncReaders`. `-IncludeLapsAcl` grants `GenericAll` only to the
new `ADAF-Cert-Laps01` object. Neither option touches a GOAD training object.

## Generated settings

The script writes `certification-work/goad-profile.env.ps1`, containing object
names, DNs, SIDs, and SPNs—but no password. The coach fills the DC address,
operator source address, and approved bind identity, then copies reviewed values
into the local ignored `.env.lab.ps1`.

Set expected verdicts per test. The DCSync group is `Confirmed` only after
`-IncludeDcsyncRights`; the LAPS group is `Confirmed` only after
`-IncludeLapsAcl`; Zerologon depends on the actual GOAD DC patch state and
packet-capture verification.

## Verify and clean up

1. Run ADAF's local preflight for one capability.
2. Run exactly one matching certification test.
3. Collect redaction-clean evidence and obtain independent review.
4. Restore the snapshot after failed/ambiguous work, or remove the profile OU
   only under disposable-lab change control.

Do not use this profile for Tier B–E tests. Those require their own restore,
latch, and evidence design.

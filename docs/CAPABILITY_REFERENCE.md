# ADAF-RedTeam Capability Reference

<!-- GENERATED: python scripts/generate_capability_reference.py -->

This reference is generated from `adaf_redteam/capabilities/registry.py`. `Executable` is a target authorization class, **not** proof of live availability.

| Capability | Group | Target class | State changing | Required ATT&CK | Availability |
|---|---|---|---|---|---|
| `adcs-esc1-validation` | adcs | LabExecutable | Yes | `T1649` | Uncertified: fixture/orchestration only; live use is unavailable |
| `adcs-esc6-editf-check` | adcs | Executable | No | `T1649` | Uncertified: fixture/orchestration only; live use is unavailable |
| `adcs-esc7-manage-rights` | adcs | Executable | No | `T1649` | Uncertified: fixture/orchestration only; live use is unavailable |
| `adcs-esc8-relay-web-enrollment` | adcs | LabExecutable | Yes | `T1649` | Uncertified: fixture/orchestration only; live use is unavailable |
| `adversary-emulation-evasion` | detection | LabExecutable | Yes | `T1562` | Uncertified: fixture/orchestration only; live use is unavailable |
| `asrep-roast-validation` | kerberos | Executable | No | `T1558.004` | Uncertified: fixture/orchestration only; live use is unavailable |
| `coercion-petitpotam` | coercion-relay | LabExecutable | Yes | `T1187` | Uncertified: fixture/orchestration only; live use is unavailable |
| `dcsync-rights-validation` | credential-access | Executable | No | `T1003.006` | Uncertified: fixture/orchestration only; live use is unavailable |
| `delegation-rights-validation` | kerberos | Executable | No | `T1558` | Uncertified: fixture/orchestration only; live use is unavailable |
| `delegation-s4u2proxy-proof` | kerberos | LabExecutable | No | `T1558` | Uncertified: fixture/orchestration only; live use is unavailable |
| `exec-proof-svcctl` | lateral | LabExecutable | Yes | `T1569.002` | Uncertified: fixture/orchestration only; live use is unavailable |
| `gmsa-read-authorization` | credential-access | Executable | No | `T1552` | Uncertified: fixture/orchestration only; live use is unavailable |
| `golden-silver-ticket` | kerberos | LabExecutable | Yes | `T1558.001` | Uncertified: fixture/orchestration only; live use is unavailable |
| `kerberoast-validation` | kerberos | Executable | No | `T1558.003` | Uncertified: fixture/orchestration only; live use is unavailable |
| `laps-read-authorization` | credential-access | Executable | No | `T1552` | Uncertified: fixture/orchestration only; live use is unavailable |
| `ntds-dpapi-read-proof` | credential-access | LabExecutable | No | `T1003.003` | Uncertified: fixture/orchestration only; live use is unavailable |
| `payload-reliability-labtest` | detection | LabExecutable | Yes | `T1550` | Uncertified: fixture/orchestration only; live use is unavailable |
| `rbcd-write-validation` | kerberos | LabExecutable | Yes | `T1558` | Uncertified: fixture/orchestration only; live use is unavailable |
| `shadow-credential-write` | kerberos | LabExecutable | Yes | `T1556` | Uncertified: fixture/orchestration only; live use is unavailable |
| `smb-ldap-relay-shadowcred` | coercion-relay | LabExecutable | Yes | `T1557.001` | Uncertified: fixture/orchestration only; live use is unavailable |
| `zerologon-detection` | detection | Executable | No | `T1210` | Uncertified: fixture/orchestration only; live use is unavailable |
| `zerologon-reset` | netlogon | LabExecutable | Yes | `T1210` | Uncertified: fixture/orchestration only; live use is unavailable |

## Stable operator error codes

| Code range | Meaning |
|---|---|
| `ADAF-RT-E100`–`E109` | Engagement scope or safety gate refusal. Read the remediation printed with the error; do not bypass it. |
| `ADAF-RT-E200` | Unknown capability. Use `list-capabilities` or this reference. |
| `ADAF-RT-E201` | An executable result needs bridge correlation IDs. Supply `--finding-id` and `--control-id`. |
| `ADAF-RT-E202` | Live collector is unavailable or not certified. Use a fixture or `--plan-only`. |
| `ADAF-RT-E203` | A cleanup latch blocks a state-changing run. Verify recovery before manual clearance. |
| `ADAF-RT-E204` | A required base runtime dependency is unavailable. Run `doctor` after installing project dependencies. |

## Safe first use

Run `adaf-redteam doctor`, then `adaf-redteam list-capabilities`, then a committed-example `run --plan-only`. See the Windows and Linux novice guides for the platform-specific safe path.

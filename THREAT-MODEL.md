# ADAF-RedTeam threat model (operator-facing)

## What this tool is
An execution tool for **authorized** Active Directory red-team / purple-team /
adversary-emulation work. It handles secrets in memory (that is the point) but
guarantees they never leave the process. It exists to prove findings and to test
whether defenses detect real techniques.

## Assets it touches
- Live credential/ticket/certificate material (in memory, transiently).
- Authorized target directory objects (read, and — in lab — write).
- Engagement authorization data (domains, targets, source addresses, approvals).

## Non-negotiable guarantees
1. **No secret leaves the process.** All secret material is converted to a handle
   the instant it is obtained (`adaf_redteam/redaction`). No serialization path,
   log, journal, result, or manifest can contain it. Enforced by the redaction
   test suite in CI.
2. **No action without authorization.** Every capability requires a schema-valid
   engagement file, an exact target inside the authorized set, a source address
   inside the authorized set, and the required ATT&CK technique. State-changing
   actions additionally require risk acceptance and positive lab containment.
3. **No mass targeting / no persistence / no C2.** Exact targets only. This tool
   proves access; it does not maintain it.
4. **Detection stays attached.** Evasion / adversary-emulation capabilities exist
   only in a purple-team framing: they emit what was attempted and whether it was
   detected. There is no "succeed silently, report nothing" mode.

## Trust boundaries
- **Process boundary:** secrets in, handles out. The redactor is the only door.
- **Bridge boundary:** only `validation-result.json` (schema-validated,
  secret-free) crosses back into ADAF.
- **Containment boundary:** state-changing capabilities run only where the
  containment probe confirms a disposable lab; cleanup failure latches the run.

## Abuse cases explicitly designed against
- Operator error exporting loot: there is no loot-export code path to invoke.
- Running outside scope: source-address and target gates refuse.
- Silent production compromise via evasion tooling: the detection-evidence
  requirement and technique allowlist make "silent" a non-mode.
- Result tampering feeding false confidence into ADAF: results are SHA-256
  hashed and optionally CMS-signed; ADAF ingest re-validates.

## Residual risks (honest)
- AD CS issuance/revocation and some directory writes leave durable records;
  cleanup verifies removal where possible and reports `durableResidue` where not.
- In-memory secret handling depends on the host not being compromised; use a
  hardened, dedicated operator workstation.
- Evasion capabilities, even purple-team-framed, can reduce a real SOC's
  telemetry during the window. Rules of engagement must define notification.

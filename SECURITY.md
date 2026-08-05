# Security policy

## Reporting
Report vulnerabilities in ADAF-RedTeam privately to the maintainer. Do not open
public issues for anything that would help misuse the tool.

## Responsible use
This is offensive tooling. Use it only under written, scoped authorization. The
runtime authorization gate is a safety floor, not a license — operating outside
your engagement is your legal and ethical responsibility, not the tool's.

## Secret handling
The supported adapters are designed not to write credential, ticket,
certificate, or key material to disk; CI redaction tests inspect their produced
artifacts for known secret shapes. Because the result schema accepts arbitrary
strings, this is not an absolute schema-level guarantee. Treat any code path
that can serialize a secret as a **security-critical bug** and report it before
use.

# Security policy

## Reporting
Report vulnerabilities in ADAF-RedTeam privately to the maintainer. Do not open
public issues for anything that would help misuse the tool.

## Responsible use
This is offensive tooling. Use it only under written, scoped authorization. The
runtime authorization gate is a safety floor, not a license — operating outside
your engagement is your legal and ethical responsibility, not the tool's.

## Secret handling
This tool never writes credential, ticket, certificate, or key material to disk.
If you find any code path that can serialize a secret, treat it as a
**security-critical bug** and report it before use.

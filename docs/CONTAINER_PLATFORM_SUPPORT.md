# Container Platform Support

ADAF-RedTeam publishes separate Linux and Windows container images. A Docker
daemon runs one operating-system container mode at a time; these are distinct
artifacts, not layers of a combined image.

| Image | Dockerfile | Runtime dependencies | Supported scope |
|---|---|---|---|
| Linux | `Dockerfile` | Base runtime plus `ldap3` and `impacket` | Offline plan-only and approved fixture workflows |
| Windows | `Dockerfile.windows` | Base runtime plus `ldap3` and `impacket` | Offline plan-only and approved fixture workflows on LTSC 2022-compatible Windows hosts |

Both images include every capability adapter in this repository and every
currently declared optional Python runtime dependency. There are no committed
native Windows executables, native Linux executables, credentials, or target
configuration files to add. The `all` extra deliberately installs the runtime
dependencies used by LDAP, Kerberos, AD CS, and relay adapters.

## Build commands

Build the Linux image from a Linux Docker daemon:

```bash
docker build --pull --tag adaf-redteam:linux .
```

Build the Windows image from a Windows-container daemon on an LTSC 2022-
compatible host:

```powershell
docker build --pull --file Dockerfile.windows --tag adaf-redteam:windows .
```

The Windows job in `.github/workflows/windows-container.yml` is deliberately
manual and runs only on an organization-managed runner labelled
`self-hosted`, `windows`, and `docker-windows`. Registering that runner and
successfully running the job is required before promoting a new Windows image
digest.

## Safety boundary

Container packaging does not certify live use. All current adapters retain their
existing `lab_certified=False` status and their authorization, containment, and
cleanup controls. Keep `--network none` for plan-only and fixture workflows.

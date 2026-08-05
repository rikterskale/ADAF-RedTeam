---
guide_id: docker-usability
guide_schema_version: 1
platform: docker-linux-container
canonical_path: docs/guides/DOCKER_USABILITY_GUIDE.md
project_name: ADAF-RedTeam
target_release: "0.1.0"
support_status: supported_offline
validation_status: CI-verified container build and offline plan-only smoke test
primary_shells: ["Bash", "PowerShell"]
maintainer_source_of_truth: "Dockerfile, .github/workflows/ci.yml, README.md"
known_limitations: ["All live capabilities are uncertified", "No target credentials are included or persisted by the image"]
---

# ADAF-RedTeam Docker Guide

## Supported scope

The container image is a supported platform for `doctor`, `list-capabilities`,
`reference`, `run --plan-only`, and engagement-approved, offline fixture runs.
Its build and no-network plan-only path are exercised in CI. It is not a daemon,
listener, or a substitute for the authorization gate.

No live capability is certified on any platform. Do not remove `--network none`
for plan-only or fixture work, and do not use a container to bypass engagement,
containment, lab-certification, or cleanup controls.

## Build

Build from the repository root. `--pull` refreshes the reviewed, digest-pinned
Python base image. Update that digest only through your organization’s normal
dependency-review process.

```bash
docker build --pull --tag adaf-redteam:local .
```

The image has no credentials or target configuration. It runs as the unprivileged
`adaf` user and writes only to `/out` when started with the hardened command
below.

## Safe first run (Bash)

```bash
mkdir -p out
docker run --rm --user "$(id -u):$(id -g)" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,source="$(pwd)/out",target=/out \
  adaf-redteam:local run --engagement examples/engagement.example.json \
  --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out /out
```

This creates `out/plan.json` and `out/manifest.json`. `--user` maps the process
to your ordinary host account so the explicit output mount is writable. The committed address and
engagement are examples, not authorization. The container has no network path,
no Linux capabilities, a read-only root filesystem, and a temporary `noexec`
scratch directory.

## Safe first run (PowerShell)

```powershell
New-Item -ItemType Directory -Force out | Out-Null
docker run --rm --network none --read-only --cap-drop ALL `
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m `
  --mount "type=bind,source=$((Get-Location).Path)\out,target=/out" `
  adaf-redteam:local run --engagement examples/engagement.example.json `
  --capability adcs-esc1-validation --source-address 192.0.2.25 --plan-only --out /out
```

## Operational boundary

Use a new, empty output directory per engagement. Treat its artifacts according
to the engagement’s retention policy. Do not mount a Docker socket, host network,
host root, credential cache, or a home directory. Never put credentials in image
layers, environment variables, shell history, or an engagement committed to the
repository.

For an approved fixture file, mount only that file read-only and continue to use
`--network none`. Live target work remains unavailable until the individual
capability’s lab-certification requirement is met; the image does not change that
status.

Run `docker run --rm adaf-redteam:local doctor --out /out` to diagnose the
container itself. For the hardened command above, retain the explicit output
mount and use `--out /out`.

## Troubleshooting

| Symptom | Safe response |
|---|---|
| Docker daemon unavailable | Start or request access through the organization-approved Docker process; do not run the image with elevated privileges. |
| `/out` permission denied | Create a user-owned, empty host output directory and mount it at `/out`; do not make the container root. |
| `ADAF-RT-E202` | The requested live collector is uncertified or unavailable. Use plan-only or an approved offline fixture. |
| Build cannot fetch base image | Use the organization’s approved registry mirror or image-cache process; do not disable TLS verification. |

# Local pilot

**Audience:** adopters evaluating the Core.
**Status:** CURRENT, synthetic private preview.
**Outcome:** first successful local call, sanitized response, metadata-only audit and
ownership-checked cleanup.

This is the canonical Core local pilot. It requires no cloud, FSE2 material, SQL,
`.env`, host .NET SDK, Node, npm, curl or PostgreSQL, or trust-store changes.
These prerequisites do not extend to the
[optional FSE2 pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md#prerequisites).

## Prerequisites

- Git to obtain the repository;
- Docker Engine/Desktop with Linux containers and Docker Compose;
- PowerShell 7 or Windows PowerShell 5.1;
- network access only if pinned images or packages used by Docker builds are not cached.

Run commands from the repository root. Do not install an SDK to complete this pilot.

## Execution

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

`Validate` checks Linux Docker/Compose and builds the sample in the pinned .NET
10.0.302 SDK image. `Run` builds and starts PostgreSQL 18, migrations, Gateway/Admin UI,
Synthetic Provider and an HTTPS/mTLS mock. .NET and Node tools run during builds or in
non-root containers; the repository is mounted read-only and the Docker socket is not mounted.
The run creates a synthetic Direct Installation and grant in the isolated environment,
then invokes `sample-secure-service/submit` once.

Success ends with these markers:

```text
ALPHA_GOLDEN_PATH_DIRECT_PASS
ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=1
ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED
ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0
ALPHA_GOLDEN_PATH_PASS
```

The decoded application response contains `accepted: true` and the reference
`synthetic-order`. These mean only that the local mock accepted the request;
they are not a business outcome or external-service qualification.

## Interruption and recovery

If the process is interrupted, run:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop
```

`Stop` removes only resources and material marked as runner-owned. After cleanup,
repeat `Validate` and `Run`; do not modify containers, volumes or the database
manually. The run does not support intermediate resume.

A maintainer can still explicitly select the developer path with
`-DotNetPath <sdk-path>`. This is not the adopter path and requires the SDK matching
`global.json`; there is no automatic download or fallback to another host SDK.

For preflight codes and common errors, use [troubleshooting.md](troubleshooting.md).
Runner internals are an [implementation reference](../operations/ALPHA-GOLDEN-PATH.md),
not an alternative path.

## Evidence boundary

The pilot uses only synthetic DevelopmentAuth, CAs and material, and a process-local
Direct key. It does not go through the Windows Local Broker. It does not prove an
installer, cloud, FSE2, production custody, API stability, HA/DR or production readiness.
The next adoption gate must measure the black-box time from available prerequisites
to `ALPHA_GOLDEN_PATH_PASS`, including cleanup.

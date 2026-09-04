# Deployment and packaging

This document separates **CURRENT** artifacts from release and production targets.
An ADR, Dockerfile or IaC skeleton does not imply published packaging,
cloud qualification or production readiness.

## CURRENT — Local Broker

The .NET Windows Service, configuration, .NET SDK source and PowerShell scripts
`deploy/windows/install-service.ps1` and `uninstall-service.ps1` are present.

The following are not present as qualified distributable artifacts:

- MSI/WiX with install/repair/upgrade/rollback/uninstall matrix;
- C ABI DLLs, COM/type libraries or x86/x64 packages;
- published and signed NuGet/CLI;
- updater, recovery or rollback packages.

Windows scripts are development/laboratory tools and do not close AC-019.

## CURRENT — Core containers

The repository contains separate images for `Gateway.Api` and `Gateway.Migrations`. The
Gateway does not auto-migrate at startup. Its image uses an ASP.NET Debian base
pinned by patch tag and manifest-list digest and runs as a non-root user. It is not chiseled and
the base contains a shell. Read-only filesystem and `tmpfs` are enforced by the
Compose/CI profiles configuring them, not by the Dockerfile alone.

`/health/live` checks the process. `/health/ready` checks the registry and provider health;
it does not prove HA, backups, restore or external-service conformance.

### .NET base images

`global.json` selects SDK `10.0.302` with `rollForward: latestPatch`. Every
`FROM mcr.microsoft.com/dotnet/...` uses a readable patch tag and manifest-list
digest. Floating tags, `ARG`/interpolation and .NET `FROM --platform` are denied.

`eng/validate-container-base-images.ps1` is the fail-closed control. In the current
baseline, the repository inventory contains seven Git-tracked Dockerfiles and fourteen
.NET `FROM` occurrences:

- `src/Gateway/Gateway.Api/Dockerfile`;
- `src/Gateway/Gateway.Migrations/Dockerfile`;
- `packs/deployment/azure/Dockerfile`;
- `packs/deployment/local-pkcs12/Dockerfile`;
- `tools/m3/VendorMock/Dockerfile`;
- `tools/m3/SyntheticVault/Dockerfile`;
- `tools/m3/Provisioner/Dockerfile`.

The validator checks ordinal inventory, parser, tags/digests, mapping and SDK
alignment. A new Dockerfile or pin rotation requires an intentional control change,
pull/no-cache builds, a non-root/read-only gate, secret/vulnerability scanning,
SBOM and exact-head qualification. An export profile without Git metadata has a separate Core
inventory and does not reduce repository controls.

## CURRENT — local no-cloud quickstart

M4/M5 quickstarts compose:

- PostgreSQL 18 and provisioner/migration runner;
- non-root Gateway with static Admin UI;
- Synthetic Provider;
- HTTPS/mTLS vendor mock;
- per-run synthetic fixtures, CA and credentials under ignored `.artifacts`.

M4 uses the CLI to list and test a Published Connector. M5 adds
local DevelopmentAuth, real challenge/PoP enrollment, separate roles, four-eyes,
binding/grants, mTLS/BGW1 runtime, audit and post-retirement denial. Only the Gateway HTTPS port
is published on loopback; PostgreSQL, provider and mock remain on the private Compose network.

These gates are build/test/evaluation environments. They are not cloud,
OfficialTest or production deployments. Compose PostgreSQL uses SSL disabled within
the private network: it is not evidence of production database TLS.

Runbooks:

- [M4 local quickstart](../operations/M4-QUICKSTART.md);
- [M5 Admin quickstart](../operations/M5-ADMIN-QUICKSTART.md).

## CURRENT, opt-in — local PKCS#12 pack

`packs/deployment/local-pkcs12` is a pack outside the Core solution/export. It depends only
on provider-neutral abstractions, declares `SecretValues=false` and supplies a generic
deny-only secret provider. The Gateway does not require secret retrieval when the Published
operation uses the declared certificate/signing capabilities.

The `deploy/fse2/docker-compose.fse2-local.yml` overlay is opt-in and recreates only the
Gateway after the canonical synthetic quickstart. Manifest and material are mounted
read-only from paths outside Git; the container remains non-root/read-only.

Repository qualification uses exclusively per-run synthetic PKCS#12/CSR/certificate
fixtures and tests validation, signing/certificate, readiness and tamper handling. It imports no
official material, establishes no HSM/KMS custody, publishes no profile and executes no
live FSE2 calls. Certificate receipt/correlation and operational import remain
distinct events.

## CURRENT — Azure pack and Bicep

`packs/deployment/azure` is optional and excluded from Core. The pack depends on the same
provider-neutral capabilities; Core contains no Azure SDKs or types.

`deploy/azure-bicep/main.bicep` is a skeleton/contract; `m3-dev.bicep` is a
non-HA smoke template for the M3B laboratory. M3B has no attested live qualification on the
baseline. The presence of the pack, Dockerfile and Bicep does not demonstrate operational App Service,
Key Vault, Managed Identity, private networking, PostgreSQL Flexible Server, observability or
backup/restore.

## CURRENT — module loader

The loader requires deployment configuration with an absolute DLL path on a local drive,
assembly full name, module type and module ID. It denies UNC/device/mapped paths, traversal,
reparse points and duplicates; reads bounded bytes once, checks identity/MVID and loads the
same buffer.

It does not yet verify an expected manifest/hash, CMS or publisher allowlist. ACLs and byte
provenance are the deployment's responsibility. A loaded module is full-trust in-process.
The default Gateway Core includes no healthcare modules; a downstream vertical image
cannot reverse the dependency direction toward Core.

## CURRENT — SBOM, export and candidate artifact writer

`eng/generate-sbom.ps1` produces SPDX documents and an aggregate manifest with SHA-256 and
exact commit. The raw manifest includes run-specific attributes: its SHA is not a
cross-run deterministic digest. Candidate `0.1.0-alpha.1` adds
`normalizedInventorySha256`, computed over commit and canonical inventory without timestamps,
and verifies it fail-closed across two independent productions.

Core export uses an allowlist and boundary/license/secret/build/test gates. The local writer
produces SDK packages, image archive, Admin archive, Core source archive, SBOM, manifest and
checksums without pushing. There is no pipeline for NuGet/container push,
Authenticode, CMS, Cosign or SemVer publication.

## TARGET — Core `0.1.0-alpha.1`

In the full repository, artifacts and gates are defined in `0.1.0-alpha-scope.md`, a
governance document excluded from Core export. The target is a non-production developer
alpha with a single synthetic REST golden path, checksum/SPDX/vulnerability
inventory, source archive, clean-clone and reproducible instructions.

Recorded candidate gates include closed ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN,
ALPHA-VER, ALPHA-ART and P3-CORE-EXPORT-DIGEST, plus ALPHA-ADOPT PASS as an independent
adopter simulation. These apply to their recorded baselines, not automatically to
every later candidate. [Licensing](../../LICENSING.md) and the
[security-reporting channel](../../SECURITY.md) are already documented; tags and
publication still require explicit authorization. MSI/native/COM are not part of
the supported golden path.

## Optional FSE2 OfficialTest path

The vertical track uses its own FSE2 image/composition, Published configuration and
authorized A1/S1 material. The shipped [validation/status pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
documents bootstrap, roles, prerequisites and observed CDA/workflow results. It does
not import operational material or qualify production custody. The
[capability summary](../../IMPLEMENTATION_STATUS.md) owns current offline/live limits;
OfficialTest is not equivalent to production.

## TARGET — production/enterprise

Production claims require at least:

- signed installers/packages and compatibility matrix;
- artifact signatures/provenance and registry/release controls;
- qualified IaC for networking, providers, PostgreSQL, observability and isolation;
- migration rollout, canary/rollback, backup/PITR and restore tests;
- RPO/RTO, load/soak, pentest, incident response, rotation and monitoring;
- demonstrated append-only DB audit hardening and least privilege.

These controls require a real target and exact-head/environment gates. They are not inferred
from synthetic laboratories or ADRs.

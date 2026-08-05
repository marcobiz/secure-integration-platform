# Secure Integration Platform

Provider-neutral integration platform for on-premise and legacy software, with a Windows Local Broker, central Gateway, Connector Runtime and React administration console.

The platform removes hard-coded secrets and distributed credentials while minimizing changes to existing products. Healthcare is a future vertical pack, not a dependency of the Core.

![Sanitized Admin UI dashboard](docs/images/admin-dashboard.png)

## Status

M0–M4 and the M3A product gate are complete. M5 Admin UI MVP is in the PR #5 gate. M3B remains a separate Azure Deployment Pack qualification and is not required by the Core. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Local quick start, no cloud account

With Docker Linux containers, .NET SDK, Node 22 and PowerShell:

```powershell
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Validate
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Start
# UI: https://localhost:18443/admin/
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop
```

This starts PostgreSQL 18, a non-root Gateway with Admin UI, Synthetic Provider and HTTPS/mTLS mock. DevelopmentAuth exposes only fixed local synthetic identities. See [the M5 runbook](docs/operations/M5-ADMIN-QUICKSTART.md).

## Components

- Local Broker: Windows Service with Named Pipe, ACL, DPAPI/CNG and deny-by-default application policy.
- Gateway: Installation authentication, server-side tenant binding, grants, replay protection and restricted egress.
- Connector Runtime/SDK: versioned JSON definitions, logical server-owned bindings and Published-only execution.
- Admin UI/API: server-side OIDC, secure cookie, CSRF, RBAC, four-eyes, audit and health.
- Provider abstractions and Synthetic Provider: a Core that builds and runs without cloud SDKs.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [OPEN_SOURCE_BOUNDARIES.md](OPEN_SOURCE_BOUNDARIES.md). Current non-goals include M3B cloud qualification, real healthcare connectors, commercial legacy adapters, marketplace, billing, HA/DR and M6+.

## Build and test

```powershell
./eng/build.ps1
./eng/test.ps1
./eng/validate-docs.ps1
./eng/scan-secrets.ps1
./eng/generate-sbom.ps1
```

Admin Web pins Node/npm and all dependencies in its lockfile; its lint, unit, Playwright, accessibility and license gates are in `.github/workflows/m5-admin-ui.yml`.

## Security and licensing

No vendor secret passes through legacy software or the Broker; the browser never receives provider secret values or private keys. Endpoints and provider references are resolved server-side. Report vulnerabilities through [SECURITY.md](SECURITY.md), never in a public issue with exploitable details.

The definitive open-source license is still [under legal/business review](docs/legal/OPEN-SOURCE-LICENSE-DECISION.md). Reserved source documents and raw evidence are excluded from the repeatable Core export.

## Documentation

The complete index and reading order are in [docs/README.md](docs/README.md). Documents under `input-docs/` are reserved source material and are never part of a public export.

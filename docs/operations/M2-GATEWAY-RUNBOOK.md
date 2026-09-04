# M2 runbook — minimal Gateway

## Prerequisites

- .NET SDK specified by `global.json`;
- PostgreSQL **18.x** for real RLS testing;
- Docker for container build/smoke;
- for production: Azure Key Vault HTTPS and Managed Identity with access only to referenced
  secrets;
- exclusively synthetic certificates and keys in test environments.

## Local build and tests

```powershell
Set-Location (& git rev-parse --show-toplevel)
.\eng\build.ps1 -Configuration Release
.\eng\test.ps1 -Configuration Release
.\eng\validate-docs.ps1
.\eng\scan-secrets.ps1
```

Without `GATEWAY_POSTGRES_ADMIN_CONNECTION`, the real PostgreSQL test is skipped because
external infrastructure is missing; this is not RLS evidence. In a dedicated PostgreSQL 18
test database:

```powershell
$env:GATEWAY_POSTGRES_ADMIN_CONNECTION = '<test database administrative connection string>'
.\.dotnet\dotnet.exe test .\tests\integration\Gateway.Integration.Tests\Gateway.Integration.Tests.csproj -c Release
Remove-Item Env:GATEWAY_POSTGRES_ADMIN_CONNECTION
```

The CI `gateway-postgresql-18` job configures this variable against an ephemeral service
container and must be green to close M2.

## Explicit migration

Use a deployment identity separate from runtime:

```powershell
$env:GATEWAY_MIGRATION_CONNECTION = '<migration owner connection string>'
.\.dotnet\dotnet.exe run --project .\src\Gateway\Gateway.Migrations\Gateway.Migrations.csproj -c Release -- apply
Remove-Item Env:GATEWAY_MIGRATION_CONNECTION
```

The runner records the name and SHA-256. If the content of an already-applied migration
has changed, it terminates with an error. M2 is additive: application rollback restores
the previous image; no destructive down-script is provided.

## Development startup with Docker Compose

Generate synthetic values for the session only; do not save them:

```powershell
$env:GATEWAY_LOCAL_DB_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
$env:GATEWAY_LOCAL_ACTIVATION_HMAC_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
docker compose -f .\deploy\docker-compose.m2.yml up --build -d
Invoke-RestMethod http://127.0.0.1:8080/health/live
Invoke-RestMethod http://127.0.0.1:8080/health/ready
docker compose -f .\deploy\docker-compose.m2.yml down
Remove-Item Env:GATEWAY_LOCAL_DB_PASSWORD,Env:GATEWAY_LOCAL_ACTIVATION_HMAC_KEY
```

Compose runs a one-shot migration container and starts Gateway only after it completes.
The Gateway process never migrates the DB on startup. This is Development Compose and
does not demonstrate live Managed Identity or Key Vault.

## Production configuration

Configure through a protected provider, never in `appsettings.json`:

- `ConnectionStrings__GatewayDatabase`: login belonging to `gateway_runtime`;
- `Gateway__Provider__Kind`: `ExternalPack`;
- `Gateway__Provider__Endpoint`: provider HTTPS endpoint;
- `Gateway__Provider__ClientIdentity`: optional identity interpreted exclusively by the pack;
- `Gateway__ActivationHmacSecretReference`:
  `keyvault://<vault>.vault.azure.net/<secret>[/<version>]`;
- `Gateway__Operations__<n>__*`: allowlisted catalog; HTTPS endpoints, auth and Vault
  references are server-side configuration.

Outside Development/Testing, startup fails if the database, Vault or activation HMAC
reference is missing. Terminate TLS at a trusted ingress or configure Kestrel HTTPS; do
not trust forwarded certificate headers without the middleware and trusted network
required by the Azure deployment.

## Operational checks

1. `/health/live` must return 200 if the process is alive.
2. `/health/ready` must return 200 only when the registry and secret provider are ready.
3. Verify the container runs as a non-root user with a read-only filesystem.
4. Verify logs contain only code/correlation metadata; no payloads, auth headers,
   certificate DER, activation codes or Vault references.
5. Revocation must produce `BGW-INSTALLATION-REVOKED` before DNS/Vault/HTTP.
6. Public errors must be sanitized `application/problem+json`.

## Diagnostics and rollback

- DB readiness not green: check schema migrations, `gateway_runtime` membership and
  connectivity; do not elevate the runtime role to owner/superuser.
- Vault not green: check Managed Identity, allowlisted host and per-Vault RBAC; do not
  replace it with secrets in files.
- Egress denied: check the operation catalog and DNS; do not disable IP checks.
- Rollback: stop the new image and redeploy the previous one. The M2 migration remains
  because it is additive; any data rollback requires an approved change.

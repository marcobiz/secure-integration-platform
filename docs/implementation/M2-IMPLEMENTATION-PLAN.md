# M2 — Minimal Gateway implementation plan

**Status:** implementation and local PostgreSQL 18 complete; container/CI pending
**Baseline:** `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12`
**Previous gate:** M0/M1 PASS-LIVE, AC-002 and AC-004 PASS-LIVE

## Objective and scope

M2 introduces an executable modular-monolith Gateway that assigns each Installation
a distinct identity, always derives the Tenant from the authenticated identity and allows
only invocations of server-configured operations. The Gateway uses PostgreSQL
as its source of truth, Azure Key Vault as its production provider and a synthetic provider
exclusively in tests.

Included:

- ASP.NET Core host with health/readiness and redacted Problem Details;
- Tenant/Application/Environment/Installation registry and grants;
- explicit PostgreSQL 18 migration, composite FKs, roles and `FORCE` RLS;
- single-use activation code, short-lived challenge and ECDSA P-256 proof of possession;
- Installation credential registration, renewal with overlap and revocation;
- runtime authentication with a ClientAuth certificate, envelope signature, timestamp,
  digest and anti-replay nonce;
- operation catalog configured exclusively on the server;
- Azure Key Vault provider through Managed Identity and a guarded synthetic provider;
- restricted HTTPS egress, fixed host/path/method/headers, disabled redirects/proxies,
  bounds, timeouts and centralized Basic/API key/mTLS;
- metadata-only audit and W3C correlation;
- non-root Dockerfile with health check;
- unit, integration, security and real PostgreSQL 18 tests in CI.

Excluded:

- Connector lifecycle/versioning/publish/rollback (M4);
- Admin UI, Entra OIDC and four-eyes (M5);
- adapter COM/C ABI/CLI (M6);
- OAuth/JWT/SOAP and extended authentication modules (M7);
- the new Broker→Gateway→Vault→mock vertical slice, which remains the M3 gate;
- enterprise CA, complete operational recovery/rotation and full Azure deployment (M9).

For M2, operations are immutable startup configuration. They are not ConnectorVersions
and do not introduce the M4 state machine ahead of schedule.

## Buildable increments

1. **Gateway foundation:** Domain/Application/Infrastructure/API projects and tests;
   contracts, error model, clock and in-memory repository.
2. **Persistence:** SQL migration, Npgsql repository, transaction-local tenant context,
   RLS and real PostgreSQL tests.
3. **Enrollment:** HMAC activation hash, challenge TTL, ClientAuth certificate and PoP,
   renewal, overlap and revocation.
4. **Runtime identity:** certificate extraction, registry lookup, server-side Tenant,
   body hash, canonical signing input, timestamp and nonce replay.
5. **Vault and egress:** Key Vault/Managed Identity, synthetic guard, operation catalog,
   Basic/API key/mTLS and restricted transport.
6. **Hosting/package:** M2 OpenAPI endpoints, health/readiness, Dockerfile and runbook.
7. **Gate:** build, tests, PostgreSQL CI, secret/dependency scan, traceability and status.

Every increment must leave `eng/build.ps1` and `eng/test.ps1` green.

## M2 traceability

| Requirement | Expected evidence |
|---|---|
| FR-001 | `IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured` |
| FR-002 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`, renewal and revocation tests |
| FR-007 / AC-011 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected` |
| AC-012 | `UT_GTW_Cross_tenant_grant_is_rejected`; `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured` |
| AC-013 | `UT_GTW_Revocation_is_immediate_for_runtime_and_grants`; full E2E in the M3 gate |
| AC-007/009/010 | invoke-contract, fixed endpoint, Basic/API key/mTLS and deny-before-side-effect tests |
| FR-016 / NFR-001 | `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`; API log/Problem canary tests |
| NFR-002/003 | SSRF/private IP, catalog HTTPS, DNS pinning and TLS configuration tests/review |
| NFR-005 | `UT_EGR_Transient_retry_occurs_only_for_idempotent_operation` |
| NFR-006 | signed/audited correlation ID; `traceparent` required by the invoke endpoint |
| AC-018 | container build/smoke in CI with health endpoint |

## PostgreSQL and test environment

The current HOST has neither Docker/Podman nor a running PostgreSQL instance. However,
the existing PostgreSQL 18 binary installation was used to start an ephemeral,
unprivileged cluster under `.artifacts`; the real suite requires
`GATEWAY_POSTGRES_ADMIN_CONNECTION`.
GitHub Actions starts PostgreSQL 18 as a service container, applies the migration from scratch
and verifies CRUD, composite FKs, `SET LOCAL app.tenant_id`, cross-Tenant RLS and nonce replay.
The local PostgreSQL 18 test is PASS; a missing CI/container result cannot close
the M2 gate.

## Security invariants

- Activation codes are stored only as HMACs; challenges and nonces have TTLs.
- The presented certificate must match the registered SPKI/certificate hashes.
- The signature covers method, normalized path/query, timestamp, nonce and exact body.
- Tenant, endpoint, method, sensitive headers and secret references do not come from the client.
- The database stores no secret values or response bodies.
- The synthetic provider fails at startup outside Development/Testing.
- Egress uses HTTPS, without redirects/proxies, with DNS/IP filtering and explicit bounds.
- Logs, Problem Details and audit contain no bodies, credentials, vault references or headers.
- Revocation and replay are checked before any Vault/egress access.

## Completion criterion

M2 is Done only when local builds and tests are green, the PostgreSQL 18 suite and
container smoke pass in CI, secret/vulnerability scans are green, documentation
and the traceability matrix list real test names and no bypass remains
within the declared scope. Missing Azure credentials allow tests with SDK client
mocks, but not a claim of live Key Vault evidence.

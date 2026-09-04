# M5 — Admin UI MVP: implementation plan

## Baseline and constraints

Immutable baseline: tag `m4-connector-configuration-baseline-20260805`, commit `49f81cb37dcd5bf8956638fe4af53c3c5cf39b2b`.

Branch: `m5/admin-ui-mvp`. M3B, real cloud, real healthcare Connectors, commercial legacy adapters and M6+ are out of scope. The M5 PR will not be merged automatically.

## Verifiable increments

1. **OSS/provider boundary**: capability-specific abstractions, separate synthetic provider, optional Azure pack, Core solution filter, architecture test and export allowlist.
2. **Administrative schema**: AdminPrincipal `(issuer, subject)`, tenant-scoped roles, audited bootstrap, checksum-specific approval records, additive migration and RLS.
3. **Authentication**: server-side OIDC authorization-code with PKCE/state/nonce, secure cookie, CSRF, logout and expiry; isolated Development fixture that fails closed in Production.
4. **Admin API v1**: provider-neutral DTOs, RBAC, ProblemDetails, correlation ID, ETag/If-Match, pagination, audit and four-eyes.
5. **Frontend**: strict React/TypeScript, routing, query cache, form/schema validation, JSON editor and diff, IT/EN i18n, themes and accessibility.
6. **Operational pages**: dashboard, tenant, application, installation/enrollment/revocation, Connector lifecycle, binding, grant, controlled test, audit and health.
7. **Local packaging**: same-origin assets, non-root container, no public sourcemaps, provider-neutral Compose quickstart and synthetic data.
8. **Gate**: backend/frontend/E2E/a11y, PostgreSQL 18, scans, SBOM, clean-clone, open-source boundary, external redacted evidence and PR #5.

Every increment ends with relevant builds/tests and a focused commit. A failure is corrected in the next commit with an automated regression test; history is not rewritten.

## Main fail-closed criteria

- Production does not start with DevelopmentAuth, an admin API key or incomplete OIDC.
- Mutations without a valid session, CSRF, role or `If-Match` are denied and audited.
- The requester/editor cannot approve their own checksum; a later change invalidates approval.
- Publication without distinct approval is denied by the default production policy.
- Tenant scope derives from the principal, not from unauthorized client data.
- API/UI do not return secret values, activation codes after the one-time response or arbitrary provider references.
- The UI uses no CDNs, telemetry, `dangerouslySetInnerHTML`, `eval` or `new Function`.

## Test strategy

- Policy and domain unit tests for every role, tenant scope, bootstrap and four-eyes.
- HTTP integration tests for cookies/OIDC/CSRF/security headers/ProblemDetails/ETag/pagination/audit.
- PostgreSQL 18 integration tests for migration apply/no-op, RLS and concurrency.
- Vitest/Testing Library for components, i18n, themes, validation and error handling.
- Playwright for the 20 required scenarios and axe for automatable WCAG 2.1 AA checks.
- Container/quickstart/clean-clone and full M0–M4 regression.

## Evidence

Raw evidence is temporary and ignored. The redacted bundle is written outside the repository to `C:\SecureEvidence\m5-gate-<timestamp>` and includes the commit, runtime/tool versions, jobs, image/SBOM/migration hashes, named tests, cleanup and hashed manifest.

## Decisions not included

- Final license: the owner's choice between Apache-2.0 and MPL-2.0 remains open.
- Specific production OIDC provider: a deployment concern; Core remains standard OIDC.
- M3B Azure smoke and real healthcare packs: later milestones that do not block M5 implementation, except for their respective declared readiness.

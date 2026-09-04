# Troubleshooting

**Audience:** adopters and operators.
**Status:** CURRENT. The following actions stay on supported surfaces; they require
no SQL, direct store access or publication of sensitive data.

## Local pilot

| Code/symptom | Likely cause | Authorized action |
|---|---|---|
| `ALPHA_GOLDEN_PATH_DOCKER_UNAVAILABLE` | Docker CLI/Engine missing, stopped or unreachable. | Install or start Docker in Linux containers mode, then repeat the same `Validate`. Do not install .NET as a workaround. |
| `ALPHA_GOLDEN_PATH_DOCKER_COMPOSE_UNAVAILABLE` | Compose plugin unavailable. | Install/enable supported Docker Compose and repeat `Validate`; do not use another orchestrator. |
| `...COMPONENT=ContainerDotNet...` or `...CHILD_CODE=M5_QUICKSTART_COMMAND_FAILED_DOTNET` | Pinned SDK image, package or container build unavailable. | Check network/cache and pinned-image availability, then manually repeat the same phase. There is no host fallback or automatic retry. |
| `ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND` / `...DOTNET_SDK_UNAVAILABLE` | The maintainer `-DotNetPath` path was explicitly selected, but its resolver is unusable or incompatible. | Correct the developer path or omit `-DotNetPath` to return to the Docker-first pilot. Do not change `global.json` or fall back to .NET 8. |
| `ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO` | Restore, build, container or child process failed. | Check Docker/Compose, network/cache and disk space; run `-Phase Stop`, then `Validate` and `Run`. Do not inspect or modify the database. |
| Docker unavailable | Engine stopped or in Windows containers mode. | Start Docker with Linux containers and check Compose. |
| Interrupted run / remaining resources | Final cleanup incomplete. | Run `./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop`; it removes only marker-owned resources. |
| Missing `ALPHA_GOLDEN_PATH_PASS` | A check or cleanup did not finish. | Treat the run as failed even if an intermediate response was 200; retain only redacted diagnostics. |

## FSE2 provisioning

| Code/symptom | Operational meaning | Authorized action |
|---|---|---|
| `FSE2_OFFICIALTEST_PLAN_*` or `...PLAN_FILE_INVALID` | Plan outside the schema, oversized, duplicated or insufficiently protected. | Correct the plan outside Git using the closed schema; do not add properties or runtime authority. |
| `FSE2_OFFICIALTEST_ADMIN_SESSION_REQUIRED` / `...INVALID` | Invalid HTTPS URL, process-local cookie or session. | Obtain a new session through the deployment, in the correct role's process. Do not put the cookie in the plan, CLI or logs. |
| `...ADMIN_REJECTED_401` / `403` | Expired session or unauthorized role. | Authenticate the same intended role and repeat the same phase; do not switch roles to bypass RBAC. |
| `FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE` / `...AMBIGUOUS` / `...INACTIVE` | Selector does not resolve exactly one active, visible Installation. | Correct the inventory through the supported Admin API; do not pick “the first” or query PostgreSQL. |
| `...INSTALLATION_ENVIRONMENT_MISMATCH` | Plan assertion does not match the server-owned Environment. | Stop and correct the plan/deployment. Do not change the Installation or binding to force a match. |
| `...PROVIDER_AUTHORITY_DRIFT`, `...BINDING_READBACK_DRIFT` | Revisions/providers/bindings no longer match. | Reread authoritative state, correct the cause and repeat the lifecycle; old approvals are no longer valid. |
| `...APPROVAL_DIGEST_STALE` / `...PUBLISHER_MUST_BE_DISTINCT_APPROVER` | Invalid four-eyes or exact artifact. | Create a new proposal against current state and use a distinct approver. |
| `BGW-PROVISIONING-RATE-LIMITED` / `BGW-RATE-LIMITED` | Admin quota exhausted, without automatic retry. | Respect any bounded `Retry-After` and repeat the same command/plan/session only if `retrySafe=true`. |
| `BGW-PROVISIONING-IDENTITY-DRIFT` / `...SERVER-STATE-INVALID` | Non-monotonic state or identity changed during the phase. | Stop, reread through Admin APIs and correct the earliest cause; do not use force, destructive cleanup or SQL. |
| `FSE2_OFFICIALTEST_PROVISIONING_FAILED` | Bounded error without further detail. | Consult Health and redacted audit as Security Administrator; do not capture response bodies, stack traces, JWTs or certificates. |

## FSE2 invocation

Use the [current validation/status runner](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
only with authorized prerequisites and OfficialTest calls. Its `Audit`, `Restart`
and status commands have documented outcomes and limits; do not build payloads or
calls from integration tests, fixtures, raw evidence or copied endpoints.

The observed FHIR `generic-error` 500 has no determined cause: it does not establish
a format, accreditation or authorization problem and does not authorize automatic
retries or speculative changes. Do not invent a missing workflow. `FOUND` after
CDA does not prove publication: see the [capability summary](../../IMPLEMENTATION_STATUS.md#product-status).

If an authorized call fails, retain only the correlation ID and bounded diagnostic
fields visible to the Security Administrator (phase, bounded category/status, safe code).
Do not retain CDA input, raw responses, JWTs, headers, cookies, chains or P12 files.

## When to report a product issue

Report an adoption issue when the normal remedy requires repository knowledge,
SQL, store access, repeated logins, manual cookie copying, specialist support or
an undocumented sequence. Do not turn the workaround into a runbook: describe the
outcome, phase, safe code and action the product should have offered.

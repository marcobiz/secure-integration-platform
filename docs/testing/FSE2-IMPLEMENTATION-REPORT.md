# FSE2 National Connector Organization profile — implementation report

Date: 2026-08-11

Qualified Core/Auth/Runtime baseline: `feec547a3e0991171fca1f8b22b136d3dd4c4ee3`

Lineage: historical PR #16; replacement branch `wave1/fse2-national-organization`

Official public freeze: guide 2.23 and OpenAPI 1.0.0 at
`430e6b5d9dde8a35b04ae635c11303db787a977e`.

## Implemented result

The Organization profile now runs as the external module `healthcare-fse2` and strategy
`healthcare-fse2-organization`. Its only declared outbound authentication kind is `mtls`.
The pack consumes the public `AuthorizedConnectorExecution` surface and has one project dependency:
`Gateway.Application`. It has no `InternalsVisibleTo`, store, provider, signing primitive,
certificate primitive, restricted-transport implementation, Gateway internal invocation object,
service locator or HTTP client.

The FSE2-specific profile is parsed and validated inside `Healthcare.FSE2` from the immutable
`AuthorizedPublishedExtensionConfiguration` copied from initially authorized Published A. The
profile supplies organization/locality/application values, the exact frozen operation semantics,
request media type and the two vertical slot names. It does not reread a generic store and is not a
second authority model. The profile's approved P.IVA plus assigning authority produce canonical CX;
the two server-owned signing policies use that value as fixed `sub`. `person_id` remains a separate
validated business CX. DAP, purpose and action are derived from the frozen operation matrix and
`use_subject_as_author` is absent. Human Actor remains deferred.

The strategy requests exactly one fresh opaque token from `authorization` and one from `integrity`.
Core owns RS256, issuer, audience, fixed subject, temporal values, `jti`, signing binding, SPKI,
`x5c` and both projections. The vertical never reads either compact JWT and never creates an
Authorization or `FSE-JWT-Signature` header. Core projects the first as Bearer and the second as the
FSE header, then performs the existing Published-A freshness, restricted-egress and server-owned
mTLS flow.

FSE2 claim composition remains connector-local. The integrity token receives only allowlisted
business/derived scalar claims. For document operations, the connector composes one immutable,
deterministic multipart body and computes lowercase SHA-256 over those exact final outbound bytes;
the same copied byte array is handed to restricted transport without later serialization. The
frozen eleven-operation inventory is unchanged: nine Production-available operations, two official
test-only operations, and no speculative FHIR create/replace, callback or consumer surface.

Responses are reduced to bounded technical identifiers and safe warnings. The module-owned workflow
store keeps technical workflow/trace correlations scoped by authenticated identities, Connector
version and exact FSE profile checksum; it never stores patient or document data. This correlation
store is process-local and is not represented as durable PostgreSQL workflow persistence.

## Production-path evidence

`Fse2OrganizationHostedIntegrationTests` crosses the real hosted path:

PostgreSQL 18 or in-memory Published store → Connector import/validation → editor → distinct
approver → publication → hosted Gateway → BGW1 request authentication → grant → dynamically loaded
FSE2 module/strategy → exact Published extension → both authorized signing slots → server-owned
mTLS/restricted HTTPS → synthetic FSE2 server → bounded response.

The server requires the exact trusted client certificate and checks the real request method, path
and content type. It verifies two distinct compact tokens and `jti` values, both RS256 signatures,
the full expected `x5c` chain, the same signing leaf, distinct `auth:`/`integrity:` issuers, fixed
organization subject, audience, `iat+exp` without `nbf`, exact Published lifetime,
DAP/purpose/action, organization/locality/application and person claims, and the SHA-256 of the
network-observed multipart bytes. The success case observes exactly one outbound request and no
retry.

Connector-specific negatives cover unknown and repeated slot selection, caller attempts to add a
subject, caller metadata attempts to select endpoint/key/certificate/profile, malformed CX/XON,
role/operation/environment profile substitution and exact-byte mutation detection. The deterministic
connector race blocks the second-slot signing flow, publishes B, resumes and receives Core stale
denial with zero FSE2 requests and zero generic transport effects. Generic signing-slot, provider,
cancellation, timeout, restricted-egress and binding-substitution matrices remain regression evidence
from the qualified Core foundation; they are not reimplemented in the vertical.

## Historical local qualification before the temporal remediation

The following results belong to predecessor candidate `45548c13df5d46cdb5f9cba1d101ee08619ef15b`.
They remain visible as historical evidence but do not qualify the temporal-remediation exact HEAD.
The replacement PR and final writer handoff record the newly executed exact-head gates.

Two historical harness invocation failures remain recorded and are not PASS evidence: a bare
`npm run test:e2e` was started without the required Gateway full-stack service and failed with
`ECONNREFUSED ::1:8443`; an initial PostgreSQL gate command selected the machine-wide .NET 8 SDK
instead of repository-pinned SDK 10.0.302 and stopped before any product test ran. The later
canonical full-stack and pinned-SDK executions do not erase or reclassify those failures.

- FSE2 public-contract unit suite: 33/33 PASS;
- Healthcare architecture slice: 8/8 PASS, including one `Gateway.Application` reference and no IVT;
- hosted FSE2 in-memory success/negatives and A→B race: 2/2 PASS;
- hosted FSE2 PostgreSQL 18 canonical test: 1/1 PASS on an ephemeral `postgres:18` container;
- migration `0001` through `0013`, including authorized signing slots: PASS; container removed;
- pack and hosted integration build: zero warnings/errors.

- full `BrokerGateway.slnx` Release build and ordinary test gate: 599 PASS, 31 explicit
  environment-gated skips and zero failures, with zero build warnings/errors;
- authorized signing-slot focused regression: 8/8 PASS; complete certificate-signing suite:
  93/93 PASS; hosted capability/execution regression: 5/5 PASS with its PostgreSQL-only case
  explicitly skipped in the ordinary run;
- Admin Web lint, generated OpenAPI diff, 28/28 Vitest, production build and npm high-severity
  audit: PASS; `FULLSTACK-01` 1/1 PASS with production images, redaction and Docker cleanup;
- documentation validation, conservative secret scan, NuGet vulnerability scan and
  `git diff --check`: PASS;
- full SPDX generation, including the indexed Gateway container, validation and SBOM-mode
  regression: PASS;
- verified Core export: PASS for 418 allowlisted files, including its clean restore, Release build,
  Core tests, Admin build and frontend-license scan; an independent inventory check found no
  Healthcare or ConnectorPacks path;
- deterministic M3 split-network, split-firewall and operator-handoff regressions: PASS.

## Canonical PostgreSQL CI qualification

The connector/CI candidate exact head `c450d7133436a6f7a3a83dcb5c35f594dcadf7b6` qualified on
2026-08-11 without rerun. General run
[`31495813159`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813159)
passed 6/6 and M5/Admin run
[`31495813186`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813186)
passed 15/15. In General job
[`gateway-postgresql-18` (`93793113966`)](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813159/job/93793113966),
the log identifies that exact SHA, restores the FSE2 integration project in locked mode, builds it
in Release, and runs the exact PostgreSQL FSE2 FQN with `REQUIRE_FSE2_POSTGRES_GATE=1` before the
always-run cleanup. The explicit result is `Healthcare.FSE2.Integration.Tests.dll`: Failed 0,
Passed 1, Skipped 0, Total 1.

The historical harness invocation failures above remain failures and are not evidence for this
qualification. This report does not claim an official FSE endpoint call or accreditation.

## Readiness boundary

- `ORGANIZATION_PROFILE = READY_FOR_INDEPENDENT_REVIEW`, after final documentation-only exact-head
  CI confirmation;
- `HUMAN_ACTOR_PROFILE = DEFERRED`;
- `NEW_CORE_PRIMITIVE_REQUIRED = NO`;
- `ACCREDITED_PRODUCTION_READY = false`.

Official provisioning, production certificate custody, approved policy values, conformance,
accreditation, monitoring and live evidence remain required before production readiness.

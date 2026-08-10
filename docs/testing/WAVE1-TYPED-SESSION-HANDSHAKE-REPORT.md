# Wave 1 typed session handshake and external admission report

## Candidate scope and reviewed baseline

This report covers only the generic Core capability described by ADR-0022. It does not qualify a
production connector, a deployment environment, a distributed cache or generic XML scripting.

- Rebased base / merged PR #22 head: `9b560ff11cc3ac35160a050ccc10b192c2782166`.
- Original independently reviewed head: `8f6218599dc7fb454a8a542184ae7ce816856c96`.
- Targeted remediation product commit: `45605a9fb3085d83af3b2d9d50e8b08f4a987f65`.
- Previous targeted re-review head: `e48c1eee4d83f76630ed8cdc1f358d91f6d1f6f1`.
- Final test/evidence remediation commit: `95eeaf5d6e2c2170570f48e7570f90b8dfb4e646`.
- Starting rebased PR #23 head: `fb5f622221d855d5be829e3516a538e87c3bda59`.
- Shared-lifecycle wiring fix: `f08eb9762fcc21dc7d6d7ba236cf6a80840dfac9`.
- `PRODUCTION_CODE_CHANGED`: **YES**, limited to the `Gateway.Api` DI alias that removes the
  independent business cache. No protocol or session implementation changed.
- Branch/PR: `wave1/auth-session-handshake`, PR #23; open and unmerged.

No Sistema TS, duplicated PR #22 dispatch composition, arbitrary XML framework, second session cache,
healthcare production connector or commercial adapter is introduced.

## Reviewed findings

| Finding | Result | Product control and named evidence |
|---|---|---|
| P1 validator owned network/credentials | FIXED | `ITypedExternalSessionValidationAdapter` only writes/parses typed XML; Core resolves Published endpoint, SOAP policy and existing credential bindings and owns restricted HTTPS/DNS/deadline/bounds. Real composition/store/Basic/HTTPS E2E and adapter mismatch zero-network matrix PASS. |
| P1 stale promotion after final await | FIXED | Shared fixed 64-stripe mutation leases cover begin through completion of publish/binding/resource changes. Final synchronous CAS requires exact generation and zero active mutations, then checks proof/intent/session generation and promotes under the same stripe with no await. Final-window and capture-during-mutation tests PASS. |
| P1 public candidate/no authenticated presentation boundary | FIXED | `ExternalSessionCandidate` is internal. Public completion accepts only authenticated principal, opaque intent reference and candidate bytes; Connector/operation/profile/key/provenance/expiry/validator are server-resolved and the grant is reauthorized. API and wrong-principal matrices PASS. |
| P1 no production composition/store path | FIXED | API composition registers real authorizer, Published resolver/stamp provider, bounded exact registry, restricted SOAP client and runtime. PostgreSQL four-eyes/runtime locator plus production restricted-HTTPS admission and subsequent business use PASS. |
| P2 fake cancellation crosses extension boundary | FIXED | Request/response/validation adapters preserve only a genuinely cancelled caller/effective token, rethrow a normalized OCE without extension message/inner, and map fake OCE/other exceptions to stable sanitized codes. |
| P2 no individual XML value bound | FIXED | The first hardened scan chunk-reads and caps each text, CDATA and attribute value at 16,384 characters before `XDocument`; below-limit, over-limit and aggregate-limit matrices prove adapter invocation/no-invocation behavior. |
| P2 concurrency/replay/final-race coverage | FIXED | Unit authority tests retain simultaneous completion, proof/candidate/intent/profile/context/generation replay and final-window precision. The final remediation adds production-host cross-context replay and PostgreSQL store races without sleep or direct invalidation. |

## Final targeted re-review findings

| Remaining finding on `e48c1eee` | Result | Exact final evidence |
|---|---|---|
| P2 production presentation E2E | **FIXED** | `Wave1_IT_PRODUCTION_HOST_authenticated_routes_store_registry_admission_replay_and_session_use` starts the actual `Program`, sends HTTP through acquire/completion, executes `AuthenticateAsync`, current grants, PostgreSQL Published resolution, DI adapters, restricted HTTPS validation, HTTP cache reuse and subsequent SOAP business use. |
| P2 production-store concurrency/replay evidence | **FIXED** | `Wave1_IT_PRODUCTION_STORE_final_race_uses_same_PostgreSQL_authority_and_denies_promotion` uses the host's `RoutingConnectorConfigurationStore` and resolver. Real publish and resource-disable variants occur after one validator success and before CAS; both deny promotion and replay with zero additional network. The hosted test separately denies valid-grant cross-Tenant, cross-Application and cross-Installation principals before validator network. |
| P2 subsequent hosted session use | **FIXED** | The production DI graph aliases `OpaqueSessionLeaseProvider` to `SoapSessionClient.OpaqueSessionLeases`. The hosted test invokes `POST /v1/connectors/{connectorId}/operations/session-business:invoke`; BGW1, grant and Published `soapBasicOpaqueSession` select `ComposedSoapExecutionStrategy`, resolve Basic and lease the promoted generation for one real restricted-HTTPS SOAP dispatch. |

The old `Wave1_IT_Internal_composition_*` tests remain useful but are explicitly classified as
`INTERNAL_COMPOSITION_TEST`; they are not production-host or production-store evidence.

## Architecture and authority

- The Published validation profile fixes adapter ID/type, endpoint binding/path, SOAP
  version/action, exact request/response QName, deadline and request/response bounds in the
  four-eyes checksum.
- Validation adapters receive no `HttpClient`, endpoint, DNS, credential locator, secret, timeout,
  proxy/redirect selector or transport. Core creates the envelope, resolves the operation's
  server-owned Basic credential bindings, pins the approved destination and performs the bounded
  HTTPS request and hardened parse.
- The bounded explicit composition registry accepts at most 256 entries per adapter role and uses
  exact logical ID/type keys without reflection, assembly scanning or caller-provided CLR types.
- The canonical host test uses `WebApplicationFactory<Program>` and the production DI graph. A
  test-only certificate feature bridge compensates only for `TestServer` lacking a TLS handshake;
  the presented certificate must still resolve in the production registry and the request must pass
  the real BGW1 timestamp, nonce, content-digest and P-256 signature checks in `AuthenticateAsync`.
- Connector setup uses the PostgreSQL admin/runtime routing pair, validation, distinct editor and
  approver roles, checksum-specific approval and `PublishApprovedAsync`. The runtime request then
  resolves the same current Published version through the runtime data source.
- The authenticated runtime completion resolves all intent authority from the existing bounded
  SOAP cache, enforces only the closed `InteractiveHandoff` provenance, reauthorizes the current
  principal/grant and constructs the internal owned candidate. The API request buffer and candidate
  are cleared on terminal paths and are excluded from JSON, diagnostics and audit metadata.
- Published, binding and provider-resource mutation paths share one process-local 64-stripe
  authority between Admin and runtime stores. A mutation lease advances generation at begin/end and
  marks the stripe active without holding a lock across database I/O. Final promotion contains no
  await and succeeds only under the exact inactive generation while the cache atomically consumes
  the candidate-bound validation proof and assigns one current session generation.
- The design retains one SOAP cache, cap 256, 64 acquisition stripes, TTL/lazy sweep and one current
  generation. `SoapSessionClient` owns it and the production `OpaqueSessionLeaseProvider` is an alias
  of `SoapSessionClient.OpaqueSessionLeases`; the composition root does not register another cache.
  The process-local authority matches this existing single-node cache; scale-out would require a
  separately reviewed distributed cache and linearization authority.

## Hosted path and exact race

- Acquire enters the mapped HTTP route, authenticates the registered certificate-bound identity,
  checks the exact operation grant, resolves the Published typed profile and composition-root
  adapters, sends one real restricted-HTTPS `CreateSession`, and returns only the opaque intent.
- Completion enters the mapped presentation route, reauthenticates, resolves intent authority
  server-side, sends one real restricted-HTTPS `ValidateSession`, and returns an opaque session.
  A second signed acquire returns the same promoted opaque reference with no network. A signed HTTP
  `session-business:invoke` then crosses inbound authentication and grant, resolves the Published
  `soapBasicOpaqueSession` operation, selects `ComposedSoapExecutionStrategy`, obtains Basic plus the
  current promoted lease and sends one real restricted-HTTPS SOAP request. Acquisition and validation
  remain unchanged, business outbound increments once and session generation remains unchanged.
- Independently enrolled cross-context principals all have an otherwise valid operation grant. A
  relationally valid cross-Tenant or cross-Application identity necessarily has its own Installation;
  the third case changes only Installation under the original Tenant/Application. All three deny
  before outbound validation, so Gateway validation count and synthetic validator count remain zero.
- The race hook is after the final awaited Published/resource revalidation and immediately before
  `TryPromoteIfCurrent`. T2 uses either four-eyes publication of version 2 or a real provider-resource
  disable through the same routing store. T1 resumes with validator count one, but the store generation
  has advanced, the CAS denies, cache/session promotion remains zero and replay makes no network call.
- Candidate canaries are absent from success/error HTTP bodies, captured logs, exception
  serialization and metadata-only PostgreSQL audit output.

## Evidence classification

| Classification | Named evidence | Claim |
|---|---|---|
| `UNIT_AUTHORITY_TEST` | `TypedSessionHandshakeTests` | Fast exact proof of adapter, cache, proof, concurrency and authority invariants. |
| `INTERNAL_COMPOSITION_TEST` | `Wave1_IT_Internal_composition_*` | Manually composed real-HTTPS/store checks; not a `Program`/HTTP proof. |
| `PRODUCTION_HOST_E2E` | `Wave1_IT_PRODUCTION_HOST_authenticated_routes_store_registry_admission_replay_and_session_use` | Actual host, authenticated routes, PostgreSQL, DI identity, acquire/completion and hosted business API through production composed strategy/transport with generation and network-count proof. |
| `ARCHITECTURE_LIFECYCLE_GUARD` | `Wave1_CT_Gateway_composition_aliases_business_leases_to_the_singleton_SOAP_session_lifecycle` | Production composition contains no second `SoapSessionCache`; business lease provider aliases the singleton client lifecycle. |
| `PRODUCTION_STORE_RACE` | `Wave1_IT_PRODUCTION_STORE_final_race_uses_same_PostgreSQL_authority_and_denies_promotion` | Same production routing store/resolver/authority; publish and disable variants at the exact final linearization window. |

## Local qualification on shared-lifecycle wiring commit

| Suite | Result | Coverage |
|---|---:|---|
| `TypedSessionHandshakeTests` | 41 PASS | authority, adapters, XML, cancellation, presentation, atomicity, concurrency, replay, bounds and redaction |
| focused session/composed/opaque/legacy unit filter | 120 PASS | typed authority, AP-02/legacy cache, opaque projection, composed dispatch and exact strategy selection |
| typed hosted/integration filter | 8 PASS | 4 existing real-HTTPS/internal cases, 1 API authentication case, 1 production-host E2E and 2 production-store race variants |
| final production-host/store cases | 3 PASS | hosted acquire/completion/replay/session use plus Published-revision and resource-disable final races |
| focused SOAP/typed/opaque integration regression | 38 PASS | typed 8, composed 20, opaque HTTP 5 and legacy SOAP 5 |
| SOAP architecture filter | 3 PASS | composed boundary, single SOAP cache and exact production lifecycle alias |
| complete Architecture suite | 26 PASS | Core/provider/auth and vertical boundaries |
| legacy SOAP plus Connector configuration unit | 35 PASS | scalar M6 and configuration compatibility |
| legacy SOAP real-HTTPS integration | 5 PASS | Login/Challenge/Business/Logout and hardening compatibility |
| ordinary solution suite | 509 total: 482 PASS, 27 PostgreSQL-conditional SKIP | all solution projects, zero failures; TRX evidence outside the repository |
| Gateway integration on fresh PostgreSQL 18 | 10 iterations × 133 PASS, 0 SKIP | 1,330 tests; 10 fresh migrations, 10 second-apply no-op checks and forced RLS; non-superuser Admin/runtime roles |
| PostgreSQL targeted stability matrices | 80/80 PASS | pagination, bootstrap fault injection, Tenant/Application concurrency and binding/publication concurrency; retry/sleep count zero |
| Release restore/build | PASS, 0 warnings, 0 errors | pinned .NET SDK and locked dependency graph |
| Admin Web | lint/API/runtime drift PASS; 28 unit, 37 UI mock, 2 accessibility, 1 canonical full-stack PASS | production build, lifecycle and redaction; Playwright used one worker, zero retries/flaky tests, then cleaned the stack; npm audit zero vulnerabilities |
| documentation validation and conservative secret scan | PASS | repository docs and tracked/untracked candidate content |
| Gitleaks | exact concluding-head run recorded externally | canonical Git candidate scan runs after the evidence commit; raw ignored full-stack fixtures are not publication content |
| SPDX SBOM generation/validation | PASS | .NET, Admin Web and Gateway container; 165 container packages indexed |
| vulnerable package scan | PASS | no vulnerable direct or transitive NuGet packages reported |
| open-source Core export | exact concluding-head run recorded externally | clean-room scan/build/test/Admin/license proof, file count and artifact-specific manifest digest run after the evidence commit |
| PR #23 exact-head CI | PENDING publication | must pass on the concluding documentation commit before targeted re-review |

## Visible failed attempts and remediation

- The first expanded production-negative test build referenced `ConnectorBindingSet.CreatedAt`,
  which does not exist. The fixture now uses the actual `UpdatedAt` contract; the full production
  matrix and solution build pass.
- The first ordinary suite run exposed cross-test interference: the new E2E disposed the shared
  `GatewayApiFactory` and cleared its process-wide Admin test key while the M4 class fixture ran in
  parallel. A dedicated typed-runtime factory now runs with Admin disabled and touches no process
  environment. The full Gateway suite and ordinary solution reruns pass with global parallelism.
- The first PostgreSQL wrapper completed 109/109 tests but then failed an optional evidence query
  against an obsolete `canonical_json` column name. The non-canonical query was removed; a fresh
  migration/idempotency/non-superuser run exits cleanly with 109/109 and container cleanup.
- The first in-progress mutation-lease build was stopped by warnings-as-errors `CA1859`. The lease
  now has a concrete, externally non-constructible return type; the complete build and affected
  gates pass with zero warnings.
- An initial combined Admin command exceeded its local command timeout during dependency setup.
  Locked `npm ci` and every Admin gate were then executed separately and passed; no product failure
  was accepted by retry.
- SBOM validation/generation passed, while Docker Scout warned that one external temporary archive
  was still open during its own best-effort deletion. This did not affect the generated SPDX result;
  repository artifacts and container resources are cleaned separately.
- The first final-remediation hosted run attempted four-eyes publication on the development
  in-memory store and was correctly denied with `BGW-ADMIN-ATOMIC-PUBLISH-REQUIRES-POSTGRES`.
  Canonical hosted evidence was therefore moved to PostgreSQL rather than weakening publication.
- The first PostgreSQL project-wide run after the targeted cases reused a populated schema; the
  one-shot Admin bootstrap test failed at login. The canonical fresh-schema precondition was
  restored by dropping only the disposable test schema and reapplying all migrations; the complete
  project then passed 112/112.
- Adding two PostgreSQL test classes first failed the isolation-policy allowlist. The policy was
  updated to enumerate the two deliberate shared-database classes while retaining global test
  parallelism; the complete PostgreSQL project rerun passed.
- A direct `npm run test:e2e` without the required full-stack services failed visibly with
  `ECONNREFUSED`. The repository's canonical `Invoke-M5FullStack.ps1` wrapper subsequently started
  the production stack and passed `FULLSTACK-01` 1/1 with zero retry/flaky results and redaction
  validation. Its first invocation also exposed a missing pinned-SDK `PATH`; rerunning the wrapper
  with the repository SDK environment corrected the harness environment, not product behavior.
- The first hosted business invocation after rebasing over PR #22 reached
  `ComposedSoapExecutionStrategy`, resolved both Basic bindings, but returned
  `BGW-EGRESS-AUTHENTICATION` before network. Inspection proved that admission promoted into the
  private `SoapSessionClient` cache while the business provider was backed by a separately
  registered `SoapSessionCache`. The fix removes that registration and aliases the provider to the
  singleton client's existing lifecycle; the same hosted test then passed with business outbound
  `0→1`, acquisition/validation/generation unchanged and all synthetic composed assertions green.
- The first compile after adding the runtime DI identity assertion lacked the opaque-session
  namespace import and stopped before test execution. Adding the contract namespace fixed only the
  test build; the canonical hosted scenario then passed on its first execution after compilation.

The shared-lifecycle production fix and hosted evidence are locally qualified. The concluding
documentation commit must retain green exact-head CI and receive a new exact-head Core export before
handoff. Independent targeted re-review remains required, and no merge is authorized by this report.

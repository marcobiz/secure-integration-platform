# Wave 1 typed session handshake and external admission report

## Candidate scope and reviewed baseline

This report covers only the generic Core capability described by ADR-0022. It does not qualify a
production connector, a deployment environment, a distributed cache or generic XML scripting.

- Base: `705e9d4bd203ca7b902ad0aeedc9d4402f9f4452`.
- Independently reviewed head: `8f6218599dc7fb454a8a542184ae7ce816856c96`.
- Targeted remediation product commit: `45605a9fb3085d83af3b2d9d50e8b08f4a987f65`.
- Branch/PR: `wave1/auth-session-handshake`, PR #23; open and unmerged.

No Sistema TS, PR #22 dispatch composition, arbitrary XML framework, second session cache,
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
| P2 concurrency/replay/final-race coverage | FIXED | Barrier/hook tests cover simultaneous completion, proof/candidate/intent/profile/context/generation replay, validation-window rotation and the post-final-await mutation window without sleep. |

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
  generation. The process-local authority matches this existing single-node cache; scale-out would
  require a separately reviewed distributed cache and linearization authority.

## Local qualification on the product commit

| Suite | Result | Coverage |
|---|---:|---|
| `TypedSessionHandshakeTests` | 41 PASS | authority, adapters, XML, cancellation, presentation, atomicity, concurrency, replay, bounds and redaction |
| focused typed plus SOAP boundary unit filter | 57 PASS | typed remediation plus unchanged scalar boundary regression |
| typed real-HTTPS integration | 4 PASS | direct/external handshake, production success/business reuse, and production authority negatives |
| typed API authentication/redaction | 1 PASS | acquire/completion require authenticated principal and never echo candidate |
| SOAP architecture filter | 4 PASS | provider neutrality, one cache, pure validation adapter and mutation CAS/lease boundary |
| complete Architecture suite | 24 PASS | Core/provider/auth and vertical boundaries |
| legacy SOAP plus Connector configuration unit | 35 PASS | scalar M6 and configuration compatibility |
| legacy SOAP real-HTTPS integration | 5 PASS | Login/Challenge/Business/Logout and hardening compatibility |
| ordinary solution suite | 453 total: 441 PASS, 12 PostgreSQL-conditional SKIP | all solution projects; zero failures |
| Gateway integration on fresh PostgreSQL 18 | 109 PASS, 0 SKIP | migration checksum/idempotency, non-superuser Admin role, four-eyes and runtime locator |
| Release restore/build | PASS, 0 warnings, 0 errors | pinned .NET SDK and locked dependency graph |
| Admin Web | lint/API drift PASS; 28 unit, 37 UI mock, 2 accessibility, 1 full-stack PASS | production build, lifecycle, redaction and cleanup; npm audit zero vulnerabilities |
| documentation validation and conservative secret scan | PASS | repository docs and tracked/untracked candidate content |
| SPDX SBOM generation/validation | PASS | .NET, Admin Web and Gateway container; 165 container packages indexed |
| vulnerable package scan | PASS | no vulnerable direct or transitive NuGet packages reported |
| open-source Core export | PASS on `45605a9fb3085d83af3b2d9d50e8b08f4a987f65` | 380 files; clean-room scan/build/test/Admin/license checks; manifest SHA-256 `FD2CCA693FE181D51A7FFA8110A1BCADACA156EFA5DB0AE14929AFDDC31C398A` |
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

The product commit is locally qualified and exported. The concluding evidence commit must retain
green exact-head CI before handoff. Independent targeted re-review remains required, and no merge is
authorized by this report.

# Healthcare Wave 1 — Regional ePrescription implementation

## Scope decision

The authorized scope is a Healthcare Pack foundation plus only those regional profiles supported
by sufficiently current official contracts. The 2026-08-08 source review did not establish a
complete current production contract for either Lombardia or Emilia-Romagna. This implementation
therefore compiles the shared foundation and records both profiles as `BLOCKED_BY_SPEC`; it does
not compile a regional wire handler.

FSE consumer, FSE2, Sistema TS national connector, generic authentication primitives and other
regional placeholders remain out of scope.

## Physical boundary

```text
src/ConnectorPacks/Healthcare/
  Healthcare.RegionalEPrescription/
    public Healthcare business contracts
    server-owned profile resolution and routing
    Wave 1 readiness metadata

tests/unit/Healthcare.RegionalEPrescription.Tests/
  common model and negative security tests
  Lombardia and Emilia-Romagna blocked HTTPS sentinels

tests/architecture/Architecture.Tests/
  Core-to-Healthcare dependency and identifier boundary
  inbound identity reinterpretation denial
```

The full product solution includes the pack. `BrokerGateway.Core.slnx` deliberately excludes it,
and no Gateway Core project references it. The pack depends only on the public
`Gateway.Application` boundary, which supplies the authenticated server-derived principal.

## Runtime design

1. Inbound Gateway authentication produces `GatewayClientPrincipal`; the pack never derives or
   accepts Tenant/Application identity from the command.
2. The caller supplies Connector/operation and a typed healthcare command. The provider-neutral
   Core `GatewayInvocationAuthorizer` consumes the already-authenticated principal, verifies active
   state plus the exact operation grant, and produces a non-publicly-constructible
   `AuthorizedGatewayInvocation`. This check is mandatory even when the operation has no credential
   binding. The Healthcare Pack never reads certificate material or the registry and the command
   has no region, profile, endpoint, route, auth, credential or secret field.
3. `PublishedRegionalEPrescriptionProfileResolver` builds the Published lookup only from the
   authenticated principal. `PublishedConnectorRegionalEPrescriptionConfigurationSource` uses
   that authority as the existing `PublishedConnectorAccessContext`, loads a validated Published
   snapshot from `IConnectorConfigurationStore`, derives canonical `OperationBindingDependencies`,
   and resolves the exact logical profile, endpoint binding, auth-policy fingerprint, credential
   binding set and revisions. An exact empty credential set is valid for `authentication.kind=none`;
   the foundation does not invent a mandatory credential.
4. `RegionalEPrescriptionRouter` verifies Tenant/Application/Connector/operation equality,
   profile availability and binding completeness, then matches endpoint/auth/credentials and the
   extension schema and regional safe-code allowlist against the server-owned compiled profile
   catalog using a composite profile/operation key and explicit ID equality. Null nested
   command/response values and undefined normalized enum values are denied with stable sanitized
   errors.
5. Immediately before dispatch, it revalidates both the resource stamp and a SHA-256 fingerprint
   covering the complete immutable authority/binding snapshot using length-prefixed fields.
   Resolver, stamp and dispatcher exceptions are normalized without retaining raw details.
6. Only then does it create `RegionalEPrescriptionExecution`, whose constructor is not public, and
   call a compiled profile dispatcher.
7. The response must have the operation-specific normalized type and the same prescription
   reference. A mismatch is denied with a sanitized code.

There is no stale fallback. `Disabled`, `BlockedBySpec`, authority mismatch, resource rotation or
response confusion all fail closed.

## Common model freeze

The shared surface is limited to:

- opaque `PrescriptionReference`;
- `PrescriptionLookupRequest/Result`;
- `DispenseRequest/Outcome`;
- `RegionalExtensionSet`, which copies bounded scalar caller input and is revalidated only against
  the exact compiled server-owned schema after profile resolution;
- normalized `NotFound`, `AuthenticationRequired`, `InvalidState`, `Rejected`,
  `TemporaryUnavailable` and `ProfileUnavailable` categories;
- `RegionalSafeCode`, validated separately from the normalized category.

Take-in-charge, cancellation, reconciliation, session/callback topology, protocol, endpoints,
auth composition, schemas and fault mappings are not frozen as common concepts.

## Profile gates

### Lombardia

`BLOCKED_BY_SPEC`. The current public SISS material establishes the ePrescription process and a
general A2A/API Manager model, but not the exact current pharmacy API/auth/helper/scopes/token,
endpoint, error, accreditation or idempotency contract. M6 OAuth is not composed and PKCE is not
added.

### Emilia-Romagna

`BLOCKED_BY_SPEC`. The current public Regione/Lepida material establishes SOLE/SAR prescription
exchange at process level; the technical lifecycle detail available publicly is historical. It
does not establish the current A2A SOAP/REST operation, Basic/session header, external portal
handoff, endpoint, fault or onboarding contract. Gateway does not implement SPID/CIE/CNS login.

## Completion gate

A concrete profile requires, independently for that region:

1. current authority-owned WSDL/OpenAPI/schema and operation version;
2. exact authentication and interactive-session contract;
3. test/production endpoint classification and accreditation rules;
4. request, response, safe fault, timeout, retry, idempotency and reconciliation mapping;
5. independently authored synthetic positive and negative vectors;
6. restricted-egress, correlation, rotation/disable and redaction tests;
7. threat/traceability update and four-eyes Published configuration;
8. separately approved live conformance evidence outside Git.

Until those conditions are met, the regional sentinels must remain zero-dispatch.

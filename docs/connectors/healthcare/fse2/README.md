# FSE2 National Connector — Organization profile

**Current entry point:** [validation and workflow status pilot](../../../user/fse2-validation-status.md).
The opt-in `fse2-organization-current-spec@1.0.0` is integrated through PR #65.
The [capability summary](../../../../IMPLEMENTATION_STATUS.md#product-status) owns current
status; the [14-route current-spec contract](current-spec.md) owns the frozen offline
scope, request/response matrix and acceptance limits.

Offline completeness does not mean full live qualification. The current pilot records
CDA VERIFICA and workflow FOUND after a Gateway restart in OfficialTest. FHIR is not
live-qualified (upstream 500, undetermined cause); live document publication, production
and overall accreditation are not qualified. Healthcare remains an optional pack, never
a Core dependency.

## Historical profiles

The [validate-only guide](../../../user/fse2-officialtest.md) retains the earlier
`fse2-officialtest-validate-cda@1.0.1` path and shared provisioner reference. Its
bootstrap/session/runner gaps do not describe the current distributed pilot.
The [history index](../../../history/README.md#earlier-fse2-paths) preserves the
11-operation profile matrix and the earlier trace/NOT_FOUND observation. Historical
Published definitions and their evidence remain immutable; qualifications do not
transfer to the current profile.

## Authority model

The only implemented actor profile is `ORGANIZATION`; Human Actor is deferred.
The Core authenticates the caller, derives Tenant/Application/Installation/Environment,
checks the grant and Published operation, then gives the `healthcare-fse2` module
bounded authority. The pack depends on provider-neutral contracts and receives no
store/provider access, `GetSecret`, signing oracle, endpoint selector or generic HTTP.

Published configuration contains Organization identity and logical bindings.
Method, path, content type, endpoint, audience, claim policy, signing slots, certificates
and revisions are server-owned. `person_id` remains validated business data and
does not become authenticated identity.

## OfficialTest `validate-cda` — historical reference

The canonical public source is
`Definitions/fse2-officialtest-validate-cda.connector.json`, containing one operation.
It contains no concrete endpoint, operational organization identities, provider locators,
P12 files, passwords or tokens. The vertical
`tools/fse2/OfficialTestProvisioner` uses authenticated Admin APIs for
`plan → configure/grant → propose → approve/publish → verify` and resolves A1/S1
from the server-side public catalog.

The provisioner does not make the live call. Qualification of this validate-only
profile came from a controlled, redacted external runner. For first adoption, now use
the [shipped current-spec runner](../../../user/fse2-validation-status.md), with
its prerequisites and limits, not integration tests, fixtures or hand-reconstructed requests.

Parity applies only to `fse2-officialtest-validate-cda@1.0.1`: both JWTs use only the
S1 leaf in `x5c`, and the `VERIFICA` body contains only `healthDataFormat=CDA`
and `activity=VERIFICA`, without `mode` or `attachment_hash`. Version `1.0.0`
is immutable historical compatibility, not contract-parity qualified.

## Providers, claims and transport

- A1 is distinct and authorized for mTLS; S1 feeds the `authorization` and
  `integrity` slots with RS256 and `ContentCommitment`.
- Endpoint, origin, path composition, method, timeout, response bound, DNS/restricted
  egress and redirect denial remain Published/Core authority.
- Organization/locality/application, `iss`, `aud`, `sub`, `iat`, `exp` and
  `jti` are server-owned; required purpose/action and hashes are derived; permitted
  business claims remain allowlisted.
- Errors and audit retain only bounded categories and safe codes, not payloads,
  raw responses, JWTs, headers, endpoints or certificates.

## Workflow correlation and limits

Technical PostgreSQL correlation is scoped exactly to Tenant, Application,
Installation, Environment, Connector/version and Published configuration.
It retains only the originating operation, action, purpose, profile checksum,
workflow/trace and technical timestamp, not clinical content. Restarts and replicas
share the same state.

The status mapper does not expose the full official `transactionData[]`: this is
an intentional security reduction. It accepts at most 1,000 ordered events and only
types `VALIDATION`, `PUBLICATION`, `SEND_TO_INI`, `SEND_TO_UAR`,
`UAR_FINAL_STATUS`, with outcome `SUCCESS` or `BLOCKING_ERROR` and a valid
timestamp. Message, subject, document ID, issuer, extra fields and raw responses
are discarded; unknown or malformed values fail closed.
A status-contract 404 is a valid technical response only when the bounded reducer
recognizes the exact allowlisted RFC7807 code `record-not-found`: it reduces this
to `statusCode=404`, `statusClassification=NOT_FOUND` and empty events, discarding
the entire problem body. Missing, non-JSON or malformed bodies, unknown codes and all
other 404s follow normal bounded upstream failure handling. No 404 triggers automatic
retry; the first case produces one success audit, the second one failure audit.

## Minimal create → status example — historical profile

This example preserves the historical factory. For the current profile, use the
[current-spec consumer contract](current-spec.md#consumer-contract), which requires
the preceding VALIDATION workflow for ordinary publication. The VERIFICA/status
evaluation runner does not enable these publication operations.

With Installation, grant and Published configuration already active, the `create`
application payload remains the canonical one already used by the Gateway client:

```csharp
byte[] createPayload = Fse2Request.Create(
    pdfBytes,
    publicationRequestJson,
    clinicalClaims).SerializeAuthorizedPayload();
```

Retain `workflowInstanceId` from the normalized response. The status request does
not require resending patient, action, purpose, profile or scope:

```csharp
byte[] statusPayload = Fse2Request
    .GetStatusByWorkflow(workflowInstanceId)
    .SerializeAuthorizedPayload();
// Produced JSON: {"resourceIdentifier":"<workflowInstanceId>"}
```

Send both payloads to the normal Published Gateway endpoint with the existing runtime
authentication. No new login, binding, grant, SQL, store access or recovery command
is needed between the two invocations.

The same model applies to a trace returned by `validate-cda`: the next request
contains only the opaque value, while action, purpose and scope are resolved from
durable correlation before signing, DNS and transport:

```csharp
byte[] traceStatusPayload = Fse2Request
    .GetStatusByTrace(traceId)
    .SerializeAuthorizedPayload();
// Produced JSON: {"resourceIdentifier":"<traceId>"}
```

The Published definition must contain both operations in the exact same
Tenant/Application/Installation/Environment/Connector/version and configuration that
recorded the trace; there is no in-memory or cross-scope fallback.

Local PKCS#12 is an optional pack/laboratory, not HSM/KMS or production custody.
Accreditation, production, Human Actor, inbound callbacks, confirmed direct FHIR
publication and overall live qualification remain out of scope. Current offline
coverage is limited to the 14 routes and explicit current-spec resolutions.

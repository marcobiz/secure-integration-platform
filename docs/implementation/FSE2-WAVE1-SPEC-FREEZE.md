# FSE2 National Connector Wave 1 - official specification freeze and capability gap

Date of freeze and access: **2026-08-08**  
Repository baseline: `m6-auth-foundation-baseline-20260808` / `6e1a7c626e0e24d0a385c611fc03faef51598889`  
Official source snapshot: `ministero-salute/it-fse-support` commit `430e6b5d9dde8a35b04ae635c11303db787a977e` (commit date 2026-08-07)  
Wave branch: `wave1/fse2-national`  
Verdict: **NO-GO before implementation - generic capability gap**

This document is a public-safe freeze produced before connector code. It uses only the
official public sources listed below. No production endpoint was contacted and no real
credential, certificate, token, document or clinical datum was used.

## Authoritative sources

| Source | Frozen version | SHA-256 | Use |
|---|---|---|---|
| [REST Gateway integration guide](https://github.com/ministero-salute/it-fse-support/blob/430e6b5d9dde8a35b04ae635c11303db787a977e/doc/integrazione-gateway/README.md) | 2.23, 2026-07-24 | `B07326F974D16F6104DF6B128F81052A953F14032BDF09C9A6E7711131CFB852` | Current operation table, endpoints, authentication, request/response semantics, workflow, errors and claim tables |
| [Gateway OpenAPI](https://github.com/ministero-salute/it-fse-support/blob/430e6b5d9dde8a35b04ae635c11303db787a977e/openapi/gateway/swagger_gtw.yaml) | OpenAPI 3.0.1, API document version 1.0.0 | `F42BB5E38A24577506B41D1EFDAB0186C6B3F3AF7CFEBFD287D5D4D8E6855FEA` | Machine-readable paths, methods, schemas, response status and security schemes |
| [Workflow callback OpenAPI](https://github.com/ministero-salute/it-fse-support/blob/430e6b5d9dde8a35b04ae635c11303db787a977e/openapi/gateway/swagger_status.yaml) | OpenAPI 3.0.1, API document version 1.0.0 | `1ECE21DF33B883A7917C8376CE5FE66404B14486D1B0686EC25B4FE49CF305E8` | Optional inbound workflow notification contract |
| [JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515) and [JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) | RFC 7515 / RFC 7519 | N/A | Public standards referenced by the JWT profile |
| [JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725) | RFC 8725 | N/A | Algorithm verification and substitution resistance |
| [Problem Details](https://www.rfc-editor.org/rfc/rfc7807) | RFC 7807 | N/A | Error representation named by version 2.23 |

The guide references Affinity Domain Italia 2.6.1 in its references and records an update
of value tables to 2.6.4 in change 2.23. This freeze does not silently normalize that
difference. Value-set implementation requires an exact, separately frozen official
Affinity Domain artifact.

## Official environments and API version

| Environment | Server-owned base URL | API major |
|---|---|---|
| Test/validation | `https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1` | `v1` |
| Production | `https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1` | `v1` |

These values are inventory data, not deployable sample configuration. A future connector
must resolve the environment, endpoint and audience exclusively from approved server-side
state.

## Frozen public operation inventory

All public operations require channel mTLS plus two freshly generated signed JWTs:
`Authorization: Bearer <token>` and `FSE-JWT-Signature: <token>`. Success responses are
`application/json`; errors are `application/problem+json`. No operation exposes a caller
choice of endpoint, signing key, certificate, provider reference or destination.

| Operation ID proposed for the pack | Method and relative path | Request | Success | Workflow semantics | Production in guide 2.23 | Retry class |
|---|---|---|---|---|---|---|
| `validate-cda` | `POST /documents/validation` | `multipart/form-data`: `file` plus JSON `requestBody` (`ValidationCDAReqDTO`) | `200` verification or `201` validation; `ValidationResDTO` | Synchronous validation. A publication-oriented validation returns the `workflowInstanceId` used by create. | Yes | `NO_AUTOMATIC_RETRY` |
| `validate-fhir` | `POST /documents/fhir-validation` | `multipart/form-data`: PDF or FHIR JSON file plus JSON `requestBody` (`ValidationFHIRReqDTO`) | `200` or `201`; `ValidationResDTO` | Synchronous verification only in the current guide. | **No** | `NO_AUTOMATIC_RETRY` |
| `create` | `POST /documents` | `multipart/form-data`: PDF/CDA file plus JSON `requestBody` (`PublicationCreationReqDTO`), including the prior `workflowInstanceId` | `202`; `PublicationResDTO` | Synchronous conversion/preparation followed by asynchronous communication; returns correlation/workflow acknowledgement. | Yes | `NO_AUTOMATIC_RETRY` |
| `replace` | `PUT /documents/{documentId}` | `multipart/form-data`: PDF/CDA file plus JSON `requestBody` (`PublicationUpdateReqDTO`) | `202`; `PublicationResDTO` | Synchronous conversion/preparation followed by asynchronous replacement; returns correlation/workflow acknowledgement. | Yes | `NO_AUTOMATIC_RETRY` |
| `delete` | `DELETE /documents/{documentId}` | Path identifier; no request body | `200` completed or `202` accepted; `ResponseWifDTO` | May complete synchronously or be accepted for continuation; inspect returned workflow state. | Yes | `NO_AUTOMATIC_RETRY` |
| `update-metadata` | `PUT /documents/{documentId}/metadata-iti-57` | `application/json`; `PublicationMetadataReqDTO` | `200` completed or `202` accepted; `ResponseWifDTO` | Updates the authoritative metadata services and may return an accepted workflow. | Yes | `NO_AUTOMATIC_RETRY` |
| `update-metadata-chain-concealment` | `PUT /documents/{documentId}/metadata-oscuramento-catena` | `application/json`; access-rule list containing the required official value | `200`; trace, span and workflow identifiers, optional safe warning | Synchronous dedicated metadata update. It is documented in guide 2.23 but absent from the frozen Gateway OpenAPI. | **No** | `NO_AUTOMATIC_RETRY` |
| `validate-and-create` | `POST /documents/validate-and-create` | `multipart/form-data`: PDF/CDA file plus JSON `requestBody` (`ValidateAndCreateDTO`) | `202`; `PublicationResDTO` | Exceptional recovery operation; validation/conversion are synchronous, downstream communication is asynchronous. | Yes | `NO_AUTOMATIC_RETRY` |
| `validate-and-replace` | `PUT /documents/validate-and-replace/{documentId}` | `multipart/form-data`: PDF/CDA file plus JSON `requestBody` (`ValidateAndReplaceDTO`) | `202`; `PublicationResDTO` | Exceptional recovery operation; validation/retrieval/conversion are synchronous, downstream communication is asynchronous. | Yes | `NO_AUTOMATIC_RETRY` |
| `get-status-by-workflow` | `GET /status/{workflowInstanceId}` | Path identifier; no body | `200`; `TransactionInspectResDTO` | Returns the ordered event history for a workflow. | Yes | `SAFE_RETRY` |
| `get-status-by-trace` | `GET /status/search/{traceId}` | Path identifier; no body | `200`; `TransactionInspectResDTO` | Returns transaction events correlated by trace identifier. | Yes | `SAFE_RETRY` |

The two validation-and-publication operations are explicitly exceptional recovery paths in
the guide and must not replace normal validation followed by publication.

### Surfaces not frozen as connector business operations

- `POST /fhir-documents` and `PUT /fhir-documents/{idDoc}` occur in the frozen OpenAPI but
  are absent from the guide 2.23 current endpoint/production table. Direct FHIR publication
  is therefore **not confirmed for implementation** by this freeze.
- `GET /status` is a health endpoint, not a business operation.
- `POST /v1/workflow/status` is an inbound callback contract for a consumer endpoint. It is
  not an outbound GTW business operation. Supporting it would require a separately
  authorized inbound, authenticated, same-tenant routing design.
- `POST /v1/ingestion/status` describes infrastructure-side workflow ingestion, not a
  producer connector operation.
- A callback destination named by an initial request cannot be caller-controlled in this
  product. Any future notification destination must be an approved server-owned binding.

## Request, payload and identifier boundary

- CDA validation accepts the officially described PDF container and embedded `cda.xml`.
  The connector must not rewrite clinical content.
- FHIR validation is a distinct operation and is not available in production according to
  the frozen current table.
- Publication accepts the specified PDF/CDA payload and metadata only. Size and content
  limits must be policy-owned; no size value was inferred where the official source does
  not provide one.
- `attachment_hash` is the SHA-256 of the exact input file bytes, represented by the
  official examples as lower-case hexadecimal. It is derived, never accepted as a claim
  override.
- `documentId` is the document `XDSDocumentEntry.uniqueId`. The guide describes it as an
  OID and examples also show the IHE `OID^extension` form. A formatter must be confined to
  the Healthcare pack after the exact allowed grammar is frozen.
- Person/user identifiers use the IHE CX form, including the assigning-authority OID and
  `ISO` universal-ID type.
- `locality` uses XON: organization name, assigning-authority OID, required `ISO` and
  organization code. This formatter belongs only in the Healthcare pack.
- `workflowInstanceId` uses the IHE CXi-style value returned by the service. It is opaque
  to callers except for bounded syntax and correlation use.

No idempotency-key header or deduplication contract is defined by the frozen guide or
OpenAPI. Consequently, no write receives automatic retry. Status reads may use bounded
retry under the existing restricted-transport deadline.

## Authentication composition required by the official profile

The required composition is:

1. resolve the immutable operation and its server-owned endpoint/policies;
2. resolve one signing certificate/key binding;
3. generate an Authentication Bearer JWT;
4. generate a distinct FSE-JWT-Signature JWT with document/operation claims;
5. resolve a distinct mTLS client-certificate binding;
6. perform one purpose-bound restricted dispatch.

The signing certificate/key and the TLS client-authentication certificate are separate
purposes and cannot be substituted. Both JWTs are signed with the signing certificate.
The official profile requires a new pair of JWTs for every request.

## Frozen JWT profile and claim ownership

The implementation algorithm would be fixed to `RS256` even though the source table also
lists other RSA algorithms. `kid` is optional and would be omitted unless an authoritative
requirement is added. `x5c` is mandatory in both protected headers and carries the DER
signing certificate encoded with standard base64.

### Authentication Bearer JWT

| Field | Ownership | Frozen derivation |
|---|---|---|
| `alg`, `typ` | `SERVER_OWNED` | Fixed `RS256` and `JWT` |
| `x5c` | `DERIVED` | Public DER signing certificate bound to the exact provider signing key |
| `iss` | `DERIVED` | `auth:` plus signing-certificate Common Name |
| `sub` | `CONTEXT_DERIVED` | Authenticated professional tax identifier or authenticated organization identifier in IHE CX form |
| `aud` | `SERVER_OWNED` | Exact approved GTW base URL including `/v1` |
| `iat`, `exp`, `jti` | `SERVER_OWNED` | Server clock, approved lifetime and cryptographically unique identifier |

### FSE-JWT-Signature JWT

| Field | Ownership | Frozen derivation |
|---|---|---|
| `alg`, `typ`, `x5c` | `SERVER_OWNED` / `DERIVED` | Same rules and same signing identity as the bearer token |
| `iss` | `DERIVED` | `integrity:` plus signing-certificate Common Name |
| `sub`, `aud`, `iat`, `exp`, `jti` | `CONTEXT_DERIVED` / `SERVER_OWNED` | Same trusted subject and destination rules as above; independently generated token identifier |
| `subject_role` | `CONTEXT_DERIVED` | Authorized role profile, never a raw claim override |
| `purpose_of_use` | `SERVER_OWNED` | Derived from operation policy (`TREATMENT` or `UPDATE` as specified) |
| `subject_organization`, `subject_organization_id`, `locality` | `CONTEXT_DERIVED` | Approved organizational/role context; XON validation for locality |
| `person_id` | `DERIVED` | Validated patient context bound to the request and document, with mismatch denial |
| `patient_consent` | `CONTEXT_DERIVED` | Trusted clinical/authorization context, not a freely supplied security claim |
| `resource_hl7_type` | `DERIVED` | Validated document metadata; absent only where the official operation permits it |
| `action_id` | `SERVER_OWNED` | Exact operation mapping: `CREATE`, `UPDATE` or `DELETE` |
| `attachment_hash` | `DERIVED` | SHA-256 of exact input file; required for creation/replacement operations |
| `subject_application_id`, `subject_application_vendor`, `subject_application_version` | `SERVER_OWNED` | Approved application profile |
| `use_subject_as_author` | `SERVER_OWNED` | Optional approved policy flag |

The source declares `iat`, `exp` and `jti` mandatory but does **not** define a token
lifetime or allowed clock skew. This freeze does not infer them from examples. The source
does not list `nbf` as a required or optional claim.

## Workflow and technical persistence

Only technical state is in scope:

- correlation ID, `traceID`, `spanID` and `workflowInstanceId`;
- connector/version/operation identity and request digest needed for audit/idempotency
  diagnostics;
- ordered workflow event type, status and timestamps;
- bounded expiry/retention and sanitized upstream code.

Clinical payloads and authoritative document/metadata state are not duplicated. Current
event types are `VALIDATION`, `PUBLICATION`, `SEND_TO_INI`, `SEND_TO_UAR` and
`UAR_FINAL_STATUS`; current event outcomes are `SUCCESS` and `BLOCKING_ERROR`.

## Sanitized error model

The official response is RFC 7807-shaped. A future mapping may preserve only:

- official `type` or allowlisted official code;
- safe SIP category;
- HTTP status and retry classification;
- correlation metadata such as trace/span/workflow identifiers when present;
- a bounded, allowlisted warning.

The common OpenAPI error set is `400`, `401`, `403`, `404`, `409`, `413`, `415`, `422`,
`429`, `500`, `501`, `502`, `503` and `504`, varying by operation. A future mapper must
not retain raw response bodies or dynamic `detail` text. JWTs, authorization headers,
clinical content, certificate material, provider diagnostics, stack traces and arbitrary
upstream data remain excluded.

## Blocking generic capability gaps

The qualified M6 public API cannot produce the frozen official JWT profile exactly:

1. `Rs256JwtSigner` hard-codes the protected header to `alg=RS256` and `typ=JWT`.
   It reserves and rejects caller claim/header names including `x5c`; no server-owned
   protected-header policy exists.
2. `ProviderSigningKeyPublicMetadata` exposes fingerprint, validity, algorithm, key size,
   version and SPKI, but no public DER signing certificate or certificate chain. The
   mandatory `x5c` value therefore cannot be derived and bound to the signing operation.
3. `AuthenticationExecutionContext` contains platform identifiers only. The signer can
   derive `sub` from Installation, Application or a fixed policy value, not from a trusted
   authenticated professional/organization context required per request.
4. The signer always emits `nbf`; the official 2.23 claim tables do not list it. Exact
   profile generation cannot silently add it.
5. `ServerOwnedRs256PolicySnapshot` requires a concrete lifetime and skew, while the
   official source does not define either. Inventing these values is prohibited.
6. The issuer must be bound to the Common Name of the same certificate carried in `x5c`.
   The current signing metadata does not expose or verify that certificate identity.

These are generic JWS/JWT and trusted-context capabilities, not Healthcare-specific
primitives. The repository rule requires implementation to stop rather than adding a
vertical workaround to Core or bypassing the qualified signer.

## Required decisions before resuming implementation

A separately authorized Core/Auth change needs an ADR, threat-model update, positive and
negative tests, and an independent gate. It must remain provider-neutral and at minimum:

- support a server-owned allowlist of protected JWS headers with exact canonicalization;
- obtain public signing-certificate DER/chain material without exposing private material;
- cryptographically bind that certificate's SPKI/fingerprint to the provider-side signing
  result and reject wrong chain, wrong SPKI, rotation races and algorithm confusion;
- support trusted context-derived registered claims without granting a generic signing
  oracle or caller claim override;
- allow a server-owned exact registered-claim set instead of unconditionally adding
  claims;
- receive an authoritative token lifetime/skew decision for this profile.

Only after that capability is qualified may Wave 1 create the Healthcare pack, connector
definition, synthetic HTTPS/mTLS server, security matrix, sample and E2E evidence.

## Deferred and readiness label

Deferred because of the mandatory stop:

- all connector production code and Connector Definition artifacts;
- Healthcare architecture tests;
- identifier/hash formatters and payload validation code;
- dual-JWT orchestration and one-shot mTLS dispatch;
- synthetic FSE2 server and all security/integration tests;
- sample configuration and runtime wiring;
- accreditation testing and any call to official systems.

Current label: **not IMPLEMENTATION_READY**.  
Accreditation label: **not ACCREDITED_PRODUCTION_READY**.

Accredited production readiness would additionally require official provisioning,
approved real certificates and custody, conformance/accreditation execution, authoritative
environment configuration, operational monitoring, key/certificate rotation drills and
evidence from the official process. None of that is claimed by this freeze.

## Independent review gate

**NO-GO** for connector implementation on the current baseline. A single independent
review may approve this freeze and the stop decision; it cannot convert the missing generic
capability or missing official lifetime into implementation evidence.

## Verification on the Wave branch

The documentation-only candidate was verified on 2026-08-08:

- Release restore/build: PASS, 0 warnings, 0 errors;
- existing .NET suites: 261 PASS, 10 PostgreSQL-conditional SKIP;
- architecture suite: 16/16 PASS within the total above;
- FSE2-specific tests: 0, intentionally not created after the mandatory stop;
- documentation validation: PASS;
- conservative secret scan: PASS;
- SBOM generation and validation: PASS;
- transitive NuGet vulnerability scan: no vulnerable package reported;
- `git diff --check` and forbidden-term check: PASS;
- live official-system or accreditation tests: not run;
- CI: pending PR execution.

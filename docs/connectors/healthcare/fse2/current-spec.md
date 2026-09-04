# FSE2 Organization — current-spec product path (offline)

Scope: the 14 outbound routes below, excluding health, inbound callbacks, Human Actor,
production and live publication qualification. Baseline:
`96943621a2d99c3e52d7f1189dbab77a3268ecab`.

`PRODUCT_PATH_OFFLINE_COMPLETE` applies to the opt-in
`fse2-organization-current-spec@1.0.0` definition and
`fse2-organization-current-spec-v1` Published profile, within the explicit limits below.
`LIVE_QUALIFIED = NO` for this profile. `LIVE_NOT_QUALIFIED_EXTERNAL_LIMITATION`:
official access/certification and live publication conformance are outside this offline
qualification. No OfficialTest request or operational FSE2 material was used for that gate.
The earlier validate-only live observation does not qualify this new definition.

A later, separately authorized [validation/status path](../../../user/fse2-validation-status.md)
qualified CDA VERIFICA and workflow status with one event after an actual Gateway restart
on 4 September 2026. FHIR VERIFICA returned upstream 500 `generic-error` and is not live
qualified. This partial observation does not qualify all 14 routes or document publication.

## Frozen authority and resolved differences

Both sources are pinned to `4d2691dcdc051fa5a842e2cac074226bb50373d2`:

| Source | SHA-256 |
|---|---|
| [OpenAPI](https://github.com/ministero-salute/it-fse-support/blob/4d2691dcdc051fa5a842e2cac074226bb50373d2/openapi/gateway/swagger_gtw.yaml) | `9697C3C027BFEC19EEA17D8ED68EE4C3593D6A0AA84837E3A0D9C7E8BF379FE3` |
| [Integration guide](https://github.com/ministero-salute/it-fse-support/blob/4d2691dcdc051fa5a842e2cac074226bb50373d2/doc/integrazione-gateway/README.md) | `B07326F974D16F6104DF6B128F81052A953F14032BDF09C9A6E7711131CFB852` |

- The two `/fhir-documents` routes reference the same creation/update multipart DTOs
  as `/documents`. They use PDF/CDA bytes, not a guessed JSON publication format.
  The guide has no corresponding production availability statement: these two routes
  remain test-only; direct native-FHIR publication is not claimed.
- The guide explicitly forbids `VALIDATION` for FHIR validation, despite the shared
  OpenAPI enum. Only `VERIFICA` is supported there. Its `mode` is required in the
  OpenAPI and optional in the guide: the profile requires it (the common valid subset).
- Ordinary creation/replacement has optional `workflowInstanceId` in the route DTOs
  and route tables, but guide §16.2 requires it for publication. The profile requires
  a nonempty workflow; omission is not claimed supported. Recovery routes do not
  accept that field and are not substitutes for normal publication sequencing.
- Metadata DTOs omit some enum constraints; the guide links those fields to the same
  facility, organizational setting, document-class, clinical-activity and administrative
  code tables. Those exact enums are validated. Chain concealment requires an access
  rules array containing `P99`, as stated by the guide.
- The OpenAPI success DTOs omit `required`. The profile requires a usable trace and,
  for asynchronous mutations / CDA `VALIDATION`, a workflow before acknowledging
  success. CDA `VERIFICA` and FHIR verification may return trace alone.
  This provides a bounded, usable correlation contract rather than accepting `{}`.

## Route and acceptance matrix

All rows are exercised through the authenticated Published runtime against the existing
synthetic HTTPS/mTLS server. `MP` means exact `requestBody` JSON + exact file bytes;
`JSON` means validated JSON only; `none` emits no HTTP content or Content-Type.
Paths are appended to the server-owned base prefix, including templated identifiers.

| Gateway operation ID | Upstream method/path | Body / hash | Success |
|---|---|---|---|
| `validate-cda` | POST /documents/validation | MP PDF/CDA; no hash | 200 VERIFICA / 201 VALIDATION |
| `validate-fhir` | POST /documents/fhir-validation | MP PDF with FHIR or JSON Bundle; no hash | 200 VERIFICA only |
| `create` | POST /documents | MP PDF/CDA; SHA-256 file | 202 |
| `replace` | PUT /documents/{idDoc} | MP PDF/CDA; SHA-256 file | 202 |
| `delete` | DELETE /documents/{idDoc} | none; no hash | 200 / 202 |
| `update-metadata-legacy` | PUT /documents/{idDoc}/metadata | JSON; no hash | 200 |
| `update-metadata` | PUT /documents/{idDoc}/metadata-iti-57 | JSON; no hash | 200 / 202 |
| `update-metadata-chain-concealment` | PUT /documents/{idDoc}/metadata-oscuramento-catena | JSON; no hash | 200 |
| `validate-and-create` | POST /documents/validate-and-create | MP PDF/CDA; SHA-256 file | 202 |
| `validate-and-replace` | PUT /documents/validate-and-replace/{idDoc} | MP PDF/CDA; SHA-256 file | 202 |
| `create-fhir` | POST /fhir-documents | MP PDF/CDA; SHA-256 file | 202 |
| `replace-fhir` | PUT /fhir-documents/{idDoc} | MP PDF/CDA; SHA-256 file | 202 |
| `get-status-by-workflow` | GET /status/{workflowInstanceId} | none; server-resolved authority | 200 FOUND; exact problem 404 NOT_FOUND |
| `get-status-by-trace` | GET /status/search/{traceId} | none; server-resolved authority | 200 FOUND; exact problem 404 NOT_FOUND |

`update-metadata` keeps its historical ITI-57 meaning; the legacy route has a new ID.
The shared claim combinations remain DAP + TREATMENT/CREATE for validation/creation,
UPDATE/UPDATE for replacement/metadata, UPDATE/DELETE for deletion and ACCESS UPDATE/UPDATE
for chain concealment. Status obtains the originating combination from durable state,
never from caller claims.

## Consumer contract

Use `Fse2Request.ForCurrentSpec` and the normal authenticated Gateway invocation
`POST /v1/connectors/fse2-organization-current-spec/operations/{operationId}:invoke`.
The returned bytes are the existing BGW payload, not an arbitrary upstream body:

```csharp
byte[] payload = Fse2Request.ForCurrentSpec(
    Fse2Operation.ValidateCda,
    document: pdfBytes,
    requestBody: """{"activity":"VERIFICA","healthDataFormat":"CDA"}"""u8.ToArray(),
    documentContentType: "application/pdf",
    clinicalClaims: clinicalClaims).SerializeAuthorizedPayload();
// Send through the already authenticated Broker/Gateway client, content type
// application/vnd.bgw.fse2+json; no endpoint, certificate or JWT comes from this payload.
```

For ordinary publication/replacement, the seven required JSON fields are
`assettoOrganizzativo`, `identificativoDoc`, `identificativoRep`,
`identificativoSottomissione`, `tipoAttivitaClinica`, `tipoDocumentoLivAlto` and
`tipologiaStruttura`, plus the validation `workflowInstanceId`.
Recovery has the seven fields but rejects workflow/priorita. Only creation accepts
boolean `priorita`. Metadata requires the five common fields excluding doc/repository IDs.
Optional fields, array cardinalities, string bounds, types and enums follow the frozen
DTOs and guide resolutions above. Unknown or duplicate properties, hash overrides,
wrong types/enums, missing required fields and excessive bodies fail before signing.
The server repeats validation even if the consumer does not use the factory.

For mutations, pass the document ID as `resourceIdentifier`; the runtime encodes it
as one path segment. Clinical claims remain business data (person CX, consent, document
LOINC); resource type is required except for deletion. Document bytes are not rewritten
or parsed into a new clinical format; clinical conformance remains the upstream's job.

After a successful response, retain its technical trace/workflow identifier:

```csharp
byte[] status = Fse2Request.GetStatusByTrace(traceId).SerializeAuthorizedPayload();
// {"resourceIdentifier":"<traceId>"} plus ordinary authentication only.
```

The existing PostgreSQL correlation table resolves Tenant/Application/Installation/
Environment/Connector/version/configuration and originating action/purpose/profile
before signing, DNS or transport. It survives restart/second instance. No clinical
claims/body/JWT are stored and there is no in-memory fallback. A trace from the historical
validate-only connector or another Published configuration cannot authorize this profile.

For `VALIDATION(W, Tv) -> create(W, Tp)` (also replace/create-fhir/replace-fhir), use
the same Published configuration with `activity: VALIDATION`. The publication response must
echo the request's W. Additive migration `0019` preserves the validation row and appends one
publication row linked to Tv in the existing table. Tv always resolves the validation profile;
Tp resolves the publication profile; W deterministically resolves publication after registration.
Both traces survive a second instance. The caller cannot supply predecessor/transition authority.
An identical store registration is idempotent, including validation after publication; competing
successors or reused traces fail atomically. This does not support arbitrary additional phases.
Standalone upstream acknowledgements without a local predecessor retain the historical root
registration behavior. A storage failure after upstream acceptance remains a bounded failure
with one failure audit: it does not prove publication was rejected, and must not trigger an
automatic resend. No document, patient or request/response content is added to persistence.

Caller success is a normal Gateway success envelope with a technical-only FSE2 response.
An upstream 202 acknowledges processing, not INI/EDS completion. Status emits at most
1,000 ordered events from the existing closed vocabulary. Only exact allowlisted
`record-not-found` reduced from a bounded RFC7807 problem maps 404 to NOT_FOUND.
All other 404s and invalid/unrecognized responses fail bounded with one failure audit.
Each success has one success audit. Raw response, clinical FHIR output and warning text
are discarded; warning presence is represented by `FSE2_UPSTREAM_WARNING` only.

Bounds: 1 MiB document; 1 MiB request JSON; 2 MiB composed request; 256 KiB retained
success response; 16 KiB problem reducer; 5-second timeout; zero automatic retries;
redirects denied. A valid but larger upstream response fails bounded. Large FHIR
transformation bodies are not returned to the consumer or made unbounded to fit.

## Supported provisioning (same tool, no SQL)

Use the existing [plan/apply/verify role workflow](../../../user/fse2-officialtest.md#1-plan--zero-effetti)
and its authenticated Admin session mechanism. For this new definition, start from the
same protected plan shape but set `schemaVersion: "2.0"` and add exactly:

```json
{"environmentClass":"synthetic","activity":"VERIFICA"}
```

These are additional plan fields, not a complete plan. `synthetic` accepts only an HTTPS
localhost base ending exactly `/gateway/v1/`; `officialTest` accepts only the existing
fixed official test base. Production is denied. The historical field name
`officialTestEndpoint` remains the endpoint field in both cases.
The authenticated Installation owns the Environment; the plan only asserts it.
A1/S1 public catalog entries must have exact Connector scope
`fse2-organization-current-spec` and operation scope `*`, active pinned revisions and
distinct SPKIs. Private material stays in the existing provider.

The tool compiles the 14 operations from the existing canonical source recipe, validates,
imports and binds through Admin APIs. `grant` creates/verifies 14 exact operation grants,
not a caller wildcard; interruption resumes from existing matching grants. `propose`
reviews all 14 operations; a distinct approver approves and publishes that exact checksum,
then `verify` reads back Published/Active and all compiled authority. No FSE2 invocation
is performed by provisioning. In the existing M3 synthetic bootstrap, value
`M3_FSE2_OFFICIALTEST_SYNTHETIC_BOOTSTRAP=current-spec` prepares the matching public
catalog scope; this is test/bootstrap configuration, not a new operational dependency.

`activity` is Published, not an authorization choice in runtime input. Select VERIFICA
or VALIDATION intentionally for CDA; an opposite caller activity is denied. FHIR validation
remains VERIFICA under either choice. Reusing the same version with a different plan is
drift, not an in-place update; legacy schema 1.0 and Published 1.0.0/1.0.1 remain unchanged.
This source version is not a general multi-organization deployment/version editor.

## Qualification summary (redacted, offline only)

- `Fse2CurrentSpecTests`: all body families, required/unknown/duplicate/type/enum/bounds,
  explicit schema 2.0 authority, full canonical definition, technical response/correlation,
  activity status mapping, warning reduction and exact/generic 404 mapping.
- `FSE2_IT_current_and_historical_Published_route_matrix_exact_bytes_claims_and_bounded_responses`:
  14 current + 11 historical HTTPS routes, public current request factory, exact path/body/file,
  dual JWT/A1 separation/hash, pre-signing negatives and audit cardinality.
- `PROVISIONER_clean_state_golden_path_stays_below_25_percent_of_each_quota`:
  both legacy and current variants reach Published/Active from empty PostgreSQL 18 using
  migrations, existing bootstrap, enrollment and supported provisioner/Admin APIs.
- Existing rollback/resumability and `FSE2_DUR_*` restart/replica/scope regression gates
  remain active alongside additive migration `0019`; historical Published definitions remain unchanged.
- `FSE2_DUR_E2E_PostgreSQL18_VALIDATION_publication_same_workflow_both_traces_second_instance`:
  sequential validation/publication/second-instance status for all four ordinary publication
  routes, original trace contexts, exact audit cardinality and no caller transition authority;
  inconsistent response workflow and storage INSERT denial after upstream 202 remain failures.
- `FSE2_DUR_DAT_PostgreSQL18_successor_is_atomic_idempotent_and_preserves_both_trace_scopes`
  and the `upgrade_from_0018` test cover migration `0019`, unchanged origins, both trace scopes,
  exact registration replay without any upstream publication, concurrent identical/competing
  registrations, upgrade and second-apply no-op. Existing least-privilege/RLS tests remain active.
- Focused Core projection/approval parity tests cover prefix preservation, historical
  authority-root behavior, single encoding, invalid prefix rejection and exact origin.
  The causal fix makes `pathTemplate` honor existing `appendToBasePath` in both
  review and runtime; no Healthcare dependency or new Core contract was introduced.

Required exact-head CI is reported by the PR checks, once at convergence. No new service,
table, worker, cache, UI, runtime dependency, SBOM or vulnerability inventory was introduced.
No live publication/accreditation conclusion can be inferred from these tests.

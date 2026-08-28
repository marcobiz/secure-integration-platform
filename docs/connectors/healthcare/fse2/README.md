# FSE2 National Connector — Organization profile

Status: **remediated; exact-head qualification pending**. This is neither an accreditation
statement nor an `ACCREDITED_PRODUCTION_READY` claim.

## Authority model

The only implemented actor profile is `ORGANIZATION`; Human Actor is deferred. Core authenticates
the caller, resolves the grant and one immutable Published operation, verifies freshness, and then
hands the external `healthcare-fse2` module an `AuthorizedConnectorExecution`. The pack depends only
on `Gateway.Application`. It has no store/provider/certificate access, signing primitive,
`HttpClient`, generic HTTP surface, direct restricted transport, IVT, or Core-internal invocation
type.

The strict Published extension contains only common Organization configuration: environment,
P.IVA and assigning authority, organization/locality, `DAP`, application identity, and the maximum
document size. It cannot select an operation, method, path, parameter name, content type, multipart
boundary, signing slot, key, certificate, endpoint, issuer, audience, subject, temporal profile, or
claim policy. Unknown fields fail closed. The exact operation comes from the already-authorized
Core context and is looked up in the frozen FSE2 catalog.

P.IVA plus assigning-authority OID produce the exact fixed-subject CX. `person_id` remains a
separate validated business CX and is never promoted to authenticated actor.
`use_subject_as_author` is absent.

## OfficialTest `validate-cda` operational source

The candidate operational slice freezes one public-safe source definition at
`Definitions/fse2-officialtest-validate-cda.connector.json`. It contains exactly one operation,
`validate-cda`, and only logical endpoint/A1/S1 bindings. It contains no concrete endpoint,
organization/locality value, provider resource ID, principal, certificate, P12, password or token.
Repository bytes and their SHA-256 are regression-tested before the deployment compiler overlays
the protected organization/locality values and exact public A1/S1 revision metadata. The application
identity is source-owned as `secure-integration-platform` / `ApoCert S.r.l.` /
`0.1.0-alpha.1` and cannot be selected by a plan or runtime caller.

`tools/fse2/OfficialTestProvisioner` is the supported vertical administrative path. Its `plan`
command runs before construction of an Admin client and reports explicit zero workflow-store,
signing, DNS, HTTPS, transport and network counters. The remaining commands reuse only the existing
authenticated Admin validate/import/bind/approval/publish/read-back endpoints. The runtime caller
cannot choose this driver, endpoint, provider, secret or certificate. Operational commands resolve
public A1/S1 authority from the exact unique active `/provider-resources` Admin API entries; an
external public-metadata file is neither required nor accepted. The full operator procedure
and closed external-plan schema are in
[`OFFICIALTEST-VALIDATE-CDA-RUNBOOK.md`](OFFICIALTEST-VALIDATE-CDA-RUNBOOK.md) and
[`fse2-officialtest-operational-plan.schema.json`](fse2-officialtest-operational-plan.schema.json).

This source and provisioner do not perform a live invocation. Official operational configuration,
two preauthorized human sessions and a later single-live handoff remain external gates.

## Frozen operation and wire matrix

| Operation ID | Availability | Method and Published `pathTemplate` | Body mode |
|---|---|---|---|
| `validate-cda` | Production | `POST /documents/validation` | REQUIRED multipart |
| `validate-fhir` | Official test only | `POST /documents/fhir-validation` | REQUIRED multipart |
| `create` | Production | `POST /documents` | REQUIRED multipart |
| `replace` | Production | `PUT /documents/{document-id}` | REQUIRED multipart |
| `delete` | Production | `DELETE /documents/{document-id}` | NONE |
| `update-metadata` | Production | `PUT /documents/{document-id}/metadata-iti-57` | REQUIRED JSON |
| `update-metadata-chain-concealment` | Official test only | `PUT /documents/{document-id}/metadata-oscuramento-catena` | REQUIRED JSON |
| `validate-and-create` | Production | `POST /documents/validate-and-create` | REQUIRED multipart |
| `validate-and-replace` | Production | `PUT /documents/validate-and-replace/{document-id}` | REQUIRED multipart |
| `get-status-by-workflow` | Production | `GET /status/{workflow-instance-id}` | NONE |
| `get-status-by-trace` | Production | `GET /status/search/{trace-id}` | NONE |

Parameter names are catalog-owned. The caller supplies only the one opaque identifier value
required by the selected operation. Core accepts only whole-segment Published placeholders,
canonical bounded names, and NFC values of at most 512 UTF-8 bytes; slash, backslash, percent,
query, fragment, dot-segment, missing, unknown, extra, and duplicate forms fail closed. There is no
connector-side URI concatenation. Core retains scheme, host, port, origin, method, template, DNS,
restricted-egress, redirect, timeout, and response-bound authority.

`bodyMode: none` creates no `HttpContent`, body bytes, or `Content-Type` on DELETE and status GET.
Payload operations use REQUIRED; omitting `bodyMode` retains Core's historical REQUIRED default.
For document operations the pack creates one deterministic multipart byte sequence for restricted
transport. Where the frozen operation requires `attachment_hash`, the claim is SHA-256 of the exact
input file bytes, never of the multipart HTTP envelope. `validate-cda` does not emit the claim.

## Exact outbound policy

`Fse2OrganizationPublishedOperationExpectationProvider` supplies mandatory semantic expectations
for `healthcare-fse2-organization`. Core compares them with the effective Published operation before
strategy entry, capability scope, signing, DNS, HTTPS, or network:

- authentication is mTLS and restricted transport is required;
- the exact slots are `authorization` and `integrity`;
- both require RS256, a leaf-first `x5c` chain, 300-second `iat`/`exp`, no `nbf`, and non-empty `jti`;
- authorization projects only as `Authorization: Bearer` and permits no business claims;
- integrity projects only as `FSE-JWT-Signature` and has the exact FSE2 claim allowlist;
- audience is derived from the strict environment class;
- subject is the canonical Organization CX;
- issuers are `auth:<verified signing-certificate CN>` and
  `integrity:<verified signing-certificate CN>`;
- the two slots use the same verified signing identity, and each is distinct from mTLS.

The pack requests two fresh opaque tokens but never reads compact JWTs or creates transport
headers. Core owns signing/key authority, certificate validation and header projection.

Claim provenance is frozen as follows:

| Authority | Claims |
|---|---|
| Server-owned | `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, organization/role/locality/application fields |
| Business allowlisted | `person_id`, `patient_consent`, `resource_hl7_type` |
| Derived | `purpose_of_use`, `action_id`, exact-byte `attachment_hash` |

## Workflow correlation

`SharedOrganizationProfileChecksumSha256` is a canonical deterministic hash of common
Organization authority only. It excludes operation ID, method, path, path/resource parameters,
content type, multipart boundary, payload, workflow/trace IDs, and all per-request data. It scopes
correlation together with Tenant, Application, Installation, Environment, Connector version and
Connector ID, allowing `create` to correlate with both status operations.

`OperationProfileChecksumSha256` separately binds the originating catalog operation and is retained
in the technical workflow record for validation/audit; it is not part of the status lookup key.
Records contain only technical operation/action/purpose and workflow/trace values—never patient or
document content. The current store is bounded and process-local; durable cross-process workflow
persistence is not claimed.

## Environment and deferred scope

Production permits only the nine Production operations and uses audience
`https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1`. OfficialTest uses
`https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1`. The synthetic audience and
HTTPS origin are test-only.

`HUMAN_ACTOR_PROFILE = DEFERRED`. Operational provider material, production certificate custody,
conformance, accreditation, monitoring, and live evidence remain outside this PR. Tests use only
ephemeral synthetic certificates and `OFFICIALTEST_NETWORK_COUNT=0`.

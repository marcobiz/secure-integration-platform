# FSE2 National Connector — initial organization profile

Status: **REMEDIATED pending targeted independent re-review**. This is not an official
accreditation statement and is not `ACCREDITED_PRODUCTION_READY`.

## Supported authority model

The only implemented actor profile is `ORGANIZATION`. The production resolver reads the real
`IConnectorConfigurationStore` with `PublishedConnectorAccessContext`, validates the exact
Published lifecycle/version/operation/canonical checksum, and requires a current exact-digest
four-eyes record from `IAdminSecurityStore`. The approved definition and active bindings bind
Tenant, Application, Installation, Environment, ConnectorVersion, Connector and operation to
an organization P.IVA and assigning-authority OID. The pack
formats the canonical CX and supplies it to the existing Core signer as
`JwtSubjectPolicy.Fixed`/`FixedSubject`.

Caller business data cannot select or override subject, organization P.IVA, endpoint,
algorithm, issuer, audience, role, purpose, action, signing identity, mTLS identity, x5c or
token lifetime. `person_id` identifies the assistito/genitore/tutore and is never promoted
to authenticated actor. `use_subject_as_author` is absent and unsupported.

Claim provenance is frozen as follows:

| Authority | Claims |
|---|---|
| `SERVER_OWNED` | `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, organization/role/locality/application fields |
| `TRUSTED_RUNTIME` | none in the initial organization profile |
| `BUSINESS_ALLOWLISTED` | `person_id`, `patient_consent`, `resource_hl7_type` |
| `DERIVED` | `purpose_of_use`, `action_id`, exact-byte `attachment_hash` |

The v1 generic Connector schema has no pack extension object. Without changing Core, the FSE2
production adapter therefore requires one checksum-bound, non-secret profile envelope in the
canonical definition `description`, prefixed `fse2-organization-profile-v1:` and encoded as
base64url JSON. Unknown envelope fields fail closed. The exact operation uses the existing
`apiKeyAndMtls` dependency shape only as a two-resource Published binding carrier: its
`secretBinding` is a provider-owned signing-key handle consumed solely through
`IKeyOperationProvider`, while `certificateBinding` is the distinct mTLS client certificate.
The FSE2 runtime never projects the former as an API-key header or retrieves a secret value.
The definition checksum and binding-bundle digest are both required by the four-eyes record.

## Frozen operation matrix

| Operation | Availability | Purpose | Action | Retry |
|---|---|---|---|---|
| CDA validation | Production | `TREATMENT` | `CREATE` | No automatic retry |
| FHIR validation | Official test only | `TREATMENT` | `CREATE` | No automatic retry |
| Create | Production | `TREATMENT` | `CREATE` | No automatic retry |
| Replace | Production | `UPDATE` | `UPDATE` | No automatic retry |
| Delete | Production | `UPDATE` | `DELETE` | No automatic retry |
| Metadata update | Production | `UPDATE` | `UPDATE` | No automatic retry |
| Chain concealment | Official test only | `ACCESS UPDATE` | `UPDATE` | No automatic retry |
| Validate and create | Production | `TREATMENT` | `CREATE` | No automatic retry |
| Validate and replace | Production | `UPDATE` | `UPDATE` | No automatic retry |
| Workflow status | Production | stored original context | stored original context | Safe retry |
| Trace status | Production | stored original context | stored original context | Safe retry |

All supported organization operations use the official `DAP` organization role. The pack
checks the exact role/purpose/action tuple for the selected operation and rechecks the
stored tuple used by status calls. Direct FHIR create/replace and inbound callback/consumer
surfaces are not available.

## Outbound security

Every call prepares a fresh `Authorization: Bearer` JWT and a fresh
`FSE-JWT-Signature` JWT. Both are RS256, contain the exact approved leaf DER in standard
Base64 `x5c`, and use `iat` plus `exp` without `nbf`. Issuers are `auth:<verified CN>` and
`integrity:<verified CN>`, where CN is read from the exact DER already matched to the
approved fingerprint/SPKI. CN means exactly one DER Subject attribute with OID `2.5.4.3`;
absence, duplicates, empty/non-normalized values and unsupported encodings fail closed. Signing
and mTLS use different logical bindings and purposes, each carrying its actual Published catalog
revision/checksum, provider reference, binding revision/checksum and approved public identity.

Both JWTs and mTLS consume one internal `Fse2DispatchLease`. After JWT signing, public `x5c`
resolution, mTLS material resolution, DNS and request preparation, the final Healthcare transport
re-reads and compares the complete Published/profile/resource/endpoint authority. Only after that
check are the two JWT headers projected synchronously and the restricted network transport called.

Production accepts only
`https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1`; OfficialTest accepts only
`https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1`. Variable synthetic HTTPS
origins require an internal test-only authority and cannot be declared Production. DNS/IP policy,
redirect/proxy restrictions, timeout, cancellation and bounded responses remain enforced by Core.

Workflow persistence uses a full immutable Tenant/Application/Installation/Environment/
ConnectorVersion/profile checksum+revision key plus the originating operation and technical
workflow/trace identifiers. It stores no patient claims or document body. Status callers provide
their current allowlisted clinical claims; those claims never become actor authority.

## Deferred scope

`HUMAN_ACTOR_PROFILE = NOT_IMPLEMENTED` because it requires a separately authenticated and
authorized trusted actor source. Possible future integration sources are not selected by
this PR. No new Core primitive, OIDC/Keycloak integration, client actor attestation or
global user principal is introduced.

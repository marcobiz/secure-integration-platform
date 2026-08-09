# FSE2 National Connector — initial organization profile

Status: **IMPLEMENTATION_READY pending independent review**. This is not an official
accreditation statement and is not `ACCREDITED_PRODUCTION_READY`.

## Supported authority model

The only implemented actor profile is `ORGANIZATION`. An immutable, four-eyes-approved
Published profile binds Tenant, Application, Installation, Environment, ConnectorVersion,
Connector and operation to an organization P.IVA and assigning-authority OID. The pack
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

Every call emits a fresh `Authorization: Bearer` JWT and a fresh
`FSE-JWT-Signature` JWT. Both are RS256, contain the exact approved leaf DER in standard
Base64 `x5c`, and use `iat` plus `exp` without `nbf`. Issuers are `auth:<verified CN>` and
`integrity:<verified CN>`, where CN is read from the exact DER already matched to the
approved fingerprint/SPKI. Signing and mTLS use different logical bindings and purposes.

All outbound calls use the purpose-bound restricted transport. The endpoint is an HTTPS
`/v1` base plus an allowlisted operation path; DNS/IP policy, redirect/proxy restrictions,
timeout, cancellation and bounded responses remain enforced by Core infrastructure.

## Deferred scope

`HUMAN_ACTOR_PROFILE = NOT_IMPLEMENTED` because it requires a separately authenticated and
authorized trusted actor source. Possible future integration sources are not selected by
this PR. No new Core primitive, OIDC/Keycloak integration, client actor attestation or
global user principal is introduced.

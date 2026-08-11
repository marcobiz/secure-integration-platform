# SistemaTSEPrescriptionConnector - Wave 1 specification freeze

Status: **CONNECTOR-LOCAL VALIDATION READY - BUSINESS DISPATCH BLOCKED BY CORE**

Freeze date: 2026-08-08
Implementation-resumption audit: 2026-08-11
Connector-first implementation baseline: `b1810eda7e96fabfc6e15e608d48867e96cd5a80`

Target pack: `ConnectorPacks.Healthcare`

## Decision

Current official WSDL/XSD and MFA material are available and have been frozen in the
[official source registry](official-source-registry.md). The 2026-08-09 currency recheck
accepted that freeze without replacement. The generic opaque-session HTTP projection supports
fixed server-owned `Authorization2F: Bearer` placement, but the composed SOAP capability still
dispatches the original authorized caller body. It cannot safely compose that body from
caller-owned business data plus Core-resolved server-owned identity fields.

Baseline `b1810ed` includes the separately qualified capability completion from PR #26: an explicit
module may register the three existing typed adapter contracts and each adapter receives an exact,
Published-mapped server-owned input set that can write only through the Core-owned XML writer.
That capability qualifies create/checkToken only; it does not close business-body composition.

`Healthcare.SistemaTs` registers the exact `healthcare-sistema-ts-eprescription` strategy and
official `CreateAuthReq`/`CreateAuthRes` and `CheckTokenReq`/`CheckTokenRes` semantics. Only
`session-create` is Published. The four business contracts have exact connector-local XML
validators/serializers and synthetic wire fixtures, but their publication and execution are
disabled until Core provides typed composed-body authority. Core continues to own Basic resolution,
opaque session custody, external-admission intent, atomic promotion, freshness and restricted
transport. Healthcare has no provider/store/service-locator access and Gateway.Api has no
Healthcare reference.

## Confirmed national business scope

The following upstream capabilities are confirmed by specification 1.5.1 and its
current WSDL/XSD. They are confirmed source capabilities, not Published connector
operations and not an implementation claim.

| Business capability | Official operation | Status for this wave |
|---|---|---|
| Retrieve and exclusively take in charge an SSN prescription | `visualizzaErogato` | Exact XML/wire fixture; `BLOCKED_BY_CORE` for product dispatch |
| Release a prior take-in-charge when the official operation mode permits it | `visualizzaErogato` with the documented operation mode | Exact frozen contract; `BLOCKED_BY_CORE` for product dispatch |
| Dispense and close, including documented modes | `invioErogato` | Exact XML/wire fixture; `BLOCKED_BY_CORE` for product dispatch |
| Suspend or revoke suspension | `sospendiErogato` | Exact XML/wire fixture; `BLOCKED_BY_CORE` for product dispatch |
| Correct or cancel a prior dispensation | `annullaErogato` | Exact XML/wire fixture; `BLOCKED_BY_CORE` for product dispatch |

Deferred/unconfirmed as public connector operations in this wave:

- deferred/offline malfunction workflows and diagnostic/report services;
- historical lookup and monthly reports;
- prescription-side operations;
- any operation described only by an example or historical characterization;
- regional SAR protocol variants;
- FSE 2.0.

## SAC/SAR routing seam

The future pack-level routing contract is server-owned and has two profile kinds:

```text
NationalSac
RegionalReference(profileId)
```

`profileId` is a logical reference resolved from authenticated Tenant/Application
configuration, region and the Published binding. It is not an endpoint and cannot be
supplied or changed by the caller. A Published operation binds exactly one business
contract, environment, routing profile, endpoint resource and credential/session profile.

The Core continues to see only Connector/version/operation, logical binding dependencies
and provider-neutral transport/auth capabilities. It does not gain prescription, NRE,
pharmacy, SAC, SAR or Sistema TS types. No universal `ISarAdapter`, SAML profile or
regional protocol implementation is introduced.

The current official portal states that SAR access uses a certificate plus a signed SAML
assertion when strong authentication is exclusive. That is recorded only as a routing
constraint; it is not implemented or generalized here.

## SOAP contract boundary

- SOAP actions, namespaces, request/response roots and environments remain server-owned.
- The official WSDL/XSD are not copied into Git and no XML is invented.
- Connector-local serializers and validators encode every frozen request/response sequence,
  cardinality, simple/complex distinction and relevant lexical/value facet. They reject arbitrary
  nesting, caller XPath, raw headers, dynamic namespaces and children inside simple values.
- The official `sospendiErogato` SOAP action is retained exactly as published, including
  its namespace difference from the WSDL target namespace.
- Endpoint addresses found in the kit remain server-side environment bindings and are
  intentionally absent from this public specification.

These serializers are not wired to product transport. The safe future boundary must accept typed
caller business data and resolve server-owned bindings inside Core before serializing the final
authenticated body. Caller-supplied `pinCode` or server identity, plaintext binding extraction,
direct provider access, injected transport/`HttpClient`, raw authenticated header/body escape,
Gateway.Api-to-Healthcare dependency and IVT remain forbidden.

## Basic, ID-session and MFA

Confirmed SAC sequence:

1. resolve the Basic credential from an approved server-side secret binding;
2. invoke typed ID-session operation `create` with the server-owned `RICETTA-DEM` context,
   `EROGATORE` application and the provisioned identity fields required by the profile;
3. complete the out-of-band interaction without assuming Direct, browser, Broker or any
   single presentation adapter, then validate and promote the supplied opaque ID-session;
4. store only an opaque reference bound to Tenant, Installation, Application,
   Connector/version, operation/profile, environment, endpoint/binding and credential
   revision;
5. attach the internal ID-session as the fixed HTTP `Authorization2F` bearer header;
6. support typed `checkToken` and `revoke` lifecycle actions where policy requires them.

Expiry must come from the current service response/profile. The test-only wildcard format
is not a production session and is never a fallback. Rotation, disable, expiry, wrong
profile and replay fail closed. No session value may enter logs, audit, errors or responses.

### Qualified composition

The module registers only the existing request, response and validation adapter contracts. Its
seven create inputs and four checkToken inputs are mapped to `opaque` bindings by the immutable
Published definition. Values have no plaintext getter and are cleared after the synchronous XML
callback. Production `create` success always returns `ExternalAdmissionRequired`; even a test-only
communication cannot issue a session. Authenticated completion validates the UUID candidate with
official `checkToken`, uses remote expiry and promotes through the one shared Core lifecycle.

## Business state and reconciliation

The future connector must not duplicate Sistema TS prescription state. It may retain only
correlation, idempotency key, technical workflow reference and reconciliation metadata.
The caller supplies typed business input, never endpoint, credential, session, region URL
or server/security state. Official state transitions and diagnostic codes remain the sole
upstream authority.

No fault taxonomy is implemented in this freeze. Future mapping must distinguish Basic
authentication, MFA/session, unavailable prescription, exclusive take-in-charge conflict,
invalid state, validation/business rejection and retryable transport only where the
official code and replay policy justify that classification. Raw SOAP Fault detail is
never returned.

## RBE

The current official RBE dispenser material separately confirms retrieve/take-in-charge,
dispense/close, suspend and cancel/correct families. RBE remains an explicit capability
family of the future connector, with separate DTOs and operation semantics. It is not
combined with SSN messages and is not implemented in this wave. Shared Basic/ID-session
custody may be reused only after the frozen-surface blocker is qualified.

## Synthetic server and security tests

`tools/healthcare/SyntheticSistemaTsServer` is a real loopback HTTPS/SOAP authority tied to the
frozen contract. Direct fixture tests cover all four business operations and assert exact SOAPAction,
SOAP 1.1, content type, Basic, `Authorization2F`, nested XML, namespaces, values and independent
operation counters. Seven meaningful network-boundary negatives are executed for every operation.

The hosted product test crosses BGW1 authentication, grant, four-eyes Published `session-create`,
server-owned create/checkToken inputs, authenticated completion and shared-session promotion, then
proves all four business operation IDs fail without business or generic transport. PostgreSQL 18
runs this admission-only path through the real routing store; CI requires execution and turns
missing database configuration into failure. It is not a full business E2E.

Generic lifecycle/race/cancellation tests remain prerequisite regression evidence and are mapped
explicitly rather than relabelled as official conformance.

`SERVER_OWNED_BUSINESS_FIELDS = BLOCKED_BY_CORE`.

`BUSINESS_SOAP = BLOCKED_BY_CORE`.

`POSTGRESQL_FULL_BUSINESS_E2E = BLOCKED_BY_CORE`.

`CORE_COMPOSITION_BLOCKER = STILL_OPEN`.

`NEW_CORE_PRIMITIVE_REQUIRED = YES`.

## Provisioning and accreditation blockers

- authorized Sistema TS test identities and provisioning are not repository assets;
- production onboarding, grants and accreditation have not been exercised;
- no live SAC or SAR call was made;
- regional profile specifications are out of scope;
- exact-head CI can qualify only this documentation freeze, not external conformance.

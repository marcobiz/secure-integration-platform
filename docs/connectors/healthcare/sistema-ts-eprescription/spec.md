# SistemaTSEPrescriptionConnector - Wave 1 specification freeze

Status: **BLOCKED_BY_GENERIC_PRIMITIVE - NO-GO for implementation**

Freeze date: 2026-08-08

Target pack: `ConnectorPacks.Healthcare`

## Decision

Current official WSDL/XSD and MFA material are available and have been frozen in the
[official source registry](official-source-registry.md). The production connector was
not started because the current SAC profile requires the opaque ID-session in the HTTP
`Authorization2F` header, while the frozen M6 SOAP/session API can place a session only
as a namespace-qualified SOAP Header element.

Adding a caller-controlled header is forbidden. Adding a new generic, server-owned
HTTP-session placement primitive is outside this wave. The requested hard stop therefore
applies before contract generation, runtime composition or synthetic connector work.

## Confirmed national business scope

The following upstream capabilities are confirmed by specification 1.5.1 and its
current WSDL/XSD. They are confirmed source capabilities, not Published connector
operations and not an implementation claim.

| Business capability | Official operation | Status for this wave |
|---|---|---|
| Retrieve and exclusively take in charge an SSN prescription | `visualizzaErogato` | Contract confirmed; not implemented |
| Release a prior take-in-charge when the official operation mode permits it | `visualizzaErogato` with the documented operation mode | Contract confirmed; not implemented |
| Dispense and close, including the documented total, partial and single-dispensation modes | `invioErogato` | Contract confirmed; not implemented |
| Suspend or revoke suspension | `sospendiErogato` | Contract confirmed; not implemented |
| Correct or cancel a prior dispensation | `annullaErogato` | Contract confirmed; not implemented |

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
- Future generated or hand-controlled typed serializers must pin the frozen artifact
  digest and reject arbitrary XML, caller XPath, raw headers and dynamic namespaces.
- The official `sospendiErogato` SOAP action is retained exactly as published, including
  its namespace difference from the WSDL target namespace.
- Endpoint addresses found in the kit remain server-side environment bindings and are
  intentionally absent from this public specification.

## Basic, ID-session and MFA

Confirmed SAC sequence:

1. resolve the Basic credential from an approved server-side secret binding;
2. use the typed ID-session service operation `create` when a session must be requested;
3. complete the out-of-band interaction without assuming Direct, browser, Broker or any
   single presentation adapter;
4. store only an opaque reference bound to Tenant, Installation, Application,
   Connector/version, operation/profile, environment, endpoint/binding and credential
   revision;
5. attach the internal ID-session as the fixed HTTP `Authorization2F` bearer header;
6. support typed `checkToken` and `revoke` lifecycle actions where policy requires them.

Expiry must come from the current service response/profile. The test-only wildcard format
is not a production session and is never a fallback. Rotation, disable, expiry, wrong
profile and replay fail closed. No session value may enter logs, audit, errors or responses.

### Blocking primitive gap

`SoapSessionProfile.SessionHeaderElement` and `SoapXmlBoundary.SerializeRequest` currently
model only an XML element inside the SOAP Header. `SoapXmlBoundary.ApplyHttpHeaders`
controls SOAPAction/content type but has no server-owned opaque-session HTTP-header
placement. Consequently the official SAC profile cannot be expressed without changing a
generic primitive.

The prerequisite for resuming this wave is a separately authorized Core change that:

- permits only a compiled allowlisted header name and scheme;
- accepts no header name or value from the caller;
- injects the opaque session immediately before restricted dispatch;
- preserves credential/binding/endpoint/profile revision checks and redaction;
- includes positive and negative architecture, replay, substitution and log tests.

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
custody may be reused only after the blocking primitive is qualified.

## Synthetic server and security tests

No Sistema TS synthetic server or connector-specific executable tests were created.
Doing so before the required auth placement exists would create a misleading, non-runnable
profile. Existing M6 synthetic tests continue to qualify only the generic SOAP Header
session profile; they are not Sistema TS conformance evidence.

When the prerequisite is available, the connector gate must add the positive lifecycle
and every negative case listed in the Wave 1 request, including caller header injection,
session spoof/replay, routing and endpoint substitution, stale/disabled credentials, XML
attacks, Fault ambiguity, timeout/cancellation, egress, response size and invalid business
transitions.

## Provisioning and accreditation blockers

- authorized Sistema TS test identities and provisioning are not repository assets;
- production onboarding, grants and accreditation have not been exercised;
- no live SAC or SAR call was made;
- regional profile specifications are out of scope;
- exact-head CI can qualify only this documentation freeze, not external conformance.

# SistemaTSEPrescriptionConnector - Wave 1 specification freeze

Status: **NOT_READY - FROZEN-SURFACE HARD STOP**

Freeze date: 2026-08-08
Implementation-resumption audit: 2026-08-09
Connector-first audit: 2026-08-10 against exact baseline `3f8667b7cb9678d6efb670f1c192cc227228ab1f`

Target pack: `ConnectorPacks.Healthcare`

## Decision

Current official WSDL/XSD and MFA material are available and have been frozen in the
[official source registry](official-source-registry.md). The 2026-08-09 currency recheck
accepted that freeze without replacement. The generic opaque-session HTTP projection now
supports the fixed server-owned `Authorization2F: Bearer` placement, so the earlier header
placement gap is closed.

Baseline `3f8667b` closes the previously recorded lifecycle and dispatch gaps: typed compiled
handshake adapters, authenticated external admission, atomic promotion into the shared lifecycle,
composed Basic plus opaque-session SOAP and an exact-authority execution bridge are present.
The connector-first audit nevertheless found that the frozen public surface cannot host the
official adapter without bypassing qualified custody. `ConnectorExecutionModuleLoader` registers
only `IConnectorExecutionStrategy`; the production `TypedSessionHandshakeAdapterRegistry` is
constructed from three Gateway.Api synthetic instances and consumes no module-owned adapter.
In addition, `TypedSessionHandshakeRequestContext` exposes Core identities and Published metadata
only. It has no provider-resolved source for the mandatory STS `userId`, encrypted
`identificativo`, `cfUtente`, `codRegione`, `codAslAo` and `codSsa` values documented for
`RICETTA-DEM`/`EROGATORE`.

Caller-supplied values, hardcoded tenant credentials, direct provider access from Healthcare,
Gateway.Api-to-Healthcare references or test-only DI replacement would each bypass or misrepresent
the qualified production boundary. The hard stop therefore applies before DTO, serializer,
runtime composition or synthetic connector implementation. This is not `BLOCKED_BY_SPEC`: the
official fields and wire structure are known. Resumption requires a separately qualified Core
surface under freeze-policy criterion C, because otherwise an existing custody boundary must be
bypassed.

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

### Frozen-surface hard stop after generic composition remediation

The typed/nested XML, external-admission and composed-SOAP runtime primitives are now present.
Two production composition requirements remain inexpressible:

- a module-loaded strategy cannot contribute `ITypedSessionHandshakeRequestAdapter`,
  `ITypedSessionHandshakeResponseAdapter` or `ITypedExternalSessionValidationAdapter` to the
  production registry through `IConnectorExecutionStrategyRegistrar`;
- a compiled request/validation adapter cannot consume the exact server-owned STS identity and
  encrypted identifier values. The public contexts expose no narrow provider-resolved input and
  accepting a caller dictionary or generic XML/request map is explicitly prohibited.

The prerequisite for resuming this wave is a separately authorized and independently qualified
Core change that registers module-owned compiled adapters without a host-to-vertical dependency
and supplies only approved, binding-scoped server values without exporting raw provider access or
a generic transformation map. It must preserve the existing Published stamp, resource revisions,
zeroization, redaction, one-shot transport and shared lifecycle. No Healthcare session cache or
parallel authority model is acceptable.

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

No Sistema TS synthetic server or connector-specific executable tests were created.
Doing so before the production host can register the vertical adapters and resolve their mandatory
server-owned inputs would create a misleading, non-runnable profile. Existing generic synthetic
tests qualify only the underlying primitives; they are not Sistema TS conformance evidence.

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

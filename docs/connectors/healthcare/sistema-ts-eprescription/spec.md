# SistemaTSEPrescriptionConnector - Wave 1 specification freeze

Status: **IMPLEMENTATION_READY - INDEPENDENT REVIEW PENDING**

Freeze date: 2026-08-08
Implementation-resumption audit: 2026-08-11
Connector-first implementation baseline: `b1810eda7e96fabfc6e15e608d48867e96cd5a80`

Target pack: `ConnectorPacks.Healthcare`

## Decision

Current official WSDL/XSD and MFA material are available and have been frozen in the
[official source registry](official-source-registry.md). The 2026-08-09 currency recheck
accepted that freeze without replacement. The generic opaque-session HTTP projection now
supports the fixed server-owned `Authorization2F: Bearer` placement, so the earlier header
placement gap is closed.

Baseline `b1810ed` includes the separately qualified capability completion from PR #26: an explicit
module may register the three existing typed adapter contracts and each adapter receives an exact,
Published-mapped server-owned input set that can write only through the Core-owned XML writer.
The former frozen-surface hard stop is therefore closed without a new Core primitive.

`Healthcare.SistemaTs` now registers the exact `healthcare-sistema-ts-eprescription` strategy,
official `CreateAuthReq`/`CreateAuthRes` and `CheckTokenReq`/`CheckTokenRes` semantics and the four
frozen SSN dispenser operations. Core continues to own Basic resolution, opaque session custody,
external-admission intent, atomic promotion, freshness, restricted transport and composed SOAP.
Healthcare has no provider/store/service-locator access and Gateway.Api has no Healthcare reference.

## Confirmed national business scope

The following upstream capabilities are confirmed by specification 1.5.1 and its
current WSDL/XSD. They are confirmed source capabilities, not Published connector
operations and not an implementation claim.

| Business capability | Official operation | Status for this wave |
|---|---|---|
| Retrieve and exclusively take in charge an SSN prescription | `visualizzaErogato` | Implemented as `visualizza-erogato` |
| Release a prior take-in-charge when the official operation mode permits it | `visualizzaErogato` with the documented operation mode | Implemented through the same frozen typed contract |
| Dispense and close, including documented modes | `invioErogato` | Implemented as `invio-erogato` |
| Suspend or revoke suspension | `sospendiErogato` | Implemented as `sospendi-erogato` |
| Correct or cancel a prior dispensation | `annullaErogato` | Implemented as `annulla-erogato` |

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
frozen contract. The canonical hosted tests cross BGW1 authentication, grant, four-eyes Published
configuration, server-owned inputs, create, authenticated completion, checkToken, shared-session
reuse and `visualizzaErogato`. Wire counters prove create/checkToken/business `1/1/1`, generic
fallback `0` and retry `0`. PostgreSQL 18 runs the same path through the real routing store.
Generic lifecycle/race/cancellation tests remain prerequisite regression evidence and are mapped
explicitly rather than relabelled as official conformance.

## Provisioning and accreditation blockers

- authorized Sistema TS test identities and provisioning are not repository assets;
- production onboarding, grants and accreditation have not been exercised;
- no live SAC or SAR call was made;
- regional profile specifications are out of scope;
- exact-head CI can qualify only this documentation freeze, not external conformance.

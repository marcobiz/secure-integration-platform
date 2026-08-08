# ADR-0021: Regional ePrescription commonality and profile boundary

**Status:** Accepted

## Context

Healthcare Wave 1 compares the current public material available from Regione
Lombardia/ARIA/SISS and Regione Emilia-Romagna/Lepida/SOLE. Both authorities describe a
regional ePrescription process in which a prescription is identified from a reference and
dispensing is communicated through regional infrastructure. The reviewed material does not,
however, publish two current and sufficiently complete application-to-application contracts.

In particular, it does not establish matching current wire operations, payload schemas,
authentication profiles, endpoints, fault taxonomies, accreditation rules, idempotency or
reconciliation behavior for both regions.

## Decision

The shared Healthcare Pack contains only:

- an opaque `PrescriptionReference`;
- `prescription.lookup` and `prescription.dispense` as minimal normalized business operations;
- minimal lookup and dispense outcomes without patient, medication or pharmacy schemas;
- a bounded scalar extension set whose schema exists only in the compiled server-owned profile,
  never in a caller contract and never as `Dictionary<string, object>`;
- normalized safe error categories with regional safe codes admitted only by the compiled
  profile's server-owned allowlist;
- a server-owned profile resolver and an opaque execution capability derived from the
  authenticated `GatewayClientPrincipal` and Published configuration;
- a production adapter over `IConnectorConfigurationStore` that resolves a validated Published
  snapshot with the existing Installation/Tenant/Application/operation access context and
  canonical `OperationBindingDependencies`;
- an opaque provider-neutral Core authorization capability produced after inbound authentication,
  active-state and exact-grant checks, including for operations with no credential dependency;
- exact logical endpoint, auth-policy and immutable credential bindings selected only by that
  resolution and matched against the compiled profile catalog;
- fail-closed profile state plus complete binding-fingerprint/resource-stamp validation immediately
  before dispatch;
- normalized boundary failures that never retain raw resolver, stamp-source or dispatcher errors;
- explicit malformed nested-command/response denial; nulls never escape as raw runtime errors;
- composite profile/operation catalog keys and explicit normalized enum-domain validation.

Take-in-charge, cancellation, reconciliation, callback/session topology, correlation semantics,
wire protocol, endpoint binding, authentication composition, field mapping, response mapping and
fault mapping remain profile-specific. No concrete Lombardia or Emilia-Romagna handler is
compiled while its current official contract is incomplete.

Both Wave 1 profiles are therefore `BLOCKED_BY_SPEC`. Their test HTTPS servers are sentinels only:
the foundation must deny dispatch and the servers must observe zero requests. They are not
synthetic claims about an undocumented SOAP, REST or OAuth contract.

## Consequences

Regional domain concepts remain physically inside `ConnectorPacks.Healthcare`; Gateway Core sees
only its existing Connector, operation, Published version, binding and principal contracts. A
small provider-neutral `AuthorizedGatewayInvocation` capability is added to Core so vertical packs
cannot perform inbound certificate or registry identity derivation. A caller cannot choose a
profile, region, endpoint, auth policy, credential or route. Adding a real
profile requires current official contract provenance, a dedicated compiled handler, positive and
negative conformance tests, threat-model review and four-eyes Published configuration.

The deliberately small model may require additive types once both official contracts support
additional shared semantics. That is preferred to freezing an imagined universal regional API.

## Alternatives rejected

- Implementing the historical or privately characterized wire contracts as if current.
- Treating a general SISS API Manager description as the Lombardia prescription OAuth profile.
- Treating historical SOLE/SAR process material as a current Emilia-Romagna SOAP/Basic/session
  contract.
- Adding 15 placeholder regions, a generic auth framework, an arbitrary object dictionary or
  regional concepts to Gateway Core.

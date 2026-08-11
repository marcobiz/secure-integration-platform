# ADR-0026: Authorized typed composed-SOAP request composition

**Status:** Accepted

## Context

The existing composed-SOAP authority combines a Published endpoint, HTTP Basic credentials, SOAP
version/action and an opaque-session projection, but historically accepts a complete caller-owned
SOAP envelope. Some approved operations need a connector-specific business request containing both
caller business data and server-owned opaque binding values. Exposing those values, provider/store
access or arbitrary authenticated request construction to a module would violate Core boundaries.

## Decision

- The existing `IAuthorizedConnectorCapabilityBridge.ExecuteComposedSoapAsync` signature remains
  unchanged. A Published operation may opt in through `typedComposedSoapRequest`; operations without
  that member send the original caller payload exactly as before.
- The opt-in block fixes one exact request adapter ID/type, one exact request QName and a bounded set
  of `name -> logical opaque secret binding` mappings. The request policy continues to own the final
  maximum body size. Canonical JSON, checksum-specific four-eyes review and the immutable Published
  revision therefore cover the complete composition authority.
- `ITypedComposedSoapRequestAdapter` is the sole new adapter category. Registration uses the existing
  deployment-owned registrar, module ownership, constructor-graph validation, duplicate rejection
  and per-category bounds. Registry lookup is exact and has no fallback or runtime growth.
- Core copies the already-authorized business payload and exposes only callback-scoped, independent,
  read-only streams plus safe identity/Published metadata. The synchronous adapter writes children of
  the exact request element through a hardened Core-owned `XmlWriter`.
- Server-owned values remain behind `AuthorizedConnectorBindingInputs.WriteRequiredXmlValue(name)`.
  Required names must equal the Published mapping exactly. The view is bound by reference to the
  current Core writer; alternate-writer use, retained use and plaintext retrieval are unavailable.
  A callback-scoped synchronized proxy serializes every adapter writer action with binding emission.
  Binding values can be emitted only as element text, never into attributes, so `XmlLang`,
  `XmlSpace`, namespace declarations and `LookupPrefix` cannot become plaintext/equality oracles.
- Core resolves only the operation dependencies in Published A, checks A after every provider await,
  clears transient payload/input buffers, hardens the adapter fragment, adds the exact SOAP
  Envelope/Body/QName and freezes the result as a bounded exact-byte snapshot.
- Existing Basic, opaque-session, SOAP metadata, DNS and restricted one-shot transport remain the only
  dispatch path. Full operation/adapter/mapping/binding/resource/endpoint/Basic/session/policy
  freshness is checked before the first network effect. A reread may confirm A but never adopt B.
- Migration `0014_typed_composed_soap_request_inputs.sql` additively extends the existing
  operation-scoped PostgreSQL locator to this exact input path. Its `SECURITY DEFINER`, fixed
  `search_path`, principal/grant/publication/binding/catalog predicates and runtime-only execute grant
  are retained; migrations `0012` and `0013` remain unchanged.

## Consequences

An approved module can implement protocol-specific business parsing and element semantics without
receiving an authenticated envelope, header bag, endpoint, credential, provider locator, transport or
plaintext binding API. SOAP mechanics and authority stay in Core. Adapter bugs are sanitized and can
deny service, but cannot select a different supported authority through this contract.

The output request necessarily contains approved server-owned values in memory and on the authorized
wire. The Gateway/provider process and local Administrator/SYSTEM remain residual privileged threats.
Publication and network dispatch are not a global transaction; a change after the first byte is sent
cannot retract that byte.

## Alternatives rejected

Reusing the handshake-specific adapter context for business authority, returning binding plaintext,
giving modules provider/store or `HttpClient` access, accepting a caller-owned final SOAP envelope for
opt-in operations, template XML/XPath, generic field dictionaries, arbitrary authenticated bytes,
header bags, a new public bridge method and rewriting historical composed-SOAP definitions.

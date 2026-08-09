# ADR-0022: Typed session handshake and authorized external admission

**Status:** Accepted

## Context

The original SOAP session lifecycle supports a backward-compatible scalar login request and
response. Some protocols require nested, ordered request and response structures, while some
session authorities require a separately presented opaque candidate to be validated before it
becomes the current session. A generic nested-field, template or scripting system would enlarge
the attack surface and would let callers influence server-owned authentication semantics.

## Decision

- Request and response mapping are one `TypedSessionHandshakeProfile` in the immutable Published
  Connector operation. The profile fixes logical adapter ID/type pairs, exact request and response
  QNames, SOAP version/action, bounds and local maximum lifetime. Its optional external-validation
  profile separately fixes the validation adapter ID/type, endpoint binding/path, SOAP
  version/action, exact QNames, deadline and request/response bounds.
- Only an already-authorized Gateway invocation and a logical profile ID may enter the resolver.
  The current Published snapshot supplies endpoint, ConnectorVersion, binding/resource revisions,
  resource stamp and policy checksum. These decisions are included in the four-eyes review digest.
- Trusted server composition registers compiled typed adapters by exact logical ID/type. There is
  no reflection serializer, caller callback, XML template, XPath, XSLT or generic nested-field map.
- Hardened Core opens the exact request element and supplies an `XmlWriter` for its structured
  children. Writes are byte-bounded while they occur. Core owns SOAP serialization and HTTP policy.
- Core validates the bounded response document, DTD/entity prohibition, depth/node/attribute
  limits, per-text/per-CDATA/per-attribute-value limits, exact Envelope/Body, one payload and exact
  payload QName before a registered response adapter receives a bounded `XmlReader`. The adapter returns only `Issued`,
  `ExternalAdmissionRequired` or `Rejected`.
- The public completion boundary accepts only the authenticated `GatewayClientPrincipal`, opaque
  intent reference and bounded candidate bytes. It recovers Connector/operation/profile, cache
  key, expiry and the closed `InteractiveHandoff` provenance from server-side intent state,
  reauthorizes the current grant and re-resolves the Published profile. Only this boundary can
  construct the internal, owned sensitive candidate. The candidate never enters the ordinary
  connector business-input contract.
- An external-admission intent is opaque, TTL-bounded, single-use and bound to authenticated
  Tenant/Application/Installation, exact cache key, ConnectorVersion/operation/profile, endpoint,
  resource revisions, Published checksum and resource stamp.
- Admission intent state is another interaction kind inside the existing bounded SOAP session
  cache. The 256-key cap, lazy expiry sweep, striped acquisition locks, one current generation and
  existing invalidation/rotation semantics remain authoritative. There is no second cache or
  lifecycle.
- A registered typed validation adapter has no transport or cache capability. It only serializes
  the protocol-specific request body and parses the already bounded response into a closed
  validity/status/remote-expiry outcome. Core alone resolves the Published endpoint and existing
  server-owned credential bindings, pins DNS/IP, denies proxy/redirect, enforces HTTPS, deadline
  and byte bounds, creates the SOAP envelope and performs the network call and hardened parse.
- Published, binding and provider-resource mutations open a fixed 64-stripe process-local authority
  lease before mutation and advance its generation again when the mutation succeeds or fails.
  Leases mark the affected stripe active without holding its lock across database I/O. Completion
  captures a generation before remote validation, performs every asynchronous Published/resource
  revalidation first, then executes a synchronous compare-and-promote only if that generation is
  current and no relevant mutation is active. The same critical section checks the intent proof and
  session generation, consumes the intent and promotes the new session; there is no await,
  in-progress-mutation window or check/write gap. Core caps remote expiry by the local maximum.
- Extension-thrown cancellation is preserved only when the actual caller/deadline token is
  cancelled, and is rethrown without extension message or inner exception. Otherwise it is a
  sanitized adapter failure, as are all other extension exceptions.

## Consequences

Nested protocols require small compiled adapters and explicit tests for order, cardinality,
allowed domains, duplicate/unexpected elements and mixed content. Existing scalar session profiles
do not register adapters and continue unchanged. Scale-out storage, generic XML mapping, arbitrary
session insertion and protocol-specific semantics remain outside this decision. The striped
mutation authority matches the existing single-node bounded session cache; a future scale-out
cache requires a correspondingly distributed linearization authority and a new decision.

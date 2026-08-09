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
  QNames, SOAP version/action, bounds, local maximum lifetime and optional external-validation
  endpoint/validator authority.
- Only an already-authorized Gateway invocation and a logical profile ID may enter the resolver.
  The current Published snapshot supplies endpoint, ConnectorVersion, binding/resource revisions,
  resource stamp and policy checksum. These decisions are included in the four-eyes review digest.
- Trusted server composition registers compiled typed adapters by exact logical ID/type. There is
  no reflection serializer, caller callback, XML template, XPath, XSLT or generic nested-field map.
- Hardened Core opens the exact request element and supplies an `XmlWriter` for its structured
  children. Writes are byte-bounded while they occur. Core owns SOAP serialization and HTTP policy.
- Core validates the bounded response document, DTD/entity prohibition, depth/node/attribute
  limits, exact Envelope/Body, one payload and exact payload QName before a registered response
  adapter receives a bounded `XmlReader`. The adapter returns only `Issued`,
  `ExternalAdmissionRequired` or `Rejected`.
- External presentation uses an owned sensitive candidate buffer and a closed
  `InteractiveHandoff` provenance. It never enters the ordinary connector business-input contract.
- An external-admission intent is opaque, TTL-bounded, single-use and bound to authenticated
  Tenant/Application/Installation, exact cache key, ConnectorVersion/operation/profile, endpoint,
  resource revisions, Published checksum and resource stamp.
- Admission intent state is another interaction kind inside the existing bounded SOAP session
  cache. The 256-key cap, lazy expiry sweep, striped acquisition locks, one current generation and
  existing invalidation/rotation semantics remain authoritative. There is no second cache or
  lifecycle.
- A registered typed validator may validate the candidate through its exact Published restricted
  endpoint and returns only validity/status/remote expiry. It has no cache capability. Core
  revalidates Published authority and resource stamps after remote validation, caps remote expiry
  by the local maximum, and alone performs atomic generation promotion.

## Consequences

Nested protocols require small compiled adapters and explicit tests for order, cardinality,
allowed domains, duplicate/unexpected elements and mixed content. Existing scalar session profiles
do not register adapters and continue unchanged. Scale-out storage, generic XML mapping, arbitrary
session insertion and protocol-specific semantics remain outside this decision.

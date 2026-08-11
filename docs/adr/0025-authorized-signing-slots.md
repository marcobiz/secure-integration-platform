# ADR-0025: Bounded authorized signing slots

**Status:** Accepted

## Context

ADR-0024 exposed one invocation-bound signing operation and one restricted transport operation. The
qualified implementation allowed one opaque token for the invocation and projected it only as an
Authorization Bearer value. A demonstrated connector requirement needs two independently fresh JWTs
for one already-authorized operation, with complete server-owned signing policies and different
outbound projections. Implementing that requirement outside Core would require token extraction,
direct provider/key access or arbitrary authenticated HTTP authority.

## Decision

- A new Published operation may declare between one and four `signingSlots`. Each slot has one
  canonical lower-case `ConnectorSigningSlotKey`, one existing RS256 signing-policy object, an
  explicit required flag and exactly one server-owned projection.
- The only projection kinds are `authorizationBearer` and `signedTokenHeader`. The latter contains a
  Published HTTP field name but never a runtime value. Hop-by-hop, transport-controlled, proxy,
  forwarding, tracing, cookie, content and Authorization names are denied. Header comparison is
  case-insensitive; duplicate custom fields and more than one Bearer projection fail validation.
- An external strategy may request a token only by slot key and existing bounded business claims.
  Core exact-matches the key against the immutable Published A captured by
  `AuthorizedConnectorExecution`. The slot does not select a key, provider, certificate, algorithm,
  purpose, endpoint or tenant.
- At most one token is generated for each slot in one invocation. The attempt set is itself capped at
  four. Different authorized slots may each be used once and always invoke the signer independently.
- The opaque token is host-constructible, bridge-owned and internally slot-bound. Core records the
  generated tokens and applies every projection during restricted transport. Required slots must all
  be present before certificate, DNS or network work. A historical request constructor carrying one
  opaque handle remains accepted only as a same-bridge proof; it cannot choose a projection.
- Signing and transport keep the ADR-0024 host-owned `ACTIVE -> CLOSING -> CLOSED` scope and the
  existing Published A freshness checks. A-to-B changes never authorize B; retained, cross-invocation
  and post-close handles are denied before network.
- Historical definitions containing `authorizedCapabilities.signing` and
  `restrictedTransport.authorization = signedTokenBearer` are not rewritten. Core derives one
  reserved internal `legacy` slot that is required and projects Authorization Bearer exactly as
  before. A definition containing both the historical profile and `signingSlots` is invalid.
- Slot keys, signing-policy objects, required flags and projections remain in canonical Connector
  JSON and therefore in its checksum, semantic review, checksum-specific distinct approval and
  immutable Published revision. Migration `0013_authorized_signing_slots.sql` extends only the
  operation-scoped signing-binding locator to the exact slot collection.

## Consequences

Two independently fresh JWTs may reuse the same approved signing identity while retaining different
server-owned issuer policies and projections. Token plaintext, private keys, provider handles,
certificate views, arbitrary claims, header bags and authenticated `HttpClient` access remain absent
from the external contract.

The feature is a Core authorization primitive, not a protocol implementation. Connector-specific
slot names, claims and semantics remain in a separately approved connector pack. Publication and
network dispatch are still not globally atomic; a change after bytes are dispatched cannot retract
them. The Gateway/provider process and local Administrator/SYSTEM remain residual privileged threats.

## Alternatives rejected

Multiple unrestricted signing calls, returning compact JWT strings, direct signing-provider access,
arbitrary authenticated headers, generic HTTP requests, one token reused in two headers, unbounded
slot collections and protocol-specific Core logic.

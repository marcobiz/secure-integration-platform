# ADR-0027: Authorized Published operation contract

**Status:** Accepted

## Context

ADR-0025 permits a neutral external execution strategy to request exact Published signing slots and
one restricted mTLS transport. The Published policies remain Core-owned, but a compiled connector
may require stricter semantic invariants: an exact two-slot set, fixed subject/audience/lifetime,
specific token projections and issuer rules, a shared signing identity that differs from mTLS, and a
bounded dynamic resource path. Without a preflight, a syntactically valid but semantically
incoherent Published operation could sign or dispatch before the module detects the mismatch.
Giving the module effective policy objects, provider/store access, a URI or an authenticated request
builder would instead broaden authority across the Core security freeze.

## Decision

- Every external strategy selected from an authoritative Published operation requires one
  startup-registered module-owned `IAuthorizedPublishedOperationExpectationProvider`. Registration
  is bounded, exact by strategy key and duplicate-rejecting. Absence or provider failure is a
  sanitized denial before strategy entry, signing and network. Built-in Core strategies retain their
  existing qualified paths.
- The provider receives only a non-constructible invocation context containing connector/version/
  operation/strategy identifiers, authentication kind and a defensive copy of open Published
  extension configuration. It receives no payload, stamp, endpoint, policy object, binding,
  provider, store, certificate, token, bridge or service locator.
- The provider returns immutable bounded generic expectations. Core alone resolves and compares the
  exact Published operation A: authentication kind; exact signing-slot set; required flags;
  RS256; Bearer/custom-header projections; fixed subject; audience; business-claim allowlist;
  lifetime; temporal mode; mandatory `jti`; x5c mode; exact issuer or fixed-prefix plus verified
  signing-certificate subject CN; equal signing identities; and signing identities distinct from
  the approved mTLS identity.
- Certificate relations use only Core-resolved, approved public material and compare cryptographic
  identity. Every asynchronous public-material lookup is followed by an exact-A revalidation. The
  expectation provider never sees certificate data. Preflight is an internal dispatcher/runtime
  operation and is not added to `IAuthorizedConnectorCapabilityBridge`.
- A new Published operation may replace static `path` with `pathTemplate`. Placeholders are unique,
  canonical and occupy an entire segment. The external request supplies only an exact bounded set of
  opaque name/value pairs. Core rejects missing, extra, duplicate, unknown, empty, non-NFC,
  oversized, control, delimiter, percent, traversal and injection values; applies one canonical
  encoding; and verifies that scheme, host and port are unchanged and query/fragment are absent.
- `authorizedCapabilities.restrictedTransport.bodyMode` is `required` or `none`. Absence maps to
  `required`. `none` is permitted only for GET/DELETE; Core sends null `HttpContent`, so the wire body
  is empty and no Content-Type is synthesized. Method, Content-Type and body mode remain Published.
- Preflight and path rendering retain the original immutable Published A stamp. Rereads may confirm A
  but never adopt B, including after certificate public-material resolution and DNS.
- Historical definitions are not rewritten or republished. Their canonical JSON and checksums are
  unchanged; static paths and the historical body request remain `required`. The new JSON members
  participate in checksum/four-eyes review only when present. No storage or locator shape changes,
  so no database migration is introduced.

## Consequences

A connector pack can state bounded semantic requirements without receiving effective policy or
authenticated transport authority. Core denies incoherence before private-key and network effects,
while still allowing an exact Published path segment projection and truly bodyless GET/DELETE.

The module and publisher remain trusted to state the intended protocol semantics; this contract
checks coherence, not external specifications. Public certificate metadata is temporarily processed
inside trusted Core. Publication and network dispatch are not globally atomic, and a mutation after
the first byte is sent cannot retract it. The Gateway/provider process and local
Administrator/SYSTEM remain residual privileged threats.

## Alternatives rejected

Connector-side policy inspection, returning certificates or compact tokens, arbitrary URI/template
expansion, query parameters, generic request/header builders, pre-encoded values, module-owned
Content-Type/method/body mode, optional preflight, public bridge validation methods, mass republish
and connector-specific Core policy code.

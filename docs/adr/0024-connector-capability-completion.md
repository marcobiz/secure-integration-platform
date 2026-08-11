# ADR-0024: Connector capability completion

**Status:** Accepted

## Context

ADR-0023 introduced a provider-neutral execution seam with two invocation-bound SOAP capabilities.
Qualification of two independent external connector packs then exposed two concrete Core gaps. A
compiled typed-session adapter could not be registered by an allowlisted module or receive an exact
provider-resolved value owned by the Published profile. A second strategy could not consume the
already-qualified RS256/X.509 and restricted mTLS primitives without receiving provider, store,
transport or service-locator authority.

Solving either gap inside a connector would require caller input, hard-coded credentials, direct
provider access, friend access or a parallel authorization path. A generic store, provider facade,
signing oracle or authenticated `HttpClient` would be broader than the demonstrated needs.

## Decision

- The existing registrar gains only three typed-adapter registrations: request, response and
  external-session validation. Implementations must be owned by the exact allowlisted module,
  implement the already-existing SOAP contracts, pass the existing constructor-graph validation
  and remain bounded. Duplicate implementations and wrong-module registrations fail startup.
- Request and validation adapters declare a bounded static set of required server-owned input
  names. The exact Published profile maps every name to one logical opaque secret binding. Missing,
  unexpected and duplicate mappings fail closed. Core resolves the provider locator and value;
  the adapter receives a non-constructible view that can only write a named value through the
  Core-owned XML writer. The writer is bound internally for only the exact synchronous adapter
  callback: the public write method accepts the name only, and a retained view is closed and cleared
  when that callback returns. It receives no string getter, provider reference or DI capability.
- `AuthorizedConnectorExecution` exposes a defensive, bounded copy of the current operation's
  `extensionConfiguration`. It contains no authority stamp, store access or mutation surface.
- The existing private invocation bridge gains one RS256 token creation operation and one
  restricted transport operation. Claims are scalar, bounded and checked against the exact
  Published signing allowlist. No algorithm, key, certificate, provider, purpose, endpoint, method,
  header or authorization selector is accepted.
- Every asynchronous bridge call registers synchronously in a per-invocation host scope before
  claim processing, provider access or network preparation. Scope close atomically prevents new
  calls, links caller/method/lifetime cancellation, cancels and drains every tracked task, and
  observes its failure before a strategy result can be accepted. Returning with an in-flight task is
  an external-strategy contract violation and becomes the existing sanitized non-retryable 502.
- Module-controlled claims are counted from actual enumeration and validated incrementally for
  name, scalar kind, per-value and aggregate bounds using fixed-capacity JSON measurement. A value
  is cloned only after its own checks pass; the bridge does not trust `Count` or call `GetRawText`.
- The signed result is non-constructible and exposes no compact token. It can only be supplied to a
  bounded transport request and is accepted only by the same live bridge. Core installs it as the
  server-owned bearer value for the exact Published endpoint and mTLS identity.
- The qualified signer composes `x5c` internally when the Published policy requires it. A separate
  public certificate view is therefore not required and is not added.
- Every policy, binding and transport revalidation rereads the current Published snapshot only to
  compare it with the immutable stamp captured for A. No reread can authorize B. The final mTLS
  binding check occurs after DNS and immediately before transport. Typed-session input resolution
  occurs before the existing final A comparison and network effect.
- PostgreSQL migration `0012_connector_capability_locator_scope.sql` extends the existing
  `SECURITY DEFINER` locator function only for signing bindings and typed-session server-owned input
  bindings declared by the exact granted Published operation. Installation/Tenant/Application,
  grant, binding checksum/revision, resource scope/revision and RLS controls remain mandatory.
- Capability and adapter failures use the existing host-owned error marker. Stale authority is 503,
  provider/transport/timeout failure is sanitized as 502, policy/configuration denial is 409, real
  caller cancellation is preserved, and external strategy exceptions remain untrusted.

## Consequences

An allowlisted external module can now implement the two demonstrated protocol shapes without
friend access and without provider, store or transport injection. Caller payload, metadata,
headers and extensions cannot select adapter, input value, signing identity, certificate, profile
or endpoint.

The public surface remains protocol-shaped and finite. There is no generic capability registry,
store facade, provider facade, raw signature API, arbitrary authenticated HTTP API, dynamic plugin
framework or new adapter category. Modules remain trusted in-process deployment components, not a
sandbox. No healthcare connector, commercial adapter or provider implementation is part of this
decision.

Capability closure cannot retract an effect that completed while the strategy was legitimately
active. It guarantees that once strategy completion begins, tracked work is prevented from
progressing toward a later effect; an early strategy success is rejected after cancellation/drain.

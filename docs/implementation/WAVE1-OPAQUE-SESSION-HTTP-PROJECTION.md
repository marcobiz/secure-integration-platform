# Wave 1 — opaque session HTTP projection

## Scope

This Wave 1 Core capability projects a Gateway-owned opaque authenticated session into one server-owned custom HTTP request header and performs one destination-bound restricted dispatch. It is provider- and industry-neutral. It does not implement a connector, OAuth, JWT/X.509 changes, or a new session foundation.

## Contract and placement kinds

`OpaqueSessionPlacementPolicy` is a closed typed contract with two kinds:

- `SoapXml`, represented by `SoapXmlOpaqueSessionPlacementPolicy` and used by every existing `SoapSessionProfile` without changing SOAP serialization;
- `HttpRequestHeader`, represented by `HttpRequestHeaderOpaqueSessionPlacementPolicy`, with only a validated field name and either `RawOpaqueValue` or `FixedSchemeAndOpaqueValue`.

There is no generic header bag, template, expression evaluator, script, callback, or public attach API.

## Server-owned policy

Connector-facing dispatch accepts only the authenticated `ConnectorAuthExecutionContext`, a logical policy ID, bounded business bytes and an optional opaque Gateway reference. `IOpaqueSessionHttpPolicySource` is the protected server-side composition seam. Its current snapshot must be derived from the Published ConnectorVersion, invoked operation, auth profile, `OperationBindingDependencies`, Environment and current binding/resource configuration. The sender verifies Connector/version, operation, profile, Environment, binding revision, endpoint revision and credential revision against authenticated server state on every resolution.

The policy snapshot owns the exact HTTPS destination, HTTP method, media type, custom header, optional fixed scheme, timeout and request/response bounds. None is accepted by `SendWithOpaqueSessionAsync`.

## Header safety and one-shot dispatch

Field names use the RFC HTTP token character set. CR/LF, whitespace and controls fail validation. The primitive denies `Authorization`, transport/hop-by-hop and security-owned fields including `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Cookie`, `Set-Cookie`, proxy authentication fields, `Forwarded`, `Via`, `Expect`, `Upgrade`, `TE`, `Trailer`, `X-Correlation-ID` and every `Proxy-*` field. The opaque value is also bounded and rejected if it contains CR, LF, NUL or controls.

`SendWithOpaqueSessionAsync` resolves the current policy and resource stamp, obtains a generation lease from the existing bounded cache, performs restricted DNS/IP validation, re-resolves policy and resource state, constructs the request internally, applies exactly one header immediately before `IRestrictedTransport.SendAsync`, and disposes the authenticated request. It returns only a bounded sanitized response.

## Destination, lifecycle and race protection

The existing session cache key now explicitly includes the invoked operation in addition to Tenant, Installation, Application, Environment, Connector/version, profile and binding/endpoint/credential revisions. A dispatch lease carries the internal generation and expiry without exposing the session value. Before header materialization the sender verifies that the lease is still the current generation.

Every security-sensitive await is followed by policy, resource-stamp or generation revalidation as applicable. A disable/rotate during the final policy await fails before header application and produces zero transport dispatches. Post-dispatch revalidation discards the response if the Published policy, resource stamp or generation changed while awaiting the bounded response.

## Synthetic qualification

`SyntheticOpaqueSessionServer` is a vendor-neutral HTTPS Kestrel endpoint with counters for valid, missing, wrong and duplicate headers plus delayed responses. Tests cover raw and fixed-scheme placement, forbidden/injected field names, operation/endpoint substitution, unknown and stale session references, expired session, credential disable/rotation, stale binding/endpoint revision, attacker destination, disable race, request/response bounds, diagnostic redaction and real TLS restricted dispatch. Existing SOAP unit and real-HTTPS tests remain the backward-compatibility gate.

No production connector or live external-system qualification is claimed by this capability.

## Local qualification

- Release build: PASS, zero warnings and zero errors.
- New targeted cases: 22 PASS (19 unit, 2 real-HTTPS integration, 1 architecture).
- Existing session/SOAP regression: 19 targeted cases are included alongside the new tests and remain PASS.
- Ordinary .NET suite: 283 total, 273 PASS and 10 PostgreSQL-conditional SKIP.
- PostgreSQL 18.4 isolated gate: 11/11 PASS after fresh migration and verified no-op second apply; container removed.
- Documentation validation, conservative secret scan, SBOM validation/generation, vulnerable-package scan and `git diff --check`: PASS.
- CI exact-head and a single independent review remain required before final GO.

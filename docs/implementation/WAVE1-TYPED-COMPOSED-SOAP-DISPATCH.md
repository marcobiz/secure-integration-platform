# Wave 1 — typed composed SOAP authenticated dispatch

## Scope

This Wave 1 Core capability composes server-owned HTTP Basic, typed SOAP HTTP metadata and one approved opaque-session custom HTTP header in one authority-bound invocation. It is provider- and industry-neutral. It does not implement a production connector, change session admission/handshake, introduce a generic header bag or add a second authorization mechanism.

## Authority model

The production chain is:

`GatewayClientPrincipal + granted Connector/operation` → current Published operation → exactly one server-selected authentication execution strategy → non-forgeable authorized execution handoff → current Published Connector snapshot → `ComposedSoapResolvedExecutionContext` → final Published/session revalidation → synchronous Basic/SOAP/session assembly → `IRestrictedTransport.SendSoapAsync`.

The inbound gateway caller supplies only its authenticated principal, logical Connector/operation and bounded payload. It cannot select an execution strategy, policy, session profile, endpoint, method, SOAP version, action, content type, credential/provider reference, header name/scheme or revision. The lower-level qualified clients remain capability APIs, while their production policy/session inputs are sourced exclusively from the Published operation and current server-owned session cache. Resolved and authorized contexts have no public constructors.

`RestrictedEgressService` selects strategies by the exact Published authentication kind only after installation scope, grant and Published operation validation. Missing or duplicate strategy registrations fail closed as `BGW-EGRESS-AUTHENTICATION`; there is no fallback to ordinary REST dispatch.

`PublishedComposedSoapAuthorityResolver` reuses `PublishedOpaqueSessionAuthorityResolver` with the closed `ComposedSoapBasic` profile kind. The shared resolver owns current Published/version/operation/binding/endpoint/session-placement/resource validation and its final revalidation closure. The SOAP resolver adds the two existing Basic logical bindings and typed SOAP metadata to the same security fingerprint.

## Typed SOAP HTTP metadata

`SoapHttpRequestMetadata` has no public constructor and contains only:

- `SoapEnvelopeVersion` (`Soap11` or `Soap12`);
- one absolute, bounded, control-free operation action URI.

It derives the wire policy:

- SOAP 1.1: `Content-Type: text/xml; charset=utf-8` plus exactly one quoted `SOAPAction` header;
- SOAP 1.2: `Content-Type: application/soap+xml; charset=utf-8; action="…"` and no `SOAPAction` header.

The same typed model now backs the pre-existing M6 SOAP header writer. The composed path validates the envelope namespace and a single Body payload before resolving credentials. Caller-provided content type or action overrides do not exist.

## Basic and opaque-session composition

Basic reuses the internal `ServerBoundBasicAuthentication` helper and internal `ResolvedBasicCredentialBinding`, using the existing username/password provider references resolved from the Published binding. Neither the helper, binding nor `ApplyAsync` is exported as a supported caller capability. The resolved provider identity, resource identifier, version, revision, checksum and active resource stamp remain exact dependencies of the authorized execution. Secret values are fetched only for the internal one-shot request; transient UTF-8/Base64 buffers are cleared and no Authorization value or mutable `HttpRequestMessage` escapes the runtime.

The session side reuses `OpaqueSessionLeaseProvider` exposed by the qualified SOAP lifecycle. The composed dispatcher receives `OpaqueSessionReference`, not a raw upstream session. Production execution obtains that reference from the server-owned cache for the Published session profile; it is never accepted from the gateway caller. Cache identity, generation, expiry, invalidation, resource stamp and final lease checks remain implemented by the existing session capability.

`Authorization` is exclusively Basic-owned. The custom placement denylist now also rejects `SOAPAction` and `Content-Type`, in addition to authorization, routing, hop-by-hop, cookie, forwarding, proxy, correlation and tracing fields. Placement is token-validated without trimming and values reject control characters. There is no arbitrary header object in schema or runtime.

## Final authorization and dispatch

The dispatcher performs XML copy/validation, request construction, DNS policy and Basic provider resolution before the last Published check. A deterministic test hook exists only before that check. After it returns, the dispatcher synchronously:

1. acquires the current opaque-session lease;
2. formats and applies exactly one approved custom header;
3. verifies Basic and typed SOAP metadata are present exactly once;
4. rechecks the session generation;
5. invokes `SendSoapAsync` immediately.

There is no await, caller callback or work-heavy operation in that final section. A second Published/session check after the network call discards a response made stale in flight. Disable, Basic resource rotation, session invalidation, endpoint/binding revision change and action-policy change before final dispatch therefore produce zero network requests.

## SOAP Fault preservation

The composed path calls `IRestrictedTransport.SendSoapAsync`, never generic `SendAsync`. The hardened transport therefore preserves an HTTP 500 response body. Real loopback HTTPS tests pass a valid SOAP 1.1 Fault to `SoapXmlBoundary.ParseResponse`, which produces the existing sanitized typed `SoapFaultException`; duplicate/ambiguous Fault structure remains denied as `SOAP-FAULT-STRUCTURE`.

## Published Connector configuration

Connector Definition v1 remains backward-compatible and adds two opt-in authentication kinds:

- `opaqueSessionHttp`: the already-qualified generic non-SOAP projection is now schema/catalog publishable;
- `soapBasicOpaqueSession`: the composed SOAP mode.

The composed public definition surface is:

```json
{
  "kind": "soapBasicOpaqueSession",
  "policyId": "composed-policy",
  "sessionProfileId": "opaque-session",
  "usernameBinding": "basic-username",
  "passwordBinding": "basic-password",
  "secretBinding": "session-resource",
  "headerName": "X-Session-Reference",
  "valueFormat": "rawOpaqueValue",
  "soapHttp": {
    "version": "1.1",
    "action": "urn:synthetic:business"
  }
}
```

`fixedScheme` is allowed only with `fixedSchemeAndOpaqueValue`. All values are server-owned Connector definition/profile configuration covered by canonical checksum, immutable Published version and four-eyes binding digest. Endpoint values and provider locators remain separate protected bindings and absent from the definition/export/runtime request. The action participates in the Connector checksum, shared authority fingerprint and composed fingerprint.

The production validator requires POST, the SOAP-version base content type, three distinct logical resources of the existing `username`/`password`/`opaque` kinds, a safe custom header and valid action. Unknown kinds, missing metadata, raw/fixed formatting mismatch and collisions fail closed. `PublishedConnectorCatalog` recognizes both capability-based kinds, and the production gateway routes them only through their exact authority-bound execution strategies.

Connector Definition v1 compatibility is preserved separately from the stricter authentication-placement policy. The historical `allowedClientHeaders` denylist remains unchanged for stored v1 definitions, so an already-valid definition containing `SOAPAction` still validates, loads, publishes and executes without rewrite or republish. New opaque-session or composed-SOAP placement of `SOAPAction` or `Content-Type` remains denied.

## Qualification matrix

Dedicated unit and real-HTTPS tests cover positive SOAP 1.1/1.2 composition, exact production strategy selection, missing/duplicate/wrong strategy denial before network, Basic/session/header cardinality, schema/catalog publication, action checksum, forbidden/colliding/control headers, missing bindings, wrong policy/method/content type/version/action, non-forgeable public surface, Basic/session/endpoint/revision/action races, SSRF, timeout, cancellation, redaction, wrong Basic at the intended TLS destination, HTTP 500 Fault preservation and malformed Fault denial.

The production integration fixture uses the real PostgreSQL configuration store, separate migration/admin/runtime roles, validation, distinct-editor four-eyes approval, atomic publication, the real Published catalog, `RestrictedEgressService`, the composed execution strategy and a pinned synthetic TLS SOAP endpoint. It does not use `MutableSnapshots`. Its denial matrix proves zero SOAP and generic network calls for invalid grant, disabled or rotated Basic resources, stale session, policy update, endpoint substitution, wrong action, wrong capability mode, SSRF and final-window rotation.

The synthetic SOAP server now exposes an optional neutral `/composed` endpoint. It validates Basic, `X-Session-Reference`, Content-Type/action semantics, SOAP version and the XML Body on a real loopback TLS socket. It records metadata-only counters and never persists credentials or sessions.

Current local targeted evidence on the implementation worktree:

- composed + SOAP/session + opaque-session + Connector configuration unit gate: 99/99 PASS;
- composed + existing SOAP/opaque real-HTTPS integration gate: 20/20 PASS;
- production PostgreSQL store → approval → publication → runtime → pinned-TLS SOAP gate: 11/11 PASS;
- architecture suite: 24/24 PASS.

Current broader local evidence:

- Release build: PASS with zero warnings and zero errors;
- ordinary .NET suite: 433 PASS, 23 PostgreSQL-conditional SKIP, zero failures (456 total); every conditional database scenario was then exercised by the dedicated database gate;
- PostgreSQL 18.4: 124/124 Gateway integration tests PASS with zero skips, including the 11/11 production composed-SOAP matrix, validation, distinct editor/approver four-eyes approval, publication and exact resource resolution;
- Admin schema consumer: lint, OpenAPI/runtime drift and negative control, 28/28 Vitest, production build and npm audit PASS;
- production-stack browser workflow: `FULLSTACK-01` PASS, redaction PASS and Docker resource cleanup PASS;
- documentation validation, conservative secret scan, NuGet/npm vulnerability checks, container-inclusive SPDX SBOM and `git diff --check`: PASS.

Core export and exact-head CI evidence must be recorded on the final candidate before independent review.

## Backward compatibility and exclusions

The new mode is opt-in. Existing `none`, Basic-only, API key, mTLS, API-key+mTLS, OAuth, SOAP session-in-envelope and generic opaque non-SOAP paths retain their contracts. Historical Connector Definition v1 `allowedClientHeaders` semantics are unchanged. The M6 SOAP cache key and multi-operation sharing behavior are unchanged.

No vertical connector, commercial adapter, cloud provider dependency, second Authorization header, arbitrary headers, retry/sleep, Hyper-V work, handshake/admission change, WS-Security, SAML, XML-DSig or production external-system claim is introduced.

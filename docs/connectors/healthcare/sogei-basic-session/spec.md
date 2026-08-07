# SOGEI Basic + session connector characterization

**Characterization status:** conditional shortlist, not implementation-ready.

## Purpose

Provide a managed profile for national human-prescription SOAP services that use pharmacy HTTP Basic credentials plus an out-of-band `ID-SESSIONE` second factor. The connector must keep credentials, session value, destination and SOAP operation profile outside the legacy client.

This profile does not cover the simpler veterinary SOGEI Basic-only service, regional SOGEI-compatible variants, or arbitrary SOAP proxying.

## Operations

| Operation | Purpose | Status |
|---|---|---|
| `begin-prescription-session` | Ask the fixed MFA SOAP service to initiate the out-of-band session process | **KNOWN** behavior; exact WSDL operation/SOAPAction **NEEDS CHARACTERIZATION** |
| `complete-prescription-session` | Accept a bounded Broker-owned local-MFA handoff and store an opaque session reference | Product handoff **INFERRED** from ADR-0015; exact artifact validation **NEEDS CHARACTERIZATION** |
| `view-dispensed-prescription` | First candidate business query, based on the supplied service reference | Business intent **KNOWN** at a high level; exact operation, request and response schema **UNKNOWN** |

No business operation may be published until its official WSDL/schema, action, authorization and idempotency are recorded.

## Allowed inbound parameters

- published connector ID and operation ID through the existing authenticated Broker/Gateway invocation;
- domain fields explicitly admitted by the operation schema once characterized;
- an opaque MFA attempt/session reference issued for the same tenant, installation, connector, environment and operator context;
- correlation and deadline metadata already permitted by the runtime contract.

The current sources do not define the domain request schema. Production payload admission is therefore **NO-GO**; synthetic fixtures are test oracles only.

## Server-owned parameters

The Connector/Binding fixes:

- national SSN versus non-SSN profile;
- MFA and business endpoint logical bindings;
- SOAP version, namespace, WSDL operation, SOAPAction, content type and XML limits;
- Basic credential binding;
- `Authorization2F` header name/format and session profile;
- timeout, response limit, TLS policy, retry/idempotency and redaction profile.

None may be overridden by caller headers, XML, query data or runtime metadata.

## Endpoint binding

At least two distinct server-side logical bindings are required: `session-service` and `prescription-service`. SSN and non-SSN services must remain separate profiles unless official documentation proves a safe common contract. Concrete URIs are environment bindings and never appear in a Connector definition, runtime request, export or audit.

The supplied PDF lists destinations but does not classify test versus production or define discovery/rotation. Binding publication remains blocked until environment ownership and TLS trust are established.

## Required secret and certificate resources

| Resource | Class | Requirement |
|---|---|---|
| `pharmacy-basic-credential` | Tenant/pharmacy secret | Server-side secret resource containing username/password with exact operation scope |
| Session artifact | Session secret | Stored behind an opaque reference with absolute expiry and context binding |
| Client certificate | None stated | No outbound client certificate is introduced by this profile |

## Outbound authentication

1. Apply HTTP Basic from the approved secret resource.
2. For business operations, resolve the opaque session reference and apply the fixed `Authorization2F` profile.
3. Send only to the approved SOAP binding over validated TLS.

The legacy application never receives Basic material or a reusable session value.

## Session/token lifecycle

- **KNOWN:** the documented `ID-SESSIONE` is received out of band and valid for 16 hours.
- **INFERRED:** the Broker performs a typed local-MFA handoff and the session is stored by the component that applies subsequent authentication.
- **UNKNOWN:** issuance response semantics, activation delay, concurrent-session rules, early invalidation, renewal, clock skew and logout.
- Expiry, publication/binding change, explicit invalidation or tenant/installation mismatch fail closed.

No automatic renewal or reuse beyond the documented absolute lifetime is allowed without authoritative evidence.

## Request mapping

- Domain input is mapped by a compiled, versioned operation handler to the characterized SOAP body.
- Authentication headers are added after XML validation and are not accepted from caller XML.
- DTD and external entities are prohibited; depth, node, attribute and byte limits are mandatory.
- The exact envelope namespace, body element order, SOAPAction and encoding are **NEEDS CHARACTERIZATION**.

## Response mapping

- Validate status, content type, size and XML parser limits before mapping.
- Return a typed domain result or sanitized status, not credentials, session values, raw security headers or unrestricted XML.
- The exact response schema and optional fields are **UNKNOWN**.

## Error mapping

| Upstream condition | Connector category | Client-visible behavior |
|---|---|---|
| Basic credential rejected | `upstream_authentication_failed` | Sanitized failure; do not reveal username/provider detail |
| Session missing/expired/rejected | `mfa_session_required` or `mfa_session_expired` | Prompt a new typed MFA attempt; never echo session |
| SOAP Client/validation fault | `request_rejected` | Stable mapped code after official fault characterization |
| SOAP Server/transient fault | `upstream_unavailable` | Stable mapped code; retry only if separately authorized |
| Malformed/oversize/unsafe XML | `upstream_protocol_invalid` | Fail closed and record metadata-only security event |

Fault codes, namespaces and retry classification remain **NEEDS CHARACTERIZATION**. Synthetic faults do not establish production mappings.

## Retry and idempotency

- Never retry session initiation or MFA completion automatically.
- Default business-operation retry count is zero.
- A query may receive bounded transient retry only after official documentation confirms idempotency and safe replay semantics.
- SOAP faults and HTTP 4xx are not transient by default.

## Timeout and limits

Production timeout, rate limit and maximum response size are **UNKNOWN**. Synthetic characterization uses a 30-second upper bound and repository-standard bounded XML handling only as a test setting, not a production default.

## Redaction

Always redact Basic authorization, session/MFA artifact, SOAP security headers, patient/operator/pharmacy identifiers, raw request/response, endpoint URI, provider reference, fault detail and stack trace. Structured errors must not include captured upstream XML.

## Audit

Allow only connector/version/operation, environment ID, tenant/installation/application derived server-side, correlation ID, attempt/session opaque ID, outcome category, upstream duration, retry count and response-size class. Clinical payload and authentication artifacts are excluded.

## Provenance

- Provided documentation: `SRC-PDF` §1.2, pages 4-5.
- Architectural inference: ADR-0015 local-MFA hybrid handoff and ADR-0010 server-owned binding.
- Synthetic vectors: `tests/characterization/healthcare/sogei-basic-session`.
- No official WSDL or captured traffic was used.

See [../../provenance.md](../provenance.md) for the exact source register and anomalies.

## Execution location

**HYBRID.** Gateway owns Basic credential, endpoint, SOAP transport and session application. Broker owns the trusted local interaction that accepts the out-of-band MFA artifact. Only a typed opaque handoff crosses the boundary.

## Security constraints

- no generic SOAP proxy, caller-selected action, header or destination;
- no `GetSecret` or session-value return path;
- session reference bound to tenant/installation/application/operator/connector/environment;
- authorization and grant checked before session, provider, DNS or transport access;
- fail closed on stale publication/binding/resource revision;
- TLS hostname validation, SSRF/DNS-rebinding defenses and redirect denial remain mandatory;
- parser and response bounds precede mapping and logging.

## Unresolved questions and GO gate

1. Which current official WSDL/schema and SOAP version apply to each target operation?
2. What are the exact SOAPAction, namespaces, content types and `Authorization2F` syntax?
3. How is session initiation acknowledged, and how is the emailed session bound to pharmacy/operator/request?
4. Are 16 hours absolute, and what are renewal, revocation, overlap and concurrent-session rules?
5. What are the authoritative faults, idempotency, retry, timeout, rate and maintenance policies?
6. Which patient/operator fields are required and how are they authorized and minimized?
7. Which endpoints and CA/trust profiles represent test and production?

**Writer decision:** GO for synthetic SOAP/Basic/session primitives; NO-GO for production SOGEI connector implementation until questions 1-7 are resolved.

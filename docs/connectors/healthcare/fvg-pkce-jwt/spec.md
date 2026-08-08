# Friuli Venezia Giulia PKCE + JWT connector characterization

**Characterization status:** conditional Wave 2 candidate, not implementation-ready.

## Purpose

Characterize a candidate FVG FSE pharmacy profile using local browser authorization, OAuth 2 Authorization Code + PKCE, server-owned token exchange, an access token and ID token, and an RS256 JWT applied to a fixed REST request. The concrete authority profile remains `NEEDS PUBLIC SOURCE`.

This is not a generic FSE connector and does not claim coverage of FVG prescriptions; delegation and scope require current official evidence.

## Operations

| Operation | Purpose | Status |
|---|---|---|
| `begin-fse-authorization` | Generate state and S256 PKCE material and return approved browser URI plus opaque attempt reference | OAuth/PKCE **KNOWN**; exact parameters **NEEDS CHARACTERIZATION** |
| `complete-fse-authorization` | Exchange the one-time code/verifier and create an opaque token session | **KNOWN** high-level behavior |
| `query-fse-prescriptions` | Perform the documented REST GET with access token, ID token and signed JWT headers | **KNOWN** high-level behavior; path/query/response schema **UNKNOWN** |
| `invalidate-fse-session` | Locally revoke the opaque session and prevent further use | Product security requirement; upstream logout/revocation **UNKNOWN** |

## Allowed inbound parameters

- bounded callback result tied to an opaque authorization attempt;
- domain query fields admitted by an authoritative FSE operation schema;
- opaque token-session reference;
- correlation/deadline metadata from the authenticated runtime.

The caller cannot provide client ID, redirect URI, scope, state, verifier/challenge, token endpoint, signing key/certificate, JWT header/claims, token values, resource endpoint or special header names.

## Server-owned parameters

The Connector/Binding fixes authorization/token/resource endpoints, client ID, redirect URI, scope, PKCE method, state/nonce policy, token validation, signing profile, issuer/audience/claims/lifetime, header names, REST path/query mapping, timeout, TLS, error and redaction policy.

## Endpoint binding

Use distinct logical bindings: `authorization-endpoint`, `token-endpoint`, and `fse-resource-api`. No concrete URL may be published until an official source establishes registered redirect URI ownership, environment taxonomy and authorization/token/resource trust boundaries.

## Required secret and certificate resources

| Resource | Class | Requirement |
|---|---|---|
| `fvg-oauth-client` | Vendor metadata/secret as applicable | Source states software-house client ID; presence and form of client authentication **NEEDS CHARACTERIZATION** |
| `fvg-jwt-signing-key` | Signing capability | Software-house RS256 key/certificate with fixed purpose and provider-managed use |
| OAuth token session | Session secret | Access token, ID token and any refresh state remain server-side |
| mTLS certificate | None stated | Do not introduce mTLS into this profile without evidence |

## Outbound authentication

1. Generate state and S256 verifier/challenge server-side for the exact profile.
2. Bind browser callback and authorization code to one attempt and registered redirect.
3. Exchange code with the fixed token endpoint; validate issuer/audience/signature/nonce for returned identity material according to the confirmed profile.
4. Generate the FVG-specific RS256 JWT using only policy-bound server-derived claims.
5. Apply access token as bearer, ID token in `ID-TOKEN`, and signed JWT in `JWT-SIGNATURE` to the fixed API request.

The raw token set, verifier and compact signed JWT are never returned to the legacy application.

## Session/token lifecycle

- **NEEDS PUBLIC SOURCE:** access-token and ID-token lifetime.
- **UNKNOWN:** refresh token presence, refresh rotation, early revocation, logout, ID-token use rules, clock skew and session concurrency.
- State, code and verifier are one-time and short-lived.
- Gateway invalidates on expiry, binding/publication/key revision, operator/tenant mismatch or explicit local invalidation.
- No refresh is implemented until authoritative documentation permits it.

## Request mapping

- The REST method is documented as GET, but exact query fields, required patient/operator/pharmacy claims and encoding are **UNKNOWN**.
- The connector constructs every authentication header and JWT claim.
- Domain parameters are allowlisted and cannot override headers, subject identity, destination, scope or signing inputs.
- Sensitive values must not be placed in a URL unless the official API requires them and the threat review explicitly accepts the exposure; current production mapping is blocked.

## Response mapping

Validate HTTP status, media type and response size, then map only the characterized FSE fields to a typed result. Tokens, signed material, raw identity claims, upstream headers and unapproved clinical data are excluded.

## Error mapping

| Condition | Connector category |
|---|---|
| State/PKCE/callback mismatch or code replay | `authorization_integrity_failed` |
| Token endpoint rejects code/client/scope | `token_exchange_rejected` |
| Token/ID token invalid, expired or wrong issuer/audience | `token_validation_failed` |
| Signing profile/key/purpose failure | `signing_unavailable` |
| FSE authentication/authorization denial | `upstream_access_denied` |
| Throttle/transient service failure | `upstream_throttled` / `upstream_unavailable` |
| Malformed/oversize/unexpected JSON | `upstream_protocol_invalid` |

Upstream codes and response bodies are **NEEDS CHARACTERIZATION** and never echoed.

## Retry rules

- Never retry authorization completion or code exchange automatically.
- No default refresh retry because refresh behavior is unknown.
- Signing may be repeated only before any dispatch and with the same bounded request intent; every dispatched attempt needs a unique policy-compliant `jti` when required.
- Resource GET may receive bounded transient retry only after official idempotency and token/JWT replay semantics are confirmed; default zero.

## Timeout

Authorization-attempt, token endpoint and resource timeouts are **UNKNOWN**. Synthetic tests use bounded short attempts and a 30-second transport ceiling only as test configuration.

## Redaction

Redact callback query, code, state, verifier/challenge correlation, client authentication, token set, compact JWT, JWT/ID-token claims, signing key/certificate reference, authorization URI, resource query, clinical data, endpoints and raw upstream errors.

## Audit

Record derived execution context, connector/version/operation, opaque attempt/session ID, authorization/token/signing stage, signing key version (not reference), expiry class, status category, duration, retry count and correlation ID. Do not record tokens, claims, subject identifiers or query/payload.

## Provenance

- Current official OAuth metadata, claim profile and API documentation are not recorded; this remains a characterization candidate.
- Synthetic vectors: `tests/characterization/healthcare/fvg-pkce-jwt`.
- Execution inference: server-owned token/API processing and ADR-0019 separate signing capability; browser presentation does not imply a Broker dependency.
- No official OAuth metadata, JWKS, claim profile or packet capture was used.

See [the provenance register](../provenance.md).

## Execution location

| Dimension | Characterization |
|---|---|
| User interaction | Local/direct browser interaction |
| Secret/certificate custody | Gateway token custody; signing key at Gateway only if central/provider-side custody is permitted |
| Token/session exchange | Gateway performs authorization-code/token exchange |
| Healthcare API execution | Gateway invokes the REST API |
| Mandatory local capability/hardware | None demonstrated |

**GATEWAY, conditional** on central/provider-side signing-key custody. If authoritative evidence later requires a local non-exportable signing key, reclassify the connector as **HYBRID** and approve a separate local-signature design.

## Security constraints

- S256 only; `plain` PKCE and caller-supplied verifier/challenge are rejected;
- authorization attempt bound to installation/application/operator/tenant/environment and exact redirect URI;
- ID token is validated, not treated as an opaque authorization oracle;
- fixed `alg=RS256`; no algorithm negotiation or caller-defined claims;
- access token, ID token and signed JWT are distinct typed artifacts and cannot be swapped;
- signing key use is exact-purpose and operation-scoped;
- all provider/key/token checks occur before resource DNS/transport;
- no generic OAuth client, browser callback forwarder, token vending or signing oracle is exposed.

## Unresolved questions and GO gate

1. What authorization-server metadata, registered redirects, scopes, client-auth method and PKCE parameters are current?
2. Are state and nonce required, and how is regional user identity bound to pharmacy/operator authorization?
3. Are access and ID token lifetimes really 16 hours; is refresh supported; what are revocation/logout rules?
4. What signature/claims/header profile is required for the additional JWT, including issuer, audience, subject, `jti`, `iat/nbf/exp`, `kid/x5c` and request binding?
5. What exact REST query schema, response schema, error taxonomy, timeout, throttle and idempotency policy apply?
6. May the software-house signing key be held by the approved Gateway provider, and what are onboarding/rotation/revocation rules?
7. Which endpoints and trust anchors represent test and production?

**Writer decision:** GO for synthetic PKCE, token-session and policy-bound RS256 primitives; NO-GO for production FVG connector implementation until questions 1-7 are resolved.

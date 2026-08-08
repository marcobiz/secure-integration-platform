# Lombardia OAuth helper connector characterization

**Characterization status:** conditional shortlist with a source-profile conflict; not implementation-ready.

## Purpose

Provide a Lombardia prescription/FSE authentication family in which a desktop/browser user authorization produces an authorization code and Gateway performs confidential token exchange, token lifecycle and bearer-protected service calls. The regional helper protocol is a fixed profile, not a generic browser or URL proxy.

## Operations

| Operation | Purpose | Status |
|---|---|---|
| `begin-user-authorization` | Create a helper authorization session and return only an approved browser URI plus opaque attempt reference | Behavior **KNOWN**; helper contract **NEEDS CHARACTERIZATION** |
| `poll-user-authorization` | Check the fixed helper result without exposing helper session credentials | Behavior **KNOWN**; polling interval/error model **UNKNOWN** |
| `complete-user-authorization` | Exchange one-time authorization code for an opaque token-session reference | **KNOWN** Authorization Code behavior |
| `query-prescriptions` | Invoke the fixed prescription API using the prescription token profile | High-level operation **KNOWN**; request/response contract **UNKNOWN** |
| `query-fse` | Invoke the fixed FSE API using its own scope/session profile | High-level operation **KNOWN**; request/response contract **UNKNOWN** |

## Allowed inbound parameters

- operation-specific domain request conforming to a future approved schema;
- opaque authorization-attempt/token-session reference;
- bounded browser callback/result data tied to that attempt;
- correlation/deadline metadata from the authenticated runtime.

The caller may not provide helper URL, authorization/token/resource URI, redirect URI, client ID/secret, scope, process authorization parameter, helper password/header, bearer token or refresh token.

## Server-owned parameters

The published profile fixes all logical endpoints, client authentication, redirect URI, grant, scope/process parameter, helper header name, polling policy, refresh window, bearer header, token skew, timeout and resource operation mapping.

Prescription and FSE profiles are distinct even when they reuse a client credential.

## Endpoint binding

Separate logical bindings are required for `desktop-helper`, `authorization-server`, `token-endpoint`, `prescription-api` and `fse-api`. Redirect/callback ownership and whether the helper is local, regional or vendor-hosted are **NEEDS CHARACTERIZATION**. All concrete bindings remain server-side and redirect following is denied except for the explicitly modeled browser navigation.

## Required secret and certificate resources

| Resource | Class | Requirement |
|---|---|---|
| `software-house-oauth-client` | Vendor secret | Client ID metadata plus client secret value at Gateway, scoped to the exact profile |
| Helper attempt credential | Session secret | Opaque helper session/password stored only for the authorization attempt |
| Access/refresh/ID tokens | Session secret | Server-side token session, never returned to legacy |
| Client certificate | None stated by primary source | Do not add one without profile evidence |

## Outbound authentication

1. Start the fixed helper/authorization profile using server-owned client metadata.
2. Bind browser completion to generated state and opaque attempt.
3. Exchange code at the fixed token endpoint using the documented client-auth profile.
4. Cache token set server-side and apply the access token as bearer to the fixed resource API.

The candidate profile assumes HTTP Basic client authentication with `grant_type=authorization_code`. No public official profile is currently recorded, and no alternate `client_credentials` layer is part of this specification. The connector must not combine or auto-negotiate unconfirmed flows.

## Session/token lifecycle

- **KNOWN:** typical access token lifetime is 30 minutes.
- **NEEDS PUBLIC SOURCE:** access/refresh lifetimes and any difference between prescription and FSE authorization windows.
- **UNKNOWN:** exact meaning of those windows, refresh-token rotation, reuse detection, clock skew, revocation and logout.
- Token refresh is single-flight and profile-scoped; failure invalidates the session without stale-token fallback.
- Authorization code and helper completion are one-time.

## Request mapping

- Helper/session/result fields are parsed into a typed internal state and are never passed through generically.
- Prescription/FSE domain input is mapped only after authoritative API/WSDL/schema characterization.
- SOAP versus REST differences stay in operation handlers; authentication reuse does not make resource mappings interchangeable.

## Response mapping

- Resource responses are size/content-type validated and mapped to typed results.
- Helper, token and business responses are parsed using separate bounded profiles and cannot be substituted for one another.
- Tokens, helper credentials, raw identity attributes and unapproved clinical fields are excluded from the client-visible result.

## Error mapping

| Condition | Connector category |
|---|---|
| Helper pending | `authorization_pending` |
| Helper/browser canceled or expired | `authorization_not_completed` |
| State/callback/attempt mismatch or code replay | `authorization_integrity_failed` |
| OAuth invalid client/grant/scope | `token_exchange_rejected` |
| Access token expired and refresh unavailable/rejected | `authorization_required` |
| 429 or transient upstream failure | `upstream_throttled` / `upstream_unavailable` |
| Malformed helper/token/resource response | `upstream_protocol_invalid` |

Exact upstream payloads and error-code mapping are **NEEDS CHARACTERIZATION** and must remain redacted.

## Retry rules

- No automatic retry for helper creation, authorization completion or authorization-code exchange.
- Helper polling uses a server-fixed interval, deadline and maximum count once documented; caller cannot busy-loop it.
- Refresh may retry only a transport failure proven not to have consumed/rotated the refresh token; default is no retry.
- Resource retry is zero until operation idempotency is confirmed.

## Timeout

Helper attempt lifetime, poll timeout and resource timeout are **UNKNOWN**. Synthetic tests use bounded attempts and the repository 30-second transport ceiling as test configuration only.

## Redaction

Redact helper session/password, callback query, state, code, verifier if added, client secret, token set, authorization headers, user identity detail, resource payload, endpoint and raw error response. Browser URIs must not be logged because they may contain sensitive query material.

## Audit

Record connector/profile/operation, opaque attempt/session ID, derived tenant/installation/application, authorization stage, outcome, expiry class, refresh outcome, upstream duration and correlation ID. Do not audit token claims, codes, helper credentials, identity documents or clinical payload.

## Provenance

- Current official authorization metadata and profile documentation are not recorded; this remains a characterization candidate.
- Synthetic vectors: `tests/characterization/healthcare/lombardia-oauth-helper`.
- Architectural inference: server-owned token/resource processing; browser/helper presentation does not imply a Broker dependency.

See [../../provenance.md](../provenance.md).

## Execution location

| Dimension | Characterization |
|---|---|
| User interaction | Local/direct browser interaction |
| Secret/certificate custody | Gateway owns the confidential client credential and token session; no client certificate is stated |
| Token/session exchange | Gateway performs authorization/token exchange where the confirmed flow permits it; helper/callback coordination is **NEEDS CHARACTERIZATION** |
| Healthcare API execution | Gateway invokes the prescription/FSE API |
| Mandatory local capability/hardware | None demonstrated |

**GATEWAY.** Helper hosting, callback ownership and browser coordination remain production blockers, but they do not establish a Broker dependency.

## Security constraints

- state, attempt and callback binding are mandatory product security requirements;
- PKCE is not assumed for Lombardia until confirmed;
- no generic browser navigation, callback listener, polling URL or redirect URI supplied by the caller;
- token/session is bound to tenant, connector profile, subject and environment;
- identity/pharmacy/operator values are validated server-side and not accepted as authority from domain payload;
- authorization occurs before helper/provider/DNS/transport side effects;
- no token or helper credential is exposed to browser storage or legacy configuration.

## Unresolved questions and GO gate

1. Is the current profile Authorization Code through the documented helper, a separate `client_credentials` layer plus CRS session, or both as distinct products?
2. Who hosts/trusts the helper, and how are session/password/header, polling and callback protected?
3. Are state, nonce and PKCE required, and what are the registered redirect URIs?
4. What exactly do the 72-hour and 8-hour refresh windows mean?
5. What are scope, subject, user/pharmacy binding, revocation, logout and refresh-rotation rules?
6. What are the current prescription SOAP/API and FSE REST schemas, errors and idempotency rules?
7. What test/production endpoints, TLS trust and onboarding apply?

**Writer decision:** GO for generic synthetic Authorization Code/token-cache/bearer primitives; NO-GO for a production Lombardia profile until the conflict and questions 1-7 are resolved.

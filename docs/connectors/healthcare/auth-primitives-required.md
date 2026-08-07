# Authentication primitives required by the first healthcare connectors

## Scope

This is a requirements handoff for the future `auth-http` and `auth-soap` writers. It does not modify shared contracts and does not authorize a production authentication module. Only primitives required by the four shortlisted connectors are included.

All APIs below are conceptual minimums. Concrete names and packaging may change during the authorized implementation milestone, but the security properties may not be weakened.

## Delivery classification

This classification follows the actual connector waves in [M6-IMPLEMENTATION-PLAN.md](M6-IMPLEMENTATION-PLAN.md). It authorizes only synthetic primitive work after a separate implementation authorization; it does not make a production connector ready.

### REQUIRED NOW - Wave 1 synthetic contracts

- AP-01 server-side HTTP Basic;
- AP-02 opaque session reference plus transport-neutral interactive challenge/completion where the SOGEI profile requires user input;
- AP-03 Authorization Code attempt/completion baseline for Lombardia, without assuming PKCE;
- AP-04 bearer application, token cache, refresh or explicit reacquisition according to the confirmed profile;
- AP-07 secure SOAP/XML boundary.

### REQUIRED BY WAVE 2

- AP-03 S256 PKCE extension for FVG;
- AP-05 policy-bound RS256 JWT signing through a certificate/key-operation abstraction;
- AP-06 purpose-bound mTLS client authentication;
- explicit certificate/key purpose separation for FVG signing and Umbria signing versus mTLS.

Implementation state (2026-08-07): AP-05 and AP-06 have a synthetic, provider-neutral
Core implementation on `m6/auth-cert-signing`. This is primitive evidence only. It does
not confirm FVG/Umbria claims, lifecycle, endpoint, custody or production readiness.
The AP-03 PKCE extension belongs to the independent HTTP/OAuth track and is not part of
the certificate/signing boundary. PR #11 remediation makes the JWT policy entirely
server-owned and mTLS transport-bound through a non-constructible one-use certificate
lease; no Connector receives a raw profile or certificate handle.

### DEFER

- generic SAML and generic WS-Security frameworks;
- universal HMAC, universal identity and generic XML-DSig frameworks;
- smart-card and VPN integration frameworks.

These deferred capabilities appear elsewhere in the inventory but are not required by the four selected connector profiles.

## Common execution context

Every primitive receives an immutable server-derived context containing:

- tenant, installation, application, environment, published connector version and operation;
- logical endpoint, secret and certificate binding names resolved from the approved publication;
- correlation/trace identifiers, deadline and redaction policy;
- authenticated operator/session reference when the operation requires it.

The runtime caller may supply domain payload and an opaque one-time handoff reference only. It cannot supply URI, tenant, client ID, credential value/reference, certificate reference, scope, audience, issuer, signing algorithm, header name or execution location.

## AP-01 - Server-bound HTTP Basic

**Used by:** `sogei-basic-session`; token endpoint of `lombardia-oauth-helper` if the documented profile is confirmed.

**Minimal API**

```text
ApplyBasicAuthorization(context, request, credentialBinding) -> authenticatedRequest
```

| Aspect | Requirement |
|---|---|
| Input | Approved outbound request plus logical credential binding; username/password values are never caller input |
| Output | Request with exactly one HTTP Basic authorization header, unavailable to logs, errors or connector response |
| Capability | Secret-value retrieval scoped to the exact published operation |
| Caching | No plaintext cache beyond the request lifetime; provider cache may hold opaque/versioned provider state only |
| Refresh | Credential rotation is a binding/provider revision change and invalidates runtime cache; no fallback to old unapproved value |
| Redaction | Remove authorization headers, provider references and encoded credential material from audit, traces and Problem Details |
| Failure | Missing/disabled/wrong-scope resource fails before DNS/transport; provider failure is not mapped to upstream credential denial |
| Vectors | SOGEI synthetic request metadata and missing-credential negative; Lombardia token exchange vector after profile confirmation |

## AP-02 - Transport-neutral interactive challenge and opaque session

**Used by:** `sogei-basic-session`.

**Minimal API**

```text
RequestInteractiveChallenge(context, profile) -> { opaqueInteractionRef, opaqueChallenge, expiresAt }
CompleteInteractiveChallenge(context, opaqueInteractionRef, userProvidedArtifact) -> opaqueSessionRef
ResolveSessionForOutbound(context, opaqueSessionRef) -> in-memory session artifact
InvalidateSession(context, opaqueSessionRef, reason) -> void
```

| Aspect | Requirement |
|---|---|
| Input | One-time opaque interaction reference plus only the bounded artifact the user must actually provide; no generic token/header field in runtime invocation |
| Output | Opaque challenge/reference plus expiry for presentation, then an opaque session reference after completion; raw session value is visible only to the component applying the outbound header |
| Capability | Session-secret storage scoped to tenant/installation/connector/profile; no `GetSecret` API exposed to legacy, Broker callers or Admin UI |
| Caching | Interaction has a bounded profile-defined expiry and single completion; resulting session uses its profile expiry (16 hours for the documented SOGEI vector); no use after expiry or publication/binding change |
| Refresh | No silent refresh is assumed. A new explicit interaction/reacquisition is required unless an authoritative profile states otherwise |
| Redaction | Challenge, completion artifact and session value are always sensitive; only opaque interaction/session IDs, state and timestamps may be audited |
| Failure | Unknown, replayed, cross-tenant, wrong-connector, expired, already-completed or invalidated reference fails closed before outbound dispatch |
| Vectors | Accepted session metadata, expired session and SOAP session fault under `sogei-basic-session` |

The interaction reference correlates request, completion, expiry and single use. Replay semantics are enforced where the characterized upstream profile supports them. Presentation may be performed by a direct application, browser, Broker or another trusted UX adapter; AP-02 and the connector do not depend on any one frontend. The artifact format is profile-specific and tightly bounded, and the API must not become a generic caller-controlled header injector or a general interactive-auth framework.

## AP-03 - Browser authorization and one-time code handoff

**Used by:** `lombardia-oauth-helper` and `fvg-pkce-jwt`.

**Minimal API**

```text
BeginAuthorization(context, profile) -> { opaqueAttemptRef, authorizationUri }
CompleteAuthorization(context, opaqueAttemptRef, callbackData) -> opaqueTokenSessionRef
PollAuthorization(context, opaqueAttemptRef) -> pending | complete | failed
```

| Aspect | Requirement |
|---|---|
| Input | Server-bound authorization profile; bounded callback containing code/state or a profile-specific helper result |
| Output | Browser URI with server-generated state and, when required, S256 challenge; final output is an opaque token-session reference |
| Capability | Secret retrieval for confidential-client authentication; session storage for state, verifier, nonce and one-time code use |
| Caching | Authorization attempts have short absolute expiry and one-time completion; token caching is AP-04 |
| Refresh | Not applicable to the authorization attempt |
| Redaction | Authorization code, state secret, verifier, helper password and callback query are never logged |
| Failure | State mismatch, code reuse, callback mismatch, expired attempt, helper credential mismatch and cross-context completion fail before token use |
| Vectors | Lombardia helper pending/completed/error vectors; FVG S256 verifier/challenge and OAuth error vectors |

Lombardia helper polling is a connector profile over this primitive. Its special header and returned redirect URI are fixed by server-side profile and may not be caller-selected.

## AP-04 - OAuth token exchange, cache and bearer application

**Used by:** `lombardia-oauth-helper` and `fvg-pkce-jwt`.

**Minimal API**

```text
ExchangeAuthorizationCode(context, attempt, code, verifier?) -> opaqueTokenSessionRef
GetValidAccessSession(context, opaqueTokenSessionRef) -> in-memory token set
RefreshAccessSession(context, opaqueTokenSessionRef) -> opaqueTokenSessionRef
ApplyBearer(context, request, opaqueTokenSessionRef) -> authenticatedRequest
RevokeOrInvalidate(context, opaqueTokenSessionRef, reason) -> void
```

| Aspect | Requirement |
|---|---|
| Input | Server-bound token endpoint, client-auth profile, redirect URI, scope and optional PKCE verifier from AP-03 state |
| Output | Opaque session reference and request with bearer header; access, refresh and ID tokens are never returned to legacy code |
| Capability | Secret retrieval for client authentication and session-secret storage for tokens |
| Caching | Per tenant/connector/profile/subject session; expiry uses server response minus bounded skew; refresh is single-flight |
| Refresh | Only if the confirmed profile permits it. Rotation replaces the old token atomically; failed refresh never falls back to an expired token |
| Redaction | Token endpoint body, tokens, codes and authorization headers are fully redacted; only grant profile, expiry and outcome are audit metadata |
| Failure | Invalid client/grant/scope, expiry, refresh rejection, 429 and upstream 5xx have distinct internal failure classes and sanitized external errors |
| Vectors | Synthetic token responses, expiry and OAuth errors for Lombardia/FVG |

The Lombardia 72-hour/8-hour figures are authorization windows described by the source, not defaults. The FVG 16-hour token statement also requires official confirmation before production configuration.

## AP-05 - Policy-bound RS256 JWT signing

**Used by:** `fvg-pkce-jwt` and `umbria-mtls-jwt`.

**Minimal API**

```text
CreateSignedJwt(context, signingProfile, boundClaims, payloadDigest?) -> compactJwt
```

| Aspect | Requirement |
|---|---|
| Input | Named immutable signing profile plus server-derived claim values and, only when specified, an approved payload digest |
| Output | Compact JWS passed directly to the configured outbound header; never returned as a reusable client value |
| Capability | Signing/key-use capability, not secret retrieval; key reference and algorithm are fixed by binding/profile |
| Caching | Public certificate metadata and provider handle may be cached by version; private key bytes never enter application memory when provider supports key-use operations |
| Refresh | Key/certificate rotation is versioned with overlap only if the authority profile explicitly permits it |
| Redaction | Compact JWT and all identity/patient claims are sensitive. Audit only profile ID, key version, algorithm, `jti` digest and outcome |
| Failure | Reject algorithm override, unapproved claims, missing bound identity, invalid lifetime, duplicate/replayed `jti`, wrong key purpose and provider failure |
| Vectors | Synthetic claim sets only; tests generate ephemeral keys per run. No committed compact JWT or private key |

At minimum, profiles must fix `alg=RS256`, issuer, audience, subject/role binding, maximum lifetime, allowed clock skew, `jti` uniqueness, header set and certificate-chain representation. All are **NEEDS CHARACTERIZATION** for the current candidates.

## AP-06 - Purpose-bound mTLS client authentication

**Used by:** `umbria-mtls-jwt`.

**Minimal API**

```text
CreateMutualTlsChannel(context, endpointBinding, certificateBinding, tlsPolicy) -> restrictedHttpChannel
```

| Aspect | Requirement |
|---|---|
| Input | Approved logical endpoint, certificate binding and TLS policy from the published connector |
| Output | Restricted HTTP channel bound to the selected client-certificate version and pinned DNS/egress decision |
| Capability | Client-certificate retrieval/use capability separate from JWT signing |
| Caching | Handler/channel reuse may be keyed by tenant/environment/endpoint/certificate version; retirement or binding change invalidates immediately |
| Refresh | Certificate renewal is provider/binding revision with explicit overlap policy; never silently choose a different certificate |
| Redaction | No PFX, private key, password, chain dump or provider reference in logs/errors |
| Failure | Wrong EKU/purpose, missing private-key use, expired/not-yet-valid/revoked certificate, untrusted server, hostname mismatch and provider failure fail closed |
| Vectors | Synthetic public metadata for distinct auth/signing certificates and mTLS failure categories; ephemeral certificates generated in tests |

The authentication certificate cannot be substituted for the signing certificate, even if both have usable private keys.

## AP-07 - Secure SOAP/XML request and fault boundary

**Used by:** `sogei-basic-session`.

This is included for the `auth-soap` writer because Basic/session application cannot be safely tested without a bounded SOAP transport boundary.

**Minimal API**

```text
InvokeSoap(context, soapProfile, operation, boundedEnvelope, authContext) -> boundedSoapResult
```

| Aspect | Requirement |
|---|---|
| Input | Fixed operation/SOAPAction/profile, bounded domain data or independently generated envelope, and AP-01/AP-02 auth context |
| Output | Validated application result or typed sanitized fault; never a generic raw proxy |
| Capability | No new secret capability; consumes Basic/session contexts |
| Caching | WSDL/schema/profile may be immutable pack resources; no response or sensitive envelope cache by default |
| Refresh | Not applicable |
| Redaction | SOAP headers, session, credentials, patient/operator data and raw fault detail are excluded from audit/errors |
| Failure | DTD/external entities, depth/node/size limits, namespace/action mismatch, invalid content type, malformed XML and oversize response fail closed |
| Vectors | Synthetic SOAP request/response/fault corpus under `sogei-basic-session` |

SOAP version, action, namespace and schema are not selected until authoritative SOGEI material is available.

## Deferred beyond the first four

Generic HMAC, SAML, WS-Security, XML-DSig, identity, smart-card/CNS access, local certificate selection and VPN management frameworks are deferred. OAuth 1, HS256 JWT, WebSocket and device protocols are also excluded. Their presence elsewhere in the inventory does not justify adding them to these contracts.

## Cross-primitive negative tests

Every writer must prove that:

- caller-supplied endpoint, tenant, pharmacy/operator authority, credential/certificate reference, scope, audience, issuer, header or algorithm is rejected before provider/DNS/transport access;
- a resource approved for connector A, operation A or certificate purpose A cannot be used by connector B, operation B or purpose B;
- expired/revoked/rotated state is not served from stale cache;
- timeout, cancellation, upstream malformed data, 401/403/429/5xx and TLS failure do not expose token, credential, key reference, payload or stack trace;
- retry occurs only when the operation profile is explicitly idempotent and never repeats authorization-code exchange, MFA completion or a signing side effect by default.

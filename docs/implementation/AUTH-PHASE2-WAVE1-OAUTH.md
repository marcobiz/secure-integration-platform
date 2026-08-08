# Auth Phase 2 / Wave 1: generic OAuth profiles

## Scope

This increment extends the provider-neutral outbound OAuth module with Authorization Code PKCE, Client Credentials, and the existing bounded in-process token-session cache and restricted transport. It does not add inbound identity, a connector implementation, a distributed cache, or a provider dependency. The authenticated Gateway runtime still creates the non-forgeable invocation capability after grant authorization; connector code selects only a logical `profileId`.

## Authorization Code and PKCE

The Published profile selects `NONE`, preserving existing behavior, or `S256_REQUIRED`. There is no plain fallback.

For `S256_REQUIRED`, the Gateway generates 32 CSPRNG bytes and base64url-encodes them into a 43-character RFC-valid verifier. The verifier is retained only inside the bounded authorization attempt, bound to the exact Published profile fingerprint, authenticated Tenant/Installation/Application, Connector/version/operation/Environment, correlation, state hash, revisions and expiry. It is zeroed on completion, denial, expiry, capacity eviction, audit failure or disposal.

Only the S256 challenge and `code_challenge_method=S256` enter the approved navigation URL. The verifier is attached internally to the one-time token exchange. A wrong state permanently fails the attempt; a completion, failed exchange or replay cannot reuse it.

Example Published authentication fragment:

```json
{
  "kind": "oauthAuthorizationCode",
  "profileId": "partner.authorization",
  "authorizationEndpointBinding": "oauth-authorization",
  "tokenEndpointBinding": "oauth-token",
  "clientId": "published-client-id",
  "clientAuthMethod": "client_secret_basic",
  "secretBinding": "oauth-client-secret",
  "scopes": ["orders.read"],
  "audience": "orders-api",
  "redirectUri": "https://gateway.example.test/oauth/callback",
  "pkcePolicy": "S256_REQUIRED",
  "authorizationLifetimeSeconds": 300,
  "tokenRequestTimeoutMilliseconds": 5000,
  "maximumTokenResponseBytes": 16384,
  "expirySkewSeconds": 30,
  "allowRefresh": true
}
```

The presentation adapter receives only `OAuthAuthorizationChallenge`: an opaque attempt reference, approved navigation URL, correlation, expiry and presentation kind. JSON and `ToString()` omit the attempt reference and URL. Connector-facing profile selection never accepts a verifier, challenge, endpoint, client secret, scope, audience or provider reference.

## Client Credentials

The Published `oauthClientCredentials` profile owns the token endpoint binding, client ID, exact secret binding, client authentication method, scopes, optional audience/resource, response bounds, timeout and expiry skew.

Only `client_secret_basic` is implemented because it is the confidential-client method already supported by the foundation. Client ID and secret are form-encoded before Basic encoding. The Authorization header is added only to the internal HTTPS token request; a secret is never placed in a URI.

```json
{
  "kind": "oauthClientCredentials",
  "profileId": "partner.machine",
  "tokenEndpointBinding": "oauth-token",
  "clientId": "published-client-id",
  "clientAuthMethod": "client_secret_basic",
  "secretBinding": "oauth-client-secret",
  "scopes": ["orders.write"],
  "audience": "orders-api",
  "resource": "https://api.example.test/orders",
  "tokenRequestTimeoutMilliseconds": 5000,
  "maximumTokenResponseBytes": 16384,
  "expirySkewSeconds": 30
}
```

`AcquireClientCredentialsAsync` returns the same opaque token-session reference used by Authorization Code. Concurrent initial acquisition is single-flight. Concurrent expiry handling uses the existing per-session gate and replaces a token only after current Published state has been revalidated.

## Cache, rotation and egress

There is one token-session dictionary for both grants. Its key distinguishes grant/policy/profile; Tenant, Installation, Application and Environment; Connector, Published version and operation; protected endpoint/method and token endpoint; binding, endpoint, secret/catalog and resource-stamp revisions; client identity and client-auth method; and exact scope, audience and resource.

Every authority, DNS, secret and token await is followed by Published-state and invalidation-generation revalidation. Rotation, disable, profile changes, endpoint changes and audit failure deny without stale fallback. Refresh and reacquisition results are tombstoned if invalidation occurs in flight.

Authorization presentation performs validation and DNS policy but no Gateway HTTP fetch. Token acquisition, refresh/reacquisition and protected-resource dispatch always use `IRestrictedTransport`. Redirects, private/loopback/link-local/metadata destinations and rebinding are denied unless an exact test-only local allowance is supplied.

## Redaction and verification

Verifier, state, client secret, access/refresh token, Basic authorization and raw token response are absent from public JSON, `ToString()`, audit and stable exceptions. Token response buffers are zeroed after parsing; cached tokens and verifier/state buffers are cleared on invalidation or disposal.

Named automated evidence is mapped in [Auth Phase 2 Wave 1 traceability](../traceability/auth-phase2-wave1-oauth.md).

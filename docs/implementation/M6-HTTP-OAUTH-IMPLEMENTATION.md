# M6 HTTP/OAuth authentication primitives

## Scope and baseline

Implementation baseline: `f34275096b4960bb5f31840553444935defc3d2d` (`main`, M6 characterization freeze).
Branch: `m6/auth-http-oauth`.

This slice implements synthetic outbound authentication from the Gateway Connector Runtime to a vendor/public service. It does not modify inbound BGW1 authentication and does not branch on `InstallationKind`.

Implemented:

- AP-02 transport-neutral opaque challenge lifecycle only: bounded capacity and artifact size, correlation, absolute expiry, cross-context denial, one completion and replay denial;
- AP-03 Authorization Code baseline without PKCE: server-generated state, opaque attempt, absolute expiry, state validation, one-time completion and code exchange;
- AP-04 confidential-client code exchange, bounded token response parsing, opaque token-session reference, bearer application, bounded in-memory LRU eviction, single-flight refresh and explicit reacquisition failure;
- metadata-only auth audit records;
- authorization and token endpoint validation through Gateway-equivalent HTTPS, DNS/IP, SSRF, private-range and restricted-transport controls.

Deferred intentionally:

- PKCE (Wave 2), `client_credentials` grant pending Lombardia characterization, fixed bearer profiles, ID-token validation and revocation endpoint;
- SOAP, Basic/session acquisition and the AP-02 resulting vendor session (owned by the SOAP writer);
- certificate, mTLS, signing and JWT primitives (owned by the Crypto writer);
- production healthcare profiles, Keycloak, Gateway user OIDC, inbound authentication and Redis.

## Connector-facing API

`OAuthAuthorizationCodeProfile` is the small declarative compiled profile. It fixes `OAuthAuthorizationCode`, profile ID, authorization/token/redirect endpoints, Connector-owned client ID, logical client-secret reference, scopes, audience, lifetimes, response bounds, skew and refresh permission. Runtime invocations cannot override those values.

`OutboundAuthContext` carries only immutable server-derived identity and security stamps: Tenant, Installation, Application, Environment, ConnectorVersion, operation, auth-binding revision, endpoint revision, secret revision, resource stamp, correlation and deadline. Every authorization attempt and token session is bound to all of these dimensions.

The presentation adapter receives only `OAuthAuthorizationChallenge` or `InteractiveChallenge`: opaque reference, presentation URI/challenge, correlation and expiry. Completion callback data is bounded and consumed once; tokens are represented only by `OAuthTokenSessionReference` and never returned.

## Lifecycle and cache

Authorization attempts are short-lived, capacity-bounded and one-time. State is retained only as SHA-256. A mismatch permanently fails the attempt before token transport.

Token sessions are process-local and capacity-bounded. The cache key covers Tenant/Installation/Application, Connector and Published version, Environment, operation, auth/endpoint/secret revisions, client identity, exact scopes/audience, resource stamp and complete profile fingerprint. A changed key removes the stale session immediately. Expired access tokens refresh only when the profile allows it and a refresh token exists; refresh is serialized per session and atomically replaces the token set. Refresh failure removes the session. Profiles without refresh require explicit reacquisition. No stale or expired token fallback exists.

## Restricted egress and synthetic server

Authorization and token endpoints are absolute HTTPS without user info or fragments. DNS is resolved through `IHostResolver`; loopback, private, link-local, metadata, carrier-grade NAT, multicast and invalid addresses are denied unless an exact test-only allowance is supplied. Token exchange uses the existing `IRestrictedTransport`, which disables redirects, proxy and cookies, pins the approved address set and applies TLS/hostname and response bounds. Authorization presentation performs no Gateway-side HTTP request.

`tools/m6/SyntheticOAuthServer` is a separate local HTTPS server used with per-run keys and credentials. It provides authorization/code issue, token exchange, rotating refresh, bearer resource, expired code/token, invalid response, wrong content type, malicious redirect and replay behavior. It has no Internet dependency and no logging provider.

## Security evidence

Named tests:

- `M6_UT_Challenge_is_transport_neutral_correlated_single_use_and_artifact_is_not_retained`;
- `M6_UT_Challenge_expiry_wrong_context_wrong_challenge_and_capacity_fail_closed`;
- `M6_IT_OAuth_real_HTTPS_authorization_bearer_cache_refresh_and_redaction`;
- `M6_IT_OAuth_invalid_token_responses_and_redirect_fail_sanitized`;
- `M6_IT_OAuth_state_replay_expired_code_scope_and_secret_rotation_fail_closed`;
- `M6_IT_OAuth_SSRF_endpoint_manipulation_and_disabled_secret_never_reach_transport`;
- `M6_IT_OAuth_cache_is_bounded_and_refresh_is_single_flight`.

The stable external failure is an existing redacted Gateway code; token, code, state, callback, authorization header, secret and provider reference are absent from exception, audit and synthetic-server logs. Existing Gateway middleware converts the same `GatewayException` to allowlisted RFC 9457 fields only.

This is a local candidate only until full repository gates, CI and one independent review pass. It is not evidence for a production healthcare connector.

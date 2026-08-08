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

Connector code supplies only an `OAuthAuthorityRequest` containing a logical profile ID. The shared runtime creates an unforgeable `OAuthAuthorizedInvocation` after inbound authentication and grant authorization. `PublishedOAuthAuthorityResolver` loads the current `PublishedConnectorSnapshot` under that capability and its authenticated `GatewayClientPrincipal`, derives `OperationBindingDependencies`, exact endpoint/binding/resource revisions and the exact provider locator, and returns an immutable `OAuthResolvedExecutionContext` whose constructor is internal. Raw `OAuthAuthorizationCodeProfile` and `OutboundAuthContext` are internal and cannot be substituted by a consumer.

Secret use is an internal capability scoped to the exact provider reference resolved for the approved secret binding. `OAuthAuthorizationCodeClient` no longer accepts a generic `ISecretValueProvider`.

The presentation adapter receives only `OAuthAuthorizationChallenge` or `InteractiveChallenge`: opaque reference, presentation URI/challenge, correlation and expiry. Completion callback data is bounded and consumed once; tokens are represented only by `OAuthTokenSessionReference` and never returned.

## Lifecycle and cache

Authorization attempts are short-lived, capacity-bounded and one-time. State is retained only as SHA-256. A mismatch permanently fails the attempt before token transport.

Token sessions are process-local and capacity-bounded. The cache key covers Tenant/Installation/Application, Connector and Published version, Environment, operation, protected-resource endpoint/method, auth/endpoint/secret revisions, client identity, exact scopes/audience, resource stamp and complete profile fingerprint. Correlation is checked on authorization attempts but intentionally not included in the final session key, so later authorized invocations may reuse a valid session. Expired access tokens refresh only when the profile allows it and a refresh token exists; refresh is serialized per session.

Every await that can observe or produce authority, secret, DNS or token state is followed by Published-snapshot and generation revalidation. Explicit invalidation/rotation creates a tombstone generation; an in-flight stale result cannot be cached, attached or dispatched.

## Restricted egress and synthetic server

Authorization and token endpoints are absolute HTTPS without user info or fragments. Reserved OAuth query parameters, including encoded aliases, are rejected on the base authorization endpoint and the module emits exactly one canonical value for each managed field. DNS is resolved through `IHostResolver`; loopback, private, link-local, metadata, carrier-grade NAT, multicast and invalid addresses are denied unless an exact test-only allowance is supplied.

Authorization presentation is explicitly `external-user-agent-navigation`: validation and DNS policy run, but the Gateway performs no HTTP fetch. Token exchange and protected-resource dispatch always use `IRestrictedTransport`. `SendAuthenticatedAsync` constructs the protected request internally from the Published endpoint and operation, injects bearer immediately before dispatch and never exposes an authenticated `HttpRequestMessage`.

Types carrying code/state/challenge/session/token/client-secret or authorization URI data are non-record diagnostic types with allowlisted `ToString` and `JsonIgnore` treatment. Synthetic server options follow the same rule.

`tools/m6/SyntheticOAuthServer` is a separate local HTTPS server used with per-run keys and credentials. It provides authorization/code issue, token exchange, rotating refresh, bearer resource, expired code/token, invalid response, wrong content type, malicious redirect and replay behavior. It has no Internet dependency and no logging provider.

## Security evidence

Named tests:

- `M6_UT_Challenge_is_transport_neutral_correlated_single_use_and_artifact_is_not_retained`;
- `M6_UT_Challenge_expiry_wrong_context_wrong_challenge_and_capacity_fail_closed`;
- `M6_IT_OAuth_real_HTTPS_authorization_bearer_cache_refresh_and_redaction`;
- `M6_IT_OAuth_invalid_token_responses_and_redirect_fail_sanitized`;
- `M6_IT_OAuth_state_replay_expired_code_and_snapshot_rotation_fail_closed`;
- `M6_IT_OAuth_SSRF_endpoint_manipulation_and_disabled_secret_never_reach_transport`;
- `M6_IT_OAuth_cache_is_bounded_and_refresh_is_single_flight`.
- `M6_IT_OAuth_Published_authority_rejects_profile_endpoint_secret_and_scope_substitution_before_provider_use`;
- `M6_IT_OAuth_completion_and_poll_require_original_correlation_but_session_cache_does_not`;
- `M6_IT_OAuth_bearer_is_destination_bound_and_attacker_server_receives_zero_requests`;
- `M6_IT_OAuth_refresh_result_is_tombstoned_when_snapshot_rotates_during_await`;
- `M6_UT_OAuth_authorization_endpoint_rejects_reserved_parameter_smuggling`;
- `M6_IT_OAuth_authorization_endpoint_is_user_agent_navigation_not_server_side_fetch`;
- `M6_IT_OAuth_diagnostics_ToString_JSON_exceptions_and_assertion_rendering_are_redacted`;
- `M6_UT_Challenge_completion_requires_original_correlation_and_diagnostics_are_redacted`.

The stable external failure is an existing redacted Gateway code; token, code, state, callback, authorization header, secret and provider reference are absent from exceptions, JSON, `ToString`, assertion diagnostics, audit and synthetic-server logs. Existing Gateway middleware converts the same `GatewayException` to allowlisted RFC 9457 fields only.

The targeted seven-finding remediation product commit is `9a7db4bcfa328542d1170c7b56c4a73170a3e139`. Full PR CI is PASS (21/21 exact-head jobs, runs `31199544979` and `31199544996`). One independent review remains required. This is not evidence for a production healthcare connector.

## Auth Phase 2 / Wave 1 extension

The historical scope above remains the record of the M6 foundation branch. The generic Phase 2 extension adds PKCE `NONE`/`S256_REQUIRED` policy and Client Credentials on the same capability, cache and restricted-transport boundary. Current behavior, connector-facing examples and named evidence are documented in [Auth Phase 2 / Wave 1: generic OAuth profiles](AUTH-PHASE2-WAVE1-OAUTH.md).

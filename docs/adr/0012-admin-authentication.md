# ADR-0012: Provider-neutral Admin authentication

**Status:** Accepted (updated in M5)

## Context

Gateway Core must run without Azure. The Admin contract therefore cannot depend on Entra types, claims or SDKs, while retaining a mandatory authentication boundary.

## Decision

The Admin API exposes a provider-neutral authorization boundary. In production, the deployment must connect it to an OIDC identity provider and administrative policies/roles; Core does not choose the provider. There are no local administrative accounts or passwords.

M4 includes a `DevelopmentApiKey` mode exclusively for `Development`, `Testing`, `M3Testing` and `M4Testing` environments. The key comes only from an environment variable, is compared in constant time, is not accepted as a CLI argument and the mode is rejected in `Production`. The default mode is `Disabled` and fails closed.

M5 uses server-side Authorization Code Flow with PKCE, state and nonce. The OIDC middleware validates ID tokens and callbacks; tokens are not saved in the browser. The browser receives only an HttpOnly, Secure, SameSite=Lax `__Host-` cookie with expiry/sliding window, and all mutations require session-bound antiforgery protection.

The Admin rate limiter protects availability without treating ordinary bursts, concurrent onboarding
or operators behind NAT as incidents. Server-owned defaults are `AUTH=60` requests every 60 seconds
per trusted remote IP and `API=600` requests every 60 seconds per server-authenticated subject,
with no queue and automatic replenishment. Login, DevelopmentAuth login, the configured OIDC callback,
pre-login CSRF and unknown `/admin/auth` endpoints use AUTH. Post-login CSRF, `me`, logout and
ordinary Admin APIs use API. DevelopmentApiKey is validated server-side before partitioning
and uses a server-owned API identity; it does not consume the browser AUTH bucket.

Security must prevent significant abuse without treating ordinary bursts, concurrent onboarding
or operators behind NAT as incidents. No supported golden path may depend on waiting for the
window, logging in again or technical support. Thresholds must leave at least four times the
ordinary consumption of a single workflow, unless evidence shows a stricter capacity limit. The Admin
limiter does not govern tenant/data-plane traffic; this configuration does not extend to the data plane without
dedicated capacity tests.

The stable principal is `(issuer, subject)`; email and display name are not keys. Global or tenant-scoped roles are persisted server-side. The four-eyes policy binds the decision to version ID and checksum and denies overlapping creator/requester/editor identities. Production rejects incomplete OIDC configurations and DevelopmentAuth; the latter uses only fixed synthetic identities, loopback/Compose and the Development environment.

## Consequences

M5 four-eyes approval is bound both to the canonical ConnectorVersion checksum and to the digest of endpoint/secret/certificate revisions. PostgreSQL publication verifies and locks both in the same transaction; the actor who created a binding revision cannot approve that bundle. `DevelopmentAuth` checks the socket peer using loopback `RemoteIpAddress`, and local Compose exposes the Gateway only on `127.0.0.1`; Host and client-controlled forwarded headers are not authority.

- The local quick start requires neither Azure nor cloud credentials.
- Deployment Packs can integrate Entra or another OIDC provider without changing Connector contracts.
- Legacy `DevelopmentApiKey` and `DevelopmentAuth` are not supported production modes.
- Audit, optimistic concurrency and Published immutability remain mandatory even in development.
- The same-origin UI does not store access/refresh tokens in Web Storage or enable permissive CORS.
- Each technical role reuses its still-valid session and CSRF across supported phases; expiry and
  server-side validation remain unchanged, with no hidden limiter resets, sleeps or retries.
- Concurrent sessions for the same principal remain valid when the exact role assignment
  already exists; only an actual privilege change revokes all sessions for the principal.
  The same-NAT gate uses three new sessions and three new cookie jars for each of the two workflows, not
  three sessions shared between workflows.
- Thresholds are a process-local control against evident abuse, not a distributed defense against
  an actor with valid credentials or a rate limit on the external OIDC identity provider.

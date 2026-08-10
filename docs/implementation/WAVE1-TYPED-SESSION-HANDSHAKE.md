# Wave 1 typed session handshake and authorized external admission

## Scope and baseline

- Base: `705e9d4bd203ca7b902ad0aeedc9d4402f9f4452`.
- Branch: `wave1/auth-session-handshake`.
- Core capability only: typed nested SOAP session bootstrap plus authorized external opaque-session
  admission.
- Existing M6 scalar Login/Challenge/Business/Logout profiles remain the default compatibility
  path.
- No new cache, distributed state, generic XML mapper, deployment pack or production connector is
  introduced.

## Published authority and adapter model

`PublishedTypedSessionHandshakeResolver` accepts `AuthorizedGatewayInvocation` and a
`TypedSessionHandshakeAuthorityRequest` containing only the logical profile ID. It reads the exact
operation from the current Published snapshot and produces a non-forgeable
`ResolvedTypedSessionHandshake`.

The `typedSessionHandshake` definition member is checksum/four-eyes controlled and fixes:

- request and response adapter logical ID/type;
- exact request and response QName;
- SOAP 1.1 or 1.2 and exact action;
- handshake endpoint/path, timeout and request/response bounds;
- local maximum session lifetime;
- optional validator ID/type, validation endpoint/path, intent TTL, timeout and response bound.

The external-validation profile also fixes SOAP version/action, exact request/response QName and
maximum request bytes. It does not grant the validation adapter any endpoint, credential, timeout,
DNS or HTTP authority.

The immutable authority fingerprint also covers ConnectorVersion ID/version/checksum, publication
revision, binding checksum/revision, resource stamp, credential resource revisions, operation and
profile. Registry lookup is exact and uses no CLR reflection.

The request adapter receives a Core-owned `XmlWriter` already inside the exact request element and
an immutable `TypedSessionHandshakeRequestContext`. The context contains authenticated identity and
Published metadata only; there is no arbitrary dictionary or ordinary business payload. A bounded
write stream stops output at the Published request limit.

The response path first applies the existing hardened XML reader settings and structural SOAP
checks, including the generic 16,384-character bound on each text, CDATA and attribute value before
`XDocument` construction. Only the expected payload is exposed through `XmlReader` to the compiled response adapter.
The adapter performs protocol-specific nested validation and returns the closed
`TypedSessionHandshakeAdapterOutcome`.

The compiled external-validation adapter is equally narrow: it writes only typed payload children
and parses only the exact bounded payload into a closed status and remote expiry. Core resolves the
validation operation from Published state, including the endpoint and the operation's existing
Basic credential bindings, then owns the SOAP envelope, restricted HTTPS transport, DNS/IP pinning,
no-proxy/no-redirect policy, deadline, request/response limits, Fault boundary and hardened parse.
No adapter constructor or context contains a URL, credential locator, secret, timeout or transport.

## Authorized external admission

`ExternalSessionAdmissionIntent` is created by Core only after the typed bootstrap returns
`ExternalAdmissionRequired`. It carries an opaque reference plus safe provenance/expiry metadata;
the cache retains only its digest and exact authority binding.

`ExternalSessionCandidate` is internal and has an owned, bounded UTF-8 buffer. The public runtime
completion method accepts only an authenticated `GatewayClientPrincipal`, the opaque intent
reference and candidate bytes. It resolves the intent from the bounded SOAP cache, reauthorizes the
principal/grant, re-resolves the current Published Connector/operation/profile and validates the
server-owned cache key, expiry and `InteractiveHandoff` provenance before constructing the internal
candidate. The completion method consumes and clears the candidate on every terminal path.
Candidate, admitted value, validation body and remote diagnostics are absent from exceptions,
`ToString`, JSON and audit metadata.

The sequence is:

1. resolve the intent and reauthorize its authenticated principal and exact current profile;
2. capture the Connector/Environment generation from the store's shared 64-stripe mutation authority;
3. reserve the exact intent once in the existing cache;
4. serialize a typed validation request and perform the Core-controlled restricted HTTPS call;
5. parse the bounded response and obtain a candidate-bound internal validation proof;
6. revalidate Published authority and resource stamp after the remote await;
7. validate the remote expiry and cap it by the Published local maximum; and
8. after all awaits, compare the captured authority generation and synchronously verify the proof,
   intent/session generation and exact fingerprint, consume the intent and promote one current
   session under the same stripe.

Every Published version, binding or provider-resource mutation opens a fixed-stripe lease before it
mutates state and advances the generation again on disposal after success or failure. No lock is
held across database I/O, but compare-and-promote rejects both stale generations and any active
mutation, including a resolver that captured after mutation begin but before commit. There is no
global lock and no await between the final generation compare and cache promotion. Deterministic
tests cover that entire in-progress window and the hook immediately after the last async check;
publish/rotate/disable in either former gap makes compare-and-promote fail.

Validation rejection/failure, cancellation, expiry, reuse, cross-context/profile/key mismatch,
rotation or disable abandons the intent and never promotes a session.

The production composition root registers one bounded explicit registry (maximum 256 entries per
adapter role), the real `GatewayInvocationAuthorizer`, Published resolver/resource-stamp provider,
restricted SOAP client and `TypedSessionHandshakeRuntime`. It exposes authenticated acquire and
completion routes. The completion route takes its candidate as a bounded request body, clears that
buffer on exit and never accepts tenant, application, installation, ConnectorVersion, profile,
lifecycle key, provenance, expiry, endpoint, credential or adapter selectors.

## Synthetic protocol and verification matrix

The neutral HTTPS synthetic server supports nested `CreateSessionRequest` /
`CreateSessionResponse` and `ValidateSessionRequest` / `ValidateSessionResponse` alongside the
unchanged legacy operations. It verifies exact nested request order and registers an externally
validated candidate so a subsequent session-authenticated business operation proves lifecycle
reuse.

Named tests cover Published adapter selection; nested request/response; strict order, cardinality,
domain, duplicate, unexpected, mixed-content and nested denial; DTD/QName/Body hardening; individual
text/CDATA/attribute and aggregate bounds before adapter invocation; fake and real cancellation at
all three adapter boundaries; direct issuance; authenticated external handoff; wrong/reused/expired/
cross-context/profile intent; candidate/proof substitution and replay; validation failure; remote
expiry validation/capping; rotate/disable during validation and in the final pre-promotion window;
simultaneous double completion; 256-key cap/lazy sweep; redaction; real TLS; subsequent session use;
architecture neutrality; production composition/store/four-eyes/authorizer/registry execution; and
the complete legacy SOAP regression. Concurrency tests use barriers/hooks rather than sleep.

The canonical production proof is
`Wave1_IT_PRODUCTION_HOST_authenticated_routes_store_registry_admission_replay_and_session_use`.
It starts the application through `WebApplicationFactory<Program>`, sends HTTP requests through the
mapped acquire/completion routes, presents a registered synthetic certificate to `TestServer`, and
still executes the production `AuthenticateAsync` BGW1 signature/digest/nonce checks. It uses the
PostgreSQL `RoutingConnectorConfigurationStore`, four-eyes application services and the
composition-root adapter registry. A second named theory,
`Wave1_IT_PRODUCTION_STORE_final_race_uses_same_PostgreSQL_authority_and_denies_promotion`, pauses only
at the existing test hook after the last asynchronous revalidation and before the synchronous CAS;
real publish and provider-resource-disable mutations advance the same store authority and deny
promotion without timing or direct invalidation calls. Older manually composed tests remain useful
`INTERNAL_COMPOSITION_TEST` coverage and are no longer described as production-host evidence.

The local full-suite, PostgreSQL 18, scan, SBOM and vulnerability evidence is recorded in the
testing report. Core export, exact-head CI and independent review are qualified only after the
thematic commits and branch publication; no merge is part of this implementation step.

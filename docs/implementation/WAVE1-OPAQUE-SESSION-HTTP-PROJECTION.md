# Wave 1 — opaque session HTTP projection

## Scope and ownership

This Wave 1 Core capability projects a Gateway-owned opaque authenticated session into one server-owned custom HTTP request header and performs one destination-bound restricted dispatch. It is provider- and industry-neutral. It does not implement a connector, OAuth, JWT/X.509 changes or a new session foundation.

The provider-neutral contracts, Published resolver, generic exception and one-shot dispatcher live in `Gateway.ConnectorRuntime.Auth.Http/OpaqueSessions`. They have no dependency on the SOAP assembly. The existing SOAP lifecycle depends in the permitted direction on the HTTP auth module and exposes a controlled `OpaqueSessionLeaseProvider` adapter plus conversion from `OpaqueSoapSessionReference` to the provider-neutral `OpaqueSessionReference`. Existing SOAP acquisition, XML placement, AP-02, logout, Fault and retry APIs remain unchanged.

## Non-forgeable authority handoff

Caller-facing code can construct only `OpaqueSessionHttpAuthorityRequest`, containing one logical policy ID, and can submit bounded business bytes plus an opaque session reference. `OpaqueSessionAuthorizedInvocation`, `OpaqueSessionResolvedExecutionContext`, the resolved endpoint/method/placement/revisions and the raw lifecycle lease have no public constructors.

`PublishedOpaqueSessionAuthorityResolver` is the production authority boundary. Its public constructor requires `IConnectorConfigurationStore`; it resolves the current Published ConnectorVersion under the authenticated `GatewayClientPrincipal`, authorized connector/operation and `PublishedConnectorAccessContext`. It derives `OperationBindingDependencies`, Environment, endpoint binding, effective path and method, session profile, credential resource revision/status stamp, custom header, formatting mode and request/response bounds. The internal snapshot delegate exists only for friend test assemblies and is not a connector-facing injection seam.

Every revalidation loads Published state again. It verifies the immutable ConnectorVersion identity/checksum, operation, policy/profile, binding identity/revision/checksum/state, endpoint binding and effective endpoint, credential resource identity/revision/checksum, resource stamp and every projection field through a complete security fingerprint. A same-revision endpoint substitution therefore fails closed.

## Header safety

Field names use the RFC HTTP token character set without trimming or permissive normalization. CR/LF, whitespace, NUL and controls fail validation. The denylist is case-insensitive and covers `Authorization`, `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Cookie`, `Set-Cookie`, proxy authentication, `Forwarded`, `Via`, `Expect`, `Upgrade`, `TE`, `Trailer`, `X-Correlation-ID`, `traceparent`, `tracestate`, `baggage`, every `Proxy-*` field and every `X-Forwarded-*` field. The opaque value is bounded and rejects CR, LF, NUL and controls.

There is no generic header bag, template, expression evaluator, script, callback, public attach API or public authenticated `HttpRequestMessage`.

## Final dispatch authorization

`OpaqueSessionHttpClient.SendAsync` first validates and copies the business body, builds the unauthenticated request and resolves restricted-egress addresses. Immediately before authenticated projection it reloads and verifies the Published authority. It then synchronously acquires the current session generation/expiry lease, formats and applies exactly one approved header, rechecks the lease and invokes `IRestrictedTransport.SendAsync` without an intervening await or expensive operation.

Deterministic test-only hooks pause before, never inside, this final authorization section. Disable, credential rotation or endpoint update while paused is observed by the final Published lookup and produces no header and zero network requests. Post-dispatch revalidation discards the bounded response if authority or session generation changed while the network operation was in progress.

## Session-cache compatibility

The qualified M6 SOAP cache identity remains Tenant, Installation, Application, Environment, Connector/version, binding revision, endpoint revision, credential revision and session profile. Operation ID and resource stamp are deliberately not part of the global SOAP cache key. Compatible operations therefore continue to share one acquired SOAP session without an unnecessary login.

HTTP authorization is separate from lifecycle identity: the non-forgeable Published invocation and final authority fingerprint bind each HTTP dispatch to the exact authorized operation, endpoint and current resource state. Sharing a compatible lifecycle session does not allow a caller to select another operation or destination.

## Synthetic qualification

`SyntheticOpaqueSessionServer` is a vendor-neutral HTTPS Kestrel endpoint with counters for valid, missing, wrong and duplicate headers plus delayed responses. The remediation matrix covers raw/fixed formatting; tracing, forwarding, casing and control-name denial; non-forgeable public surface; stale ConnectorVersion; same-revision endpoint substitution; generation and expiry; deterministic disable/rotate/endpoint races; attacker destination; redaction; real restricted HTTPS; real-HTTPS rotate/disable zero-network; and the complete SOAP lifecycle regression including multi-operation sharing.

No production connector or live external-system qualification is claimed.

## Release evidence semantics

Ordinary, targeted unit, targeted integration, architecture and PostgreSQL results are recorded separately from the exact remediation HEAD. Counts from the reviewed predecessor are not reused.

The Core export manifest contains per-run `generatedAtUtc`. Consequently, a SHA-256 over the whole manifest is an **artifact-specific manifest digest**, useful for integrity of that one export artifact, not a reproducible exact-HEAD identity. This remediation does not modify `Export-OpenSourceCore.ps1` or claim reproducibility for that digest.

## Local remediation qualification

- Release build: PASS, zero warnings and zero errors.
- Ordinary .NET suite: 312 total, 302 PASS and 10 PostgreSQL-conditional SKIP.
- Targeted unit session/SOAP gate: 49 PASS, comprising 34 generic projection cases and 15 SOAP lifecycle cases including the new multi-operation regression.
- Targeted real-HTTPS integration gate: 10 PASS, comprising 5 generic projection cases and 5 existing SOAP cases.
- Architecture suite: 17/17 PASS.
- PostgreSQL 18 isolated gate: fresh migrations plus verified second-apply no-op and 11/11 relevant tests PASS; the labeled container was removed.

Documentation, scans, SBOM, package vulnerability checks, Core export and CI are recorded only after they run on the remediation candidate. CI success from the reviewed predecessor is not reused.

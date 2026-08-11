# Wave 1 Connector capability completion

## Scope

This change is the single Core freeze exception supported by the concrete execution blockers found
after ADR-0023. It completes only:

1. registration of the three existing typed-session adapter categories;
2. Published-approved server-owned inputs for request and external-validation adapters;
3. an exact Published extension-configuration view;
4. invocation-bound use of the existing RS256/X.509 and restricted mTLS primitives.

It does not implement either connector that motivated the work. It adds no healthcare vocabulary,
generic plugin system, provider/store facade, signing oracle, arbitrary HTTP client, new provider,
new adapter family or public certificate export.

## Authority flow

The authority chain is unchanged through inbound execution:

`BGW1 -> authenticated principal -> exact grant -> Published snapshot A -> operation/auth kind/strategy -> AuthorizedConnectorExecution`.

All added capabilities inherit the opaque stamp captured from A. The current store is reread only
to prove equality with A. A later Published B is never adopted as authority.

For a typed session request, the exact adapter ID/type and its statically snapshotted required names
are matched against the Published mappings. Core resolves only those logical bindings, prepares the
bounded adapter call, internally binds the input view to that call's exact Core writer, clears the
writable character buffers as soon as the synchronous adapter callback returns,
then performs the full final A check after provider and DNS preparation before dispatch.

For signing, the host derives policy ID/revision, issuer, audience, subject source, claim allowlist,
lifetime, temporal mode, key binding, catalog revision, SPKI and x5c policy from A. The module can
supply only the bounded allowlisted claim values. The signed object is opaque to the module and is
owned by the same bridge. Actual enumeration, name, scalar-kind, serialized-value and aggregate
bounds are enforced incrementally with fixed-capacity measurement before each immutable clone;
reported collection `Count` is not authority and `GetRawText` is not used.

For transport, the host derives endpoint, method, content type, timeout, response bound, bearer
semantics, certificate binding, catalog revision and SPKI from A. The module can supply only a
bounded body and the opaque signed object created by the same invocation. Restricted DNS/egress,
HTTPS validation and mTLS remain in the existing host primitive. The last resource check occurs
after DNS with no security-significant await before transport.

## Exact Published profile

`extensionConfiguration` is an object limited to 32 KiB UTF-8, depth 8 and 256 semantic nodes.
The runtime receives a defensive read-only stream over a copy. The Connector schema additionally
requires both capability blocks together:

- `signing`: exact profile/revision, key binding, SPKI, issuer, audience, subject policy, claim
  allowlist, lifetime/skew, x5c mode, temporal mode and minimum RSA size;
- `restrictedTransport`: exact profile/revision, client-certificate SPKI, fixed
  `signedTokenBearer` authorization and near-expiry window.

The operation must declare an external execution strategy and `mtls` authentication. Both signing
and mTLS bindings are certificate dependencies included in binding validation, the checksum-specific
four-eyes review artifact, runtime locator selection and the resource stamp.

`serverOwnedInputs` is a bounded array of exact name/`secretBinding` pairs on the typed handshake
and external-admission profiles. Only logical bindings declared with kind `opaque` are accepted.
Those dependencies are likewise included in binding validation, four-eyes review, runtime locator
selection and the resource stamp.

## Public API inventory

| Surface | Public members added | Why it is the minimum |
|---|---|---|
| Exact Published view | `AuthorizedConnectorExecution.OpenPublishedExtensionConfiguration`; non-constructible `AuthorizedPublishedExtensionConfiguration` with `JsonLength` and `OpenJsonStream` | lets compiled protocol logic read only the current bounded configuration copy; no stamp/store/provider |
| Restricted adapter registration | `AddTypedSessionHandshakeRequestAdapter<T>`, `AddTypedSessionHandshakeResponseAdapter<T>`, `AddExternalSessionValidationAdapter<T>` | exactly the three existing registries with real consumers; loader performs the concrete contract/module checks |
| Adapter input declaration | `RequiredServerOwnedInputs` on request and validation adapters | static bounded names are frozen at startup; no runtime locator selection |
| Adapter input use | non-constructible `AuthorizedConnectorBindingInputs`; `Count`, `Contains`, `WriteRequiredXmlValue(name)`; context `ServerOwnedInputs` properties | Core binds the sink internally to the exact callback; values cannot be redirected, returned as strings/provider references or reused after the synchronous XML call |
| Signing | `CreateSignedTokenAsync(claims, cancellationToken)` and non-constructible opaque `AuthorizedConnectorSignedToken` | current Published policy/key/purpose only; compact token and public material are not exposed |
| Restricted transport | `AuthorizedConnectorRestrictedTransportRequest(body, signedToken)` with `BodyLength`; `ExecuteRestrictedTransportAsync` | endpoint/method/content type/auth header/certificate remain server-owned; token must belong to the same bridge |

No public concrete bridge/dispatcher/runtime is exported. `AuthorizedConnectorSignedToken` has no
public constructor or property. The transport request has no URI, method, header, profile, key,
certificate, locator or provider member. Public certificate view status is `NOT_REQUIRED`: x5c is
composed and verified inside the qualified signer and observed only at the sanctioned endpoint.

## Adapter loading and failure model

The module loader retains the ADR-0023 exact assembly identity and same-image rules. Adapter
descriptors are buffered with strategy/service descriptors, capped at 64 per category and 128 total,
and committed only after recursive module-owned constructor validation. Duplicate implementation,
wrong contract, wrong module, direct provider/store/transport dependency, cross-module edge and
constructor cycle fail before the host serves requests.

Published adapter ID/type selection remains exact. Unknown IDs do not fall back to built-ins.
Adapter-required input names and Published mappings must form an exact set. Provider failures and
timeouts are sanitized as upstream failures; fake cancellation and arbitrary adapter exceptions do
not acquire host authority; actual cancellation preserves the caller token.

Every bridge method enters the same internal per-execution `ACTIVE -> CLOSING -> CLOSED` scope before
any claim/provider/network work. Its effective token links the real invocation token, the method
token and a host-only lifetime token. Strategy return closes registration, cancels lifetime work,
drains and observes all tracked tasks, then rejects any result returned while a task was still
in-flight as `BGW-EGRESS-UPSTREAM-REJECTED` 502 non-retryable. Result validation and success audit
occur only after a clean close.

## PostgreSQL least privilege

Migration `0012_connector_capability_locator_scope.sql` (SHA-256
`6F77D7EC57CCCA5FD68A6C37DF89536AC881276B340D934FE08ADEB85D797202`) replaces only the body of the existing
operation-scoped `SECURITY DEFINER` function. It recognizes a locator when the logical binding is:

- the operation's existing authentication binding;
- `authorizedCapabilities.signing.keyBinding` on that same operation; or
- a `serverOwnedInputs[*].secretBinding` on that operation's typed handshake/admission profile.

All pre-existing exact connector, operation, environment, Installation/Tenant/Application, grant,
Published version, active binding ID/revision/checksum, resource scope/type/revision/checksum and
catalog-latest predicates remain. The runtime role still cannot enumerate locator storage.

## Verification map

- Neutral session family: external request/response/validator registration, server-owned
  organization value, hosted admission and shared-session composed SOAP path; caller spoof,
  alternate-writer/retained-view, missing/unexpected mapping, duplicate/wrong-module and A-to-B
  negatives. The organization canary contains XML metacharacters, so the accepted request also
  proves normal escaped text emission into only the Core request writer.
- Neutral signing/mTLS family: real local HTTPS listener requiring the exact client certificate,
  RS256 token with x5c and exact Published claim/body; caller endpoint/key/certificate/profile/claim
  spoof and denied-claim zero-network negatives.
- PostgreSQL 18: both families traverse the production host, distinct editor/approver,
  checksum-specific approval, publication, BGW1 identity, exact operation grant, runtime locator
  function and real external effect.
- Race evidence: provider-input preparation final check, signing/public-material revalidation and
  mTLS change after DNS all deny B before their protected effect.
- Lifetime/bounds evidence: external no-IVT signing and transport fire-and-forget strategies pause
  before effect, return success and are deterministically cancelled/drained/rejected with zero
  transport and zero success audit; dishonest `Count`, claim 33, name/value/aggregate and nested-kind
  adversaries are denied before the signing dispatcher.
- Regression gates: ordinary .NET, architecture, Admin/full-stack, M3, Core export, docs, secret
  scan, Gitleaks, vulnerable packages, SBOM and exact-head CI.

The remediation candidate completed the local regression gates on 2026-08-11: Release build with
zero warnings/errors; 549 ordinary tests PASS with 30 PostgreSQL-conditional skips; 172/172 Gateway
integration tests on PostgreSQL 18 after fresh migration and verified second-apply no-op; 93/93
certificate/signing and 33/33 architecture tests; Admin 28 unit, 37 UI-mock, 2 accessibility and
`FULLSTACK-01`; the 17-scenario deterministic M3 driver plus split-host regressions; a 416-file Core
export; conservative secret scan; Gitleaks over the 23 staged paths and 285 Git commits; no vulnerable
NuGet packages; and the complete container SBOM with 165 indexed packages. Exact-head General and
M5/Admin CI and the final independent micro-rereview remain pending; merge is not authorized.

## Residual limits

The final freshness boundary does not make publication and a network send globally transactional;
bytes already dispatched cannot be retracted. The provider, store, Gateway process and allowlisted
module remain trusted. Local Administrator/SYSTEM remains a residual privileged threat. Public
release and either motivating connector require their own specification, implementation,
qualification and independent review.

The host does not claim rollback of an effect completed while a strategy was still active. Scope
closure only prevents a tracked operation paused before effect from continuing toward that future
effect after strategy completion begins.

The later bounded per-slot evolution of this same signing and transport bridge is specified by
ADR-0025 and `WAVE1-AUTHORIZED-SIGNING-SLOTS.md`; this historical completion report and its single
profile checksum evidence are not rewritten.

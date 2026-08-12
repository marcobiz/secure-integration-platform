# Wave 1 provider-neutral Connector execution seam

## Scope and authority flow

The seam extends the existing production host; it does not introduce a second host or change the
qualified outbound authentication implementations. The invocation sequence is:

1. the production route authenticates BGW1 and creates `GatewayClientPrincipal`;
2. Core checks active identity state and the exact Connector/operation grant;
3. the catalog resolves one immutable Published snapshot for the authenticated Environment and
   captures an internal opaque execution stamp from that same snapshot;
4. Core obtains the explicit execution key, or its legacy server-side mapping;
5. the bounded registry resolves exactly one strategy and verifies its startup-snapshotted auth-kind
   compatibility;
6. for every external/non-Core strategy, Core requires an authoritative current Published operation,
   exact authority stamp, exact-key expectation provider and internal dispatcher; a non-authoritative
   external path is denied;
7. Core creates `AuthorizedConnectorExecution` over an owned bounded payload snapshot and the
   exact internal Published stamp used for operation/authentication/key resolution;
8. Core validates complete module expectations against that exact Published A; `false/empty` means
   exact verified absence of restricted transport and signing, not an opt-out;
9. only then does the strategy return the existing bounded `QualifiedGatewayExecutionResult`.

Outbound authentication remains a separate Published property. Core rejects an incompatible
strategy/auth-kind pair before `ExecuteAsync`; the request caller cannot choose either the
authentication policy or the execution strategy.

## Registration and loading

`Gateway:ExecutionModules` is a deployment-owned startup list. Every entry supplies `ModuleId`, a
canonical absolute `AssemblyPath`, exact `AssemblyFullName` and exact `ModuleType`. The loader caps
the list at 32 entries and admits only a canonical direct `.dll` on a local fixed drive. UNC,
mapped-network, device, traversal, symbolic-link and reparse-point paths are denied. It reads at
most 64 MiB once through one file handle, parses identity and MVID from that buffer, and passes the
same buffer to `AssemblyLoadContext.Default.LoadFromStream`; there is no `GetAssemblyName(path)` then
`LoadFromAssemblyPath(path)` gap. It requires one visible parameterless module type and rejects
duplicate path, type or ID. It does not enumerate directories or assemblies.

The module receives `IConnectorExecutionStrategyRegistrar`, not the application service collection
or provider. Registration is buffered until validation completes. The registrar caps each module
at 64 strategies and 128 total registrations, requires exactly one public constructor per concrete
implementation and recursively validates a maximum depth of 32. Every constructor edge must target
an explicitly registered type from the same module assembly. `IServiceProvider`, scope factories,
strategy collections, delegates, framework/host services, cross-module types and hidden recursive
variants are therefore denied. `SAFE_HOST_DEPENDENCIES` is empty. The final registry caps all
strategies at 256 and rejects duplicate keys before the host serves requests.

The minimum load model is one self-contained module assembly plus already loaded framework/Core
contracts. There is no companion probing. A future need for companion binaries requires an exact
deployment allowlist and resolver; it does not silently fall back to path or directory probing.

This is `EXPLICIT_ALLOWLISTED_LOADING`. A separate static composition host would require extracting
the current top-level API startup and duplicating or migrating its entry point, so it is not the
minimum safe change. The allowlist is configuration, not connector data; there is no discovery,
runtime installation, remote resolution, reload, unload or tenant-specific activation.

## Authorized capability bridge

`AuthorizedConnectorExecution.Capabilities` is the only sanctioned delegation path from an
external strategy to existing qualified capabilities. ADR-0023 initially admitted two methods:

- `ExecuteTypedSessionHandshakeAsync(CancellationToken)` validates the current store state against
  the initially authorized Published operation, derives its profile and reuses
  `TypedSessionHandshakeRuntime` and `SoapSessionClient`;
- `ExecuteComposedSoapAsync(CancellationToken)` reuses the internal authorized entry point of
  `ComposedSoapExecutionStrategy`.

Neither method accepts identity, Connector/operation, profile, endpoint, credential, provider,
transport or an arbitrary capability key. The concrete bridge is private, constructed with the
handoff, active only inside the owning strategy call and consumed once. A mutable active-scope check
plus exact bridge identity prevents a retained bridge from being invoked by a later execution,
including an inherited asynchronous execution context.

ADR-0024 adds only the signing and restricted-transport methods required by the qualified
capability-completion case. They preserve the same current-scope/exact-stamp enforcement and expose
no selectors; their complete API inventory and verification are in
`WAVE1-CONNECTOR-CAPABILITY-COMPLETION.md`.

The internal stamp binds Connector/version IDs, semantic version, publication revision, canonical
definition checksum, binding ID/revision/checksum, resource stamp, operation checksum,
authentication kind and execution strategy key. A resolver reread is only a validation of that
original authority; it can never adopt a newer Published snapshot. Handshake and composed SOAP
perform their final full stamp comparison after provider/DNS/resource preparation and immediately
before the first network or session-mutating effect. No unrelated awaited authority work occurs
between that comparison and dispatch. This is a final freshness check, not a claim that database
publication and network I/O are globally atomic; a revocation after dispatch starts cannot retract
bytes already sent.

Capability failures cross the external strategy through an internal non-constructible marker bound
to that exact bridge. The outer boundary preserves the qualified host failure only when the marker
belongs to the current execution. An external strategy cannot construct that path; its own
`GatewayException`, status and retryability are discarded and mapped to the stable generic failure.

## Failure behavior

| Condition | Behavior |
|---|---|
| malformed, missing or mismatched module identity | deterministic startup failure |
| duplicate module ID/path/type | deterministic startup failure |
| module registers no strategy or a non-owned type | deterministic startup failure |
| constructor reaches host DI, strategy collection, cross-module or nested forbidden dependency | deterministic startup failure before descriptors are committed |
| duplicate strategy key | startup failure before serving |
| explicit key absent from deployment | stable `BGW-EGRESS-AUTHENTICATION`, no default fallback |
| strategy does not declare the current Published authentication kind | stable `BGW-EGRESS-AUTHENTICATION` before strategy/network |
| external strategy has no authoritative Published operation/authority | stable `BGW-EGRESS-AUTHENTICATION`; provider, scope and strategy are not entered |
| external strategy lacks exact provider or dispatcher | stable `BGW-EGRESS-AUTHENTICATION` before expectation creation/scope/strategy |
| empty expectations but Published transport/signing is present | stable `BGW-EGRESS-AUTHENTICATION` before scope/signing/DNS/network |
| unexpected strategy exception or fake cancellation | stable `BGW-EGRESS-UPSTREAM-REJECTED`, no extension diagnostic |
| external strategy throws a valid-looking `GatewayException` | code/status/retryability discarded; stable `BGW-EGRESS-UPSTREAM-REJECTED` |
| provider failure raised by Core's built-in `default-http` strategy | existing sanitized `BGW-PROVIDER-*` code and retryability are preserved; an external module cannot forge this path |
| exact current bridge reports a qualified host capability failure | existing sanitized host code is preserved through exact authority ownership |
| current Published state differs from the bridge's initially authorized stamp | host-generated `BGW-CONNECTOR-CONFIGURATION-STALE` (503, retryable), with no provider/network/session effect after the stale boundary |
| retained, reused or unavailable bridge | denied; cross-invocation marker cannot be accepted as current authority |
| actual caller cancellation | cancellation preserved with the actual token |
| invalid or oversized strategy result | existing bounded egress failure |

Publication and module installation are deliberately independent. The immutable Published artifact
is portable, while every deployment still fails closed if its allowlist does not provide the exact
referenced key.

## Public API inventory

| Public surface | External need | Authority and mutation control |
|---|---|---|
| `ConnectorExecutionStrategyKey`, `MaximumLength`, `Value`, `Parse`, `TryParse`, `ToString` | a strategy declares its exact canonical key | contains no invocation authority; construction is validated and immutable |
| `ConnectorExecutionModuleId`, `MaximumLength`, `Value`, `Parse`, `ToString` | a module proves its identity against deployment configuration | contains no invocation authority; construction is validated and immutable |
| `IConnectorExecutionStrategy.Key`, `SupportedAuthenticationKinds` and `ExecuteAsync` | minimum execution contract and immutable startup compatibility declaration | Core snapshots metadata and receives only Core-created authority; no service locator or transport parameter |
| `IConnectorExecutionModule.Id` and `RegisterExecutionStrategies` | explicit startup hook | gets only the restricted registrar and is invoked once at startup |
| `IAuthorizedPublishedOperationExpectationProvider` and bounded expectation types | declare complete strategy semantics or exact absence for the current safe context | mandatory for every external strategy; exposes no policy, endpoint, provider, certificate, store or bridge authority |
| `IConnectorExecutionStrategyRegistrar.AddSingleton` overloads and `AddStrategy` | register module-owned dependencies and strategies | implementation rejects non-module-owned types and bounds registrations |
| `AuthorizedConnectorExecution` identity/version/operation/correlation/auth/key/content-type/length getters, `OpenPayloadStream` and `Capabilities` | read safe facts/business payload and invoke only sanctioned current-operation capabilities | no public constructor/factory/setter; payload is copied; the private bridge is scope-bound and one-shot |
| `IAuthorizedConnectorCapabilityBridge.ExecuteTypedSessionHandshakeAsync` and `ExecuteComposedSoapAsync` | reuse the two original qualified host capabilities without friend access | no selector parameters or exported implementation; exact current authority only |
| `GatewayOperationDefinition.ExecutionStrategy` | carry the already parsed Published choice through the internal catalog/runtime boundary | record is existing server-side catalog data; caller wire contracts cannot populate it |
| `GatewayOperationConfiguration.ExecutionStrategy` | bind an explicitly configured development/runtime catalog entry | startup configuration only; validated into the same key type |
| `GatewayHostOptions.ExecutionModules`; `GatewayExecutionModuleOptions` and its four properties | bind the deployment allowlist | startup configuration only; the loader revalidates every field before loading |

`QualifiedGatewayExecutionResult` is reused unchanged. The earlier strategy interface and handoff
names are replaced rather than kept as a parallel extension surface.

## Compatibility and qualification

Legacy definitions remain byte-for-byte stored and load without republish. Their server mappings are:

- ordinary no-auth, Basic, API key, mTLS and combined API key/mTLS: `default-http`;
- opaque-session HTTP: `opaque-session-http`;
- composed SOAP: `composed-soap`.

The neutral support assembly references only public `Gateway.Application` execution contracts,
receives no friend access and
proves the production HTTP/BGW1/grant/Published/registry path. It also proves caller override
attempts in payload, query, header and metadata, missing and duplicate keys, immutable payload,
auth-kind mismatch before strategy/network, constructor-graph denial, sanitized forged host errors,
real versus fake cancellation, retained-bridge denial and same-image TOCTOU loading. A second hosted
path selects the external strategy for both session bootstrap and business operation, completes the
existing authenticated external-admission route, and proves composed SOAP reuse of the same promoted
session generation. The same complete lifecycle also runs against real PostgreSQL Published state,
distinct editor/approver four-eyes publication, authenticated hosted admission and the real HTTPS
synthetic SOAP server. Deterministic external-bridge A-to-B races prove zero handshake provider/
network/session effects and zero composed SOAP dispatch or session reacquisition; the latter also
changes the Published strategy key. Separate startup negatives prove cross-module dependency and a
module-owned constructor cycle are rejected without descriptors from the failing module. Existing
ordinary HTTP, opaque-session, composed SOAP and typed session suites remain regression gates.

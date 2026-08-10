# ADR-0023: Provider-neutral Connector execution seam

**Status:** Accepted

## Context

The production Gateway already supports ordinary restricted HTTP, opaque-session HTTP and composed
SOAP dispatch. Its strategy choice was coupled to outbound authentication kind, and the API
composition root named every supported strategy. Adding an optional trusted connector runtime would
therefore require a Core source change, a friend-assembly grant or another host.

Authentication kind and execution strategy answer different questions. Authentication kind defines
the server-owned outbound credential semantics. An execution strategy identifies the trusted runtime
that receives an already authenticated, granted and Published-resolved invocation.

## Decision

- `ConnectorExecutionStrategyKey` is an immutable lower-case ASCII identifier, 1--64 characters,
  stored optionally on a Connector operation. The Connector schema, canonical JSON checksum and
  checksum-specific four-eyes artifact cover an explicit key. Invocation payload, metadata, query
  and headers are not selection inputs.
- Definitions without the member are not rewritten. Core derives `default-http`,
  `opaque-session-http` or `composed-soap` from the existing authentication kind. Unsupported legacy
  modes remain denied as before.
- After inbound authentication, active-state checks, exact grant and current Published operation
  resolution, `RestrictedEgressService` derives one key and performs an exact lookup in a bounded
  startup registry. Duplicate keys fail startup. Missing and unknown keys fail the invocation; an
  explicit key never falls back to default HTTP.
- A strategy implements `Key`, a closed `SupportedAuthenticationKinds` declaration and
  `ExecuteAsync(AuthorizedConnectorExecution, CancellationToken)`. Core validates and snapshots
  the compatibility metadata at startup, then rejects a Published auth-kind mismatch before the
  strategy or network can run. The existing `QualifiedGatewayExecutionResult` remains the result
  contract.
- `AuthorizedConnectorExecution` has no public constructor or factory and no writable public state.
  It exposes authenticated Tenant/Application/Installation/Environment identity, Published
  Connector/version/operation, correlation, authentication kind, selected key, content type and
  payload length. Each payload stream is an independent read-only view of a Core-owned copied
  snapshot. It exposes no inbound credential, request header, endpoint, provider locator or secret
  reference.
- The handoff exposes one non-constructible, per-invocation `IAuthorizedConnectorCapabilityBridge`
  with only typed-session-handshake and composed-SOAP methods. Both methods operate on the current
  handoff and accept only its cancellation token: there is no identity, operation, profile,
  endpoint, credential, provider, transport or service selector. The bridge is active only while
  the owning strategy executes, is one-shot and rejects retention or cross-invocation replay.
- Deployment configuration explicitly identifies each optional module by canonical absolute path,
  exact assembly full name, exact module type and exact module ID. Startup loads only those entries;
  it never scans a directory, loaded assemblies or filename convention. IDs, types and paths are
  unique and module/strategy counts are bounded.
- Module paths must be canonical direct files on a local fixed drive. UNC, mapped-network, device,
  traversal, symbolic-link and reparse-point paths are denied. Core reads one bounded assembly
  image once, verifies metadata from that buffer and loads the same buffer, checking its MVID; the
  path is never reopened between identity acceptance and activation.
- `IConnectorExecutionModule` receives a narrow registrar. It may register only types owned by its
  own assembly, as singleton services or execution strategies. It receives neither
  `IServiceCollection` nor `IServiceProvider`. Before committing descriptors, the registrar
  recursively validates one unambiguous public constructor per implementation, bounds graph depth
  and registrations and permits only explicitly registered module-owned dependencies. There is no
  safe host-service allowlist, strategy collection injection or cross-module constructor edge.
  Modules are fixed at startup; install, upload, download, dependency negotiation, reload and
  unload are not runtime features.
- Only built-in strategies marked through an internal Core contract may preserve their qualified
  `GatewayException` or provider failure. Every external exception, including a forged
  `GatewayException`, becomes `BGW-EGRESS-UPSTREAM-REJECTED`. A capability failure is preserved
  only through a non-constructible internal marker bound to the exact current bridge authority.
- Optional modules are trusted in-process deployment components, not sandboxed plugins. Exact
  identity and path prevent accidental or connector-controlled discovery but are not a code-signing
  claim. Host ACLs, deployment provenance and release controls remain responsible for module bytes.

## Consequences

Core starts with no optional modules and retains its existing built-in execution behavior. A new
trusted module can be deployed without a per-module API source branch, a reverse dependency or
friend access. Publication is allowed even when a referenced module is unavailable so the same
immutable definition can move between deployments; runtime availability remains independently
fail-closed.

The minimum loader supports one self-contained module assembly whose dependencies are already
shared framework/Core contracts. Companion probing and dependency resolution are not implicit;
adding companion assemblies requires a future exact allowlisted resolver and is not part of this
decision.

An explicit outer composition host was rejected because the current top-level API startup has no
small reusable hosting boundary; extracting one would be a wider host migration. Explicit
allowlisted loading is the smaller change and follows the existing deployment-owned pack principle.
A general plugin framework, dynamic discovery and untrusted in-process extensions remain outside
this decision.

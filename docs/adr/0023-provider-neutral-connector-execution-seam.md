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
- A strategy implements only `Key` and `ExecuteAsync(AuthorizedConnectorExecution,
  CancellationToken)`. The existing `QualifiedGatewayExecutionResult` remains the result contract.
- `AuthorizedConnectorExecution` has no public constructor or factory and no writable public state.
  It exposes authenticated Tenant/Application/Installation/Environment identity, Published
  Connector/version/operation, correlation, authentication kind, selected key, content type and
  payload length. Each payload stream is an independent read-only view of a Core-owned copied
  snapshot. It exposes no inbound credential, request header, endpoint, provider locator or secret
  reference.
- Deployment configuration explicitly identifies each optional module by canonical absolute path,
  exact assembly full name, exact module type and exact module ID. Startup loads only those entries;
  it never scans a directory, loaded assemblies or filename convention. IDs, types and paths are
  unique and module/strategy counts are bounded.
- `IConnectorExecutionModule` receives a narrow registrar. It may register only types owned by its
  own assembly, as singleton services or execution strategies. It receives neither
  `IServiceCollection` nor `IServiceProvider`. Modules are fixed at startup; install, upload,
  download, dependency negotiation, reload and unload are not runtime features.
- Optional modules are trusted in-process deployment components, not sandboxed plugins. Exact
  identity and path prevent accidental or connector-controlled discovery but are not a code-signing
  claim. Host ACLs, deployment provenance and release controls remain responsible for module bytes.

## Consequences

Core starts with no optional modules and retains its existing built-in execution behavior. A new
trusted module can be deployed without a per-module API source branch, a reverse dependency or
friend access. Publication is allowed even when a referenced module is unavailable so the same
immutable definition can move between deployments; runtime availability remains independently
fail-closed.

An explicit outer composition host was rejected because the current top-level API startup has no
small reusable hosting boundary; extracting one would be a wider host migration. Explicit
allowlisted loading is the smaller change and follows the existing deployment-owned pack principle.
A general plugin framework, dynamic discovery and untrusted in-process extensions remain outside
this decision.

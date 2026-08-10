# Wave 1 provider-neutral Connector execution seam

## Scope and authority flow

The seam extends the existing production host; it does not introduce a second host or change the
qualified outbound authentication implementations. The invocation sequence is:

1. the production route authenticates BGW1 and creates `GatewayClientPrincipal`;
2. Core checks active identity state and the exact Connector/operation grant;
3. the catalog resolves the current immutable Published operation for the authenticated
   Environment;
4. Core obtains the explicit execution key, or its legacy server-side mapping;
5. the bounded registry resolves exactly one strategy;
6. Core creates `AuthorizedConnectorExecution` over an owned bounded payload snapshot;
7. the strategy returns the existing bounded `QualifiedGatewayExecutionResult`.

Outbound authentication remains a separate Published property. A strategy may reject an
incompatible authentication kind, but the request caller cannot choose either the authentication
policy or the execution strategy.

## Registration and loading

`Gateway:ExecutionModules` is a deployment-owned startup list. Every entry supplies `ModuleId`, a
canonical absolute `AssemblyPath`, exact `AssemblyFullName` and exact `ModuleType`. The loader caps
the list at 32 entries, loads only an exact configured path in the default load context, verifies
the disk and loaded identities, requires one visible parameterless module type and rejects duplicate
path, type or ID. It does not enumerate directories or assemblies.

The module receives `IConnectorExecutionStrategyRegistrar`, not the application service collection
or provider. The registrar accepts only module-owned types, caps each module at 64 strategies and
registers them once as singletons. The final registry caps all strategies at 256 and rejects duplicate
keys before the host serves requests.

This is `EXPLICIT_ALLOWLISTED_LOADING`. A separate static composition host would require extracting
the current top-level API startup and duplicating or migrating its entry point, so it is not the
minimum safe change. The allowlist is configuration, not connector data; there is no discovery,
runtime installation, remote resolution, reload, unload or tenant-specific activation.

## Failure behavior

| Condition | Behavior |
|---|---|
| malformed, missing or mismatched module identity | deterministic startup failure |
| duplicate module ID/path/type | deterministic startup failure |
| module registers no strategy or a non-owned type | deterministic startup failure |
| duplicate strategy key | startup failure before serving |
| explicit key absent from deployment | stable `BGW-EGRESS-AUTHENTICATION`, no default fallback |
| unexpected strategy exception or fake cancellation | stable `BGW-EGRESS-UPSTREAM-REJECTED`, no extension diagnostic |
| provider failure raised by Core's built-in `default-http` strategy | existing sanitized `BGW-PROVIDER-*` code and retryability are preserved; an external module cannot forge this path |
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
| `IConnectorExecutionStrategy.Key` and `ExecuteAsync` | minimum execution contract | receives only Core-created authority; no service locator or transport parameter |
| `IConnectorExecutionModule.Id` and `RegisterExecutionStrategies` | explicit startup hook | gets only the restricted registrar and is invoked once at startup |
| `IConnectorExecutionStrategyRegistrar.AddSingleton` overloads and `AddStrategy` | register module-owned dependencies and strategies | implementation rejects non-module-owned types and bounds registrations |
| `AuthorizedConnectorExecution` identity/version/operation/correlation/auth/key/content-type/length getters and `OpenPayloadStream` | read the safe facts and business payload needed for execution | no public constructor/factory/setter; payload is copied and exposed only through a non-writable, non-publicly-visible stream buffer |
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

The neutral support assembly references only `Gateway.Application`, receives no friend access and
proves the production HTTP/BGW1/grant/Published/registry path. It also proves caller override
attempts in payload, query, header and metadata, missing and duplicate keys, immutable payload,
sanitized extension failures and real versus fake cancellation. Existing ordinary HTTP,
opaque-session, composed SOAP and typed session suites remain regression gates.

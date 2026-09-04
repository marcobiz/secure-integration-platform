# ADR-0020: Direct Gateway Access and unified runtime principal

**Status:** Accepted

## Context

Until M5, the Local Broker was the Gateway's only runtime client. However, enrollment,
mTLS, BGW1 signing, replay protection, grants and Tenant/Application resolution were already
`Installation` concepts, not properties of the Broker process. A second runtime or
protocol would have duplicated security-critical controls.

## Decision

- `InstallationKind` distinguishes `Broker` and `Direct`; existing M5 rows are migrated
  additively to `Broker`.
- both kinds use the existing ClientAuth mTLS, ECDSA P-256 key, enrollment PoP, BGW1,
  timestamp, nonce, renewal, overlap and revocation;
- `BrokerVersion` remains compatible and subject to Application policy for
  Broker installations; a Direct installation uses `ClientVersion` and cannot send
  `BrokerVersion`;
- authentication produces one `GatewayClientPrincipal`, derived exclusively
  from the server-side registry;
- Connector Runtime, grants, binding, providers, cache, restricted egress and audit
  consume that principal and do not create caller-specific pipelines;
- `/v1/broker-policy` intentionally remains Broker-only; enrollment, renewal and invoke
  retain the existing routes;
- runtime requests contain no Tenant, Application, destination, provider or
  secret/certificate references.

## Consequences

A modern application can invoke the Gateway without installing or simulating the Broker,
but must protect its own client key. Theft of a Direct installation key remains
a client-endpoint risk and requires revocation/rotation. The Gateway's trusted computing
base does not change and no new `GetSecret` is introduced.

## Rejected alternatives

BGW2, `DirectConnectorRuntime`, static bearer tokens, client-supplied Tenant/Application,
Named Pipe or DPAPI in the Direct path and late bindings chosen by the caller.

# Connector SDK v1

The definition SDK is the portable contract comprising JSON Schema, samples, Admin
REST API and contract tests. The original M4 slice did not introduce a binary plugin
ABI. For current compiled extensions, use the
[authorized execution contract](../../src/Gateway/Gateway.Application/ConnectorExecutionContracts.cs)
and [runtime authentication contract](../architecture/connector-runtime-auth-contract.md);
modules receive bounded Core capabilities, not generic provider or HTTP access.

## Developer workflow

1. Copy [sample-secure-service.connector.json](examples/sample-secure-service.connector.json).
2. Declare operations and logical bindings without URIs or provider references.
3. Run `connector validate`.
4. Import, observe `rowVersion` and validate the stored version.
5. Configure server-owned Environment bindings and exact Installation/operation grants,
   then request distinct four-eyes approval and publish with optimistic concurrency.
6. Verify Published/Active read-back, run the supported controlled test and invoke
   through the Direct runtime or Legacy/Broker SDK as appropriate.

The [guided onboarding procedure](../user/guided-connector-onboarding.md) owns the
current role handoffs and recovery sequence. Bindings precede approval/publication;
this is not a manual SQL or direct-store workflow.

## Minimum contract suite

A definition is acceptable when it passes Draft 2020-12 and documented semantic rules, its canonical checksum is stable, every binding is declared, no protected header is client-controlled and retry/idempotency are consistent. Tests in `ConnectorConfigurationTests` form the reference suite.

## Compatibility

M4 supports only `schemaVersion: "1.0"`. Compatible additive changes remain in major 1; incompatible semantics require a new schema major and an explicit Core update. No unknown fields are accepted.

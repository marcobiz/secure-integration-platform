# Developing a Connector

**Audience:** Connector developers and runtime maintainers.
**Status:** CURRENT.

A Connector is a declarative, versioned JSON definition, plus a compiled extension
only where strictly necessary for a protocol that the existing runtime cannot express.
It is not a workflow engine and contains no concrete endpoints, credentials,
provider locators, tenants, scripts or dynamic code.

## Minimum path

1. Read the [minimal anatomy](minimal-connector-anatomy.md).
2. Copy the [REST sample](../connectors/examples/sample-secure-service.connector.json).
3. Validate against the [schema](../connectors/connector-definition.schema.json)
   and [specification](../connectors/connector-specification.md) rules.
4. Implement the [golden path](golden-path.md) from clean state to the first call.
5. Add positive and negative tests only for boundaries actually introduced.

## Product rules

- Callers select only already-authorized Connectors and operations. Tenant,
  Installation, Environment, endpoints, providers and credentials remain server-owned.
- Lifecycle: `Draft → Validated → Published → Superseded → Retired`; Published is
  immutable and requires four-eyes approval of the exact checksum/digest.
- Deny-by-default grants and complete bindings precede every invocation.
- First-use adoption is Connector functionality: one idempotent
  `plan → apply → verify` or equivalent Admin workflow must exist.
- No adopter should need to know migrations, tables, test fixtures, milestones or
  internal repository structure.
- If the same onboarding friction appears in a second Connector, resolve it at the
  narrowest shared boundary; do not duplicate vertical runbooks or bootstrap.

The SDK reference is [docs/connectors/connector-sdk.md](../connectors/connector-sdk.md).
Simplicity and compensation rules are in
[docs/internal/complexity-governance.md](../internal/complexity-governance.md).

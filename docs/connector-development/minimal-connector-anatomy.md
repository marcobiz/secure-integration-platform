# Minimal Connector anatomy

**Audience:** Connector developers.
**Status:** CURRENT for Connector Definition JSON v1.

The machine-readable source is
[connector-definition.schema.json](../connectors/connector-definition.schema.json).
The [REST sample](../connectors/examples/sample-secure-service.connector.json)
is the executable starting point.

## Required content

| Part | Contains | Does not contain |
|---|---|---|
| Identity | `schemaVersion`, Connector ID, semantic version, name. | Tenant, Environment or runtime identity. |
| Logical bindings | Required endpoint, secret and certificate names. | URIs, secret values, P12 files, paths or provider locators. |
| Operation | Authorized ID, method/path/template, content type, timeout and bounded limits. | Caller-selected URLs, arbitrary headers or workflows. |
| Authentication | A supported profile and logical capability references. | Runtime-selectable algorithms, keys or certificates. |
| Reliability | Consistent idempotency/retry and redirect denial. | Unlimited retries or stale fallback. |
| Extension | Only closed configuration covered by the checksum, if a typed strategy is needed. | Scripts, reflection, dynamic code or service locators. |

## Server-owned bindings

For each Environment, the administrator associates logical names with HTTPS endpoints
and revisioned provider resources. Secret retrieval, client certificates, signing/MAC,
health and capability discovery remain separate contracts. The exported definition
and runtime request do not contain concrete values.

## When compiled code is needed

Use existing REST operations and supported profiles first. A compiled strategy/module
is justified only by a current requirement that cannot be expressed safely with typed
primitives. It must receive an already-authenticated, granted and Published invocation,
without general-purpose store, provider, secret, HTTP or signing access.

Do not introduce a generic framework/plugin for a possible future Connector.
If an abstraction does not remove measured duplication in at least two current cases,
keep it local to the capability that requires it.

## Minimum pre-import checklist

- Schema-compliant JSON, unknown fields denied and stable canonical checksum;
- logical bindings declared once and used by known operations;
- no client-controlled sensitive/hop-by-hop headers;
- bounded requests/responses/timeouts;
- retries allowed only with idempotent semantics or a mandatory idempotency key;
- destination, authentication and provider absent from caller-owned payloads;
- negative tests for missing grants, missing/drifted bindings, unknown operations and
  oversized input;
- [first-call path](golden-path.md) defined before expanding the surface.

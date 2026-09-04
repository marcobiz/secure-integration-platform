# Connector Definition JSON v1

The machine-readable source is [connector-definition.schema.json](connector-definition.schema.json), JSON Schema Draft 2020-12. The executable sample is [sample-secure-service.connector.json](examples/sample-secure-service.connector.json).

## Format boundary

A definition declares:

- `schemaVersion`, identity and semantic version;
- logical endpoint and secret names;
- REST operations with fixed method/path;
- request/response limits and timeout;
- built-in REST authentication `none`, `basic`, `apiKey`, `mtls` or `apiKeyAndMtls`, capability-bound OAuth profiles and opt-in `opaqueSessionHttp`/`soapBasicOpaqueSession` modes applied by the Gateway;
- redirect denial, client-header allowlist, idempotency and bounded retries.

It contains no URIs, secret values, provider references, tenant, code, scripts, expressions or workflows. The runtime client selects only `connectorId` and `operationId`; endpoints, credentials and Published version are resolved server-side.

## Lifecycle

| State | Administrative use | Invocable |
|---|---|---|
| Draft | Initial import | No |
| Validated | Schema and semantics verified | No |
| Published | Active immutable version | Yes |
| Superseded | Previously published version replaced | No; may be a rollback target |
| Retired | Permanently revoked | No |

Reimporting the same version is rejected. Validation, publication, rollback and retirement require the observed `rowVersion`; publication also requires `publicationRevision`. Rollback reactivates a previously published Superseded version and does not create a copy.

## Canonicalization and checksum

Object members are ordered ordinally, insignificant whitespace is removed and integers are normalized. JSON v1 accepts no noninteger numbers. Uppercase SHA-256 of canonical UTF-8 JSON accompanies import/export and detects transfer or storage corruption.

## Server-side bindings

For each Environment, the administrator maps logical names to HTTPS endpoint URIs and opaque Secret Provider references. Values are not returned by export or included in audit. Missing bindings, non-Published Connectors, missing operations or unavailable stores fail closed.

## Runtime cache

The Published snapshot has a configurable TTL. Before every invocation, the Gateway reads a reduced stamp (`version`, checksum, publication revision and binding revision). If the stamp changes, the cache is invalidated and reloaded; if loading fails, the previous snapshot is not used. Publication, rollback, retirement and binding changes also invalidate the local cache.

## Additional semantic rules

- every logical binding and `operationId` is unique;
- every reference used by an operation must be declared;
- sensitive or hop-by-hop headers cannot be client-controlled;
- `opaqueSessionHttp` uses only typed custom placement (`headerName`, `valueFormat`, optional `fixedScheme`) and cannot use Authorization, SOAPAction, Content-Type, routing, proxy, forwarding, tracing or correlation headers;
- `soapBasicOpaqueSession` requires POST, logical username/password/session bindings, opaque placement and typed `soapHttp` (`version` 1.1/1.2 and absolute action); Content-Type and SOAPAction are derived and there is no header bag;
- retries require an idempotent operation or mandatory idempotency key;
- redirect is always `deny` in v1;
- endpoints and paths cannot be overridden by payloads;
- Installation/Connector/operation grants are deny-by-default.

## Outside M4 and generic capability scope

YAML, UI, plugins, scripting, arbitrary workflows, SAML, WS-Security, XML-DSig, additional cloud providers and real connectors. Generic OAuth/SOAP/session capabilities do not automatically qualify any external production profile. Older managed/secure-layer examples describe pre-M4 analysis and are not executable Connector Definition v1 files.

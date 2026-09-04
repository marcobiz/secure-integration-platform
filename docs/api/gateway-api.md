# Gateway API

The machine-readable specification is [gateway-openapi.yaml](gateway-openapi.yaml).

OpenAPI `info.version` identifies the product/API candidate `0.1.0-alpha.1`. It does not change
runtime protocol `1.0` or canonical Connector `sample-secure-service/1.0.0`.

## Runtime

`POST /v1/connectors/{connectorId}/operations/{operationId}:invoke` retains the M2/M3 contract. Installation certificate, ECDSA P-256 signature, timestamp, nonce, content hash and `traceparent` are mandatory. Tenant and Environment derive from the authenticated Installation; they are not authoritative if present in the body.

The client selects only already authorized Connector and operation IDs. URL, method, endpoint binding, secret reference, algorithm and credentials are not part of the request. The runtime accepts only a Published version and applies deny-by-default grants before resolving secrets or invoking the network.

The minimal public request is:

```json
{
  "protocolVersion": "1.0",
  "payload": {
    "contentType": "application/json",
    "encoding": "base64",
    "data": "eyJtZXNzYWdlIjoiZGlyZWN0LWdhdGV3YXktc2FtcGxlIn0="
  },
  "correlationId": "11111111-1111-1111-1111-111111111111"
}
```

`payload.encoding` accepts `base64` or `utf8`. `idempotencyKey`, `operatorContext`,
`metadata` and `extensions` are optional and provide no authority over Tenant, Published
profile, endpoint, provider, transport or credentials. Additional fields are rejected.

HTTP `200` success uses `application/json` and the public named schema
`InvokeResponse`:

```json
{
  "correlationId": "11111111-1111-1111-1111-111111111111",
  "connectorVersion": "1.0.0",
  "result": {
    "contentType": "application/json; charset=utf-8",
    "encoding": "base64",
    "data": "eyJhY2NlcHRlZCI6dHJ1ZSwidmVuZG9yUmVmZXJlbmNlIjoic3ludGhldGljLW9yZGVyIn0="
  }
}
```

`result` contains only the bounded application result returned by the
authorized Connector; it exposes no upstream HTTP status/headers, resolved endpoints,
provider references or credentials. The caller decodes `result.data` according to
`result.encoding` and deserializes the application type expected by the operation.

## Admin Connector API

| Method and path | Function |
|---|---|
| `POST /admin/v1/connectors:validate` | validates a definition without persisting it |
| `POST /admin/v1/connectors:import` | imports a new Draft version |
| `GET /admin/v1/connectors` | redacted list |
| `GET /admin/v1/connectors/{id}/versions` | versions and lifecycle |
| `GET /admin/v1/connectors/{id}/versions/{version}` | version metadata |
| `GET /admin/v1/connectors/{id}/versions/{version}:export` | canonical JSON, without bindings |
| `POST .../{version}:validate` | Draft → Validated with `expectedRowVersion` |
| `POST .../{version}:publish` | Validated → Published with row/publication revision |
| `POST /admin/v1/connectors/{id}:rollback` | reactivates a previously published Superseded version |
| `POST .../{version}:retire` | revokes a version |
| `PUT /admin/v1/connectors/{id}/bindings` | configures server-side Environment bindings |
| `POST /admin/v1/connectors/{id}:test` | nondestructive Published + binding check |

Import/export uses JSON only. An optional expected checksum protects import; export returns canonical form. A concurrency mismatch returns a stable error and applies no partial transitions.

## Admin authentication

The default mode is `Disabled`. `DevelopmentApiKey` is allowed only in the non-production environments specified by ADR-0012 and reads the key from the configured variable. The CLI does not accept the key as an argument. A production deployment must connect the Admin boundary to OIDC/policy without changing the Connector format.

## Errors and redaction

Errors use stable `BGW-*` codes. Responses and audit include no payloads, resolved URIs, provider references, authentication headers or secret values. Checksum/storage corruption, non-Published state, missing bindings, unavailable stores and concurrency preconditions fail closed.

## Health

`GET /health/live` checks the process. `GET /health/ready` checks the registry and Secret Provider. Connector runtime availability is also checked during Published-stamp resolution: stale-on-error is not allowed.

# Local Broker IPC protocol

> **Contract status:** provisional after M1. Implemented framing and operations are stable for internal tests, but IPC v1 is not frozen for COM/C ABI/CLI. Freezing requires validation through M2 and the production-like M3 vertical slice, including streaming and the compatibility matrix.

## Transport

Windows Named Pipe `\\.\pipe\<Vendor>.<Product>.Broker.v1`, byte mode, full duplex. A localhost API is outside the MVP.

## Framing

Each frame uses network byte order:

| Field | Bytes | Description |
|---|---:|---|
| Magic | 4 | ASCII `BGR1`. |
| Major | 1 | Protocol major. |
| Minor | 1 | Protocol minor. |
| Type | 1 | Control, Data, End, Cancel or Error. |
| Flags | 1 | Reserved; must be zero in v1. |
| Length | 4 | Body length, maximum depends on frame type. |
| Correlation ID | 16 | UUID bytes. |
| Sequence | 8 | Monotonic counter per connection. |
| Body | N | UTF-8 JSON or bytes. |

Maximum control frame 1 MiB. Maximum data chunk 64 KiB. Standard aggregate payload 16 MiB; maximum stream 64 MiB. Incomplete frames, incorrect magic/version, duplicate sequences or nonzero reserved flags close the connection.

## Handshake

Client:

```json
{
  "message": "HandshakeRequest",
  "supported": {"major": 1, "minMinor": 0, "maxMinor": 0},
  "applicationRegistrationId": "sample.legacy",
  "clientNonce": "synthetic-base64url"
}
```

Server:

```json
{
  "message": "HandshakeResponse",
  "selected": {"major": 1, "minor": 0},
  "connectionId": "00000000-0000-7000-8000-000000000001",
  "serverChallenge": "synthetic-base64url",
  "limits": {"controlBytes": 1048576, "payloadBytes": 16777216, "streamBytes": 67108864}
}
```

Before responding, the Broker acquires the client PID, process handle, creation time and Windows identity. The Application manifest determines path, publisher/hash and operation grants.

## Request envelope

```json
{
  "message": "Request",
  "operation": "ComputeHmac",
  "protocolVersion": "1.0",
  "correlationId": "00000000-0000-7000-8000-000000000001",
  "connectionChallenge": "synthetic-base64url",
  "requestNonce": "synthetic-base64url",
  "deadlineUtc": "2026-08-02T12:00:00Z",
  "body": {}
}
```

Unknown properties are rejected, except within `extensions`. Maximum deadline 60 seconds. Duplicate nonces are rejected.

## v1 operations

| Operation | Essential input | Output | Notes |
|---|---|---|---|
| `PutLocalSecret` | logical name, class, bytes, allowed uses | opaque ref | Tenant/Session only; never Vendor Secret. |
| `DeleteLocalSecret` | opaque ref | status | Idempotent. |
| `ProtectData` | purpose, content type, bytes | AEAD envelope | Key/AAD scoped to the Application. |
| `UnprotectData` | purpose, envelope | bytes | Fails entirely on authentication error. |
| `PutSession` | connector, operation, value, expiry | sessionRef | Memory default, DPAPI only if requested/allowed. |
| `DeleteSession` | sessionRef | status | Idempotent. |
| `ComputeHmac` | connector, operation, secretRef, message | digest | Algorithm fixed by policy. |
| `SignData` | connector, operation, key policy, digest/data | signature | Claims/payload constraints enforced. |
| `UseLocalCertificate` | connector, operation, certificate policy, request | result | Private key never exported. |
| `InvokeGateway` | connector, operation, payload/context | result/sessionRef | No arbitrary URLs or secret names. |
| `GetBrokerStatus` | detail level | health/version | No sensitive metadata. |
| `Cancel` | target correlation ID | status | Best effort. |

`GetSecret` does not exist. A future `RevealCompatibilitySecret` requires a feature flag, Application/secret allowlist, expiry, audit and an ADR; it must never expose Vendor Secrets.

## Responses and errors

```json
{
  "message": "Response",
  "correlationId": "00000000-0000-7000-8000-000000000001",
  "success": false,
  "error": {
    "code": "BGR-AUTHZ-003",
    "category": "authorization",
    "retryable": false
  }
}
```

Categories: protocol, identity, authorization, validation, storage, cryptography, gateway, timeout, cancelled and internal. Errors and exceptions contain no confidential paths, values, payloads or stack traces.

## Concurrency and cancellation

- Multiple connections per process are allowed within policy.
- Each connection supports concurrent requests distinguished by correlation ID.
- Default: 16 concurrent requests per Application; configurable only by the administrator.
- Backpressure before reading large payloads.
- Cancel does not interrupt a cryptographic primitive already in progress, but prevents subsequent phases.

## Compatibility

- Different major: handshake rejected.
- Minor selected as the highest common value.
- New operations require a minor increment.
- New optional fields are allowed only within `extensions` until the minor is negotiated.
- SDK and Broker maintain a tested compatibility matrix.

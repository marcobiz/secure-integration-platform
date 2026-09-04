# Observability and operations

## Principles

- OpenTelemetry for logs, metrics and tracing.
- W3C `traceparent` and correlation ID from the adapter to the external service.
- Redaction before export.
- No health check exposes configuration or detailed secret metadata.
- Audit and telemetry have distinct purposes and retention policies.

## Health

### Local Broker

- service/pipe availability;
- storage and synthetic DPAPI round-trip;
- identity key accessibility;
- enrollment/credential state and expiry;
- Gateway last contact;
- broker/version compatibility;
- queue/concurrency saturation.

Offline diagnostics return reason codes, not blobs/paths/secrets.

### Gateway

- liveness: event loop/process.
- readiness: minimal DB query, active deployment cache and rate-limited Vault metadata call.
- dependency details available only to admins.
- Connector health runs on demand or on schedule with a synthetic payload, not in global readiness.

## Minimum metrics

- `broker_ipc_requests_total` by operation/result.
- `broker_ipc_duration_ms` histogram.
- `broker_authorization_denied_total`.
- `gateway_invocations_total` by Connector/operation/outcome.
- `gateway_duration_ms` and `external_duration_ms` histograms.
- `gateway_authentication_failures_total`.
- `gateway_cross_tenant_denials_total`.
- `vault_requests_total`, latency and throttling.
- `connector_config_errors_total`.
- `connector_cache_age_seconds`.
- `certificate_expiry_days`.
- `token_refresh_failures_total`.
- `revoked_installation_attempts_total`.
- `broker_version_distribution` and outdated brokers.
- `egress_policy_denials_total` by reason code.

Tenant and Installation do not become high-cardinality metric labels; they remain in searchable audits/events.

## Tracing

Main spans:

```text
sdk.invoke
  broker.ipc
    broker.authorize
    gateway.http
      gateway.authenticate
      connector.resolve
      connector.validate
      vault.operation
      external.http
```

Payloads, authorization headers and sensitive queries are not span attributes. External URLs are normalized to endpoint/operation IDs, not recorded in full when they contain parameters.

## Logging

Structured JSON. Common fields: timestamp, level, event code, correlation, trace/span, component, connector, operation, installation, tenant, outcome, duration and reason code.

Mandatory redaction tests cover:

- Authorization/Cookie/API key;
- access/refresh/session tokens;
- passwords/PINs/OTPs;
- private keys/certificate bundles;
- XML/JSON payloads;
- external provider exceptions.

## Initial alerts

- Authentication failure rate above baseline.
- Attempts by revoked Installations.
- Nonzero cross-Tenant denials.
- Sustained Vault errors/throttling.
- External failure rate or latency by Connector.
- Stale Connector configuration/cache.
- Certificates expiring in 30/14/7 days.
- Brokers below the minimum supported version.
- Overdue secret rotation.
- Readiness failure or DB failover.
- Sudden increase in egress policy denials.

Numeric thresholds are calibrated in test/preproduction and documented per Environment.

## Retry and circuit breaker

- Connect timeout: 5 seconds; default operation timeout: 30 seconds.
- At most 2 retries with exponential backoff and jitter.
- Only transient errors and idempotent operations.
- No automatic retry on 4xx auth/validation or non-idempotent responses.
- Circuit breaker isolated per endpoint/Connector, not global.

## Minimum runbooks

- Revoke/re-enroll an Installation.
- Rotate Vendor/Tenant Secrets without downtime.
- Diagnose Vault/DB/external outages.
- Publish and roll back ConnectorVersions.
- Handle expiring certificates.
- Restore PostgreSQL and verify RLS/audit.
- Upgrade Broker and repair ACLs/service identity.
- Incident response for possible secret exposure.

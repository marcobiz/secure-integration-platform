# Osservabilità e operazioni

## Principi

- OpenTelemetry per log, metrics e tracing.
- W3C `traceparent` e correlation ID dall'adapter al servizio esterno.
- Redaction prima dell'export.
- Nessun health check espone configurazione o secret metadata dettagliati.
- Audit e telemetry hanno scopi e retention distinti.

## Health

### Local Broker

- servizio/pipe disponibili;
- storage e DPAPI round-trip sintetico;
- identity key accessibile;
- enrollment/credential state e scadenza;
- Gateway last contact;
- broker/version compatibility;
- queue/concurrency saturation.

La diagnostica offline restituisce reason code, non blob/path/secret.

### Gateway

- liveness: event loop/process.
- readiness: DB query minimale, active deployment cache e Vault metadata call rate-limited.
- dependency detail disponibile solo agli admin.
- Connector health eseguito on-demand o schedulato con payload sintetico; non in readiness globale.

## Metriche minime

- `broker_ipc_requests_total` per operation/result.
- `broker_ipc_duration_ms` histogram.
- `broker_authorization_denied_total`.
- `gateway_invocations_total` per Connector/operation/outcome.
- `gateway_duration_ms` e `external_duration_ms` histogram.
- `gateway_authentication_failures_total`.
- `gateway_cross_tenant_denials_total`.
- `vault_requests_total`, latency e throttling.
- `connector_config_errors_total`.
- `connector_cache_age_seconds`.
- `certificate_expiry_days`.
- `token_refresh_failures_total`.
- `revoked_installation_attempts_total`.
- `broker_version_distribution` e broker non aggiornati.
- `egress_policy_denials_total` per reason code.

Tenant e Installation non diventano label metriche ad alta cardinalità; restano negli audit/eventi ricercabili.

## Tracing

Span principali:

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

Payload, authorization header e query sensibili non sono span attribute. URL esterno viene normalizzato a endpoint/operation ID, non registrato integralmente quando contiene parametri.

## Logging

Strutturato JSON. Campi comuni: timestamp, level, event code, correlation, trace/span, component, connector, operation, installation, tenant, outcome, duration e reason code.

Test di redaction obbligatori su:

- Authorization/Cookie/API key;
- access/refresh/session token;
- password/PIN/OTP;
- private key/certificate bundle;
- XML/JSON payload;
- exception di provider esterni.

## Alert iniziali

- Authentication failure rate sopra baseline.
- Tentativi da Installation revocate.
- Cross-Tenant denial diverso da zero.
- Vault errors/throttling sostenuti.
- External failure rate o latency per Connector.
- Connector config/cache stale.
- Certificato in scadenza a 30/14/7 giorni.
- Broker sotto minimum supported version.
- Secret rotation overdue.
- Readiness failure o DB failover.
- Improvviso aumento egress policy denial.

Le soglie numeriche vengono calibrate in test/preprod e documentate per Environment.

## Retry e circuit breaker

- Connect timeout 5 secondi; operation timeout 30 secondi default.
- Retry massimo 2 con exponential backoff e jitter.
- Solo errori transient e operation idempotenti.
- Nessun retry automatico su 4xx auth/validation o response non idempotente.
- Circuit breaker isolato per endpoint/Connector, non globale.

## Runbook minimi

- Revocare/re-enrollare una Installation.
- Ruotare Vendor/Tenant Secret senza downtime.
- Diagnosticare Vault/DB/external outage.
- Pubblicare e rollbackare ConnectorVersion.
- Gestire certificato in scadenza.
- Ripristinare PostgreSQL e verificare RLS/audit.
- Aggiornare Broker e riparare ACL/service identity.
- Incident response per possibile secret exposure.


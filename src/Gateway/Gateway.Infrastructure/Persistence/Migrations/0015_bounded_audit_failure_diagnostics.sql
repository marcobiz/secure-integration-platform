-- Explicit bounded failure diagnostics. These columns are not a generic metadata bag and may be
-- populated only for one failed operation invocation.
ALTER TABLE gateway.audit_event
  ADD COLUMN IF NOT EXISTS failure_phase varchar(64),
  ADD COLUMN IF NOT EXISTS upstream_status integer,
  ADD COLUMN IF NOT EXISTS status_category varchar(32),
  ADD COLUMN IF NOT EXISTS safe_upstream_code varchar(96),
  ADD COLUMN IF NOT EXISTS local_safe_code varchar(96);

DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_audit_failure_diagnostics_closed'
      AND conrelid = 'gateway.audit_event'::regclass
  ) THEN
    ALTER TABLE gateway.audit_event
    ADD CONSTRAINT ck_audit_failure_diagnostics_closed CHECK (
    (failure_phase IS NULL AND upstream_status IS NULL AND status_category IS NULL AND
      safe_upstream_code IS NULL AND local_safe_code IS NULL)
    OR
    (
      action = 'operation.invoke' AND outcome = 'failure' AND
      failure_phase IN (
        'DNS_FAILURE', 'TCP_CONNECT_FAILURE', 'TLS_SERVER_VALIDATION_FAILURE',
        'MTLS_CLIENT_AUTH_FAILURE', 'TIMEOUT', 'TRANSPORT_FAILURE_OTHER',
        'UPSTREAM_HTTP_RESPONSE', 'LOCAL_RESPONSE_MAPPING_FAILURE') AND
      status_category IN (
        'NO_UPSTREAM_RESPONSE', 'INFORMATIONAL', 'SUCCESS', 'REDIRECTION',
        'CLIENT_ERROR', 'SERVER_ERROR') AND
      (safe_upstream_code IS NULL OR safe_upstream_code ~ '^[A-Za-z0-9._-]{1,96}$') AND
      (local_safe_code IS NULL OR local_safe_code ~ '^[A-Za-z0-9._-]{1,96}$') AND
      (
        (failure_phase IN (
          'DNS_FAILURE', 'TCP_CONNECT_FAILURE', 'TLS_SERVER_VALIDATION_FAILURE',
          'MTLS_CLIENT_AUTH_FAILURE', 'TIMEOUT', 'TRANSPORT_FAILURE_OTHER') AND
          upstream_status IS NULL AND status_category = 'NO_UPSTREAM_RESPONSE' AND
          safe_upstream_code IS NULL AND local_safe_code IS NULL)
        OR
        (failure_phase = 'UPSTREAM_HTTP_RESPONSE' AND
          upstream_status BETWEEN 100 AND 599 AND local_safe_code IS NULL)
        OR
        (failure_phase = 'LOCAL_RESPONSE_MAPPING_FAILURE' AND
          upstream_status BETWEEN 100 AND 599 AND local_safe_code IS NOT NULL)
      ) AND
      status_category = CASE
        WHEN upstream_status IS NULL THEN 'NO_UPSTREAM_RESPONSE'
        WHEN upstream_status BETWEEN 100 AND 199 THEN 'INFORMATIONAL'
        WHEN upstream_status BETWEEN 200 AND 299 THEN 'SUCCESS'
        WHEN upstream_status BETWEEN 300 AND 399 THEN 'REDIRECTION'
        WHEN upstream_status BETWEEN 400 AND 499 THEN 'CLIENT_ERROR'
        WHEN upstream_status BETWEEN 500 AND 599 THEN 'SERVER_ERROR'
      END
    )
    );
  END IF;
END
$migration$;

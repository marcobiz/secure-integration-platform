-- Close the persisted diagnostics codes to the immutable server-owned profile. This is additive:
-- 0015 remains checksum-stable for existing installations and the migration runner records this
-- migration once, making a second complete apply a no-op.
DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_audit_failure_diagnostic_codes_allowlisted'
      AND conrelid = 'gateway.audit_event'::regclass
  ) THEN
    ALTER TABLE gateway.audit_event
    ADD CONSTRAINT ck_audit_failure_diagnostic_codes_allowlisted CHECK (
      (
        safe_upstream_code IS NULL OR safe_upstream_code IN (
          'cda-element', 'cda-extraction', 'cda-match', 'cda-validation', 'document-hash',
          'document-type', 'eds-document-missing', 'eds-error', 'empty-file', 'fhir-element',
          'fhir-extraction', 'fhir-mapping-type', 'generic-error', 'generic-timeout', 'ini-error',
          'invalid-format', 'jwt-validation', 'mandatory-element', 'mandatory-element-token',
          'max-day-limit-exceed', 'missing-token', 'record-not-found', 'semantic', 'service-error',
          'syntax', 'vocabulary', 'workflow-id-error-extraction'
        )
      ) AND
      (local_safe_code IS NULL OR local_safe_code = 'FSE2_RESPONSE_INVALID')
    );
  END IF;
END
$migration$;

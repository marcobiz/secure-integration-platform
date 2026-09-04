-- Preserve the immutable origin and its trace while admitting one protocol-authorized successor.
-- Runtime remains SELECT/INSERT-only; existing rows, trace uniqueness and forced RLS are unchanged.
ALTER TABLE gateway.connector_workflow_context
  ADD COLUMN IF NOT EXISTS predecessor_trace_id varchar(100)
  CHECK (predecessor_trace_id IS NULL OR (
    workflow_instance_id IS NOT NULL AND trace_id IS NOT NULL AND trace_id <> predecessor_trace_id AND
    predecessor_trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'));

-- Keep the historical index name so repeat application of the historical idempotent scripts
-- cannot recreate the old one-context-per-workflow constraint.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='gateway'
      AND indexname='ux_connector_workflow_context_workflow'
      AND indexdef NOT LIKE '%predecessor_trace_id%') THEN
    DROP INDEX gateway.ux_connector_workflow_context_workflow;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_workflow_context_workflow
  ON gateway.connector_workflow_context(
    tenant_id,application_id,installation_id,environment_id,connector_id,connector_version,
    published_context_sha256,workflow_instance_id,(predecessor_trace_id IS NOT NULL))
  WHERE workflow_instance_id IS NOT NULL;

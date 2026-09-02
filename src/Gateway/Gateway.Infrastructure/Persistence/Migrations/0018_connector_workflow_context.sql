-- Durable provider-neutral technical workflow correlation. The authority columns are server-derived
-- and the bounded context has no payload, patient, document, endpoint, credential or metadata bag.
CREATE TABLE IF NOT EXISTS gateway.connector_workflow_context (
  tenant_id uuid NOT NULL,
  application_id uuid NOT NULL,
  installation_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  connector_id varchar(100) NOT NULL,
  connector_version varchar(64) NOT NULL,
  published_context_sha256 bytea NOT NULL CHECK (octet_length(published_context_sha256) = 32),
  originating_operation_id varchar(100) NOT NULL
    CHECK (originating_operation_id ~ '^[a-z][a-z0-9._-]{0,99}$' AND
           originating_operation_id ~ '[a-z0-9]$'),
  action_code varchar(64) NOT NULL
    CHECK (action_code ~ '^[A-Z][A-Z0-9 _-]{0,63}$' AND action_code = btrim(action_code)),
  purpose_of_use_code varchar(64) NOT NULL
    CHECK (purpose_of_use_code ~ '^[A-Z][A-Z0-9 _-]{0,63}$' AND purpose_of_use_code = btrim(purpose_of_use_code)),
  operation_profile_checksum_sha256 bytea NOT NULL
    CHECK (octet_length(operation_profile_checksum_sha256) = 32),
  workflow_instance_id varchar(256),
  trace_id varchar(100),
  recorded_at timestamptz NOT NULL,
  FOREIGN KEY (installation_id, tenant_id) REFERENCES gateway.installation(id, tenant_id),
  CHECK (workflow_instance_id IS NOT NULL OR trace_id IS NOT NULL),
  CHECK (workflow_instance_id IS NULL OR (
    workflow_instance_id = btrim(workflow_instance_id) AND
    workflow_instance_id !~ '[[:cntrl:]/?#\\]')),
  CHECK (trace_id IS NULL OR trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_workflow_context_workflow
  ON gateway.connector_workflow_context(
    tenant_id,application_id,installation_id,environment_id,connector_id,connector_version,
    published_context_sha256,workflow_instance_id)
  WHERE workflow_instance_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_workflow_context_trace
  ON gateway.connector_workflow_context(
    tenant_id,application_id,installation_id,environment_id,connector_id,connector_version,
    published_context_sha256,trace_id)
  WHERE trace_id IS NOT NULL;

ALTER TABLE gateway.connector_workflow_context ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.connector_workflow_context FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS connector_workflow_context_runtime_scope ON gateway.connector_workflow_context;
CREATE POLICY connector_workflow_context_runtime_scope ON gateway.connector_workflow_context
  USING (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid AND
    installation_id = nullif(current_setting('app.installation_id', true), '')::uuid)
  WITH CHECK (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid AND
    installation_id = nullif(current_setting('app.installation_id', true), '')::uuid);

REVOKE ALL PRIVILEGES ON TABLE gateway.connector_workflow_context
  FROM PUBLIC, gateway_runtime, gateway_admin, gateway_readonly;
GRANT SELECT, INSERT ON TABLE gateway.connector_workflow_context TO gateway_runtime;

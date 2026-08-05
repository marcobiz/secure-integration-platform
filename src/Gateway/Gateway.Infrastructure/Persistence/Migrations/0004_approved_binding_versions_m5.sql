-- Immutable, checksum-bound Connector binding bundle revisions and atomic approved publication.
CREATE TABLE IF NOT EXISTS gateway.connector_binding_bundle_version (
  id uuid PRIMARY KEY,
  connector_id uuid NOT NULL REFERENCES gateway.connector_definition(id),
  connector_version_id uuid NOT NULL REFERENCES gateway.connector_version(id) ON DELETE CASCADE,
  environment_id uuid NOT NULL REFERENCES gateway.environment(id),
  revision bigint NOT NULL CHECK (revision > 0),
  state varchar(16) NOT NULL CHECK (state IN ('draft','active','retired')),
  endpoints_json jsonb NOT NULL,
  secret_references_json jsonb NOT NULL,
  certificate_references_json jsonb NOT NULL,
  checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
  created_at timestamptz NOT NULL,
  created_by varchar(256) NOT NULL,
  UNIQUE (connector_version_id, environment_id, revision)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_binding_bundle_revision_checksum
  ON gateway.connector_binding_bundle_version(connector_version_id, environment_id, checksum_sha256);
CREATE INDEX IF NOT EXISTS ix_connector_binding_bundle_runtime
  ON gateway.connector_binding_bundle_version(connector_version_id, environment_id, state, revision DESC);

ALTER TABLE gateway.connector_approval
  ADD COLUMN IF NOT EXISTS binding_digest_sha256 bytea;
ALTER TABLE gateway.connector_approval
  DROP CONSTRAINT IF EXISTS ck_connector_approval_binding_digest;
ALTER TABLE gateway.connector_approval
  ADD CONSTRAINT ck_connector_approval_binding_digest
  CHECK (binding_digest_sha256 IS NULL OR octet_length(binding_digest_sha256) = 32);

GRANT SELECT ON gateway.connector_binding_bundle_version TO gateway_runtime, gateway_readonly;
GRANT SELECT, INSERT, UPDATE ON gateway.connector_binding_bundle_version TO gateway_admin;

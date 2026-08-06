-- M5 server-owned provider resource catalog. This table contains metadata and provider references, never secret values.
CREATE TABLE IF NOT EXISTS gateway.provider_resource_catalog_version (
  id uuid PRIMARY KEY,
  provider_id varchar(128) NOT NULL,
  provider_display_name varchar(256) NOT NULL,
  provider_type varchar(64) NOT NULL,
  resource_id varchar(128) NOT NULL,
  resource_type varchar(32) NOT NULL CHECK (resource_type IN ('secret','client_certificate')),
  display_name varchar(256) NOT NULL,
  environment_id uuid NOT NULL REFERENCES gateway.environment(id),
  connector_scope varchar(128) NOT NULL,
  operation_scope varchar(128) NOT NULL,
  status varchar(16) NOT NULL CHECK (status IN ('active','disabled')),
  version varchar(128),
  revision bigint NOT NULL CHECK (revision > 0),
  public_metadata_revision bigint,
  certificate_metadata_json jsonb,
  checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
  created_at timestamptz NOT NULL,
  CHECK ((resource_type = 'client_certificate' AND certificate_metadata_json IS NOT NULL AND public_metadata_revision IS NOT NULL) OR
         (resource_type = 'secret' AND certificate_metadata_json IS NULL))
);

-- Protected runtime locator. It is deliberately separated from the reviewable metadata catalog
-- and is never granted to gateway_readonly or exposed by an Admin contract.
CREATE TABLE IF NOT EXISTS gateway.provider_resource_locator (
  provider_resource_catalog_id uuid PRIMARY KEY REFERENCES gateway.provider_resource_catalog_version(id) ON DELETE RESTRICT,
  provider_reference varchar(1024) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_provider_resource_catalog_revision
  ON gateway.provider_resource_catalog_version(provider_id, resource_id, resource_type, coalesce(version, ''), revision);

CREATE INDEX IF NOT EXISTS ix_provider_resource_catalog_current
  ON gateway.provider_resource_catalog_version(provider_id, resource_id, resource_type, coalesce(version, ''), revision DESC);
CREATE INDEX IF NOT EXISTS ix_provider_resource_catalog_scope
  ON gateway.provider_resource_catalog_version(environment_id, connector_scope, operation_scope, status);

COMMENT ON COLUMN gateway.provider_resource_locator.provider_reference IS
  'Provider-owned physical locator used only by Gateway runtime; never returned by Admin APIs and never a secret value.';
COMMENT ON COLUMN gateway.provider_resource_catalog_version.certificate_metadata_json IS
  'Public certificate metadata only: fingerprint, subject, issuer, validity and public-key characteristics.';

-- Re-establish exact privileges even when a qualification database reapplies older
-- idempotent migrations whose historical all-table grant can see these newer tables.
REVOKE ALL ON gateway.provider_resource_catalog_version, gateway.provider_resource_locator
  FROM PUBLIC, gateway_runtime, gateway_admin, gateway_readonly;
GRANT SELECT ON gateway.provider_resource_catalog_version TO gateway_runtime, gateway_readonly;
GRANT SELECT, INSERT ON gateway.provider_resource_catalog_version TO gateway_admin;
GRANT SELECT ON gateway.provider_resource_locator TO gateway_runtime;
GRANT SELECT, INSERT ON gateway.provider_resource_locator TO gateway_admin;

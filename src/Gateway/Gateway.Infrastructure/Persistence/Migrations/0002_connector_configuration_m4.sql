-- M4 additive Connector Configuration lifecycle. No provider-specific type or secret value is stored.
ALTER TABLE gateway.connector_definition
  ADD COLUMN IF NOT EXISTS active_version_id uuid,
  ADD COLUMN IF NOT EXISTS publication_revision bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS gateway.connector_version (
  id uuid PRIMARY KEY,
  connector_id uuid NOT NULL REFERENCES gateway.connector_definition(id) ON DELETE CASCADE,
  version varchar(64) NOT NULL,
  schema_version varchar(16) NOT NULL,
  state varchar(32) NOT NULL CHECK (state IN ('draft','validated','published','superseded','retired')),
  configuration_json jsonb NOT NULL,
  checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
  created_by varchar(256) NOT NULL,
  created_at timestamptz NOT NULL,
  validated_at timestamptz,
  published_at timestamptz,
  retired_at timestamptz,
  row_version bigint NOT NULL DEFAULT 1,
  UNIQUE (connector_id, version),
  UNIQUE (id, connector_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_one_published_version
  ON gateway.connector_version(connector_id) WHERE state = 'published';
CREATE INDEX IF NOT EXISTS ix_connector_version_lifecycle
  ON gateway.connector_version(connector_id, state, created_at DESC);

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'fk_connector_active_version'
       AND conrelid = 'gateway.connector_definition'::regclass
  ) THEN
    ALTER TABLE gateway.connector_definition
      ADD CONSTRAINT fk_connector_active_version
      FOREIGN KEY (active_version_id, id)
      REFERENCES gateway.connector_version(id, connector_id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS gateway.connector_environment_binding (
  connector_id uuid NOT NULL REFERENCES gateway.connector_definition(id) ON DELETE CASCADE,
  environment_id uuid NOT NULL REFERENCES gateway.environment(id) ON DELETE CASCADE,
  endpoints_json jsonb NOT NULL,
  secret_references_json jsonb NOT NULL,
  revision bigint NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL,
  updated_by varchar(256) NOT NULL,
  PRIMARY KEY (connector_id, environment_id)
);

-- Published JSON and checksum are immutable even for gateway_admin. Lifecycle state may
-- change only through reviewed publication/rollback/retirement transactions.
CREATE OR REPLACE FUNCTION gateway.protect_published_connector_version() RETURNS trigger
LANGUAGE plpgsql SET search_path = gateway, pg_temp AS $$
BEGIN
  IF OLD.published_at IS NOT NULL AND
     (NEW.configuration_json IS DISTINCT FROM OLD.configuration_json OR
      NEW.checksum_sha256 IS DISTINCT FROM OLD.checksum_sha256 OR
      NEW.version IS DISTINCT FROM OLD.version OR
      NEW.schema_version IS DISTINCT FROM OLD.schema_version OR
      NEW.connector_id IS DISTINCT FROM OLD.connector_id) THEN
    RAISE EXCEPTION 'published connector definition is immutable' USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS connector_version_immutable ON gateway.connector_version;
CREATE TRIGGER connector_version_immutable
BEFORE UPDATE ON gateway.connector_version
FOR EACH ROW EXECUTE FUNCTION gateway.protect_published_connector_version();

GRANT SELECT ON gateway.connector_version, gateway.connector_environment_binding TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON gateway.connector_version, gateway.connector_environment_binding TO gateway_admin;
GRANT EXECUTE ON FUNCTION gateway.protect_published_connector_version() TO gateway_admin;

CREATE SCHEMA IF NOT EXISTS gateway;

CREATE TABLE IF NOT EXISTS gateway.tenant (
  id uuid PRIMARY KEY,
  code varchar(64) NOT NULL UNIQUE,
  display_name varchar(256) NOT NULL,
  status varchar(32) NOT NULL CHECK (status IN ('active','suspended','retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS gateway.application (
  id uuid PRIMARY KEY,
  code varchar(100) NOT NULL UNIQUE,
  display_name varchar(256) NOT NULL,
  status varchar(32) NOT NULL CHECK (status IN ('active','suspended','retired')),
  minimum_broker_version varchar(64) NOT NULL,
  maximum_broker_version varchar(64),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS gateway.environment (
  id uuid PRIMARY KEY,
  code varchar(32) NOT NULL UNIQUE,
  display_name varchar(256) NOT NULL,
  production_controls boolean NOT NULL,
  endpoint_policy_json jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS gateway.installation (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES gateway.tenant(id),
  application_id uuid NOT NULL REFERENCES gateway.application(id),
  environment_id uuid NOT NULL REFERENCES gateway.environment(id),
  status varchar(32) NOT NULL CHECK (status IN ('pending','active','suspended','revoked','retired')),
  broker_version varchar(64),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  revocation_reason varchar(1000),
  row_version bigint NOT NULL DEFAULT 1,
  UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS ix_installation_tenant_status ON gateway.installation(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_installation_application_status ON gateway.installation(application_id, status);

CREATE TABLE IF NOT EXISTS gateway.installation_credential (
  id uuid PRIMARY KEY,
  installation_id uuid NOT NULL REFERENCES gateway.installation(id),
  certificate_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(certificate_sha256) = 32),
  spki_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(spki_sha256) = 32),
  certificate_der bytea NOT NULL,
  serial_number varchar(128) NOT NULL,
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL CHECK (not_after > not_before),
  status varchar(32) NOT NULL CHECK (status IN ('pending','active','overlap','revoked','expired')),
  replaced_by_id uuid REFERENCES gateway.installation_credential(id),
  created_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_installation_one_active_credential ON gateway.installation_credential(installation_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_credential_installation_status_expiry ON gateway.installation_credential(installation_id, status, not_after);

CREATE TABLE IF NOT EXISTS gateway.activation_code (
  id uuid PRIMARY KEY,
  installation_id uuid NOT NULL REFERENCES gateway.installation(id),
  code_hmac bytea NOT NULL UNIQUE CHECK (octet_length(code_hmac) = 32),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL,
  attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
  created_by varchar(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway.connector_definition (
  id uuid PRIMARY KEY,
  slug varchar(100) NOT NULL UNIQUE,
  display_name varchar(256) NOT NULL,
  status varchar(32) NOT NULL CHECK (status IN ('active','retired')),
  created_at timestamptz NOT NULL,
  created_by varchar(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway.installation_connector_grant (
  id uuid PRIMARY KEY,
  installation_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  connector_id uuid NOT NULL REFERENCES gateway.connector_definition(id),
  operation_id varchar(100) NOT NULL,
  enabled boolean NOT NULL,
  constraints_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  valid_from timestamptz NOT NULL,
  valid_until timestamptz,
  FOREIGN KEY (installation_id, tenant_id) REFERENCES gateway.installation(id, tenant_id),
  UNIQUE (installation_id, connector_id, operation_id)
);

CREATE TABLE IF NOT EXISTS gateway.replay_nonce (
  installation_id uuid NOT NULL REFERENCES gateway.installation(id),
  nonce_sha256 bytea NOT NULL CHECK (octet_length(nonce_sha256) = 32),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (installation_id, nonce_sha256)
);

CREATE TABLE IF NOT EXISTS gateway.audit_event (
  id uuid NOT NULL,
  occurred_at timestamptz NOT NULL,
  tenant_id uuid,
  actor_type varchar(64) NOT NULL,
  actor_id varchar(256) NOT NULL,
  action varchar(128) NOT NULL,
  target_type varchar(64) NOT NULL,
  target_id varchar(256) NOT NULL,
  correlation_id uuid NOT NULL,
  outcome varchar(32) NOT NULL,
  reason_code varchar(128) NOT NULL,
  metadata_redacted jsonb NOT NULL,
  PRIMARY KEY (occurred_at, id)
);

CREATE TABLE IF NOT EXISTS gateway.invocation_event (
  id uuid NOT NULL,
  occurred_at timestamptz NOT NULL,
  tenant_id uuid NOT NULL,
  installation_id uuid NOT NULL,
  connector_id uuid NOT NULL,
  operation_id varchar(100) NOT NULL,
  correlation_id uuid NOT NULL,
  outcome varchar(32) NOT NULL,
  duration_ms integer NOT NULL CHECK (duration_ms >= 0),
  external_status_category varchar(32),
  error_code varchar(128),
  payload_bytes bigint NOT NULL CHECK (payload_bytes >= 0),
  PRIMARY KEY (occurred_at, id),
  FOREIGN KEY (installation_id, tenant_id) REFERENCES gateway.installation(id, tenant_id)
);

-- Narrow authentication indexes are intentionally not tenant query surfaces. They are
-- accessible only through SECURITY DEFINER functions that establish RLS context before
-- reading tenant-scoped rows.
CREATE TABLE IF NOT EXISTS gateway.installation_locator (
  installation_id uuid PRIMARY KEY REFERENCES gateway.installation(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES gateway.tenant(id)
);
CREATE TABLE IF NOT EXISTS gateway.credential_locator (
  certificate_sha256 bytea PRIMARY KEY CHECK (octet_length(certificate_sha256) = 32),
  credential_id uuid NOT NULL UNIQUE REFERENCES gateway.installation_credential(id) ON DELETE CASCADE,
  installation_id uuid NOT NULL REFERENCES gateway.installation(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES gateway.tenant(id)
);
CREATE TABLE IF NOT EXISTS gateway.activation_locator (
  activation_code_id uuid PRIMARY KEY REFERENCES gateway.activation_code(id) ON DELETE CASCADE,
  installation_id uuid NOT NULL REFERENCES gateway.installation(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES gateway.tenant(id)
);

CREATE OR REPLACE FUNCTION gateway.index_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
BEGIN
  INSERT INTO installation_locator(installation_id,tenant_id) VALUES(NEW.id,NEW.tenant_id);
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION gateway.index_credential() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT tenant_id INTO STRICT located_tenant FROM installation_locator WHERE installation_id=NEW.installation_id;
  INSERT INTO credential_locator(certificate_sha256,credential_id,installation_id,tenant_id)
  VALUES(NEW.certificate_sha256,NEW.id,NEW.installation_id,located_tenant);
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION gateway.index_activation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT tenant_id INTO STRICT located_tenant FROM installation_locator WHERE installation_id=NEW.installation_id;
  INSERT INTO activation_locator(activation_code_id,installation_id,tenant_id)
  VALUES(NEW.id,NEW.installation_id,located_tenant);
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS installation_locator_insert ON gateway.installation;
CREATE TRIGGER installation_locator_insert AFTER INSERT ON gateway.installation FOR EACH ROW EXECUTE FUNCTION gateway.index_installation();
DROP TRIGGER IF EXISTS credential_locator_insert ON gateway.installation_credential;
CREATE TRIGGER credential_locator_insert AFTER INSERT ON gateway.installation_credential FOR EACH ROW EXECUTE FUNCTION gateway.index_credential();
DROP TRIGGER IF EXISTS activation_locator_insert ON gateway.activation_code;
CREATE TRIGGER activation_locator_insert AFTER INSERT ON gateway.activation_code FOR EACH ROW EXECUTE FUNCTION gateway.index_activation();

INSERT INTO gateway.installation_locator SELECT id,tenant_id FROM gateway.installation ON CONFLICT DO NOTHING;
INSERT INTO gateway.credential_locator
SELECT c.certificate_sha256,c.id,c.installation_id,i.tenant_id FROM gateway.installation_credential c JOIN gateway.installation i ON i.id=c.installation_id
ON CONFLICT DO NOTHING;
INSERT INTO gateway.activation_locator
SELECT a.id,a.installation_id,i.tenant_id FROM gateway.activation_code a JOIN gateway.installation i ON i.id=a.installation_id
ON CONFLICT DO NOTHING;

ALTER TABLE gateway.installation ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.installation FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.installation_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.installation_credential FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.activation_code ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.activation_code FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.installation_connector_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.installation_connector_grant FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.replay_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.replay_nonce FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.audit_event FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway.invocation_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.invocation_event FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS installation_tenant_policy ON gateway.installation;
CREATE POLICY installation_tenant_policy ON gateway.installation
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS credential_tenant_policy ON gateway.installation_credential;
CREATE POLICY credential_tenant_policy ON gateway.installation_credential
  USING (EXISTS (SELECT 1 FROM gateway.installation i WHERE i.id = installation_id));
DROP POLICY IF EXISTS activation_tenant_policy ON gateway.activation_code;
CREATE POLICY activation_tenant_policy ON gateway.activation_code
  USING (EXISTS (SELECT 1 FROM gateway.installation i WHERE i.id = installation_id));
DROP POLICY IF EXISTS grant_tenant_policy ON gateway.installation_connector_grant;
CREATE POLICY grant_tenant_policy ON gateway.installation_connector_grant
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS nonce_tenant_policy ON gateway.replay_nonce;
CREATE POLICY nonce_tenant_policy ON gateway.replay_nonce
  USING (EXISTS (SELECT 1 FROM gateway.installation i WHERE i.id = installation_id));
DROP POLICY IF EXISTS audit_tenant_policy ON gateway.audit_event;
CREATE POLICY audit_tenant_policy ON gateway.audit_event
  USING (tenant_id IS NULL OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id IS NULL OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS invocation_tenant_policy ON gateway.invocation_event;
CREATE POLICY invocation_tenant_policy ON gateway.invocation_event
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- Runtime identity resolution is deliberately narrow and returns public credential material only.
CREATE OR REPLACE FUNCTION gateway.resolve_installation_identity(p_certificate_sha256 bytea)
RETURNS TABLE (
  installation_id uuid, tenant_id uuid, application_id uuid, environment_id uuid,
  tenant_status varchar, application_status varchar, installation_status varchar,
  credential_id uuid, credential_status varchar,
  certificate_der bytea, credential_not_before timestamptz, credential_not_after timestamptz,
  minimum_broker_version varchar, maximum_broker_version varchar)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT l.tenant_id INTO located_tenant FROM credential_locator l WHERE l.certificate_sha256=p_certificate_sha256;
  IF located_tenant IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id',located_tenant::text,true);
  RETURN QUERY SELECT i.id, i.tenant_id, i.application_id, i.environment_id, t.status, a.status, i.status,
         c.id, c.status, c.certificate_der, c.not_before, c.not_after,
         a.minimum_broker_version, a.maximum_broker_version
    FROM installation_credential c
    JOIN installation i ON i.id = c.installation_id
    JOIN tenant t ON t.id = i.tenant_id
    JOIN application a ON a.id = i.application_id
   WHERE c.certificate_sha256 = p_certificate_sha256;
END;
$$;
REVOKE ALL ON FUNCTION gateway.resolve_installation_identity(bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION gateway.resolve_installation_tenant(p_installation_id uuid)
RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
  SELECT tenant_id FROM installation_locator WHERE installation_id = p_installation_id;
$$;
REVOKE ALL ON FUNCTION gateway.resolve_installation_tenant(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION gateway.resolve_activation_code(p_activation_code_id uuid)
RETURNS TABLE (id uuid, installation_id uuid, code_hmac bytea, expires_at timestamptz,
               created_at timestamptz, created_by varchar, attempt_count smallint, used_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT l.tenant_id INTO located_tenant FROM activation_locator l WHERE l.activation_code_id=p_activation_code_id;
  IF located_tenant IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id',located_tenant::text,true);
  RETURN QUERY SELECT a.id, a.installation_id, a.code_hmac, a.expires_at, a.created_at,
         a.created_by, a.attempt_count, a.used_at
    FROM activation_code a WHERE a.id = p_activation_code_id;
END;
$$;
REVOKE ALL ON FUNCTION gateway.resolve_activation_code(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION gateway.record_activation_failure(p_activation_code_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT l.tenant_id INTO located_tenant FROM activation_locator l WHERE l.activation_code_id=p_activation_code_id;
  IF located_tenant IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id',located_tenant::text,true);
  UPDATE activation_code SET attempt_count = least(5, attempt_count + 1)
   WHERE id = p_activation_code_id;
END;
$$;
REVOKE ALL ON FUNCTION gateway.record_activation_failure(uuid) FROM PUBLIC;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_runtime') THEN CREATE ROLE gateway_runtime NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_admin') THEN CREATE ROLE gateway_admin NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_readonly') THEN CREATE ROLE gateway_readonly NOLOGIN; END IF;
END $$;

GRANT USAGE ON SCHEMA gateway TO gateway_runtime, gateway_admin, gateway_readonly;
GRANT SELECT, INSERT, UPDATE ON gateway.installation, gateway.installation_credential, gateway.activation_code TO gateway_runtime;
GRANT SELECT, INSERT, DELETE ON gateway.replay_nonce TO gateway_runtime;
GRANT SELECT ON gateway.application, gateway.environment, gateway.connector_definition TO gateway_runtime;
GRANT SELECT ON gateway.installation_connector_grant TO gateway_runtime;
GRANT INSERT ON gateway.audit_event, gateway.invocation_event TO gateway_runtime;
GRANT EXECUTE ON FUNCTION gateway.resolve_installation_identity(bytea), gateway.resolve_installation_tenant(uuid), gateway.resolve_activation_code(uuid), gateway.record_activation_failure(uuid) TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA gateway TO gateway_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA gateway TO gateway_admin;
GRANT SELECT ON gateway.tenant, gateway.application, gateway.environment, gateway.connector_definition TO gateway_readonly;

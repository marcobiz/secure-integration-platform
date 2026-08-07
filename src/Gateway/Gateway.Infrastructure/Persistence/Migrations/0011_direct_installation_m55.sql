-- M5.5: distinguish Broker and Direct machine identities without changing BGW1.
ALTER TABLE gateway.installation
  ADD COLUMN IF NOT EXISTS installation_kind varchar(16),
  ADD COLUMN IF NOT EXISTS client_version varchar(64),
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE gateway.installation SET installation_kind = 'broker' WHERE installation_kind IS NULL;
UPDATE gateway.installation
   SET updated_at = COALESCE(revoked_at, last_seen_at, created_at)
 WHERE updated_at IS NULL;

ALTER TABLE gateway.installation
  ALTER COLUMN installation_kind SET DEFAULT 'broker',
  ALTER COLUMN installation_kind SET NOT NULL,
  ALTER COLUMN updated_at SET DEFAULT now(),
  ALTER COLUMN updated_at SET NOT NULL;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ck_installation_kind'
       AND conrelid = 'gateway.installation'::regclass
  ) THEN
    ALTER TABLE gateway.installation
      ADD CONSTRAINT ck_installation_kind CHECK (installation_kind IN ('broker','direct'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ck_installation_kind_version'
       AND conrelid = 'gateway.installation'::regclass
  ) THEN
    ALTER TABLE gateway.installation
      ADD CONSTRAINT ck_installation_kind_version CHECK (
        (installation_kind = 'broker' AND client_version IS NULL)
        OR (installation_kind = 'direct' AND broker_version IS NULL)
      );
  END IF;
END $$;

-- Keep the M2 identity function's return type frozen for existing Broker clients.
-- This additive resolver exposes only the new public classification metadata.
CREATE OR REPLACE FUNCTION gateway.resolve_installation_client_metadata(p_certificate_sha256 bytea)
RETURNS TABLE (installation_kind varchar, client_version varchar)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = gateway, pg_temp AS $$
DECLARE located_tenant uuid;
BEGIN
  SELECT l.tenant_id INTO located_tenant FROM credential_locator l WHERE l.certificate_sha256=p_certificate_sha256;
  IF located_tenant IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id',located_tenant::text,true);
  RETURN QUERY SELECT i.installation_kind, i.client_version
    FROM installation_credential c
    JOIN installation i ON i.id = c.installation_id
   WHERE c.certificate_sha256 = p_certificate_sha256;
END;
$$;

REVOKE ALL ON FUNCTION gateway.resolve_installation_client_metadata(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gateway.resolve_installation_client_metadata(bytea) TO gateway_runtime, gateway_admin;

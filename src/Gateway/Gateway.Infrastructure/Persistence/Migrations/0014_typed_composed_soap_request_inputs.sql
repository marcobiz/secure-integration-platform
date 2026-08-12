-- Authorized typed composed-SOAP request inputs. Extend the operation-scoped runtime locator only
-- to exact opaque server-owned inputs declared by the granted Published business operation.
CREATE OR REPLACE FUNCTION gateway.resolve_published_provider_locator(
  p_catalog_id uuid,
  p_connector_slug text,
  p_operation_id text,
  p_logical_binding_id text,
  p_environment_id uuid,
  p_binding_id uuid,
  p_binding_revision bigint,
  p_binding_checksum_sha256 bytea,
  p_installation_id uuid,
  p_tenant_id uuid,
  p_application_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, gateway
AS $$
DECLARE
  located_reference text;
BEGIN
  IF p_connector_slug IS NULL OR p_operation_id IS NULL OR p_logical_binding_id IS NULL OR
     length(p_connector_slug) NOT BETWEEN 1 AND 100 OR
     length(p_operation_id) NOT BETWEEN 1 AND 100 OR
     length(p_logical_binding_id) NOT BETWEEN 1 AND 128 OR
     octet_length(p_binding_checksum_sha256) <> 32 THEN
    RETURN NULL;
  END IF;

  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);

  SELECT l.provider_reference
    INTO located_reference
    FROM gateway.provider_resource_catalog_version r
    JOIN gateway.provider_resource_locator l ON l.provider_resource_catalog_id = r.id
    JOIN gateway.connector_definition c ON c.slug = p_connector_slug
    JOIN gateway.connector_version v ON v.id = c.active_version_id
    JOIN gateway.connector_binding_bundle_version b
      ON b.id = p_binding_id
     AND b.connector_id = c.id
     AND b.connector_version_id = v.id
     AND b.environment_id = p_environment_id
    JOIN gateway.installation i
      ON i.id = p_installation_id
     AND i.tenant_id = p_tenant_id
     AND i.application_id = p_application_id
     AND i.environment_id = p_environment_id
    JOIN gateway.tenant t ON t.id = i.tenant_id
    JOIN gateway.application a ON a.id = i.application_id
    JOIN gateway.installation_connector_grant g
      ON g.installation_id = i.id
     AND g.tenant_id = i.tenant_id
     AND g.connector_id = c.id
     AND g.operation_id = p_operation_id
   WHERE r.id = p_catalog_id
     AND r.status = 'active'
     AND r.environment_id = p_environment_id
     AND (r.connector_scope = '*' OR r.connector_scope = p_connector_slug)
     AND (r.operation_scope = '*' OR r.operation_scope = p_operation_id)
     AND NOT EXISTS (
       SELECT 1 FROM gateway.provider_resource_catalog_version newer
        WHERE newer.provider_id = r.provider_id
          AND newer.resource_id = r.resource_id
          AND newer.resource_type = r.resource_type
          AND coalesce(newer.version, '') = coalesce(r.version, '')
          AND newer.revision > r.revision)
     AND c.status = 'active'
     AND v.state = 'published'
     AND b.state = 'active'
     AND b.revision = p_binding_revision
     AND b.checksum_sha256 = p_binding_checksum_sha256
     AND i.status = 'active'
     AND t.status = 'active'
     AND a.status = 'active'
     AND g.enabled
     AND g.valid_from <= now()
     AND (g.valid_until IS NULL OR g.valid_until > now())
     AND EXISTS (
       SELECT 1
         FROM jsonb_array_elements(v.configuration_json -> 'operations') operation
        WHERE operation ->> 'operationId' = p_operation_id
          AND CASE r.resource_type
                WHEN 'client_certificate' THEN
                  operation -> 'authentication' ->> 'certificateBinding' = p_logical_binding_id OR
                  operation -> 'authorizedCapabilities' -> 'signing' ->> 'keyBinding' = p_logical_binding_id OR
                  EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(coalesce(
                        operation -> 'authorizedCapabilities' -> 'signingSlots', '[]'::jsonb)) signing_slot
                     WHERE signing_slot -> 'signing' ->> 'keyBinding' = p_logical_binding_id)
                WHEN 'secret' THEN
                  p_logical_binding_id IN (
                    operation -> 'authentication' ->> 'usernameBinding',
                    operation -> 'authentication' ->> 'passwordBinding',
                    operation -> 'authentication' ->> 'secretBinding') OR
                  EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(coalesce(
                        operation -> 'typedSessionHandshake' -> 'serverOwnedInputs', '[]'::jsonb)) input
                     WHERE input ->> 'secretBinding' = p_logical_binding_id) OR
                  EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(coalesce(
                        operation -> 'typedSessionHandshake' -> 'externalAdmission' -> 'serverOwnedInputs', '[]'::jsonb)) input
                     WHERE input ->> 'secretBinding' = p_logical_binding_id) OR
                  EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(coalesce(
                        operation -> 'typedComposedSoapRequest' -> 'serverOwnedInputs', '[]'::jsonb)) input
                     WHERE input ->> 'secretBinding' = p_logical_binding_id)
                ELSE false
              END)
     AND EXISTS (
       SELECT 1
         FROM jsonb_each(b.secret_references_json || b.certificate_references_json) resource
        WHERE resource.key = p_logical_binding_id
          AND resource.value ->> 'ProviderId' = r.provider_id
          AND resource.value ->> 'ResourceId' = r.resource_id
          AND resource.value ->> 'ResourceType' = CASE r.resource_type WHEN 'secret' THEN '0' WHEN 'client_certificate' THEN '1' END
          AND coalesce(resource.value ->> 'Version', '') = coalesce(r.version, '')
          AND (resource.value ->> 'CatalogRevision')::bigint = r.revision
          AND upper(resource.value ->> 'CatalogChecksumSha256') = upper(encode(r.checksum_sha256, 'hex'))
          AND (resource.value ->> 'PublicMetadataRevision')::bigint IS NOT DISTINCT FROM r.public_metadata_revision)
   LIMIT 1;

  RETURN located_reference;
END;
$$;

ALTER FUNCTION gateway.resolve_published_provider_locator(uuid,text,text,text,uuid,uuid,bigint,bytea,uuid,uuid,uuid)
  OWNER TO gateway_locator_owner;
REVOKE ALL ON FUNCTION gateway.resolve_published_provider_locator(uuid,text,text,text,uuid,uuid,bigint,bytea,uuid,uuid,uuid)
  FROM PUBLIC, gateway_admin, gateway_readonly;
GRANT EXECUTE ON FUNCTION gateway.resolve_published_provider_locator(uuid,text,text,text,uuid,uuid,bigint,bytea,uuid,uuid,uuid)
  TO gateway_runtime;

REVOKE CREATE ON SCHEMA gateway FROM gateway_locator_owner;

-- Enforce immutable binding revisions and approval-gated activation at the PostgreSQL boundary.
CREATE OR REPLACE FUNCTION gateway.enforce_connector_binding_bundle_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'draft' THEN
      RAISE EXCEPTION 'connector binding revisions must be created as draft' USING ERRCODE = '23000';
    END IF;
    UPDATE gateway.connector_approval
       SET status = 'invalidated', invalidated_at = COALESCE(invalidated_at, NEW.created_at)
     WHERE connector_version_id = NEW.connector_version_id
       AND status IN ('requested', 'approved');
    RETURN NEW;
  END IF;

  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.connector_id IS DISTINCT FROM OLD.connector_id
     OR NEW.connector_version_id IS DISTINCT FROM OLD.connector_version_id
     OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
     OR NEW.revision IS DISTINCT FROM OLD.revision
     OR NEW.endpoints_json IS DISTINCT FROM OLD.endpoints_json
     OR NEW.secret_references_json IS DISTINCT FROM OLD.secret_references_json
     OR NEW.certificate_references_json IS DISTINCT FROM OLD.certificate_references_json
     OR NEW.checksum_sha256 IS DISTINCT FROM OLD.checksum_sha256
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
    RAISE EXCEPTION 'connector binding revisions are immutable' USING ERRCODE = '23000';
  END IF;

  IF NEW.state = OLD.state THEN
    RETURN NEW;
  END IF;
  IF OLD.state <> 'draft' OR NEW.state <> 'active' THEN
    RAISE EXCEPTION 'connector binding lifecycle transition is not allowed' USING ERRCODE = '23000';
  END IF;
  IF NEW.revision <> (SELECT max(candidate.revision)
                        FROM gateway.connector_binding_bundle_version candidate
                       WHERE candidate.connector_version_id = NEW.connector_version_id
                         AND candidate.environment_id = NEW.environment_id) THEN
    RAISE EXCEPTION 'only the latest binding revision may be activated' USING ERRCODE = '23000';
  END IF;
  IF NOT EXISTS (
      SELECT 1
        FROM gateway.connector_approval approval
        JOIN gateway.connector_version version ON version.id = approval.connector_version_id
       WHERE approval.connector_version_id = NEW.connector_version_id
         AND approval.checksum_sha256 = version.checksum_sha256
         AND approval.status = 'approved'
         AND approval.approved_by IS NOT NULL
         AND approval.approved_by <> approval.requested_by
         AND approval.approved_by::text <> version.created_by) THEN
    RAISE EXCEPTION 'binding activation requires a current four-eyes approval' USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_connector_binding_bundle_immutable ON gateway.connector_binding_bundle_version;
CREATE TRIGGER trg_connector_binding_bundle_immutable
BEFORE INSERT OR UPDATE ON gateway.connector_binding_bundle_version
FOR EACH ROW EXECUTE FUNCTION gateway.enforce_connector_binding_bundle_immutability();

REVOKE UPDATE ON gateway.connector_binding_bundle_version FROM gateway_admin;
GRANT UPDATE (state) ON gateway.connector_binding_bundle_version TO gateway_admin;

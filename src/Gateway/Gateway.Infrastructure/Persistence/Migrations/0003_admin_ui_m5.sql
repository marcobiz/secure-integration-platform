-- M5 provider-neutral Admin identities, scoped roles and checksum-specific four-eyes approvals.
CREATE TABLE IF NOT EXISTS gateway.admin_principal (
  id uuid PRIMARY KEY,
  issuer varchar(512) NOT NULL,
  subject varchar(256) NOT NULL,
  display_name varchar(256) NOT NULL,
  email varchar(320),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL,
  last_login_at timestamptz NOT NULL,
  UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS gateway.admin_role_assignment (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES gateway.admin_principal(id) ON DELETE CASCADE,
  role varchar(64) NOT NULL CHECK (role IN ('viewer','connector_editor','connector_approver','operator','security_administrator')),
  tenant_id uuid REFERENCES gateway.tenant(id),
  granted_by uuid NOT NULL REFERENCES gateway.admin_principal(id),
  granted_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_admin_role_assignment_scope
  ON gateway.admin_role_assignment(principal_id, role, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE IF NOT EXISTS gateway.admin_bootstrap (
  singleton_id smallint PRIMARY KEY CHECK (singleton_id = 1),
  principal_id uuid NOT NULL UNIQUE REFERENCES gateway.admin_principal(id),
  completed_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway.connector_approval (
  id uuid PRIMARY KEY,
  connector_version_id uuid NOT NULL REFERENCES gateway.connector_version(id) ON DELETE CASCADE,
  checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
  requested_by uuid NOT NULL REFERENCES gateway.admin_principal(id),
  approved_by uuid REFERENCES gateway.admin_principal(id),
  status varchar(32) NOT NULL CHECK (status IN ('requested','approved','invalidated')),
  requested_at timestamptz NOT NULL,
  approved_at timestamptz,
  invalidated_at timestamptz,
  CHECK ((status = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL) OR status <> 'approved'),
  CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_connector_approval_current
  ON gateway.connector_approval(connector_version_id) WHERE status IN ('requested','approved');
CREATE INDEX IF NOT EXISTS ix_connector_approval_checksum
  ON gateway.connector_approval(connector_version_id, checksum_sha256, status);

GRANT SELECT, INSERT, UPDATE ON gateway.admin_principal, gateway.admin_role_assignment, gateway.admin_bootstrap, gateway.connector_approval TO gateway_admin;
GRANT SELECT ON gateway.connector_approval TO gateway_readonly;

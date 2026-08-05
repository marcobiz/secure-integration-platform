-- M5 revocable, server-side administrator sessions. Clear handles are never persisted.
CREATE TABLE IF NOT EXISTS gateway.admin_session (
  id uuid PRIMARY KEY,
  handle_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(handle_sha256) = 32),
  principal_id uuid NOT NULL REFERENCES gateway.admin_principal(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (absolute_expires_at > created_at),
  CHECK (idle_expires_at <= absolute_expires_at),
  CHECK (last_seen_at >= created_at)
);

CREATE INDEX IF NOT EXISTS ix_admin_session_principal_active
  ON gateway.admin_session(principal_id, absolute_expires_at)
  WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.admin_session TO gateway_admin;

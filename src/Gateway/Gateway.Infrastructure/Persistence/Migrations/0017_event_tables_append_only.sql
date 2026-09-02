-- Application roles may append event rows but must not mutate existing records. The migration
-- owner and privileged PostgreSQL/host administrators remain part of the trusted computing base.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE gateway.audit_event FROM gateway_admin;

-- No Admin product path reads or writes invocation_event; runtime remains the sole application
-- writer through the INSERT grant established by 0001.
REVOKE ALL PRIVILEGES ON TABLE gateway.invocation_event FROM gateway_admin;

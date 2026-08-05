-- M5: the administrative role-revocation transaction deletes one assignment and
-- revokes affected sessions. Keep the runtime role unchanged.
GRANT DELETE ON gateway.admin_role_assignment TO gateway_admin;

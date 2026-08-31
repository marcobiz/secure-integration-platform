using System.Data;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL implementation of provider-neutral Admin security state.</summary>
public sealed class PostgresAdminSecurityStore(AdminPostgresDataSource adminDataSource, IAdminTransactionFaultInjector? faultInjector = null) : IAdminSecurityStore
{
    private readonly NpgsqlDataSource dataSource = adminDataSource.Value;
    /// <inheritdoc />
    public async Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(identity.Issuer, UriKind.Absolute, out Uri? issuer) || issuer.Scheme != Uri.UriSchemeHttps || identity.Issuer.Length > 512 || string.IsNullOrWhiteSpace(identity.Subject) || identity.Subject.Length > 256 || string.IsNullOrWhiteSpace(identity.DisplayName) || identity.DisplayName.Length > 256)
            throw new GatewayException("BGW-ADMIN-IDENTITY", 401);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "INSERT INTO gateway.admin_principal(id,issuer,subject,display_name,email,active,created_at,last_login_at) VALUES($1,$2,$3,$4,$5,true,now(),now()) ON CONFLICT(issuer,subject) DO UPDATE SET display_name=excluded.display_name,email=excluded.email,last_login_at=excluded.last_login_at RETURNING id,issuer,subject,display_name,email,active,created_at";
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(identity.Issuer);
        command.Parameters.AddWithValue(identity.Subject);
        command.Parameters.AddWithValue(identity.DisplayName);
        command.Parameters.AddWithValue((object?)identity.Email ?? DBNull.Value);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-IDENTITY", 401);
        return ReadPrincipal(reader);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken)
    {
        List<AdminRoleAssignmentRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT id,principal_id,role,tenant_id,granted_by,granted_at FROM gateway.admin_role_assignment WHERE principal_id=$1 ORDER BY role,tenant_id NULLS FIRST", connection);
        command.Parameters.AddWithValue(principalId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadAssignment(reader));
        return result;
    }

    /// <inheritdoc />
    public async Task<AdminPage<AdminRoleAssignmentRecord>> ListAssignmentsAsync(int offset, int limit, Guid? principalId, Guid? tenantId, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit); List<AdminRoleAssignmentRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = new("SELECT count(*) FROM gateway.admin_role_assignment WHERE ($1::uuid IS NULL OR principal_id=$1) AND ($2::uuid IS NULL OR tenant_id=$2)", connection))
        {
            Add(count, principalId, tenantId);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        }
        await using NpgsqlCommand command = new("SELECT id,principal_id,role,tenant_id,granted_by,granted_at FROM gateway.admin_role_assignment WHERE ($3::uuid IS NULL OR principal_id=$3) AND ($4::uuid IS NULL OR tenant_id=$4) ORDER BY role,principal_id,tenant_id NULLS FIRST,id OFFSET $1 LIMIT $2", connection);
        Add(command, offset, limit, principalId, tenantId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadAssignment(reader));
        return new(result, offset, limit, total);
    }

    /// <inheritdoc />
    public async Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand bootstrap = new("INSERT INTO gateway.admin_bootstrap(singleton_id,principal_id,completed_at) SELECT 1,$1,$2 WHERE EXISTS(SELECT 1 FROM gateway.admin_principal WHERE id=$1 AND active) ON CONFLICT(singleton_id) DO NOTHING RETURNING principal_id", connection, transaction);
        bootstrap.Parameters.AddWithValue(principalId);
        bootstrap.Parameters.AddWithValue(now);
        bool claimed = await bootstrap.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is Guid;
        if (claimed)
        {
            await using NpgsqlCommand role = new("INSERT INTO gateway.admin_role_assignment(id,principal_id,role,tenant_id,granted_by,granted_at) VALUES($1,$2,'security_administrator',NULL,$2,$3)", connection, transaction);
            role.Parameters.AddWithValue(Guid.NewGuid());
            role.Parameters.AddWithValue(principalId);
            role.Parameters.AddWithValue(now);
            await role.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            faultInjector?.Check("admin.bootstrap.after-state");
            await InsertAuditAsync(connection, transaction, null, principalId.ToString("D"), "admin.bootstrap", "admin_principal", principalId.ToString("D"), correlationId, "BGW-ADMIN-BOOTSTRAP-COMPLETE", now, cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return claimed;
    }

    /// <inheritdoc />
    public async Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // READ COMMITTED gives the convergence read a fresh statement snapshot after a
        // competing identical INSERT has committed. The expression conflict target is
        // the exact persisted assignment tuple, so unrelated conflicts still fail.
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        Guid id = Guid.NewGuid();
        const string sql = "INSERT INTO gateway.admin_role_assignment(id,principal_id,role,tenant_id,granted_by,granted_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (principal_id,role,(coalesce(tenant_id,'00000000-0000-0000-0000-000000000000'::uuid))) DO NOTHING RETURNING id,principal_id,role,tenant_id,granted_by,granted_at";
        await using NpgsqlCommand insert = new(sql, connection, transaction);
        Add(insert, id, principalId, Role(role), tenantId, grantedBy, now);
        AdminRoleAssignmentRecord? result = null;
        bool privilegesChanged = false;
        await using (NpgsqlDataReader reader = await insert.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                result = ReadAssignment(reader);
                privilegesChanged = true;
            }
        if (result is null)
        {
            await using NpgsqlCommand select = new("SELECT id,principal_id,role,tenant_id,granted_by,granted_at FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role=$2 AND tenant_id IS NOT DISTINCT FROM $3", connection, transaction);
            Add(select, principalId, Role(role), tenantId);
            await using NpgsqlDataReader existing = await select.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
            if (!await existing.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-ROLE-ASSIGNMENT", 409);
            result = ReadAssignment(existing);
        }
        if (result.PrincipalId != principalId || result.Role != role || result.TenantId != tenantId)
            throw new GatewayException("BGW-ADMIN-ROLE-ASSIGNMENT", 409);
        if (privilegesChanged)
        {
            faultInjector?.Check("admin.role.assign.after-state");
            await InsertAuditAsync(connection, transaction, tenantId, grantedBy.ToString("D"), "admin.role.assign", "admin_principal", principalId.ToString("D"), correlationId, "BGW-ADMIN-ROLE-ASSIGNED", now, cancellationToken).ConfigureAwait(false);
            await RevokeSessionsAsync(connection, transaction, principalId, now, cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public async Task<bool> RevokeRoleAsync(Guid assignmentId, Guid revokedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        Guid principalId; Guid? tenantId;
        await using (NpgsqlCommand select = new("SELECT principal_id,tenant_id FROM gateway.admin_role_assignment WHERE id=$1 FOR UPDATE", connection, transaction))
        {
            select.Parameters.AddWithValue(assignmentId);
            await using NpgsqlDataReader reader = await select.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return false;
            principalId = reader.GetGuid(0); tenantId = reader.IsDBNull(1) ? null : reader.GetGuid(1);
        }
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        await using (NpgsqlCommand delete = new("DELETE FROM gateway.admin_role_assignment WHERE id=$1", connection, transaction)) { delete.Parameters.AddWithValue(assignmentId); await delete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false); }
        faultInjector?.Check("admin.role.revoke.after-state");
        await InsertAuditAsync(connection, transaction, tenantId, revokedBy.ToString("D"), "admin.role.revoke", "admin_principal", principalId.ToString("D"), correlationId, "BGW-ADMIN-ROLE-REVOKED", now, cancellationToken).ConfigureAwait(false);
        await RevokeSessionsAsync(connection, transaction, principalId, now, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, byte[] bindingDigestSha256, Guid requester, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await InvalidateAsync(connection, transaction, version.Id, now, cancellationToken).ConfigureAwait(false);
        Guid id = Guid.NewGuid();
        await using NpgsqlCommand insert = new("INSERT INTO gateway.connector_approval(id,connector_version_id,checksum_sha256,binding_digest_sha256,requested_by,status,requested_at) VALUES($1,$2,$3,$4,$5,'requested',$6)", connection, transaction);
        Add(insert, id, version.Id, version.ChecksumSha256, bindingDigestSha256, requester, now);
        await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        faultInjector?.Check("connector.approval.request.after-state");
        await InsertAuditAsync(connection, transaction, null, requester.ToString("D"), "connector.approval.request", "connectorVersion", version.ConnectorSlug + "/" + version.Version, correlationId, "BGW-ADMIN-APPROVAL-REQUESTED", now, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new(id, version.Id, Convert.ToHexString(version.ChecksumSha256), Convert.ToHexString(bindingDigestSha256), requester, null, null, ConnectorApprovalStatus.Requested, now, null, null, null, null);
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> ApproveAsync(Guid approvalRequestId, Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        const string sql = "UPDATE gateway.connector_approval a SET status='approved',approved_by=$5,approved_at=$6,decision_comment=$7 FROM gateway.connector_version v WHERE a.id=$1 AND a.connector_version_id=$2 AND a.connector_version_id=v.id AND a.checksum_sha256=$3 AND a.binding_digest_sha256=$4 AND a.status='requested' AND a.requested_by<>$5 AND v.created_by<>$5::text AND NOT EXISTS(SELECT 1 FROM gateway.connector_binding_bundle_version b WHERE b.connector_version_id=v.id AND b.created_by=$5::text) RETURNING a.id,a.connector_version_id,a.checksum_sha256,a.binding_digest_sha256,a.requested_by,a.approved_by,a.rejected_by,a.status,a.requested_at,a.approved_at,a.rejected_at,a.decision_comment,a.invalidated_at";
        await using NpgsqlCommand command = new(sql, connection, transaction);
        Add(command, approvalRequestId, connectorVersionId, checksumSha256, bindingDigestSha256, approver, now, comment);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
        ConnectorApprovalRecord result = ReadApproval(reader); await reader.DisposeAsync().ConfigureAwait(false);
        faultInjector?.Check("connector.approval.approve.after-state");
        await InsertAuditAsync(connection, transaction, null, approver.ToString("D"), "connector.approval.approve", "connectorVersion", connectorVersionId.ToString("D"), correlationId, "BGW-ADMIN-APPROVAL-APPROVED", now, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid rejector, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        const string sql = "UPDATE gateway.connector_approval a SET status='rejected',rejected_by=$4,rejected_at=$5,decision_comment=$6 FROM gateway.connector_version v WHERE a.connector_version_id=$1 AND a.connector_version_id=v.id AND a.checksum_sha256=$2 AND a.binding_digest_sha256=$3 AND a.status='requested' AND a.requested_by<>$4 AND v.created_by<>$4::text RETURNING a.id,a.connector_version_id,a.checksum_sha256,a.binding_digest_sha256,a.requested_by,a.approved_by,a.rejected_by,a.status,a.requested_at,a.approved_at,a.rejected_at,a.decision_comment,a.invalidated_at";
        await using NpgsqlCommand command = new(sql, connection, transaction);
        Add(command, connectorVersionId, checksumSha256, bindingDigestSha256, rejector, now, comment);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
        ConnectorApprovalRecord result = ReadApproval(reader); await reader.DisposeAsync().ConfigureAwait(false);
        faultInjector?.Check("connector.approval.reject.after-state");
        await InsertAuditAsync(connection, transaction, null, rejector.ToString("D"), "connector.approval.reject", "connectorVersion", connectorVersionId.ToString("D"), correlationId, "BGW-ADMIN-APPROVAL-REJECTED", now, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public async Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string actor, CancellationToken cancellationToken)
    {
        if (!Guid.TryParseExact(actor, "D", out Guid publisher)) return false;
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "SELECT EXISTS(SELECT 1 FROM gateway.connector_approval a JOIN gateway.connector_version v ON v.id=a.connector_version_id WHERE a.connector_version_id=$1 AND a.checksum_sha256=$2 AND a.binding_digest_sha256=$3 AND a.approved_by=$4 AND a.status='approved' AND a.approved_by<>a.requested_by AND a.approved_by::text<>v.created_by AND NOT EXISTS(SELECT 1 FROM gateway.connector_binding_bundle_version b WHERE b.connector_version_id=v.id AND b.created_by=a.approved_by::text))";
        await using NpgsqlCommand command = new(sql, connection);
        Add(command, connectorVersionId, checksumSha256, bindingDigestSha256, publisher);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is true;
    }

    /// <inheritdoc />
    public async Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await InvalidateAsync(connection, null, connectorVersionId, now, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        List<ConnectorApprovalRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT id,connector_version_id,checksum_sha256,binding_digest_sha256,requested_by,approved_by,rejected_by,status,requested_at,approved_at,rejected_at,decision_comment,invalidated_at FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC", connection);
        command.Parameters.AddWithValue(connectorVersionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadApproval(reader));
        return result;
    }

    /// <inheritdoc />
    public async Task<AdminPage<ConnectorApprovalRecord>> ListApprovalsPageAsync(Guid connectorVersionId, int offset, int limit, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit); List<ConnectorApprovalRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = new("SELECT count(*) FROM gateway.connector_approval WHERE connector_version_id=$1", connection))
        {
            Add(count, connectorVersionId);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        }
        await using NpgsqlCommand command = new("SELECT id,connector_version_id,checksum_sha256,binding_digest_sha256,requested_by,approved_by,rejected_by,status,requested_at,approved_at,rejected_at,decision_comment,invalidated_at FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC,id DESC OFFSET $2 LIMIT $3", connection);
        Add(command, connectorVersionId, offset, limit);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadApproval(reader));
        return new(result, offset, limit, total);
    }

    private static async Task InvalidateAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, Guid versionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("UPDATE gateway.connector_approval SET status='invalidated',invalidated_at=$2 WHERE connector_version_id=$1 AND status IN ('requested','approved')", connection, transaction);
        Add(command, versionId, now);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertAuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid? tenantId, string actorId, string action, string targetType, string targetId, Guid correlationId, string reasonCode, DateTimeOffset now, CancellationToken cancellationToken)
    {
        string metadata = JsonSerializer.Serialize(new Dictionary<string, string>());
        await using NpgsqlCommand command = new("INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,$3,'administrator',$4,$5,$6,$7,$8,'success',$9,$10::jsonb)", connection, transaction);
        Add(command, Guid.NewGuid(), now, tenantId, actorId, action, targetType, targetId, correlationId, reasonCode, metadata);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task SetTenantAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid? tenantId, CancellationToken cancellationToken)
    {
        if (tenantId is null) return;
        await using NpgsqlCommand command = new("SELECT set_config('app.tenant_id',$1,true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId.Value.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RevokeSessionsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid principalId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("UPDATE gateway.admin_session SET revoked_at=coalesce(revoked_at,$2) WHERE principal_id=$1", connection, transaction);
        Add(command, principalId, now);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static AdminPrincipalRecord ReadPrincipal(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetBoolean(5), reader.GetFieldValue<DateTimeOffset>(6));
    private static AdminRoleAssignmentRecord ReadAssignment(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetGuid(1), ParseRole(reader.GetString(2)), reader.IsDBNull(3) ? null : reader.GetGuid(3), reader.GetGuid(4), reader.GetFieldValue<DateTimeOffset>(5));
    private static ConnectorApprovalRecord ReadApproval(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetGuid(1), Convert.ToHexString(reader.GetFieldValue<byte[]>(2)), reader.IsDBNull(3) ? string.Empty : Convert.ToHexString(reader.GetFieldValue<byte[]>(3)), reader.GetGuid(4), reader.IsDBNull(5) ? null : reader.GetGuid(5), reader.IsDBNull(6) ? null : reader.GetGuid(6), Enum.Parse<ConnectorApprovalStatus>(reader.GetString(7), true), reader.GetFieldValue<DateTimeOffset>(8), reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9), reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10), reader.IsDBNull(11) ? null : reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12));
    private static string Role(AdminRole role) => role switch { AdminRole.Viewer => "viewer", AdminRole.ConnectorEditor => "connector_editor", AdminRole.ConnectorApprover => "connector_approver", AdminRole.Operator => "operator", AdminRole.SecurityAdministrator => "security_administrator", _ => throw new ArgumentOutOfRangeException(nameof(role)) };
    private static AdminRole ParseRole(string role) => role switch { "viewer" => AdminRole.Viewer, "connector_editor" => AdminRole.ConnectorEditor, "connector_approver" => AdminRole.ConnectorApprover, "operator" => AdminRole.Operator, "security_administrator" => AdminRole.SecurityAdministrator, _ => throw new InvalidOperationException("Unknown Admin role.") };
    private static void ValidatePage(int offset, int limit) { if (offset < 0 || limit is < 1 or > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400); }
    private static void Add(NpgsqlCommand command, params object?[] values) { foreach (object? value in values) command.Parameters.AddWithValue(value ?? DBNull.Value); }
}

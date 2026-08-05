using System.Data;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL implementation of provider-neutral Admin security state.</summary>
public sealed class PostgresAdminSecurityStore(NpgsqlDataSource dataSource) : IAdminSecurityStore
{
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
    public async Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken)
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
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return claimed;
    }

    /// <inheritdoc />
    public async Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        Guid id = Guid.NewGuid();
        const string sql = "INSERT INTO gateway.admin_role_assignment(id,principal_id,role,tenant_id,granted_by,granted_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING id,principal_id,role,tenant_id,granted_by,granted_at";
        await using NpgsqlCommand insert = new(sql, connection);
        Add(insert, id, principalId, Role(role), tenantId, grantedBy, now);
        await using (NpgsqlDataReader reader = await insert.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return ReadAssignment(reader);
        await using NpgsqlCommand select = new("SELECT id,principal_id,role,tenant_id,granted_by,granted_at FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role=$2 AND tenant_id IS NOT DISTINCT FROM $3", connection);
        Add(select, principalId, Role(role), tenantId);
        await using NpgsqlDataReader existing = await select.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await existing.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-ROLE-ASSIGNMENT", 409);
        return ReadAssignment(existing);
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, Guid requester, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await InvalidateAsync(connection, transaction, version.Id, now, cancellationToken).ConfigureAwait(false);
        Guid id = Guid.NewGuid();
        await using NpgsqlCommand insert = new("INSERT INTO gateway.connector_approval(id,connector_version_id,checksum_sha256,requested_by,status,requested_at) VALUES($1,$2,$3,$4,'requested',$5)", connection, transaction);
        Add(insert, id, version.Id, version.ChecksumSha256, requester, now);
        await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new(id, version.Id, Convert.ToHexString(version.ChecksumSha256), requester, null, ConnectorApprovalStatus.Requested, now, null, null);
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> ApproveAsync(Guid connectorVersionId, byte[] checksumSha256, string createdBy, Guid approver, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "UPDATE gateway.connector_approval a SET status='approved',approved_by=$3,approved_at=$4 FROM gateway.connector_version v WHERE a.connector_version_id=$1 AND a.connector_version_id=v.id AND a.checksum_sha256=$2 AND a.status='requested' AND a.requested_by<>$3 AND v.created_by<>$3::text RETURNING a.id,a.connector_version_id,a.checksum_sha256,a.requested_by,a.approved_by,a.status,a.requested_at,a.approved_at,a.invalidated_at";
        await using NpgsqlCommand command = new(sql, connection);
        Add(command, connectorVersionId, checksumSha256, approver, now);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
        return ReadApproval(reader);
    }

    /// <inheritdoc />
    public async Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, string actor, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "SELECT EXISTS(SELECT 1 FROM gateway.connector_approval a JOIN gateway.connector_version v ON v.id=a.connector_version_id WHERE a.connector_version_id=$1 AND a.checksum_sha256=$2 AND a.status='approved' AND a.approved_by<>a.requested_by AND a.approved_by::text<>v.created_by)";
        await using NpgsqlCommand command = new(sql, connection);
        Add(command, connectorVersionId, checksumSha256);
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
        await using NpgsqlCommand command = new("SELECT id,connector_version_id,checksum_sha256,requested_by,approved_by,status,requested_at,approved_at,invalidated_at FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC", connection);
        command.Parameters.AddWithValue(connectorVersionId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadApproval(reader));
        return result;
    }

    private static async Task InvalidateAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, Guid versionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("UPDATE gateway.connector_approval SET status='invalidated',invalidated_at=$2 WHERE connector_version_id=$1 AND status IN ('requested','approved')", connection, transaction);
        Add(command, versionId, now);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static AdminPrincipalRecord ReadPrincipal(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetBoolean(5), reader.GetFieldValue<DateTimeOffset>(6));
    private static AdminRoleAssignmentRecord ReadAssignment(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetGuid(1), ParseRole(reader.GetString(2)), reader.IsDBNull(3) ? null : reader.GetGuid(3), reader.GetGuid(4), reader.GetFieldValue<DateTimeOffset>(5));
    private static ConnectorApprovalRecord ReadApproval(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetGuid(1), Convert.ToHexString(reader.GetFieldValue<byte[]>(2)), reader.GetGuid(3), reader.IsDBNull(4) ? null : reader.GetGuid(4), Enum.Parse<ConnectorApprovalStatus>(reader.GetString(5), true), reader.GetFieldValue<DateTimeOffset>(6), reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7), reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8));
    private static string Role(AdminRole role) => role switch { AdminRole.Viewer => "viewer", AdminRole.ConnectorEditor => "connector_editor", AdminRole.ConnectorApprover => "connector_approver", AdminRole.Operator => "operator", AdminRole.SecurityAdministrator => "security_administrator", _ => throw new ArgumentOutOfRangeException(nameof(role)) };
    private static AdminRole ParseRole(string role) => role switch { "viewer" => AdminRole.Viewer, "connector_editor" => AdminRole.ConnectorEditor, "connector_approver" => AdminRole.ConnectorApprover, "operator" => AdminRole.Operator, "security_administrator" => AdminRole.SecurityAdministrator, _ => throw new InvalidOperationException("Unknown Admin role.") };
    private static void Add(NpgsqlCommand command, params object?[] values) { foreach (object? value in values) command.Parameters.AddWithValue(value ?? DBNull.Value); }
}

using System.Data;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL administrative catalogue. Tenant rows are always read with transaction-local RLS context.</summary>
public sealed class PostgresAdminDirectoryStore(AdminPostgresDataSource adminDataSource) : IAdminDirectoryStore
{
    private readonly NpgsqlDataSource dataSource = adminDataSource.Value;
    /// <inheritdoc />
    public Task<AdminPage<TenantRecord>> ListTenantsAsync(int offset, int limit, CancellationToken cancellationToken) => QueryAsync<TenantRecord>(
        "SELECT id,code,display_name,status,created_at,row_version FROM gateway.tenant ORDER BY code,id OFFSET $1 LIMIT $2", "SELECT count(*) FROM gateway.tenant",
        ReadTenant, offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<TenantRecord?> GetTenantAsync(Guid tenantId, CancellationToken cancellationToken) => GetAsync(
        "SELECT id,code,display_name,status,created_at,row_version FROM gateway.tenant WHERE id=$1", tenantId, ReadTenant, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<ApplicationRecord>> ListApplicationsAsync(int offset, int limit, CancellationToken cancellationToken) => QueryAsync<ApplicationRecord>(
        "SELECT id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at,row_version FROM gateway.application ORDER BY code,id OFFSET $1 LIMIT $2", "SELECT count(*) FROM gateway.application",
        ReadApplication, offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<ApplicationRecord?> GetApplicationAsync(Guid applicationId, CancellationToken cancellationToken) => GetAsync(
        "SELECT id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at,row_version FROM gateway.application WHERE id=$1", applicationId, ReadApplication, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<GatewayEnvironmentRecord>> ListEnvironmentsAsync(int offset, int limit, CancellationToken cancellationToken) => QueryAsync<GatewayEnvironmentRecord>(
        "SELECT id,code,display_name,production_controls FROM gateway.environment ORDER BY code,id OFFSET $1 LIMIT $2", "SELECT count(*) FROM gateway.environment",
        reader => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetBoolean(3)), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<InstallationRecord>> ListInstallationsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) => QueryTenantAsync<InstallationRecord>(tenantId,
        "SELECT i.id,i.tenant_id,i.application_id,i.environment_id,i.status,i.broker_version,i.created_at,i.last_seen_at,i.revoked_at,i.revocation_reason,i.installation_kind,i.client_version,i.updated_at,c.id,c.status,encode(c.certificate_sha256,'hex'),encode(c.spki_sha256,'hex'),c.serial_number,c.not_before,c.not_after FROM gateway.installation i LEFT JOIN LATERAL (SELECT ic.* FROM gateway.installation_credential ic WHERE ic.installation_id=i.id ORDER BY CASE ic.status WHEN 'active' THEN 0 WHEN 'overlap' THEN 1 ELSE 2 END,ic.created_at DESC LIMIT 1) c ON true WHERE i.tenant_id=$1 ORDER BY i.created_at DESC,i.id OFFSET $2 LIMIT $3", "SELECT count(*) FROM gateway.installation WHERE tenant_id=$1",
        reader => ReadInstallation(reader), offset, limit, cancellationToken);

    /// <inheritdoc />
    public async Task<InstallationRecord?> GetInstallationAsync(Guid tenantId, Guid installationId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT i.id,i.tenant_id,i.application_id,i.environment_id,i.status,i.broker_version,i.created_at,i.last_seen_at,i.revoked_at,i.revocation_reason,i.installation_kind,i.client_version,i.updated_at,c.id,c.status,encode(c.certificate_sha256,'hex'),encode(c.spki_sha256,'hex'),c.serial_number,c.not_before,c.not_after FROM gateway.installation i LEFT JOIN LATERAL (SELECT ic.* FROM gateway.installation_credential ic WHERE ic.installation_id=i.id ORDER BY CASE ic.status WHEN 'active' THEN 0 WHEN 'overlap' THEN 1 ELSE 2 END,ic.created_at DESC LIMIT 1) c ON true WHERE i.tenant_id=$1 AND i.id=$2", connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(installationId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? ReadInstallation(reader) : null;
    }

    /// <inheritdoc />
    public Task<AdminPage<InstallationGrantRecord>> ListGrantsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) => QueryTenantAsync<InstallationGrantRecord>(tenantId,
        "SELECT g.id,g.installation_id,g.tenant_id,c.slug,g.operation_id,g.enabled,g.valid_from,g.valid_until FROM gateway.installation_connector_grant g JOIN gateway.connector_definition c ON c.id=g.connector_id WHERE g.tenant_id=$1 ORDER BY c.slug,g.operation_id,g.id OFFSET $2 LIMIT $3", "SELECT count(*) FROM gateway.installation_connector_grant WHERE tenant_id=$1",
        reader => new(reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2), reader.GetString(3), reader.GetString(4), reader.GetBoolean(5), reader.GetFieldValue<DateTimeOffset>(6), reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7)), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<GatewayAuditEvent>> ListAuditAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) => QueryTenantAsync<GatewayAuditEvent>(tenantId,
        "SELECT id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted::text FROM gateway.audit_event WHERE tenant_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET $2 LIMIT $3", "SELECT count(*) FROM gateway.audit_event WHERE tenant_id=$1",
        reader => new(reader.GetGuid(0), reader.GetFieldValue<DateTimeOffset>(1), reader.GetGuid(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetGuid(8), reader.GetString(9), reader.GetString(10), JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(11)) ?? new()), offset, limit, cancellationToken);

    private async Task<AdminPage<T>> QueryAsync<T>(string sql, string countSql, Func<NpgsqlDataReader, T> read, int offset, int limit, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit);
        List<T> values = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = new(countSql, connection)) total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(offset); command.Parameters.AddWithValue(limit);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) values.Add(read(reader));
        return new(values, offset, limit, total);
    }

    private async Task<T?> GetAsync<T>(string sql, Guid id, Func<NpgsqlDataReader, T> read, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(id);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? read(reader) : default;
    }

    private async Task<AdminPage<T>> QueryTenantAsync<T>(Guid tenantId, string sql, string countSql, Func<NpgsqlDataReader, T> read, int offset, int limit, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit);
        List<T> values = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = new(countSql, connection, transaction))
        {
            count.Parameters.AddWithValue(tenantId);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        }
        await using NpgsqlCommand command = new(sql, connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(offset); command.Parameters.AddWithValue(limit);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) values.Add(read(reader));
        return new(values, offset, limit, total);
    }

    private static async Task SetTenantAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid tenantId, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new("SELECT set_config('app.tenant_id',$1,true)", connection, transaction);
        command.Parameters.AddWithValue(tenantId.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static InstallationRecord ReadInstallation(NpgsqlDataReader reader)
    {
        InstallationCredentialPublicMetadata? credential = reader.IsDBNull(13) ? null : new(
            reader.GetGuid(13),
            Enum.Parse<CredentialStatus>(reader.GetString(14), true),
            reader.GetString(15).ToUpperInvariant(),
            reader.GetString(16).ToUpperInvariant(),
            reader.GetString(17),
            reader.GetFieldValue<DateTimeOffset>(18),
            reader.GetFieldValue<DateTimeOffset>(19));
        return new(reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2), reader.GetGuid(3), Enum.Parse<InstallationStatus>(reader.GetString(4), true), reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6), reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7), reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8), reader.IsDBNull(9) ? null : reader.GetString(9), Enum.Parse<InstallationKind>(reader.GetString(10), true), reader.IsDBNull(11) ? null : reader.GetString(11), reader.GetFieldValue<DateTimeOffset>(12), credential);
    }
    private static TenantRecord ReadTenant(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), Enum.Parse<TenantStatus>(reader.GetString(3), true), reader.GetFieldValue<DateTimeOffset>(4), reader.GetInt64(5));
    private static ApplicationRecord ReadApplication(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), Enum.Parse<ApplicationStatus>(reader.GetString(3), true), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6), reader.GetInt64(7));
    private static void ValidatePage(int offset, int limit) { if (offset < 0 || limit is < 1 or > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400); }
}

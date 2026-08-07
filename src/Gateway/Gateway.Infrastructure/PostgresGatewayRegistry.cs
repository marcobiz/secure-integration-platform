using System.Data;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL 18 registry. Tenant-scoped operations set the RLS context transaction-locally.</summary>
public sealed class PostgresGatewayRegistry(NpgsqlDataSource dataSource, IAdminTransactionFaultInjector? faultInjector = null) : IGatewayRegistry, IAdminGatewayRegistry
{
    /// <inheritdoc />
    public async Task AddTenantAsync(TenantRecord tenant, CancellationToken cancellationToken) => await ExecuteAsync(
        "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,$3,$4,$5)", cancellationToken,
        tenant.Id, tenant.Code, tenant.DisplayName, Db(tenant.Status), tenant.CreatedAt).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task AddTenantWithAuditAsync(TenantRecord tenant, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        if (auditEvent.TenantId != tenant.Id) throw new ArgumentException("Tenant audit scope is inconsistent.", nameof(auditEvent));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenant.Id, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,$3,$4,$5)", cancellationToken, tenant.Id, tenant.Code, tenant.DisplayName, Db(tenant.Status), tenant.CreatedAt).ConfigureAwait(false);
        faultInjector?.Check("tenant.create.after-state");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<TenantRecord> UpdateTenantWithAuditAsync(Guid tenantId, string displayName, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) =>
        MutateTenantWithAuditAsync(tenantId, expectedRowVersion, "display_name=$2", displayName, "tenant.update.after-state", auditEvent, cancellationToken);

    /// <inheritdoc />
    public Task<TenantRecord> DisableTenantWithAuditAsync(Guid tenantId, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) =>
        MutateTenantWithAuditAsync(tenantId, expectedRowVersion, "status=$2", Db(TenantStatus.Suspended), "tenant.disable.after-state", auditEvent, cancellationToken);

    /// <inheritdoc />
    public async Task AddApplicationAsync(ApplicationRecord application, CancellationToken cancellationToken) => await ExecuteAsync(
        "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)", cancellationToken,
        application.Id, application.Code, application.DisplayName, Db(application.Status), application.MinimumBrokerVersion, application.MaximumBrokerVersion, application.CreatedAt).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task AddApplicationWithAuditAsync(ApplicationRecord application, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)", cancellationToken, application.Id, application.Code, application.DisplayName, Db(application.Status), application.MinimumBrokerVersion, application.MaximumBrokerVersion, application.CreatedAt).ConfigureAwait(false);
        faultInjector?.Check("application.create.after-state");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ApplicationRecord> UpdateApplicationWithAuditAsync(Guid applicationId, string displayName, string minimumBrokerVersion, string? maximumBrokerVersion, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await LockApplicationAsync(connection, transaction, applicationId, expectedRowVersion, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("UPDATE gateway.application SET display_name=$2,minimum_broker_version=$3,maximum_broker_version=$4,row_version=row_version+1 WHERE id=$1 RETURNING id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at,row_version", connection, transaction);
        command.Parameters.AddWithValue(applicationId); command.Parameters.AddWithValue(displayName); command.Parameters.AddWithValue(minimumBrokerVersion); command.Parameters.AddWithValue((object?)maximumBrokerVersion ?? DBNull.Value);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-APPLICATION-NOT-FOUND", 404);
        ApplicationRecord result = ReadApplication(reader); await reader.CloseAsync().ConfigureAwait(false);
        faultInjector?.Check("application.update.after-state");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <inheritdoc />
    public async Task<ApplicationRecord> DisableApplicationWithAuditAsync(Guid applicationId, long expectedRowVersion, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await LockApplicationAsync(connection, transaction, applicationId, expectedRowVersion, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("UPDATE gateway.application SET status='suspended',row_version=row_version+1 WHERE id=$1 RETURNING id,code,display_name,status,minimum_broker_version,maximum_broker_version,created_at,row_version", connection, transaction);
        command.Parameters.AddWithValue(applicationId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-APPLICATION-NOT-FOUND", 404);
        ApplicationRecord result = ReadApplication(reader); await reader.CloseAsync().ConfigureAwait(false);
        faultInjector?.Check("application.disable.after-state");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task<TenantRecord> MutateTenantWithAuditAsync(Guid tenantId, long expectedRowVersion, string assignment, object value, string faultBoundary, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        if (auditEvent.TenantId != tenantId) throw new ArgumentException("Tenant audit scope is inconsistent.", nameof(auditEvent));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        await using (NpgsqlCommand select = new("SELECT row_version FROM gateway.tenant WHERE id=$1 FOR UPDATE", connection, transaction))
        {
            select.Parameters.AddWithValue(tenantId);
            object? current = await select.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (current is null) throw new GatewayException("BGW-TENANT-NOT-FOUND", 404);
            if (Convert.ToInt64(current, System.Globalization.CultureInfo.InvariantCulture) != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        }
        await using NpgsqlCommand command = new($"UPDATE gateway.tenant SET {assignment},row_version=row_version+1 WHERE id=$1 RETURNING id,code,display_name,status,created_at,row_version", connection, transaction);
        command.Parameters.AddWithValue(tenantId); command.Parameters.AddWithValue(value);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-TENANT-NOT-FOUND", 404);
        TenantRecord result = new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), Enum.Parse<TenantStatus>(reader.GetString(3), true), reader.GetFieldValue<DateTimeOffset>(4), reader.GetInt64(5));
        await reader.CloseAsync().ConfigureAwait(false);
        faultInjector?.Check(faultBoundary);
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static ApplicationRecord ReadApplication(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), Enum.Parse<ApplicationStatus>(reader.GetString(3), true), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6), reader.GetInt64(7));

    private static async Task LockApplicationAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid applicationId, long expectedRowVersion, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand select = new("SELECT row_version FROM gateway.application WHERE id=$1 FOR UPDATE", connection, transaction);
        select.Parameters.AddWithValue(applicationId);
        object? current = await select.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (current is null) throw new GatewayException("BGW-APPLICATION-NOT-FOUND", 404);
        if (Convert.ToInt64(current, System.Globalization.CultureInfo.InvariantCulture) != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
    }

    /// <inheritdoc />
    public async Task AddEnvironmentAsync(GatewayEnvironmentRecord environment, CancellationToken cancellationToken) => await ExecuteAsync(
        "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,$3,$4)", cancellationToken,
        environment.Id, environment.Code, environment.DisplayName, environment.ProductionControls).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task AddInstallationAsync(InstallationRecord installation, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, installation.TenantId, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction,
            "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,broker_version,created_at,last_seen_at,revoked_at,revocation_reason,installation_kind,client_version,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)", cancellationToken,
            installation.Id, installation.TenantId, installation.ApplicationId, installation.EnvironmentId, Db(installation.Status), installation.BrokerVersion, installation.CreatedAt, installation.LastSeenAt, installation.RevokedAt, installation.RevocationReason, Db(installation.InstallationKind), installation.ClientVersion, installation.UpdatedAt ?? installation.CreatedAt).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task AddActivationCodeAsync(ActivationCodeRecord activationCode, CancellationToken cancellationToken)
    {
        Guid tenantId = await ResolveTenantAsync(activationCode.InstallationId, cancellationToken).ConfigureAwait(false);
        await ExecuteTenantAsync(tenantId,
            "INSERT INTO gateway.activation_code(id,installation_id,code_hmac,expires_at,created_at,created_by,attempt_count,used_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", cancellationToken,
            activationCode.Id, activationCode.InstallationId, activationCode.CodeHmac, activationCode.ExpiresAt, activationCode.CreatedAt, activationCode.CreatedBy, activationCode.AttemptCount, activationCode.UsedAt).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task AddInstallationActivationWithAuditAsync(InstallationRecord installation, ActivationCodeRecord activationCode, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        if (activationCode.InstallationId != installation.Id || auditEvent.TenantId != installation.TenantId) throw new ArgumentException("Administrative installation aggregate is inconsistent.");
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, installation.TenantId, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,broker_version,created_at,last_seen_at,revoked_at,revocation_reason,installation_kind,client_version,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)", cancellationToken, installation.Id, installation.TenantId, installation.ApplicationId, installation.EnvironmentId, Db(installation.Status), installation.BrokerVersion, installation.CreatedAt, installation.LastSeenAt, installation.RevokedAt, installation.RevocationReason, Db(installation.InstallationKind), installation.ClientVersion, installation.UpdatedAt ?? installation.CreatedAt).ConfigureAwait(false);
        faultInjector?.Check("installation.create.after-installation");
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.activation_code(id,installation_id,code_hmac,expires_at,created_at,created_by,attempt_count,used_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", cancellationToken, activationCode.Id, activationCode.InstallationId, activationCode.CodeHmac, activationCode.ExpiresAt, activationCode.CreatedAt, activationCode.CreatedBy, activationCode.AttemptCount, activationCode.UsedAt).ConfigureAwait(false);
        faultInjector?.Check("installation.create.after-activation");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task AddGrantAsync(InstallationGrantRecord grant, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, grant.TenantId, cancellationToken).ConfigureAwait(false);
        Guid connectorId = Guid.NewGuid();
        await ExecuteAsync(connection, transaction,
            "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$2,'active',now(),'gateway-provisioning') ON CONFLICT(slug) DO NOTHING", cancellationToken, connectorId, grant.ConnectorId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction,
            "INSERT INTO gateway.installation_connector_grant(id,installation_id,tenant_id,connector_id,operation_id,enabled,valid_from,valid_until) SELECT $1,$2,$3,id,$4,$5,$6,$7 FROM gateway.connector_definition WHERE slug=$8", cancellationToken,
            grant.Id, grant.InstallationId, grant.TenantId, grant.OperationId, grant.Enabled, grant.ValidFrom, grant.ValidUntil, grant.ConnectorId).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task AddGrantWithAuditAsync(InstallationGrantRecord grant, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, grant.TenantId, cancellationToken).ConfigureAwait(false);
        Guid connectorId = Guid.NewGuid();
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$2,'active',now(),'gateway-provisioning') ON CONFLICT(slug) DO NOTHING", cancellationToken, connectorId, grant.ConnectorId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.installation_connector_grant(id,installation_id,tenant_id,connector_id,operation_id,enabled,valid_from,valid_until) SELECT $1,$2,$3,id,$4,$5,$6,$7 FROM gateway.connector_definition WHERE slug=$8", cancellationToken, grant.Id, grant.InstallationId, grant.TenantId, grant.OperationId, grant.Enabled, grant.ValidFrom, grant.ValidUntil, grant.ConnectorId).ConfigureAwait(false);
        faultInjector?.Check("grant.create.after-state");
        await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ActivationCodeRecord?> FindActivationCodeAsync(Guid activationCodeId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT id,installation_id,code_hmac,expires_at,created_at,created_by,attempt_count,used_at FROM gateway.resolve_activation_code($1)", connection);
        command.Parameters.AddWithValue(activationCodeId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new(reader.GetGuid(0), reader.GetGuid(1), reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<DateTimeOffset>(3), reader.GetFieldValue<DateTimeOffset>(4), reader.GetString(5), reader.GetInt16(6), reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7))
            : null;
    }

    /// <inheritdoc />
    public async Task RecordActivationFailureAsync(Guid activationCodeId, CancellationToken cancellationToken) => await ExecuteAsync(
        "SELECT gateway.record_activation_failure($1)", cancellationToken, activationCodeId).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<bool> ActivateAsync(Guid activationCodeId, byte[] expectedCodeHmac, InstallationCredentialRecord credential, string? brokerVersion, string? clientVersion, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ActivationCodeRecord? activation = await FindActivationCodeAsync(activationCodeId, cancellationToken).ConfigureAwait(false);
        if (activation is null) return false;
        Guid tenantId = await ResolveTenantAsync(activation.InstallationId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        InstallationKind installationKind;
        await using (NpgsqlCommand policy = CreateCommand(connection, transaction, "SELECT i.installation_kind,a.minimum_broker_version,a.maximum_broker_version FROM gateway.installation i JOIN gateway.application a ON a.id=i.application_id WHERE i.id=$1", activation.InstallationId))
        await using (NpgsqlDataReader policyReader = await policy.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
        {
            if (!await policyReader.ReadAsync(cancellationToken).ConfigureAwait(false)) return false;
            installationKind = Parse<InstallationKind>(policyReader.GetString(0));
            string minimum = policyReader.GetString(1);
            string? maximum = policyReader.IsDBNull(2) ? null : policyReader.GetString(2);
            if (installationKind == InstallationKind.Broker)
            {
                if (clientVersion is not null || string.IsNullOrWhiteSpace(brokerVersion) || !Version.TryParse(brokerVersion, out _)) throw new GatewayException("BGW-INSTALLATION-BROKER-VERSION", 400);
                if (!IsVersionAllowed(brokerVersion, minimum, maximum)) throw new GatewayException("BGW-INSTALLATION-BROKER-INCOMPATIBLE", 409);
            }
            else if (brokerVersion is not null || string.IsNullOrWhiteSpace(clientVersion) || !Version.TryParse(clientVersion, out _))
            {
                throw new GatewayException("BGW-INSTALLATION-CLIENT-VERSION", 400);
            }
        }
        await using NpgsqlCommand consume = CreateCommand(connection, transaction,
            "UPDATE gateway.activation_code SET used_at=$2 WHERE id=$1 AND used_at IS NULL AND expires_at>$2 AND attempt_count<5 AND code_hmac=$3 RETURNING installation_id", activationCodeId, now, expectedCodeHmac);
        object? installationValue = await consume.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (installationValue is not Guid installationId || installationId != credential.InstallationId) { await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false); return false; }
        int activated = await ExecuteAsync(connection, transaction, "UPDATE gateway.installation SET status='active',broker_version=$2,client_version=$3,last_seen_at=$4,updated_at=$4,row_version=row_version+1 WHERE id=$1 AND status='pending'", cancellationToken, installationId, installationKind == InstallationKind.Broker ? brokerVersion : null, installationKind == InstallationKind.Direct ? clientVersion : null, now).ConfigureAwait(false);
        if (activated != 1) { await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false); return false; }
        await InsertCredentialAsync(connection, transaction, credential, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <inheritdoc />
    public async Task<RegisteredInstallationIdentity?> FindIdentityByCertificateAsync(byte[] certificateSha256, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT identity.*,metadata.installation_kind,metadata.client_version FROM gateway.resolve_installation_identity($1) identity CROSS JOIN gateway.resolve_installation_client_metadata($1) metadata", connection);
        command.Parameters.AddWithValue(certificateSha256);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        return new(reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2), reader.GetGuid(3), Parse<TenantStatus>(reader.GetString(4)), Parse<ApplicationStatus>(reader.GetString(5)), Parse<InstallationStatus>(reader.GetString(6)), reader.GetGuid(7), Parse<CredentialStatus>(reader.GetString(8)), reader.GetFieldValue<byte[]>(9), reader.GetFieldValue<DateTimeOffset>(10), reader.GetFieldValue<DateTimeOffset>(11), reader.GetString(12), reader.IsDBNull(13) ? null : reader.GetString(13), Parse<InstallationKind>(reader.GetString(14)), reader.IsDBNull(15) ? null : reader.GetString(15));
    }

    /// <inheritdoc />
    public async Task<bool> RenewCredentialAsync(Guid installationId, Guid currentCredentialId, InstallationCredentialRecord replacement, DateTimeOffset overlapEndsAt, CancellationToken cancellationToken)
    {
        Guid tenantId = await ResolveTenantAsync(installationId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        int updated = await ExecuteAsync(connection, transaction, "UPDATE gateway.installation_credential SET status='overlap',not_after=least(not_after,$3) WHERE id=$1 AND installation_id=$2 AND status='active'", cancellationToken, currentCredentialId, installationId, overlapEndsAt).ConfigureAwait(false);
        if (updated != 1) { await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false); return false; }
        await InsertCredentialAsync(connection, transaction, replacement, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.installation_credential SET replaced_by_id=$2 WHERE id=$1", cancellationToken, currentCredentialId, replacement.Id).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.installation SET updated_at=$2 WHERE id=$1", cancellationToken, installationId, replacement.CreatedAt).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> RevokeInstallationAsync(Guid installationId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        Guid tenantId = await ResolveTenantAsync(installationId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        int result = await ExecuteAsync(connection, transaction, "UPDATE gateway.installation SET status='revoked',revoked_at=$2,revocation_reason=$3,updated_at=$2,row_version=row_version+1 WHERE id=$1 AND status NOT IN ('revoked','retired')", cancellationToken, installationId, now, reason).ConfigureAwait(false);
        if (result == 1) await ExecuteAsync(connection, transaction, "UPDATE gateway.installation_credential SET status='revoked',revoked_at=$2 WHERE installation_id=$1 AND status IN ('active','overlap')", cancellationToken, installationId, now).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result == 1;
    }

    /// <inheritdoc />
    public async Task<bool> RevokeInstallationWithAuditAsync(Guid installationId, string reason, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        Guid tenantId = auditEvent.TenantId ?? throw new ArgumentException("Installation audit must be tenant scoped.", nameof(auditEvent));
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        int result = await ExecuteAsync(connection, transaction, "UPDATE gateway.installation SET status='revoked',revoked_at=$2,revocation_reason=$3,updated_at=$2,row_version=row_version+1 WHERE id=$1 AND tenant_id=$4 AND status NOT IN ('revoked','retired')", cancellationToken, installationId, now, reason, tenantId).ConfigureAwait(false);
        if (result == 1) await ExecuteAsync(connection, transaction, "UPDATE gateway.installation_credential SET status='revoked',revoked_at=$2 WHERE installation_id=$1 AND status IN ('active','overlap')", cancellationToken, installationId, now).ConfigureAwait(false);
        if (result == 1)
        {
            faultInjector?.Check("installation.revoke.after-state");
            await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result == 1;
    }

    /// <inheritdoc />
    public async Task<bool> IsGrantedAsync(Guid installationId, Guid tenantId, string connectorId, string operationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        object? result = await ScalarTenantAsync(tenantId, "SELECT EXISTS(SELECT 1 FROM gateway.installation_connector_grant g JOIN gateway.connector_definition c ON c.id=g.connector_id WHERE g.installation_id=$1 AND g.tenant_id=$2 AND c.slug=$3 AND g.operation_id=$4 AND g.enabled AND g.valid_from<=$5 AND (g.valid_until IS NULL OR g.valid_until>$5))", cancellationToken, installationId, tenantId, connectorId, operationId, now).ConfigureAwait(false);
        return result is true;
    }

    /// <inheritdoc />
    public async Task<bool> TryStoreNonceAsync(Guid installationId, byte[] nonceSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        Guid tenantId = await ResolveTenantAsync(installationId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "DELETE FROM gateway.replay_nonce WHERE installation_id=$1 AND expires_at<=now()", cancellationToken, installationId).ConfigureAwait(false);
        int result = await ExecuteAsync(connection, transaction, "INSERT INTO gateway.replay_nonce(installation_id,nonce_sha256,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", cancellationToken, installationId, nonceSha256, expiresAt).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result == 1;
    }

    /// <inheritdoc />
    public async Task AppendAuditAsync(GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        string metadata = JsonSerializer.Serialize(auditEvent.Metadata);
        if (auditEvent.TenantId is Guid tenantId)
            await ExecuteTenantAsync(tenantId, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)", cancellationToken, auditEvent.Id, auditEvent.OccurredAt, tenantId, auditEvent.ActorType, auditEvent.ActorId, auditEvent.Action, auditEvent.TargetType, auditEvent.TargetId, auditEvent.CorrelationId, auditEvent.Outcome, auditEvent.ReasonCode, metadata).ConfigureAwait(false);
        else
            await ExecuteAsync("INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,NULL,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)", cancellationToken, auditEvent.Id, auditEvent.OccurredAt, auditEvent.ActorType, auditEvent.ActorId, auditEvent.Action, auditEvent.TargetType, auditEvent.TargetId, auditEvent.CorrelationId, auditEvent.Outcome, auditEvent.ReasonCode, metadata).ConfigureAwait(false);
    }

    private static Task<int> InsertAuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        string metadata = JsonSerializer.Serialize(auditEvent.Metadata);
        return ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)", cancellationToken, auditEvent.Id, auditEvent.OccurredAt, auditEvent.TenantId, auditEvent.ActorType, auditEvent.ActorId, auditEvent.Action, auditEvent.TargetType, auditEvent.TargetId, auditEvent.CorrelationId, auditEvent.Outcome, auditEvent.ReasonCode, metadata);
    }

    /// <inheritdoc />
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try { return Equals(await ScalarAsync("SELECT to_regclass('gateway.installation') IS NOT NULL", cancellationToken).ConfigureAwait(false), true); }
        catch (NpgsqlException) { return false; }
    }

    private async Task<Guid> ResolveTenantAsync(Guid installationId, CancellationToken cancellationToken)
    {
        object? result = await ScalarAsync("SELECT gateway.resolve_installation_tenant($1)", cancellationToken, installationId).ConfigureAwait(false);
        return result is Guid tenantId ? tenantId : throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    }

    private static async Task InsertCredentialAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, InstallationCredentialRecord value, CancellationToken cancellationToken) => await ExecuteAsync(connection, transaction,
        "INSERT INTO gateway.installation_credential(id,installation_id,certificate_sha256,spki_sha256,certificate_der,serial_number,not_before,not_after,status,created_at,replaced_by_id,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", cancellationToken,
        value.Id, value.InstallationId, value.CertificateSha256, value.SpkiSha256, value.CertificateDer, value.SerialNumber, value.NotBefore, value.NotAfter, Db(value.Status), value.CreatedAt, value.ReplacedById, value.RevokedAt).ConfigureAwait(false);

    private async Task<int> ExecuteTenantAsync(Guid tenantId, string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        int result = await ExecuteAsync(connection, transaction, sql, cancellationToken, values).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task<object?> ScalarTenantAsync(Guid tenantId, string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await SetTenantAsync(connection, transaction, tenantId, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = CreateCommand(connection, transaction, sql, values);
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task<int> ExecuteAsync(string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = CreateCommand(connection, null, sql, values);
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<object?> ScalarAsync(string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = CreateCommand(connection, null, sql, values);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlCommand command = CreateCommand(connection, transaction, sql, values);
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task SetTenantAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid tenantId, CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = CreateCommand(connection, transaction, "SELECT set_config('app.tenant_id',$1,true)", tenantId.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static NpgsqlCommand CreateCommand(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, params object?[] values)
    {
        NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object? value in values) command.Parameters.AddWithValue(value ?? DBNull.Value);
        return command;
    }

    private static string Db<T>(T value) where T : struct, Enum => value.ToString().ToLowerInvariant();
    private static T Parse<T>(string value) where T : struct, Enum => Enum.Parse<T>(value, true);
    private static bool IsVersionAllowed(string value, string minimum, string? maximum) => Version.TryParse(value, out Version? parsed) && Version.TryParse(minimum, out Version? min) && parsed >= min && (maximum is null || (Version.TryParse(maximum, out Version? max) && parsed <= max));
}

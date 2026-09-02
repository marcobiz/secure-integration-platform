using System.Data;
using Npgsql;
using NpgsqlTypes;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL-backed exact technical workflow correlation for the authorized Connector bridge.</summary>
internal sealed class PostgresConnectorWorkflowContextStore(NpgsqlDataSource dataSource) : IConnectorWorkflowContextStore
{
    public async Task<ConnectorWorkflowContextRecordResult> RecordAsync(
        ConnectorWorkflowContextStorageRecord record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await SetScopeAsync(connection, transaction, record.Authority, cancellationToken).ConfigureAwait(false);

        const string insertSql = """
            INSERT INTO gateway.connector_workflow_context(
              tenant_id,application_id,installation_id,environment_id,connector_id,connector_version,
              published_context_sha256,originating_operation_id,action_code,purpose_of_use_code,
              operation_profile_checksum_sha256,workflow_instance_id,trace_id,recorded_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            ON CONFLICT DO NOTHING
            RETURNING 1
            """;
        await using NpgsqlCommand insert = Command(connection, transaction, insertSql,
            record.Authority.TenantId,
            record.Authority.ApplicationId,
            record.Authority.InstallationId,
            record.Authority.EnvironmentId,
            record.Authority.ConnectorId,
            record.Authority.ConnectorVersion,
            record.Authority.PublishedContextSha256,
            record.Context.OriginatingOperationId,
            record.Context.ActionCode,
            record.Context.PurposeOfUseCode,
            Convert.FromHexString(record.Context.OperationProfileChecksumSha256),
            record.Context.WorkflowInstanceId,
            record.Context.TraceId,
            record.RecordedAtUtc);
        insert.Parameters[11].NpgsqlDbType = NpgsqlDbType.Varchar;
        insert.Parameters[12].NpgsqlDbType = NpgsqlDbType.Varchar;
        bool created = await insert.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not null;

        List<AuthorizedConnectorWorkflowContext> matches = await ReadMatchesAsync(
            connection,
            transaction,
            record.Authority,
            record.Context.WorkflowInstanceId,
            record.Context.TraceId,
            cancellationToken).ConfigureAwait(false);
        ConnectorWorkflowContextRecordResult result = matches.Count == 1 && Same(matches[0], record.Context)
            ? created ? ConnectorWorkflowContextRecordResult.Created : ConnectorWorkflowContextRecordResult.Unchanged
            : ConnectorWorkflowContextRecordResult.Conflict;
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async Task<AuthorizedConnectorWorkflowContext?> ResolveAsync(
        ConnectorWorkflowContextAuthorityScope authority,
        ConnectorWorkflowContextLookup lookup,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(lookup);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await SetScopeAsync(connection, transaction, authority, cancellationToken).ConfigureAwait(false);
        string predicate = lookup.Kind == ConnectorWorkflowIdentifierKind.WorkflowInstanceId
            ? "workflow_instance_id=$8"
            : "trace_id=$8";
        string sql = $"""
            SELECT originating_operation_id,action_code,purpose_of_use_code,
                   operation_profile_checksum_sha256,workflow_instance_id,trace_id,recorded_at
              FROM gateway.connector_workflow_context
             WHERE tenant_id=$1 AND application_id=$2 AND installation_id=$3 AND environment_id=$4
               AND connector_id=$5 AND connector_version=$6 AND published_context_sha256=$7
               AND {predicate}
            """;
        await using NpgsqlCommand command = Command(connection, transaction, sql,
            authority.TenantId,
            authority.ApplicationId,
            authority.InstallationId,
            authority.EnvironmentId,
            authority.ConnectorId,
            authority.ConnectorVersion,
            authority.PublishedContextSha256,
            lookup.Identifier);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        AuthorizedConnectorWorkflowContext? result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? Read(reader)
            : null;
        await reader.CloseAsync().ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static async Task<List<AuthorizedConnectorWorkflowContext>> ReadMatchesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ConnectorWorkflowContextAuthorityScope authority,
        string? workflowInstanceId,
        string? traceId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT originating_operation_id,action_code,purpose_of_use_code,
                   operation_profile_checksum_sha256,workflow_instance_id,trace_id,recorded_at
              FROM gateway.connector_workflow_context
             WHERE tenant_id=$1 AND application_id=$2 AND installation_id=$3 AND environment_id=$4
               AND connector_id=$5 AND connector_version=$6 AND published_context_sha256=$7
               AND (($8::varchar IS NOT NULL AND workflow_instance_id=$8) OR
                    ($9::varchar IS NOT NULL AND trace_id=$9))
             ORDER BY recorded_at
            """;
        await using NpgsqlCommand command = Command(connection, transaction, sql,
            authority.TenantId,
            authority.ApplicationId,
            authority.InstallationId,
            authority.EnvironmentId,
            authority.ConnectorId,
            authority.ConnectorVersion,
            authority.PublishedContextSha256,
            workflowInstanceId,
            traceId);
        command.Parameters[7].NpgsqlDbType = NpgsqlDbType.Varchar;
        command.Parameters[8].NpgsqlDbType = NpgsqlDbType.Varchar;
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        List<AuthorizedConnectorWorkflowContext> result = [];
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(Read(reader));
        return result;
    }

    private static AuthorizedConnectorWorkflowContext Read(NpgsqlDataReader reader) => new(
        reader.GetString(0),
        reader.GetString(1),
        reader.GetString(2),
        Convert.ToHexStringLower(reader.GetFieldValue<byte[]>(3)),
        reader.IsDBNull(4) ? null : reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.GetFieldValue<DateTimeOffset>(6));

    private static bool Same(AuthorizedConnectorWorkflowContext persisted, ConnectorWorkflowContextRecord candidate) =>
        string.Equals(persisted.OriginatingOperationId, candidate.OriginatingOperationId, StringComparison.Ordinal) &&
        string.Equals(persisted.ActionCode, candidate.ActionCode, StringComparison.Ordinal) &&
        string.Equals(persisted.PurposeOfUseCode, candidate.PurposeOfUseCode, StringComparison.Ordinal) &&
        string.Equals(persisted.OperationProfileChecksumSha256, candidate.OperationProfileChecksumSha256, StringComparison.Ordinal) &&
        string.Equals(persisted.WorkflowInstanceId, candidate.WorkflowInstanceId, StringComparison.Ordinal) &&
        string.Equals(persisted.TraceId, candidate.TraceId, StringComparison.Ordinal);

    private static async Task SetScopeAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ConnectorWorkflowContextAuthorityScope authority,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = Command(connection, transaction,
            "SELECT set_config('app.tenant_id',$1,true),set_config('app.installation_id',$2,true)",
            authority.TenantId.ToString("D"),
            authority.InstallationId.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static NpgsqlCommand Command(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        params object?[] values)
    {
        NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object? value in values) command.Parameters.AddWithValue(value ?? DBNull.Value);
        return command;
    }
}

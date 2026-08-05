using System.Data;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL 18 Connector lifecycle store with transactional publication and rollback.</summary>
public sealed class PostgresConnectorConfigurationStore(NpgsqlDataSource dataSource) : IConnectorConfigurationStore
{
    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        Guid connectorId;
        await using (NpgsqlCommand insertConnector = Command(connection, transaction, "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$3,'active',$4,$5) ON CONFLICT(slug) DO UPDATE SET slug=excluded.slug RETURNING id", Guid.NewGuid(), draft.ConnectorSlug, draft.ConnectorSlug, draft.CreatedAt, draft.CreatedBy))
            connectorId = (Guid)(await insertConnector.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-STORE", 503));
        int inserted;
        try
        {
            inserted = await ExecuteAsync(connection, transaction, "INSERT INTO gateway.connector_version(id,connector_id,version,schema_version,state,configuration_json,checksum_sha256,created_by,created_at,row_version) VALUES($1,$2,$3,$4,'draft',$5::jsonb,$6,$7,$8,1)", cancellationToken,
                draft.Id, connectorId, draft.Version, draft.SchemaVersion, draft.CanonicalJson, draft.ChecksumSha256, draft.CreatedBy, draft.CreatedAt).ConfigureAwait(false);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            throw new GatewayException("BGW-CONNECTOR-VERSION-DUPLICATE", 409);
        }
        if (inserted != 1) throw new GatewayException("BGW-CONNECTOR-STORE", 503);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return draft with { ConnectorId = connectorId, RowVersion = 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at FROM gateway.connector_version v JOIN gateway.connector_definition c ON c.id=v.connector_id WHERE c.slug=$1 AND v.version=$2", connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? ReadVersion(reader) : null;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken)
    {
        List<ConnectorSummary> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT c.slug,p.version,count(v.id)::int FROM gateway.connector_definition c LEFT JOIN gateway.connector_version p ON p.id=c.active_version_id LEFT JOIN gateway.connector_version v ON v.connector_id=c.id GROUP BY c.slug,p.version ORDER BY c.slug", connection);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(new(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetInt32(2)));
        return result;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken)
    {
        List<ConnectorVersionRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at FROM gateway.connector_version v JOIN gateway.connector_definition c ON c.id=v.connector_id WHERE c.slug=$1 ORDER BY v.created_at DESC,v.version", connection);
        command.Parameters.AddWithValue(connectorId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadVersion(reader));
        if (result.Count == 0) throw new GatewayException("BGW-CONNECTOR-NOT-FOUND", 404);
        return result;
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken) =>
        TransitionAsync(versionId, expectedRowVersion, "draft", "validated", "validated_at", now, cancellationToken);

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord target = await ReadVersionForUpdateAsync(connection, transaction, versionId, cancellationToken).ConfigureAwait(false);
        Ensure(target, expectedRowVersion, ConnectorVersionState.Validated);
        object? revisionValue;
        await using (NpgsqlCommand revision = Command(connection, transaction, "SELECT publication_revision FROM gateway.connector_definition WHERE id=$1 FOR UPDATE", target.ConnectorId))
            revisionValue = await revision.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (revisionValue is not long publicationRevision || publicationRevision != expectedPublicationRevision) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='superseded',row_version=row_version+1 WHERE connector_id=$1 AND state='published'", cancellationToken, target.ConnectorId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='published',published_at=coalesce(published_at,$2),row_version=row_version+1 WHERE id=$1", cancellationToken, versionId, now).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=$2,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1", cancellationToken, target.ConnectorId, versionId).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Published, PublishedAt = target.PublishedAt ?? now, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        Guid connectorGuid;
        Guid activeId;
        await using (NpgsqlCommand connector = Command(connection, transaction, "SELECT id,active_version_id FROM gateway.connector_definition WHERE slug=$1 FOR UPDATE", connectorId))
        await using (NpgsqlDataReader reader = await connector.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(1)) throw new GatewayException("BGW-CONNECTOR-NOT-PUBLISHED", 409);
            connectorGuid = reader.GetGuid(0);
            activeId = reader.GetGuid(1);
        }
        ConnectorVersionRecord active = await ReadVersionForUpdateAsync(connection, transaction, activeId, cancellationToken).ConfigureAwait(false);
        if (active.RowVersion != expectedActiveRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        Guid targetId;
        await using (NpgsqlCommand targetCommand = Command(connection, transaction, "SELECT id FROM gateway.connector_version WHERE connector_id=$1 AND version=$2", connectorGuid, targetVersion))
            targetId = (Guid)(await targetCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404));
        ConnectorVersionRecord target = await ReadVersionForUpdateAsync(connection, transaction, targetId, cancellationToken).ConfigureAwait(false);
        if (target.State != ConnectorVersionState.Superseded || target.PublishedAt is null) throw new GatewayException("BGW-CONNECTOR-ROLLBACK-TARGET", 409);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='superseded',row_version=row_version+1 WHERE id=$1", cancellationToken, activeId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='published',row_version=row_version+1 WHERE id=$1", cancellationToken, targetId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=$2,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1", cancellationToken, connectorGuid, targetId).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Published, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord target = await ReadVersionForUpdateAsync(connection, transaction, versionId, cancellationToken).ConfigureAwait(false);
        if (target.RowVersion != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (target.State == ConnectorVersionState.Retired) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='retired',retired_at=$2,row_version=row_version+1 WHERE id=$1", cancellationToken, versionId, now).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=NULL,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1 AND active_version_id=$2", cancellationToken, target.ConnectorId, versionId).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Retired, RetiredAt = now, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, CancellationToken cancellationToken)
    {
        string endpointJson = JsonSerializer.Serialize(bindings.Endpoints.ToDictionary(item => item.Key, item => item.Value.AbsoluteUri, StringComparer.Ordinal));
        string secretJson = JsonSerializer.Serialize(bindings.SecretReferences);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        long current = 0;
        await using (NpgsqlCommand select = Command(connection, transaction, "SELECT revision FROM gateway.connector_environment_binding WHERE connector_id=$1 AND environment_id=$2 FOR UPDATE", bindings.ConnectorId, bindings.EnvironmentId))
        {
            object? value = await select.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (value is long revision) current = revision;
        }
        if (expectedRevision is not null && expectedRevision.Value != current) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        long next = current + 1;
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.connector_environment_binding(connector_id,environment_id,endpoints_json,secret_references_json,revision,updated_at,updated_by) VALUES($1,$2,$3::jsonb,$4::jsonb,$5,$6,$7) ON CONFLICT(connector_id,environment_id) DO UPDATE SET endpoints_json=excluded.endpoints_json,secret_references_json=excluded.secret_references_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by", cancellationToken,
            bindings.ConnectorId, bindings.EnvironmentId, endpointJson, secretJson, next, bindings.UpdatedAt, bindings.UpdatedBy).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return bindings with { Revision = next };
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT c.active_version_id,c.publication_revision,coalesce(b.revision,0) FROM gateway.connector_definition c LEFT JOIN gateway.connector_environment_binding b ON b.connector_id=c.id AND b.environment_id=$2 WHERE c.slug=$1 AND c.active_version_id IS NOT NULL", connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? new(reader.GetGuid(0), reader.GetInt64(1), reader.GetInt64(2)) : null;
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at,c.publication_revision,b.endpoints_json::text,b.secret_references_json::text,b.revision,b.updated_at,b.updated_by,b.environment_id FROM gateway.connector_definition c JOIN gateway.connector_version v ON v.id=c.active_version_id JOIN gateway.connector_environment_binding b ON b.connector_id=c.id AND b.environment_id=$2 WHERE c.slug=$1 AND v.state='published'";
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        ConnectorVersionRecord version = ReadVersion(reader);
        Dictionary<string, string> endpointStrings = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(15)) ?? [];
        Dictionary<string, Uri> endpoints = endpointStrings.ToDictionary(item => item.Key, item => new Uri(item.Value, UriKind.Absolute), StringComparer.Ordinal);
        Dictionary<string, string> secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(16)) ?? [];
        long bindingRevision = reader.GetInt64(17);
        ConnectorBindingSet binding = new(version.ConnectorId, reader.GetGuid(20), endpoints, secrets, bindingRevision, reader.GetFieldValue<DateTimeOffset>(18), reader.GetString(19));
        return new(version, binding, new(version.Id, reader.GetInt64(14), bindingRevision));
    }

    private async Task<ConnectorVersionRecord> TransitionAsync(Guid versionId, long expectedRowVersion, string expectedState, string nextState, string timestampColumn, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        string sql = $"UPDATE gateway.connector_version SET state='{nextState}',{timestampColumn}=$3,row_version=row_version+1 WHERE id=$1 AND row_version=$2 AND state='{expectedState}' RETURNING id";
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(versionId);
        command.Parameters.AddWithValue(expectedRowVersion);
        command.Parameters.AddWithValue(now);
        if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        ConnectorVersionRecord result = await GetByIdAsync(connection, null, versionId, false, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static async Task<ConnectorVersionRecord> ReadVersionForUpdateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid id, CancellationToken cancellationToken) =>
        await GetByIdAsync(connection, transaction, id, true, cancellationToken).ConfigureAwait(false);

    private static async Task<ConnectorVersionRecord> GetByIdAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, Guid id, bool forUpdate, CancellationToken cancellationToken)
    {
        string sql = "SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at FROM gateway.connector_version v JOIN gateway.connector_definition c ON c.id=v.connector_id WHERE v.id=$1" + (forUpdate ? " FOR UPDATE OF v" : string.Empty);
        await using NpgsqlCommand command = Command(connection, transaction, sql, id);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        return ReadVersion(reader);
    }

    private static ConnectorVersionRecord ReadVersion(NpgsqlDataReader reader) => new(
        reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), ParseState(reader.GetString(5)), reader.GetString(6), reader.GetFieldValue<byte[]>(7), reader.GetString(8), reader.GetFieldValue<DateTimeOffset>(9), reader.GetInt64(10),
        reader.IsDBNull(11) ? null : reader.GetFieldValue<DateTimeOffset>(11), reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12), reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13));

    private static ConnectorVersionState ParseState(string value) => Enum.Parse<ConnectorVersionState>(value, true);
    private static void Ensure(ConnectorVersionRecord value, long expectedRowVersion, ConnectorVersionState expectedState)
    {
        if (value.RowVersion != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (value.State != expectedState) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
    }
    private static NpgsqlCommand Command(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, params object?[] values)
    {
        NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object? value in values) command.Parameters.AddWithValue(value ?? DBNull.Value);
        return command;
    }
    private static async Task<int> ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, CancellationToken cancellationToken, params object?[] values)
    {
        await using NpgsqlCommand command = Command(connection, transaction, sql, values);
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}

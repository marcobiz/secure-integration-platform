using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL 18 Connector lifecycle store with transactional publication and rollback.</summary>
public sealed class PostgresConnectorConfigurationStore(NpgsqlDataSource dataSource, IAdminTransactionFaultInjector? faultInjector = null) : IConnectorConfigurationStore
{
    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken)
        => await CreateDraftCoreAsync(draft, null, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> CreateDraftWithAuditAsync(ConnectorVersionRecord draft, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
        => await CreateDraftCoreAsync(draft, auditEvent, cancellationToken).ConfigureAwait(false);

    private async Task<ConnectorVersionRecord> CreateDraftCoreAsync(ConnectorVersionRecord draft, GatewayAuditEvent? auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        Guid connectorId;
        await using (NpgsqlCommand insertConnector = Command(connection, transaction, "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$3,'active',$4,$5) ON CONFLICT(slug) DO UPDATE SET display_name=excluded.display_name RETURNING id", Guid.NewGuid(), draft.ConnectorSlug, DisplayName(draft.CanonicalJson, draft.ConnectorSlug), draft.CreatedAt, draft.CreatedBy))
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
        if (auditEvent is not null)
        {
            faultInjector?.Check("connector.import.after-state");
            await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        }
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
        await using NpgsqlCommand command = new("SELECT c.slug,c.display_name,count(v.id)::int,p.version,c.publication_revision FROM gateway.connector_definition c LEFT JOIN gateway.connector_version p ON p.id=c.active_version_id LEFT JOIN gateway.connector_version v ON v.connector_id=c.id GROUP BY c.slug,c.display_name,p.version,c.publication_revision ORDER BY c.slug", connection);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetInt64(4)));
        return result;
    }

    /// <inheritdoc />
    public async Task<AdminPage<ConnectorSummary>> ListConnectorsPageAsync(int offset, int limit, string? filter, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit, filter);
        List<ConnectorSummary> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = Command(connection, null, "SELECT count(*) FROM gateway.connector_definition c WHERE $1::text IS NULL OR c.slug ILIKE '%'||$1||'%' OR c.display_name ILIKE '%'||$1||'%'", filter))
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        const string sql = "SELECT q.slug,q.display_name,q.version_count,q.published_version,q.publication_revision FROM (SELECT c.slug,c.display_name,count(v.id)::int version_count,p.version published_version,c.publication_revision FROM gateway.connector_definition c LEFT JOIN gateway.connector_version p ON p.id=c.active_version_id LEFT JOIN gateway.connector_version v ON v.connector_id=c.id WHERE $3::text IS NULL OR c.slug ILIKE '%'||$3||'%' OR c.display_name ILIKE '%'||$3||'%' GROUP BY c.slug,c.display_name,p.version,c.publication_revision) q ORDER BY q.slug OFFSET $1 LIMIT $2";
        await using NpgsqlCommand command = Command(connection, null, sql, offset, limit, filter);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetInt64(4)));
        return new(result, offset, limit, total);
    }

    private static string DisplayName(string canonicalJson, string fallback)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        return document.RootElement.TryGetProperty("displayName", out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : fallback;
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
    public async Task<AdminPage<ConnectorVersionRecord>> ListVersionsPageAsync(string connectorId, int offset, int limit, string? filter, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit, filter);
        List<ConnectorVersionRecord> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = Command(connection, null, "SELECT count(*) FROM gateway.connector_version v JOIN gateway.connector_definition c ON c.id=v.connector_id WHERE c.slug=$1 AND ($2::text IS NULL OR v.version ILIKE '%'||$2||'%')", connectorId, filter))
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        const string sql = "SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at FROM gateway.connector_version v JOIN gateway.connector_definition c ON c.id=v.connector_id WHERE c.slug=$1 AND ($4::text IS NULL OR v.version ILIKE '%'||$4||'%') ORDER BY v.created_at DESC,v.version,v.id OFFSET $2 LIMIT $3";
        await using NpgsqlCommand command = Command(connection, null, sql, connectorId, offset, limit, filter);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) result.Add(ReadVersion(reader));
        return new(result, offset, limit, total);
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken) =>
        TransitionAsync(versionId, expectedRowVersion, "draft", "validated", "validated_at", now, null, cancellationToken);

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedWithAuditAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) =>
        TransitionAsync(versionId, expectedRowVersion, "draft", "validated", "validated_at", now, auditEvent, cancellationToken);

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
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_binding_bundle_version b SET state='active' WHERE b.connector_version_id=$1 AND b.revision=(SELECT max(latest.revision) FROM gateway.connector_binding_bundle_version latest WHERE latest.connector_version_id=b.connector_version_id AND latest.environment_id=b.environment_id)", cancellationToken, versionId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='published',published_at=coalesce(published_at,$2),row_version=row_version+1 WHERE id=$1", cancellationToken, versionId, now).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=$2,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1", cancellationToken, target.ConnectorId, versionId).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Published, PublishedAt = target.PublishedAt ?? now, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> PublishApprovedAsync(Guid versionId, byte[] expectedBindingDigestSha256, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            return await PublishApprovedCoreAsync(versionId, expectedBindingDigestSha256, expectedRowVersion, expectedPublicationRevision, actor, correlationId, now, cancellationToken).ConfigureAwait(false);
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.SerializationFailure)
        {
            throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        }
    }

    private async Task<ConnectorVersionRecord> PublishApprovedCoreAsync(Guid versionId, byte[] expectedBindingDigestSha256, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord target = await ReadVersionForUpdateAsync(connection, transaction, versionId, cancellationToken).ConfigureAwait(false);
        Ensure(target, expectedRowVersion, ConnectorVersionState.Validated);
        object? revisionValue;
        await using (NpgsqlCommand revision = Command(connection, transaction, "SELECT publication_revision FROM gateway.connector_definition WHERE id=$1 FOR UPDATE", target.ConnectorId))
            revisionValue = await revision.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (revisionValue is not long publicationRevision || publicationRevision != expectedPublicationRevision) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);

        IReadOnlyList<ConnectorBindingSet> bindings = await ReadLatestBindingsAsync(connection, transaction, target, forUpdate: true, cancellationToken).ConfigureAwait(false);
        if (bindings.Count == 0) throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 409);
        byte[] bindingDigest = ConnectorBindingDigests.Bundle(target.ChecksumSha256, bindings);
        if (!CryptographicOperations.FixedTimeEquals(bindingDigest, expectedBindingDigestSha256)) throw new GatewayException("BGW-ADMIN-APPROVAL-STALE", 409);
        const string approvalSql = "SELECT a.approved_by,a.requested_by FROM gateway.connector_approval a WHERE a.connector_version_id=$1 AND a.checksum_sha256=$2 AND a.binding_digest_sha256=$3 AND a.status='approved' FOR UPDATE";
        Guid approvedBy;
        Guid requestedBy;
        await using (NpgsqlCommand approval = Command(connection, transaction, approvalSql, versionId, target.ChecksumSha256, bindingDigest))
        await using (NpgsqlDataReader reader = await approval.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0)) throw new GatewayException("BGW-ADMIN-APPROVAL-REQUIRED", 409);
            approvedBy = reader.GetGuid(0);
            requestedBy = reader.GetGuid(1);
        }
        if (approvedBy == requestedBy || string.Equals(target.CreatedBy, approvedBy.ToString("D"), StringComparison.OrdinalIgnoreCase) || bindings.Any(value => string.Equals(value.UpdatedBy, approvedBy.ToString("D"), StringComparison.OrdinalIgnoreCase)))
            throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);

        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='superseded',row_version=row_version+1 WHERE connector_id=$1 AND state='published'", cancellationToken, target.ConnectorId).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_binding_bundle_version SET state='active' WHERE id=ANY($1) AND state='draft'", cancellationToken, bindings.Select(value => value.Id).ToArray()).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='published',published_at=coalesce(published_at,$2),row_version=row_version+1 WHERE id=$1", cancellationToken, versionId, now).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=$2,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1", cancellationToken, target.ConnectorId, versionId).ConfigureAwait(false);
        faultInjector?.Check("connector.publish.after-state");
        string metadata = JsonSerializer.Serialize(new Dictionary<string, string> { ["state"] = ConnectorVersionState.Published.ToString(), ["checksum"] = Convert.ToHexString(target.ChecksumSha256), ["bindingDigest"] = Convert.ToHexString(bindingDigest) });
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,NULL,'administrator',$3,'connector.publish','connectorVersion',$4,$5,'success','BGW-CONNECTOR-PUBLISHED',$6::jsonb)", cancellationToken, Guid.NewGuid(), now, actor, target.ConnectorSlug + "/" + target.Version, correlationId, metadata).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Published, PublishedAt = target.PublishedAt ?? now, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
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
        faultInjector?.Check("connector.rollback.after-state");
        await InsertAuditAsync(connection, transaction, target, actor, correlationId, now, "connector.rollback", "BGW-CONNECTOR-ROLLED-BACK", cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Published, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord target = await ReadVersionForUpdateAsync(connection, transaction, versionId, cancellationToken).ConfigureAwait(false);
        if (target.RowVersion != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (target.State == ConnectorVersionState.Retired) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_version SET state='retired',retired_at=$2,row_version=row_version+1 WHERE id=$1", cancellationToken, versionId, now).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_definition SET active_version_id=NULL,publication_revision=publication_revision+1,row_version=row_version+1 WHERE id=$1 AND active_version_id=$2", cancellationToken, target.ConnectorId, versionId).ConfigureAwait(false);
        faultInjector?.Check("connector.retire.after-state");
        await InsertAuditAsync(connection, transaction, target, actor, correlationId, now, "connector.retire", "BGW-CONNECTOR-RETIRED", cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return target with { State = ConnectorVersionState.Retired, RetiredAt = now, RowVersion = target.RowVersion + 1 };
    }

    /// <inheritdoc />
    public async Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, Guid correlationId, CancellationToken cancellationToken)
    {
        string endpointJson = JsonSerializer.Serialize(bindings.Endpoints.ToDictionary(item => item.Key, item => item.Value.AbsoluteUri, StringComparer.Ordinal));
        string secretJson = JsonSerializer.Serialize(bindings.SecretReferences);
        string certificateJson = JsonSerializer.Serialize(bindings.CertificateReferences);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await using (NpgsqlCommand versionLock = Command(connection, transaction, "SELECT state FROM gateway.connector_version WHERE id=$1 FOR UPDATE", bindings.ConnectorVersionId))
        {
            object? state = await versionLock.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(state as string, "validated", StringComparison.Ordinal)) throw new GatewayException("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", 409);
        }
        long current = 0;
        await using (NpgsqlCommand select = Command(connection, transaction, "SELECT revision FROM gateway.connector_binding_bundle_version WHERE connector_version_id=$1 AND environment_id=$2 ORDER BY revision DESC LIMIT 1 FOR UPDATE", bindings.ConnectorVersionId, bindings.EnvironmentId))
        {
            object? value = await select.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (value is long revision) current = revision;
        }
        if (current > 0 && expectedRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
        if (current == 0 && expectedRevision is not null) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (expectedRevision is not null && expectedRevision.Value != current) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        long next = current + 1;
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.connector_binding_bundle_version(id,connector_id,connector_version_id,environment_id,revision,state,endpoints_json,secret_references_json,certificate_references_json,checksum_sha256,created_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12)", cancellationToken,
            bindings.Id, bindings.ConnectorId, bindings.ConnectorVersionId, bindings.EnvironmentId, next, bindings.State.ToString().ToLowerInvariant(), endpointJson, secretJson, certificateJson, Convert.FromHexString(bindings.ChecksumSha256), bindings.UpdatedAt, bindings.UpdatedBy).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_approval SET status='invalidated',invalidated_at=$2 WHERE connector_version_id=$1 AND status IN ('requested','approved')", cancellationToken, bindings.ConnectorVersionId, bindings.UpdatedAt).ConfigureAwait(false);
        faultInjector?.Check("connector.binding.after-state");
        string metadata = JsonSerializer.Serialize(new Dictionary<string, string> { ["revision"] = next.ToString(System.Globalization.CultureInfo.InvariantCulture), ["checksum"] = bindings.ChecksumSha256 });
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,NULL,'administrator',$3,'connector.bindings.update','connectorVersion',$4,$5,'success','BGW-CONNECTOR-BINDINGS-UPDATED',$6::jsonb)", cancellationToken, Guid.NewGuid(), bindings.UpdatedAt, bindings.UpdatedBy, bindings.ConnectorVersionId.ToString("D"), correlationId, metadata).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return bindings with { Revision = next };
    }

    /// <inheritdoc />
    public async Task<AdminPage<ConnectorBindingSet>> ListBindingsPageAsync(Guid connectorVersionId, int offset, int limit, Guid? environmentId, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit, null);
        List<ConnectorBindingSet> result = [];
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord version = await GetByIdAsync(connection, null, connectorVersionId, false, cancellationToken).ConfigureAwait(false);
        int total;
        await using (NpgsqlCommand count = Command(connection, null, "SELECT count(*) FROM gateway.connector_binding_bundle_version WHERE connector_version_id=$1 AND ($2::uuid IS NULL OR environment_id=$2)", connectorVersionId, environmentId))
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        const string sql = "SELECT id,environment_id,endpoints_json::text,secret_references_json::text,certificate_references_json::text,revision,encode(checksum_sha256,'hex'),state,created_at,created_by FROM gateway.connector_binding_bundle_version WHERE connector_version_id=$1 AND ($4::uuid IS NULL OR environment_id=$4) ORDER BY environment_id,revision DESC,id OFFSET $2 LIMIT $3";
        await using NpgsqlCommand command = Command(connection, null, sql, connectorVersionId, offset, limit, environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            Dictionary<string, string> endpointStrings = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(2)) ?? [];
            Dictionary<string, Uri> endpoints = endpointStrings.ToDictionary(value => value.Key, value => new Uri(value.Value, UriKind.Absolute), StringComparer.Ordinal);
            Dictionary<string, string> secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(3)) ?? [];
            Dictionary<string, string> certificates = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(4)) ?? [];
            result.Add(new(reader.GetGuid(0), version.ConnectorId, connectorVersionId, reader.GetGuid(1), endpoints, secrets, certificates, reader.GetInt64(5), reader.GetString(6).ToUpperInvariant(), Enum.Parse<ConnectorBindingState>(reader.GetString(7), true), reader.GetFieldValue<DateTimeOffset>(8), reader.GetString(9)));
        }
        return new(result, offset, limit, total);
    }

    /// <inheritdoc />
    public async Task<byte[]> GetBindingBundleDigestAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord version = await GetByIdAsync(connection, null, connectorVersionId, false, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ConnectorBindingSet> bindings = await ReadLatestBindingsAsync(connection, null, version, forUpdate: false, cancellationToken).ConfigureAwait(false);
        if (bindings.Count == 0) throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 409);
        return ConnectorBindingDigests.Bundle(version.ChecksumSha256, bindings);
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT c.active_version_id,c.publication_revision,coalesce(b.revision,0),coalesce(encode(b.checksum_sha256,'hex'),'') FROM gateway.connector_definition c LEFT JOIN gateway.connector_binding_bundle_version b ON b.connector_version_id=c.active_version_id AND b.environment_id=$2 AND b.state='active' WHERE c.slug=$1 AND c.active_version_id IS NOT NULL ORDER BY b.revision DESC NULLS LAST LIMIT 1", connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? new(reader.GetGuid(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetString(3).ToUpperInvariant()) : null;
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "SELECT v.id,v.connector_id,c.slug,v.version,v.schema_version,v.state,v.configuration_json::text,v.checksum_sha256,v.created_by,v.created_at,v.row_version,v.validated_at,v.published_at,v.retired_at,c.publication_revision,b.endpoints_json::text,b.secret_references_json::text,b.certificate_references_json::text,b.revision,b.created_at,b.created_by,b.environment_id,b.id,encode(b.checksum_sha256,'hex'),b.state FROM gateway.connector_definition c JOIN gateway.connector_version v ON v.id=c.active_version_id JOIN gateway.connector_binding_bundle_version b ON b.connector_version_id=v.id AND b.environment_id=$2 AND b.state='active' WHERE c.slug=$1 AND v.state='published' ORDER BY b.revision DESC LIMIT 1";
        await using NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        ConnectorVersionRecord version = ReadVersion(reader);
        Dictionary<string, string> endpointStrings = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(15)) ?? [];
        Dictionary<string, Uri> endpoints = endpointStrings.ToDictionary(item => item.Key, item => new Uri(item.Value, UriKind.Absolute), StringComparer.Ordinal);
        Dictionary<string, string> secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(16)) ?? [];
        Dictionary<string, string> certificates = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(17)) ?? [];
        long bindingRevision = reader.GetInt64(18);
        string checksum = reader.GetString(23).ToUpperInvariant();
        ConnectorBindingSet binding = new(reader.GetGuid(22), version.ConnectorId, version.Id, reader.GetGuid(21), endpoints, secrets, certificates, bindingRevision, checksum, Enum.Parse<ConnectorBindingState>(reader.GetString(24), true), reader.GetFieldValue<DateTimeOffset>(19), reader.GetString(20));
        string actual = ConnectorBindingDigests.Revision(version.Id, binding.EnvironmentId, endpoints, secrets, certificates);
        if (!string.Equals(actual, checksum, StringComparison.Ordinal)) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        return new(version, binding, new(version.Id, reader.GetInt64(14), bindingRevision, checksum));
    }

    private static async Task<IReadOnlyList<ConnectorBindingSet>> ReadLatestBindingsAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, ConnectorVersionRecord version, bool forUpdate, CancellationToken cancellationToken)
    {
        const string columns = "b.id,b.environment_id,b.endpoints_json::text,b.secret_references_json::text,b.certificate_references_json::text,b.revision,encode(b.checksum_sha256,'hex'),b.state,b.created_at,b.created_by";
        string sql = $"SELECT {columns} FROM gateway.connector_binding_bundle_version b JOIN (SELECT environment_id,max(revision) revision FROM gateway.connector_binding_bundle_version WHERE connector_version_id=$1 GROUP BY environment_id) latest ON latest.environment_id=b.environment_id AND latest.revision=b.revision WHERE b.connector_version_id=$1 ORDER BY b.environment_id" + (forUpdate ? " FOR UPDATE OF b" : string.Empty);
        List<ConnectorBindingSet> result = [];
        await using NpgsqlCommand command = Command(connection, transaction, sql, version.Id);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            Dictionary<string, string> endpointStrings = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(2)) ?? [];
            Dictionary<string, Uri> endpoints = endpointStrings.ToDictionary(value => value.Key, value => new Uri(value.Value, UriKind.Absolute), StringComparer.Ordinal);
            Dictionary<string, string> secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(3)) ?? [];
            Dictionary<string, string> certificates = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(4)) ?? [];
            string checksum = reader.GetString(6).ToUpperInvariant();
            string actual = ConnectorBindingDigests.Revision(version.Id, reader.GetGuid(1), endpoints, secrets, certificates);
            if (!string.Equals(actual, checksum, StringComparison.Ordinal)) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
            result.Add(new(reader.GetGuid(0), version.ConnectorId, version.Id, reader.GetGuid(1), endpoints, secrets, certificates, reader.GetInt64(5), checksum, Enum.Parse<ConnectorBindingState>(reader.GetString(7), true), reader.GetFieldValue<DateTimeOffset>(8), reader.GetString(9)));
        }
        return result;
    }

    private async Task<ConnectorVersionRecord> TransitionAsync(Guid versionId, long expectedRowVersion, string expectedState, string nextState, string timestampColumn, DateTimeOffset now, GatewayAuditEvent? auditEvent, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        string sql = $"UPDATE gateway.connector_version SET state='{nextState}',{timestampColumn}=$3,row_version=row_version+1 WHERE id=$1 AND row_version=$2 AND state='{expectedState}' RETURNING id";
        await using NpgsqlCommand command = new(sql, connection, transaction);
        command.Parameters.AddWithValue(versionId);
        command.Parameters.AddWithValue(expectedRowVersion);
        command.Parameters.AddWithValue(now);
        if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (auditEvent is not null)
        {
            faultInjector?.Check("connector.validate.after-state");
            await InsertAuditAsync(connection, transaction, auditEvent, cancellationToken).ConfigureAwait(false);
        }
        ConnectorVersionRecord result = await GetByIdAsync(connection, transaction, versionId, false, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static Task<int> InsertAuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) =>
        ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)", cancellationToken,
            auditEvent.Id, auditEvent.OccurredAt, (object?)auditEvent.TenantId ?? DBNull.Value, auditEvent.ActorType, auditEvent.ActorId, auditEvent.Action, auditEvent.TargetType, auditEvent.TargetId, auditEvent.CorrelationId, auditEvent.Outcome, auditEvent.ReasonCode, JsonSerializer.Serialize(auditEvent.Metadata));

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
    private static void ValidatePage(int offset, int limit, string? filter)
    {
        if (offset < 0 || limit is < 1 or > 100 || filter?.Length > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400);
    }
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

    private static Task<int> InsertAuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ConnectorVersionRecord version, string actor, Guid correlationId, DateTimeOffset now, string action, string reason, CancellationToken cancellationToken)
    {
        string metadata = JsonSerializer.Serialize(new Dictionary<string, string> { ["state"] = version.State.ToString(), ["checksum"] = Convert.ToHexString(version.ChecksumSha256) });
        return ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,NULL,'administrator',$3,$4,'connectorVersion',$5,$6,'success',$7,$8::jsonb)", cancellationToken, Guid.NewGuid(), now, actor, action, version.ConnectorSlug + "/" + version.Version, correlationId, reason, metadata);
    }
}

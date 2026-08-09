using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL 18 Connector lifecycle store with transactional publication and rollback.</summary>
public sealed class PostgresConnectorConfigurationStore(
    NpgsqlDataSource dataSource,
    IAdminTransactionFaultInjector? faultInjector = null,
    PublishedConnectorMutationAuthority? runtimeMutationAuthority = null) : IConnectorConfigurationStore, IPublishedConnectorMutationAuthoritySource
{
    /// <inheritdoc />
    public PublishedConnectorMutationAuthority RuntimeMutationAuthority { get; } = runtimeMutationAuthority ?? new();

    /// <inheritdoc />
    public async Task<ProviderResourceCatalogRecord> RegisterProviderResourceAsync(ProviderResourceCatalogRecord resource, CancellationToken cancellationToken)
    {
        using PublishedConnectorMutationAuthority.MutationLease mutation = BeginResourceMutation(resource);
        ProviderResourceReferenceValidator.Validate(new(resource.ProviderId, resource.ResourceId, resource.ResourceType, resource.Version, resource.PublicMetadataRevision));
        if (resource.ResourceType == ProviderResourceType.ClientCertificate && resource.CertificateMetadata is null) throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-REQUIRED", 409);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        ProviderResourceReference registrationReference = new(resource.ProviderId, resource.ResourceId, resource.ResourceType, resource.Version, resource.PublicMetadataRevision);
        await LockProviderResourceAsync(connection, transaction, registrationReference, cancellationToken).ConfigureAwait(false);
        try
        {
            ProviderResourceCatalogRecord currentResource = await ReadCurrentResourceAsync(connection, transaction, registrationReference, cancellationToken).ConfigureAwait(false);
            if (SameRegistration(currentResource, resource)) return currentResource;
        }
        catch (GatewayException exception) when (exception.Code == "BGW-PROVIDER-RESOURCE-NOT-FOUND") { }
        long revision;
        await using (NpgsqlCommand current = Command(connection, transaction, "SELECT coalesce(max(revision),0) FROM gateway.provider_resource_catalog_version WHERE provider_id=$1 AND resource_id=$2 AND resource_type=$3 AND coalesce(version,'')=coalesce($4,'')", resource.ProviderId, resource.ResourceId, ResourceType(resource.ResourceType), resource.Version))
            revision = Convert.ToInt64(await current.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) + 1;
        ProviderResourceCatalogRecord saved = resource with { Revision = revision };
        saved = saved with { ChecksumSha256 = ResourceChecksum(saved) };
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.provider_resource_catalog_version(id,provider_id,provider_display_name,provider_type,resource_id,resource_type,display_name,environment_id,connector_scope,operation_scope,status,version,revision,public_metadata_revision,certificate_metadata_json,checksum_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17)", cancellationToken,
            saved.Id, saved.ProviderId, saved.ProviderDisplayName, saved.ProviderType, saved.ResourceId, ResourceType(saved.ResourceType), saved.DisplayName, saved.EnvironmentId, saved.ConnectorScope, saved.OperationScope, saved.Status.ToString().ToLowerInvariant(), saved.Version, saved.Revision, saved.PublicMetadataRevision, saved.CertificateMetadata is null ? null : JsonSerializer.Serialize(saved.CertificateMetadata), Convert.FromHexString(saved.ChecksumSha256), saved.CreatedAt).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.provider_resource_locator(provider_resource_catalog_id,provider_reference) VALUES($1,$2)", cancellationToken, saved.Id, saved.ProviderReference).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return saved;
    }

    /// <inheritdoc />
    public async Task<ProviderResourceCatalogRecord> ResolveProviderResourceAsync(ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds, CancellationToken cancellationToken)
    {
        ProviderResourceReferenceValidator.Validate(reference);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        ProviderResourceCatalogRecord resource = await ReadCurrentResourceMetadataAsync(connection, null, reference, cancellationToken).ConfigureAwait(false);
        EnsureResourceScope(resource, reference, environmentId, connectorId, operationIds);
        return resource;
    }

    /// <inheritdoc />
    public async Task<AdminPage<ProviderResourceCatalogRecord>> ListProviderResourcesPageAsync(int offset, int limit, Guid? environmentId, ProviderResourceType? resourceType, CancellationToken cancellationToken)
    {
        ValidatePage(offset, limit, null);
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        const string predicate = "($1::uuid IS NULL OR r.environment_id=$1) AND ($2::text IS NULL OR r.resource_type=$2) AND r.revision=(SELECT max(latest.revision) FROM gateway.provider_resource_catalog_version latest WHERE latest.provider_id=r.provider_id AND latest.resource_id=r.resource_id AND latest.resource_type=r.resource_type AND coalesce(latest.version,'')=coalesce(r.version,''))";
        int total;
        await using (NpgsqlCommand count = Command(connection, null, $"SELECT count(*) FROM gateway.provider_resource_catalog_version r WHERE {predicate}", environmentId, resourceType is null ? null : ResourceType(resourceType.Value)))
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        List<ProviderResourceCatalogRecord> values = [];
        await using NpgsqlCommand command = Command(connection, null, $"SELECT {ResourceMetadataColumns} FROM gateway.provider_resource_catalog_version r WHERE {predicate} ORDER BY r.provider_id,r.resource_id OFFSET $3 LIMIT $4", environmentId, resourceType is null ? null : ResourceType(resourceType.Value), offset, limit);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) values.Add(ReadResource(reader));
        return new(values, offset, limit, total);
    }

    /// <inheritdoc />
    public async Task ValidateBindingResourcesAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord version = await GetByIdAsync(connection, null, connectorVersionId, false, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ConnectorBindingSet> bindings = await ReadLatestBindingsAsync(connection, null, version, false, cancellationToken).ConfigureAwait(false);
        await ValidateCurrentResourcesAsync(connection, null, bindings, false, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> ApproveCanonicalAsync(IAdminSecurityStore fallbackStore, Guid approvalRequestId, Guid connectorVersionId, string expectedDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        _ = fallbackStore;
        byte[] expected;
        try { expected = Convert.FromHexString(expectedDigestSha256); }
        catch (FormatException) { throw new GatewayException("BGW-ADMIN-APPROVAL-DIGEST", 400); }
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        const string select = "SELECT a.id,a.connector_version_id,a.checksum_sha256,a.binding_digest_sha256,a.requested_by,a.approved_by,a.rejected_by,a.status,a.requested_at,a.approved_at,a.rejected_at,a.decision_comment,a.invalidated_at FROM gateway.connector_approval a WHERE a.id=$1 AND a.connector_version_id=$2 FOR UPDATE";
        ConnectorApprovalRecord request;
        await using (NpgsqlCommand command = Command(connection, transaction, select, approvalRequestId, connectorVersionId))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-APPROVAL-REQUIRED", 409);
            request = ReadApproval(reader);
        }
        ConnectorVersionRecord version = await ReadVersionForUpdateAsync(connection, transaction, connectorVersionId, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ConnectorBindingSet> bindings = await ReadLatestBindingsAsync(connection, transaction, version, true, cancellationToken).ConfigureAwait(false);
        await ValidateCurrentResourcesAsync(connection, transaction, bindings, true, cancellationToken).ConfigureAwait(false);
        byte[] digest = ConnectorBindingDigests.Bundle(version, bindings);
        if (expected.Length != 32 || !CryptographicOperations.FixedTimeEquals(expected, digest)) throw new GatewayException("BGW-ADMIN-APPROVAL-STALE", 409);
        if (request.Status != ConnectorApprovalStatus.Requested || !string.Equals(request.ChecksumSha256, Convert.ToHexString(version.ChecksumSha256), StringComparison.Ordinal) ||
            !string.Equals(request.BindingDigestSha256, Convert.ToHexString(digest), StringComparison.Ordinal)) throw new GatewayException("BGW-ADMIN-APPROVAL-STALE", 409);
        if (request.RequestedBy == approver || string.Equals(createdBy, approver.ToString("D"), StringComparison.OrdinalIgnoreCase) || bindings.Any(value => string.Equals(value.UpdatedBy, approver.ToString("D"), StringComparison.OrdinalIgnoreCase)))
            throw new GatewayException("BGW-ADMIN-FOUR-EYES", 403);
        await ExecuteAsync(connection, transaction, "UPDATE gateway.connector_approval SET status='approved',approved_by=$2,approved_at=$3,decision_comment=$4 WHERE id=$1 AND status='requested'", cancellationToken, approvalRequestId, approver, now, comment).ConfigureAwait(false);
        faultInjector?.Check("connector.approval.approve.after-state");
        string metadata = JsonSerializer.Serialize(new Dictionary<string, string> { ["digest"] = Convert.ToHexString(digest) });
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,$2,NULL,'administrator',$3,'connector.approval.approve','connectorVersion',$4,$5,'success','BGW-ADMIN-APPROVAL-APPROVED',$6::jsonb)", cancellationToken, Guid.NewGuid(), now, approver.ToString("D"), connectorVersionId.ToString("D"), correlationId, metadata).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return request with { ApprovedBy = approver, Status = ConnectorApprovalStatus.Approved, ApprovedAt = now, DecisionComment = comment };
    }

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
        using PublishedConnectorMutationAuthority.MutationLease mutation = RuntimeMutationAuthority.BeginMutationAll();
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
        using PublishedConnectorMutationAuthority.MutationLease mutation = RuntimeMutationAuthority.BeginMutationAll();
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
        await ValidateCurrentResourcesAsync(connection, transaction, bindings, true, cancellationToken).ConfigureAwait(false);
        byte[] bindingDigest = ConnectorBindingDigests.Bundle(target, bindings);
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
        using PublishedConnectorMutationAuthority.MutationLease mutation = RuntimeMutationAuthority.BeginMutationAll();
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
        using PublishedConnectorMutationAuthority.MutationLease mutation = RuntimeMutationAuthority.BeginMutationAll();
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
        using PublishedConnectorMutationAuthority.MutationLease mutation = RuntimeMutationAuthority.BeginMutationAll();
        try
        {
            string endpointJson = JsonSerializer.Serialize(bindings.Endpoints.ToDictionary(item => item.Key, item => item.Value.AbsoluteUri, StringComparer.Ordinal));
            string secretJson = JsonSerializer.Serialize(bindings.SecretResources);
            string certificateJson = JsonSerializer.Serialize(bindings.CertificateResources);
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
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.SerializationFailure)
        {
            throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        }
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
            Dictionary<string, ProviderResourceBinding> secrets = DeserializeResources(reader.GetString(3));
            Dictionary<string, ProviderResourceBinding> certificates = DeserializeResources(reader.GetString(4));
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
        await ValidateCurrentResourcesAsync(connection, null, bindings, false, cancellationToken).ConfigureAwait(false);
        return ConnectorBindingDigests.Bundle(version, bindings);
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("SELECT c.active_version_id,c.publication_revision,coalesce(b.revision,0),coalesce(encode(b.checksum_sha256,'hex'),''),b.id,b.secret_references_json::text,b.certificate_references_json::text,v.configuration_json::text FROM gateway.connector_definition c JOIN gateway.connector_version v ON v.id=c.active_version_id LEFT JOIN gateway.connector_binding_bundle_version b ON b.connector_version_id=c.active_version_id AND b.environment_id=$2 AND b.state='active' WHERE c.slug=$1 AND c.active_version_id IS NOT NULL ORDER BY b.revision DESC NULLS LAST LIMIT 1", connection);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(environmentId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        Guid versionId = reader.GetGuid(0);
        long publicationRevision = reader.GetInt64(1);
        long bindingRevision = reader.GetInt64(2);
        string bindingChecksum = reader.GetString(3).ToUpperInvariant();
        if (reader.IsDBNull(4)) return new(versionId, publicationRevision, bindingRevision, bindingChecksum, string.Empty);
        Guid bindingId = reader.GetGuid(4);
        Dictionary<string, ProviderResourceBinding> secrets = DeserializeResources(reader.GetString(5));
        Dictionary<string, ProviderResourceBinding> certificates = DeserializeResources(reader.GetString(6));
        OperationBindingDependencies? dependencies = accessContext is null ? null : ConnectorOperationBindings.Required(reader.GetString(7), accessContext.OperationId);
        await reader.DisposeAsync().ConfigureAwait(false);
        ConnectorBindingSet binding = SelectedBinding(new(bindingId, Guid.Empty, versionId, environmentId, new Dictionary<string, Uri>(), secrets, certificates, bindingRevision, bindingChecksum, ConnectorBindingState.Active, default, string.Empty), dependencies);
        string resourceStamp = await ValidateCurrentResourcesAsync(connection, null, [binding], false, cancellationToken).ConfigureAwait(false);
        if (accessContext is not null)
        {
            _ = await ResolveProviderReferencesAsync(connection, null, connectorId, binding, accessContext, binding.SecretResources, cancellationToken).ConfigureAwait(false);
            _ = await ResolveProviderReferencesAsync(connection, null, connectorId, binding, accessContext, binding.CertificateResources, cancellationToken).ConfigureAwait(false);
        }
        return new(versionId, publicationRevision, bindingRevision, bindingChecksum, resourceStamp);
    }

    /// <inheritdoc />
    public async Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
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
        Dictionary<string, ProviderResourceBinding> secrets = DeserializeResources(reader.GetString(16));
        Dictionary<string, ProviderResourceBinding> certificates = DeserializeResources(reader.GetString(17));
        long bindingRevision = reader.GetInt64(18);
        long publicationRevision = reader.GetInt64(14);
        string checksum = reader.GetString(23).ToUpperInvariant();
        ConnectorBindingSet binding = new(reader.GetGuid(22), version.ConnectorId, version.Id, reader.GetGuid(21), endpoints, secrets, certificates, bindingRevision, checksum, Enum.Parse<ConnectorBindingState>(reader.GetString(24), true), reader.GetFieldValue<DateTimeOffset>(19), reader.GetString(20));
        string actual = ConnectorBindingDigests.Revision(version.Id, binding.EnvironmentId, endpoints, secrets, certificates);
        if (!string.Equals(actual, checksum, StringComparison.Ordinal)) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        await reader.DisposeAsync().ConfigureAwait(false);
        OperationBindingDependencies? dependencies = accessContext is null ? null : ConnectorOperationBindings.Required(version.CanonicalJson, accessContext.OperationId);
        ConnectorBindingSet selected = SelectedBinding(binding, dependencies);
        string resourceStamp = await ValidateCurrentResourcesAsync(connection, null, [selected], false, cancellationToken).ConfigureAwait(false);
        Dictionary<string, string> secretProviderReferences = await ResolveProviderReferencesAsync(connection, null, connectorId, selected, accessContext, selected.SecretResources, cancellationToken).ConfigureAwait(false);
        Dictionary<string, string> certificateProviderReferences = await ResolveProviderReferencesAsync(connection, null, connectorId, selected, accessContext, selected.CertificateResources, cancellationToken).ConfigureAwait(false);
        return new(version, binding, new(version.Id, publicationRevision, bindingRevision, checksum, resourceStamp), secretProviderReferences, certificateProviderReferences);
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
            Dictionary<string, ProviderResourceBinding> secrets = DeserializeResources(reader.GetString(3));
            Dictionary<string, ProviderResourceBinding> certificates = DeserializeResources(reader.GetString(4));
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

    private const string ResourceColumns = "r.id,r.provider_id,r.provider_display_name,r.provider_type,r.resource_id,r.resource_type,r.display_name,r.environment_id,r.connector_scope,r.operation_scope,l.provider_reference,r.status,r.version,r.revision,r.public_metadata_revision,r.certificate_metadata_json::text,encode(r.checksum_sha256,'hex'),r.created_at";
    private const string ResourceMetadataColumns = "r.id,r.provider_id,r.provider_display_name,r.provider_type,r.resource_id,r.resource_type,r.display_name,r.environment_id,r.connector_scope,r.operation_scope,''::text,r.status,r.version,r.revision,r.public_metadata_revision,r.certificate_metadata_json::text,encode(r.checksum_sha256,'hex'),r.created_at";

    private static async Task<ProviderResourceCatalogRecord> ReadCurrentResourceAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, ProviderResourceReference reference, CancellationToken cancellationToken)
    {
        string sql = $"SELECT {ResourceColumns} FROM gateway.provider_resource_catalog_version r JOIN gateway.provider_resource_locator l ON l.provider_resource_catalog_id=r.id WHERE r.provider_id=$1 AND r.resource_id=$2 AND r.resource_type=$3 AND coalesce(r.version,'')=coalesce($4,'') ORDER BY r.revision DESC LIMIT 1";
        await using NpgsqlCommand command = Command(connection, transaction, sql, reference.ProviderId, reference.ResourceId, ResourceType(reference.ResourceType), reference.Version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-PROVIDER-RESOURCE-NOT-FOUND", 400);
        return ReadResource(reader);
    }

    private static async Task<ProviderResourceCatalogRecord> ReadCurrentResourceMetadataAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, ProviderResourceReference reference, CancellationToken cancellationToken)
    {
        string sql = $"SELECT {ResourceMetadataColumns} FROM gateway.provider_resource_catalog_version r WHERE r.provider_id=$1 AND r.resource_id=$2 AND r.resource_type=$3 AND coalesce(r.version,'')=coalesce($4,'') ORDER BY r.revision DESC LIMIT 1";
        await using NpgsqlCommand command = Command(connection, transaction, sql, reference.ProviderId, reference.ResourceId, ResourceType(reference.ResourceType), reference.Version);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-PROVIDER-RESOURCE-NOT-FOUND", 400);
        return ReadResource(reader);
    }

    private static ProviderResourceCatalogRecord ReadResource(NpgsqlDataReader reader)
    {
        CertificatePublicMetadata? metadata = reader.IsDBNull(15) ? null : JsonSerializer.Deserialize<CertificatePublicMetadata>(reader.GetString(15)) ?? throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-INVALID", 503);
        return new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), ParseResourceType(reader.GetString(5)), reader.GetString(6), reader.GetGuid(7), reader.GetString(8), reader.GetString(9), reader.GetString(10), Enum.Parse<ProviderResourceStatus>(reader.GetString(11), true), reader.IsDBNull(12) ? null : reader.GetString(12), reader.GetInt64(13), reader.IsDBNull(14) ? null : reader.GetInt64(14), metadata, reader.GetString(16).ToUpperInvariant(), reader.GetFieldValue<DateTimeOffset>(17));
    }

    private static async Task<string> ValidateCurrentResourcesAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, IEnumerable<ConnectorBindingSet> bindings, bool forUpdate, CancellationToken cancellationToken)
    {
        List<object> stamps = [];
        foreach (ProviderResourceBinding binding in bindings.SelectMany(value => value.SecretResources.Values.Concat(value.CertificateResources.Values)))
        {
            ProviderResourceReference reference = new(binding.ProviderId, binding.ResourceId, binding.ResourceType, binding.Version, binding.PublicMetadataRevision);
            if (forUpdate)
            {
                if (transaction is null) throw new InvalidOperationException("A transaction is required to lock provider resources.");
                await LockProviderResourceAsync(connection, transaction, reference, cancellationToken).ConfigureAwait(false);
            }
            ProviderResourceCatalogRecord current = await ReadCurrentResourceMetadataAsync(connection, transaction, reference, cancellationToken).ConfigureAwait(false);
            if (current.Status != ProviderResourceStatus.Active || current.Revision != binding.CatalogRevision || current.PublicMetadataRevision != binding.PublicMetadataRevision ||
                !string.Equals(current.ChecksumSha256, binding.CatalogChecksumSha256, StringComparison.Ordinal))
                throw new GatewayException("BGW-PROVIDER-RESOURCE-REVISION-STALE", 409);
            stamps.Add(new { current.ProviderId, current.ResourceId, current.ResourceType, current.Version, current.Revision, current.PublicMetadataRevision, current.Status, current.ChecksumSha256 });
        }
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(stamps.OrderBy(value => JsonSerializer.Serialize(value), StringComparer.Ordinal))));
    }

    private static async Task LockProviderResourceAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ProviderResourceReference reference, CancellationToken cancellationToken)
    {
        byte[] keyMaterial = System.Text.Encoding.UTF8.GetBytes($"{reference.ProviderId}\n{reference.ResourceId}\n{ResourceType(reference.ResourceType)}\n{reference.Version ?? string.Empty}");
        long lockKey = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(SHA256.HashData(keyMaterial));
        await using NpgsqlCommand command = Command(connection, transaction, "SELECT pg_advisory_xact_lock($1)", lockKey);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<Dictionary<string, string>> ResolveProviderReferencesAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string connectorId, ConnectorBindingSet bindingSet, PublishedConnectorAccessContext? accessContext, IReadOnlyDictionary<string, ProviderResourceBinding> bindings, CancellationToken cancellationToken)
    {
        Dictionary<string, string> result = new(StringComparer.Ordinal);
        foreach ((string logicalId, ProviderResourceBinding binding) in bindings)
        {
            ProviderResourceReference reference = new(binding.ProviderId, binding.ResourceId, binding.ResourceType, binding.Version, binding.PublicMetadataRevision);
            ProviderResourceCatalogRecord current = accessContext is null
                ? await ReadCurrentResourceAsync(connection, transaction, reference, cancellationToken).ConfigureAwait(false)
                : await ReadCurrentResourceMetadataAsync(connection, transaction, reference, cancellationToken).ConfigureAwait(false);
            if (current.Revision != binding.CatalogRevision || current.Status != ProviderResourceStatus.Active) throw new GatewayException("BGW-PROVIDER-RESOURCE-REVISION-STALE", 409);
            string? providerReference = current.ProviderReference;
            if (accessContext is not null)
            {
                const string sql = "SELECT gateway.resolve_published_provider_locator($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)";
                await using NpgsqlCommand command = Command(connection, transaction, sql, current.Id, connectorId, accessContext.OperationId, logicalId, bindingSet.EnvironmentId, bindingSet.Id,
                    bindingSet.Revision, Convert.FromHexString(bindingSet.ChecksumSha256), accessContext.InstallationId, accessContext.TenantId, accessContext.ApplicationId);
                providerReference = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            }
            if (string.IsNullOrWhiteSpace(providerReference)) throw new GatewayException("BGW-PROVIDER-LOCATOR-DENIED", 403);
            result.Add(logicalId, providerReference);
        }
        return result;
    }

    private static ConnectorBindingSet SelectedBinding(ConnectorBindingSet binding, OperationBindingDependencies? dependencies)
    {
        if (dependencies is null) return binding;
        Dictionary<string, ProviderResourceBinding> secrets = dependencies.SecretBindingIds.ToDictionary(id => id,
            id => binding.SecretResources.TryGetValue(id, out ProviderResourceBinding? value) ? value : throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503), StringComparer.Ordinal);
        Dictionary<string, ProviderResourceBinding> certificates = dependencies.CertificateBindingIds.ToDictionary(id => id,
            id => binding.CertificateResources.TryGetValue(id, out ProviderResourceBinding? value) ? value : throw new GatewayException("BGW-CONNECTOR-CERTIFICATE-BINDING-MISSING", 503), StringComparer.Ordinal);
        return binding with { SecretResources = secrets, CertificateResources = certificates };
    }

    private static Dictionary<string, ProviderResourceBinding> DeserializeResources(string json)
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, ProviderResourceBinding>>(json) ?? []; }
        catch (JsonException) { throw new GatewayException("BGW-PROVIDER-RESOURCE-LEGACY-REFERENCE", 409); }
    }

    private static void EnsureResourceScope(ProviderResourceCatalogRecord resource, ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds)
    {
        bool connectorAllowed = string.Equals(resource.ConnectorScope, "*", StringComparison.Ordinal) || string.Equals(resource.ConnectorScope, connectorId, StringComparison.Ordinal);
        bool operationsAllowed = operationIds.All(operationId => string.Equals(resource.OperationScope, "*", StringComparison.Ordinal) || string.Equals(resource.OperationScope, operationId, StringComparison.Ordinal));
        if (resource.Status != ProviderResourceStatus.Active || resource.EnvironmentId != environmentId || resource.ResourceType != reference.ResourceType || resource.PublicMetadataRevision != reference.PublicMetadataRevision || !connectorAllowed || !operationsAllowed)
            throw new GatewayException("BGW-PROVIDER-RESOURCE-SCOPE", 403);
    }

    private static string ResourceChecksum(ProviderResourceCatalogRecord resource)
    {
        var canonical = new { resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId, resource.ResourceType, resource.DisplayName, resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope, resource.Status, resource.Version, resource.Revision, resource.PublicMetadataRevision, resource.CertificateMetadata };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    private static bool SameRegistration(ProviderResourceCatalogRecord current, ProviderResourceCatalogRecord candidate) =>
        current.ProviderDisplayName == candidate.ProviderDisplayName && current.ProviderType == candidate.ProviderType && current.DisplayName == candidate.DisplayName &&
        current.EnvironmentId == candidate.EnvironmentId && current.ConnectorScope == candidate.ConnectorScope && current.OperationScope == candidate.OperationScope &&
        current.ProviderReference == candidate.ProviderReference && current.Status == candidate.Status && current.PublicMetadataRevision == candidate.PublicMetadataRevision && current.CertificateMetadata == candidate.CertificateMetadata;

    private PublishedConnectorMutationAuthority.MutationLease BeginResourceMutation(ProviderResourceCatalogRecord resource) =>
        resource.EnvironmentId != Guid.Empty && !string.IsNullOrWhiteSpace(resource.ConnectorScope) && !string.Equals(resource.ConnectorScope, "*", StringComparison.Ordinal)
            ? RuntimeMutationAuthority.BeginMutation(resource.ConnectorScope, resource.EnvironmentId)
            : RuntimeMutationAuthority.BeginMutationAll();

    private static string ResourceType(ProviderResourceType value) => value == ProviderResourceType.ClientCertificate ? "client_certificate" : "secret";
    private static ProviderResourceType ParseResourceType(string value) => value == "client_certificate" ? ProviderResourceType.ClientCertificate : ProviderResourceType.Secret;

    private static ConnectorApprovalRecord ReadApproval(NpgsqlDataReader reader) => new(
        reader.GetGuid(0), reader.GetGuid(1), Convert.ToHexString(reader.GetFieldValue<byte[]>(2)), Convert.ToHexString(reader.GetFieldValue<byte[]>(3)), reader.GetGuid(4), reader.IsDBNull(5) ? null : reader.GetGuid(5), reader.IsDBNull(6) ? null : reader.GetGuid(6), Enum.Parse<ConnectorApprovalStatus>(reader.GetString(7), true), reader.GetFieldValue<DateTimeOffset>(8), reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9), reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10), reader.IsDBNull(11) ? null : reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12));

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

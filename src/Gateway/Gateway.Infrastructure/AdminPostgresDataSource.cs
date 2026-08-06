using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Distinct least-privilege connection pool for the authenticated Admin plane.</summary>
public sealed class AdminPostgresDataSource(string connectionString) : IAsyncDisposable
{
    /// <summary>Administrative PostgreSQL pool; never used by runtime invocation services.</summary>
    public NpgsqlDataSource Value { get; } = NpgsqlDataSource.Create(connectionString);
    /// <inheritdoc />
    public ValueTask DisposeAsync() => Value.DisposeAsync();
}

/// <summary>Routes lifecycle writes to the Admin pool while Published runtime reads stay on the runtime pool.</summary>
public sealed class RoutingConnectorConfigurationStore : IConnectorConfigurationStore
{
    private readonly PostgresConnectorConfigurationStore admin;
    private readonly PostgresConnectorConfigurationStore runtime;

    /// <summary>Creates a store with physically distinct connection pools.</summary>
    public RoutingConnectorConfigurationStore(AdminPostgresDataSource adminDataSource, NpgsqlDataSource runtimeDataSource)
    {
        admin = new(adminDataSource.Value);
        runtime = new(runtimeDataSource);
    }

    /// <inheritdoc />
    public Task<ProviderResourceCatalogRecord> RegisterProviderResourceAsync(ProviderResourceCatalogRecord resource, CancellationToken cancellationToken) => admin.RegisterProviderResourceAsync(resource, cancellationToken);
    /// <inheritdoc />
    public Task<ProviderResourceCatalogRecord> ResolveProviderResourceAsync(ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds, CancellationToken cancellationToken) => admin.ResolveProviderResourceAsync(reference, environmentId, connectorId, operationIds, cancellationToken);
    /// <inheritdoc />
    public Task<AdminPage<ProviderResourceCatalogRecord>> ListProviderResourcesPageAsync(int offset, int limit, Guid? environmentId, ProviderResourceType? resourceType, CancellationToken cancellationToken) => admin.ListProviderResourcesPageAsync(offset, limit, environmentId, resourceType, cancellationToken);
    /// <inheritdoc />
    public Task ValidateBindingResourcesAsync(Guid connectorVersionId, CancellationToken cancellationToken) => admin.ValidateBindingResourcesAsync(connectorVersionId, cancellationToken);

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken) => admin.CreateDraftAsync(draft, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> CreateDraftWithAuditAsync(ConnectorVersionRecord draft, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) => admin.CreateDraftWithAuditAsync(draft, auditEvent, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken) => admin.GetVersionAsync(connectorId, version, cancellationToken);
    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken) => admin.ListConnectorsAsync(cancellationToken);
    /// <inheritdoc />
    public Task<AdminPage<ConnectorSummary>> ListConnectorsPageAsync(int offset, int limit, string? filter, CancellationToken cancellationToken) => admin.ListConnectorsPageAsync(offset, limit, filter, cancellationToken);
    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken) => admin.ListVersionsAsync(connectorId, cancellationToken);
    /// <inheritdoc />
    public Task<AdminPage<ConnectorVersionRecord>> ListVersionsPageAsync(string connectorId, int offset, int limit, string? filter, CancellationToken cancellationToken) => admin.ListVersionsPageAsync(connectorId, offset, limit, filter, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken) => admin.MarkValidatedAsync(versionId, expectedRowVersion, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedWithAuditAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken) => admin.MarkValidatedWithAuditAsync(versionId, expectedRowVersion, now, auditEvent, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken) => admin.PublishAsync(versionId, expectedRowVersion, expectedPublicationRevision, actor, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> PublishApprovedAsync(Guid versionId, byte[] expectedBindingDigestSha256, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => admin.PublishApprovedAsync(versionId, expectedBindingDigestSha256, expectedRowVersion, expectedPublicationRevision, actor, correlationId, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => admin.RollbackAsync(connectorId, targetVersion, expectedActiveRowVersion, actor, correlationId, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => admin.RetireAsync(versionId, expectedRowVersion, actor, correlationId, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, Guid correlationId, CancellationToken cancellationToken) => admin.PutBindingsAsync(bindings, expectedRevision, correlationId, cancellationToken);
    /// <inheritdoc />
    public Task<AdminPage<ConnectorBindingSet>> ListBindingsPageAsync(Guid connectorVersionId, int offset, int limit, Guid? environmentId, CancellationToken cancellationToken) => admin.ListBindingsPageAsync(connectorVersionId, offset, limit, environmentId, cancellationToken);
    /// <inheritdoc />
    public Task<byte[]> GetBindingBundleDigestAsync(Guid connectorVersionId, CancellationToken cancellationToken) => admin.GetBindingBundleDigestAsync(connectorVersionId, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorApprovalRecord> ApproveCanonicalAsync(IAdminSecurityStore fallbackStore, Guid approvalRequestId, Guid connectorVersionId, string expectedDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) => admin.ApproveCanonicalAsync(fallbackStore, approvalRequestId, connectorVersionId, expectedDigestSha256, createdBy, approver, comment, correlationId, now, cancellationToken);
    /// <inheritdoc />
    public Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken) =>
        (accessContext is null ? admin : runtime).GetPublishedStampAsync(connectorId, environmentId, accessContext, cancellationToken);
    /// <inheritdoc />
    public Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken) =>
        (accessContext is null ? admin : runtime).GetPublishedSnapshotAsync(connectorId, environmentId, accessContext, cancellationToken);
}

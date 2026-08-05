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
    public Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken) => admin.CreateDraftAsync(draft, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken) => admin.GetVersionAsync(connectorId, version, cancellationToken);
    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken) => admin.ListConnectorsAsync(cancellationToken);
    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken) => admin.ListVersionsAsync(connectorId, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken) => admin.MarkValidatedAsync(versionId, expectedRowVersion, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken) => admin.PublishAsync(versionId, expectedRowVersion, expectedPublicationRevision, actor, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken) => admin.RollbackAsync(connectorId, targetVersion, expectedActiveRowVersion, actor, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken) => admin.RetireAsync(versionId, expectedRowVersion, actor, now, cancellationToken);
    /// <inheritdoc />
    public Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, CancellationToken cancellationToken) => admin.PutBindingsAsync(bindings, expectedRevision, cancellationToken);
    /// <inheritdoc />
    public Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken) => runtime.GetPublishedStampAsync(connectorId, environmentId, cancellationToken);
    /// <inheritdoc />
    public Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken) => runtime.GetPublishedSnapshotAsync(connectorId, environmentId, cancellationToken);
}

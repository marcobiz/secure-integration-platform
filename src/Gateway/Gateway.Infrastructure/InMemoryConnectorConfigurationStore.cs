using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Deterministic Connector lifecycle store for Development and tests.</summary>
public sealed class InMemoryConnectorConfigurationStore : IConnectorConfigurationStore
{
    private readonly object gate = new();
    private readonly Dictionary<string, Guid> connectorIds = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, ConnectorVersionRecord> versions = [];
    private readonly Dictionary<string, Guid> versionKeys = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Guid> activeVersions = [];
    private readonly Dictionary<Guid, long> publicationRevisions = [];
    private readonly Dictionary<string, ConnectorBindingSet> bindingSets = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> CreateDraftAsync(ConnectorVersionRecord draft, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            string key = VersionKey(draft.ConnectorSlug, draft.Version);
            if (versionKeys.ContainsKey(key)) throw new GatewayException("BGW-CONNECTOR-VERSION-DUPLICATE", 409);
            if (!connectorIds.TryGetValue(draft.ConnectorSlug, out Guid connectorId))
            {
                connectorId = Guid.NewGuid();
                connectorIds.Add(draft.ConnectorSlug, connectorId);
                publicationRevisions.Add(connectorId, 0);
            }
            ConnectorVersionRecord created = Clone(draft with { ConnectorId = connectorId, State = ConnectorVersionState.Draft, RowVersion = 1 });
            versions.Add(created.Id, created);
            versionKeys.Add(key, created.Id);
            return Task.FromResult(Clone(created));
        }
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord?> GetVersionAsync(string connectorId, string version, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) return Task.FromResult(versionKeys.TryGetValue(VersionKey(connectorId, version), out Guid id) ? Clone(versions[id]) : null);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorSummary>> ListConnectorsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorSummary[] result = connectorIds.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item =>
            {
                string? published = activeVersions.TryGetValue(item.Value, out Guid active) ? versions[active].Version : null;
                int count = versions.Values.Count(version => version.ConnectorId == item.Value);
                return new ConnectorSummary(item.Key, published, count);
            }).ToArray();
            return Task.FromResult<IReadOnlyList<ConnectorSummary>>(result);
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ConnectorVersionRecord>> ListVersionsAsync(string connectorId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id)) throw new GatewayException("BGW-CONNECTOR-NOT-FOUND", 404);
            return Task.FromResult<IReadOnlyList<ConnectorVersionRecord>>(versions.Values.Where(value => value.ConnectorId == id).OrderByDescending(value => value.CreatedAt).ThenBy(value => value.Version, StringComparer.Ordinal).Select(Clone).ToArray());
        }
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> MarkValidatedAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorVersionRecord value = Required(versionId);
            Ensure(value, expectedRowVersion, ConnectorVersionState.Draft);
            ConnectorVersionRecord updated = value with { State = ConnectorVersionState.Validated, ValidatedAt = now, RowVersion = value.RowVersion + 1 };
            versions[versionId] = updated;
            return Task.FromResult(Clone(updated));
        }
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> PublishAsync(Guid versionId, long expectedRowVersion, long expectedPublicationRevision, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorVersionRecord target = Required(versionId);
            Ensure(target, expectedRowVersion, ConnectorVersionState.Validated);
            if (publicationRevisions[target.ConnectorId] != expectedPublicationRevision) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            if (activeVersions.TryGetValue(target.ConnectorId, out Guid activeId))
            {
                ConnectorVersionRecord active = versions[activeId];
                versions[activeId] = active with { State = ConnectorVersionState.Superseded, RowVersion = active.RowVersion + 1 };
            }
            ConnectorVersionRecord updated = target with { State = ConnectorVersionState.Published, PublishedAt = target.PublishedAt ?? now, RowVersion = target.RowVersion + 1 };
            versions[versionId] = updated;
            activeVersions[target.ConnectorId] = versionId;
            publicationRevisions[target.ConnectorId]++;
            return Task.FromResult(Clone(updated));
        }
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid connectorGuid) || !activeVersions.TryGetValue(connectorGuid, out Guid activeId)) throw new GatewayException("BGW-CONNECTOR-NOT-PUBLISHED", 409);
            ConnectorVersionRecord active = versions[activeId];
            if (active.RowVersion != expectedActiveRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            ConnectorVersionRecord target = versionKeys.TryGetValue(VersionKey(connectorId, targetVersion), out Guid targetId) ? versions[targetId] : throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
            if (target.State != ConnectorVersionState.Superseded || target.PublishedAt is null) throw new GatewayException("BGW-CONNECTOR-ROLLBACK-TARGET", 409);
            versions[activeId] = active with { State = ConnectorVersionState.Superseded, RowVersion = active.RowVersion + 1 };
            ConnectorVersionRecord reactivated = target with { State = ConnectorVersionState.Published, RowVersion = target.RowVersion + 1 };
            versions[target.Id] = reactivated;
            activeVersions[connectorGuid] = target.Id;
            publicationRevisions[connectorGuid]++;
            return Task.FromResult(Clone(reactivated));
        }
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorVersionRecord value = Required(versionId);
            if (value.RowVersion != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            if (value.State == ConnectorVersionState.Retired) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
            ConnectorVersionRecord retired = value with { State = ConnectorVersionState.Retired, RetiredAt = now, RowVersion = value.RowVersion + 1 };
            versions[versionId] = retired;
            if (activeVersions.TryGetValue(value.ConnectorId, out Guid active) && active == versionId)
            {
                activeVersions.Remove(value.ConnectorId);
                publicationRevisions[value.ConnectorId]++;
            }
            return Task.FromResult(Clone(retired));
        }
    }

    /// <inheritdoc />
    public Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.ContainsValue(bindings.ConnectorId)) throw new GatewayException("BGW-CONNECTOR-NOT-FOUND", 404);
            string key = BindingKey(bindings.ConnectorId, bindings.EnvironmentId);
            long current = bindingSets.TryGetValue(key, out ConnectorBindingSet? existing) ? existing.Revision : 0;
            if (expectedRevision is not null && expectedRevision.Value != current) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            ConnectorBindingSet saved = Clone(bindings with { Revision = current + 1 });
            bindingSets[key] = saved;
            return Task.FromResult(Clone(saved));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active)) return Task.FromResult<PublishedConnectorStamp?>(null);
            long bindingRevision = bindingSets.TryGetValue(BindingKey(id, environmentId), out ConnectorBindingSet? binding) ? binding.Revision : 0;
            return Task.FromResult<PublishedConnectorStamp?>(new(active, publicationRevisions[id], bindingRevision));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active) || !bindingSets.TryGetValue(BindingKey(id, environmentId), out ConnectorBindingSet? binding)) return Task.FromResult<PublishedConnectorSnapshot?>(null);
            PublishedConnectorStamp stamp = new(active, publicationRevisions[id], binding.Revision);
            return Task.FromResult<PublishedConnectorSnapshot?>(new(Clone(versions[active]), Clone(binding), stamp));
        }
    }

    private ConnectorVersionRecord Required(Guid id) => versions.TryGetValue(id, out ConnectorVersionRecord? value) ? value : throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
    private static void Ensure(ConnectorVersionRecord value, long expectedRowVersion, ConnectorVersionState state)
    {
        if (value.RowVersion != expectedRowVersion) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
        if (value.State != state) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
    }
    private static string VersionKey(string connector, string version) => connector + "\n" + version;
    private static string BindingKey(Guid connector, Guid environment) => connector.ToString("N") + "\n" + environment.ToString("N");
    private static ConnectorVersionRecord Clone(ConnectorVersionRecord value) => value with { ChecksumSha256 = value.ChecksumSha256.ToArray() };
    private static ConnectorBindingSet Clone(ConnectorBindingSet value) => value with { Endpoints = new Dictionary<string, Uri>(value.Endpoints, StringComparer.Ordinal), SecretReferences = new Dictionary<string, string>(value.SecretReferences, StringComparer.Ordinal) };
}

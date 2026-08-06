using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Deterministic Connector lifecycle store for Development and tests.</summary>
public sealed class InMemoryConnectorConfigurationStore(IGatewayRegistry? auditRegistry = null) : IConnectorConfigurationStore
{
    private readonly object gate = new();
    private readonly Dictionary<string, Guid> connectorIds = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, ConnectorVersionRecord> versions = [];
    private readonly Dictionary<string, Guid> versionKeys = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Guid> activeVersions = [];
    private readonly Dictionary<Guid, long> publicationRevisions = [];
    private readonly Dictionary<string, List<ConnectorBindingSet>> bindingSets = new(StringComparer.Ordinal);

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
    public async Task<ConnectorVersionRecord> CreateDraftWithAuditAsync(ConnectorVersionRecord draft, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord created = await CreateDraftAsync(draft, cancellationToken).ConfigureAwait(false);
        try
        {
            if (auditRegistry is not null) await auditRegistry.AppendAuditAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            lock (gate)
            {
                versions.Remove(created.Id);
                versionKeys.Remove(VersionKey(created.ConnectorSlug, created.Version));
                if (!versions.Values.Any(value => value.ConnectorId == created.ConnectorId))
                {
                    connectorIds.Remove(created.ConnectorSlug);
                    publicationRevisions.Remove(created.ConnectorId);
                }
            }
            throw;
        }
        return created;
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
                ConnectorVersionRecord? newest = versions.Values.Where(version => version.ConnectorId == item.Value).OrderByDescending(version => version.CreatedAt).FirstOrDefault();
                string displayName = newest is null ? item.Key : DisplayName(newest.CanonicalJson, item.Key);
                return new ConnectorSummary(item.Key, displayName, count, published, publicationRevisions[item.Value]);
            }).ToArray();
            return Task.FromResult<IReadOnlyList<ConnectorSummary>>(result);
        }
    }

    private static string DisplayName(string canonicalJson, string fallback)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        return document.RootElement.TryGetProperty("displayName", out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : fallback;
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
    public async Task<ConnectorVersionRecord> MarkValidatedWithAuditAsync(Guid versionId, long expectedRowVersion, DateTimeOffset now, GatewayAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord previous;
        lock (gate) previous = Clone(Required(versionId));
        ConnectorVersionRecord validated = await MarkValidatedAsync(versionId, expectedRowVersion, now, cancellationToken).ConfigureAwait(false);
        try
        {
            if (auditRegistry is not null) await auditRegistry.AppendAuditAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            lock (gate) versions[versionId] = previous;
            throw;
        }
        return validated;
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
            foreach (ConnectorBindingSet binding in LatestBindings(versionId))
            {
                List<ConnectorBindingSet> revisions = bindingSets[BindingKey(versionId, binding.EnvironmentId)];
                revisions[^1] = binding with { State = ConnectorBindingState.Active };
            }
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
    public Task<ConnectorVersionRecord> PublishApprovedAsync(Guid versionId, byte[] expectedBindingDigestSha256, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new GatewayException("BGW-ADMIN-ATOMIC-PUBLISH-REQUIRES-POSTGRES", 503);
    }

    /// <inheritdoc />
    public Task<ConnectorVersionRecord> RollbackAsync(string connectorId, string targetVersion, long expectedActiveRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
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
    public Task<ConnectorVersionRecord> RetireAsync(Guid versionId, long expectedRowVersion, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
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
    public Task<ConnectorBindingSet> PutBindingsAsync(ConnectorBindingSet bindings, long? expectedRevision, Guid correlationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.ContainsValue(bindings.ConnectorId)) throw new GatewayException("BGW-CONNECTOR-NOT-FOUND", 404);
            string key = BindingKey(bindings.ConnectorVersionId, bindings.EnvironmentId);
            if (!bindingSets.TryGetValue(key, out List<ConnectorBindingSet>? revisions)) bindingSets.Add(key, revisions = []);
            long current = revisions.Count == 0 ? 0 : revisions[^1].Revision;
            if (current > 0 && expectedRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
            if (current == 0 && expectedRevision is not null) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            if (expectedRevision is not null && expectedRevision.Value != current) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
            ConnectorBindingSet saved = Clone(bindings with { Revision = current + 1 });
            revisions.Add(saved);
            return Task.FromResult(Clone(saved));
        }
    }

    /// <inheritdoc />
    public Task<AdminPage<ConnectorBindingSet>> ListBindingsPageAsync(Guid connectorVersionId, int offset, int limit, Guid? environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorBindingSet[] values = bindingSets.Values.SelectMany(value => value)
                .Where(value => value.ConnectorVersionId == connectorVersionId && (environmentId is null || value.EnvironmentId == environmentId))
                .OrderBy(value => value.EnvironmentId).ThenByDescending(value => value.Revision).Select(Clone).ToArray();
            return Task.FromResult(new AdminPage<ConnectorBindingSet>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
        }
    }

    /// <inheritdoc />
    public Task<byte[]> GetBindingBundleDigestAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ConnectorVersionRecord version = Required(connectorVersionId);
            ConnectorBindingSet[] bindings = LatestBindings(connectorVersionId);
            if (bindings.Length == 0) throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 409);
            return Task.FromResult(ConnectorBindingDigests.Bundle(version, bindings));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active)) return Task.FromResult<PublishedConnectorStamp?>(null);
            if (!bindingSets.TryGetValue(BindingKey(active, environmentId), out List<ConnectorBindingSet>? revisions) || revisions.Count == 0 || revisions[^1].State != ConnectorBindingState.Active) return Task.FromResult<PublishedConnectorStamp?>(new(active, publicationRevisions[id], 0, string.Empty));
            ConnectorBindingSet binding = revisions[^1];
            return Task.FromResult<PublishedConnectorStamp?>(new(active, publicationRevisions[id], binding.Revision, binding.ChecksumSha256));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active) || !bindingSets.TryGetValue(BindingKey(active, environmentId), out List<ConnectorBindingSet>? revisions) || revisions.Count == 0 || revisions[^1].State != ConnectorBindingState.Active) return Task.FromResult<PublishedConnectorSnapshot?>(null);
            ConnectorBindingSet binding = revisions[^1];
            PublishedConnectorStamp stamp = new(active, publicationRevisions[id], binding.Revision, binding.ChecksumSha256);
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
    private ConnectorBindingSet[] LatestBindings(Guid connectorVersionId) => bindingSets.Where(value => value.Key.StartsWith(connectorVersionId.ToString("N") + "\n", StringComparison.Ordinal) && value.Value.Count > 0).Select(value => value.Value[^1]).OrderBy(value => value.EnvironmentId).ToArray();
    private static string BindingKey(Guid connectorVersion, Guid environment) => connectorVersion.ToString("N") + "\n" + environment.ToString("N");
    private static ConnectorVersionRecord Clone(ConnectorVersionRecord value) => value with { ChecksumSha256 = value.ChecksumSha256.ToArray() };
    private static ConnectorBindingSet Clone(ConnectorBindingSet value) => value with { Endpoints = new Dictionary<string, Uri>(value.Endpoints, StringComparer.Ordinal), SecretReferences = new Dictionary<string, string>(value.SecretReferences, StringComparer.Ordinal), CertificateReferences = new Dictionary<string, string>(value.CertificateReferences, StringComparer.Ordinal) };
}

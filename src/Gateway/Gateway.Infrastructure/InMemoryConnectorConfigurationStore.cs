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
    private readonly Dictionary<string, List<ProviderResourceCatalogRecord>> providerResources = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<ProviderResourceCatalogRecord> RegisterProviderResourceAsync(ProviderResourceCatalogRecord resource, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProviderResourceReferenceValidator.Validate(new(resource.ProviderId, resource.ResourceId, resource.ResourceType, resource.Version, resource.PublicMetadataRevision));
        if (resource.ResourceType == ProviderResourceType.ClientCertificate && resource.CertificateMetadata is null) throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-REQUIRED", 409);
        lock (gate)
        {
            string key = ResourceKey(resource.ProviderId, resource.ResourceId, resource.ResourceType, resource.Version);
            if (!providerResources.TryGetValue(key, out List<ProviderResourceCatalogRecord>? revisions)) providerResources.Add(key, revisions = []);
            if (revisions.Count > 0 && SameRegistration(revisions[^1], resource)) return Task.FromResult(revisions[^1]);
            long next = revisions.Count == 0 ? 1 : revisions[^1].Revision + 1;
            ProviderResourceCatalogRecord saved = resource with { Revision = next, ChecksumSha256 = ResourceChecksum(resource with { Revision = next }) };
            revisions.Add(saved);
            return Task.FromResult(saved);
        }
    }

    /// <inheritdoc />
    public Task<ProviderResourceCatalogRecord> ResolveProviderResourceAsync(ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProviderResourceReferenceValidator.Validate(reference);
        lock (gate)
        {
            string key = ResourceKey(reference.ProviderId, reference.ResourceId, reference.ResourceType, reference.Version);
            if (!providerResources.TryGetValue(key, out List<ProviderResourceCatalogRecord>? revisions) || revisions.Count == 0) throw new GatewayException("BGW-PROVIDER-RESOURCE-NOT-FOUND", 400);
            ProviderResourceCatalogRecord resource = revisions[^1];
            EnsureResourceScope(resource, reference, environmentId, connectorId, operationIds);
            return Task.FromResult(resource);
        }
    }

    /// <inheritdoc />
    public Task<AdminPage<ProviderResourceCatalogRecord>> ListProviderResourcesPageAsync(int offset, int limit, Guid? environmentId, ProviderResourceType? resourceType, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ProviderResourceCatalogRecord[] values = providerResources.Values.Select(value => value[^1])
                .Where(value => (environmentId is null || value.EnvironmentId == environmentId) && (resourceType is null || value.ResourceType == resourceType))
                .OrderBy(value => value.ProviderId, StringComparer.Ordinal).ThenBy(value => value.ResourceId, StringComparer.Ordinal).ToArray();
            return Task.FromResult(new AdminPage<ProviderResourceCatalogRecord>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
        }
    }

    /// <inheritdoc />
    public Task ValidateBindingResourcesAsync(Guid connectorVersionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            foreach (ConnectorBindingSet binding in LatestBindings(connectorVersionId)) ValidateCurrentResources(binding);
            return Task.CompletedTask;
        }
    }

    /// <inheritdoc />
    public async Task<ConnectorApprovalRecord> ApproveCanonicalAsync(IAdminSecurityStore fallbackStore, Guid approvalRequestId, Guid connectorVersionId, string expectedDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord version;
        byte[] digest;
        lock (gate)
        {
            version = Clone(Required(connectorVersionId));
            ConnectorBindingSet[] bindings = LatestBindings(connectorVersionId);
            foreach (ConnectorBindingSet binding in bindings) ValidateCurrentResources(binding);
            digest = ConnectorBindingDigests.Bundle(version, bindings);
            byte[] expected;
            try { expected = Convert.FromHexString(expectedDigestSha256); }
            catch (FormatException) { throw new GatewayException("BGW-ADMIN-APPROVAL-DIGEST", 400); }
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, digest)) throw new GatewayException("BGW-ADMIN-APPROVAL-STALE", 409);
        }
        return await fallbackStore.ApproveAsync(approvalRequestId, connectorVersionId, version.ChecksumSha256, digest, createdBy, approver, comment, correlationId, now, cancellationToken).ConfigureAwait(false);
    }

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
            foreach (ConnectorBindingSet binding in bindings) ValidateCurrentResources(binding);
            return Task.FromResult(ConnectorBindingDigests.Bundle(version, bindings));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorStamp?> GetPublishedStampAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active)) return Task.FromResult<PublishedConnectorStamp?>(null);
            if (!bindingSets.TryGetValue(BindingKey(active, environmentId), out List<ConnectorBindingSet>? revisions) || revisions.Count == 0 || revisions[^1].State != ConnectorBindingState.Active) return Task.FromResult<PublishedConnectorStamp?>(new(active, publicationRevisions[id], 0, string.Empty, string.Empty));
            ConnectorBindingSet binding = revisions[^1];
            ValidateCurrentResources(binding);
            return Task.FromResult<PublishedConnectorStamp?>(new(active, publicationRevisions[id], binding.Revision, binding.ChecksumSha256, ResourceStamp(binding)));
        }
    }

    /// <inheritdoc />
    public Task<PublishedConnectorSnapshot?> GetPublishedSnapshotAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!connectorIds.TryGetValue(connectorId, out Guid id) || !activeVersions.TryGetValue(id, out Guid active) || !bindingSets.TryGetValue(BindingKey(active, environmentId), out List<ConnectorBindingSet>? revisions) || revisions.Count == 0 || revisions[^1].State != ConnectorBindingState.Active) return Task.FromResult<PublishedConnectorSnapshot?>(null);
            ConnectorBindingSet binding = revisions[^1];
            PublishedConnectorStamp stamp = new(active, publicationRevisions[id], binding.Revision, binding.ChecksumSha256, ResourceStamp(binding));
            ValidateCurrentResources(binding);
            Dictionary<string, string> secrets = binding.SecretResources.ToDictionary(value => value.Key, value => RequiredResource(value.Value).ProviderReference, StringComparer.Ordinal);
            Dictionary<string, string> certificates = binding.CertificateResources.ToDictionary(value => value.Key, value => RequiredResource(value.Value).ProviderReference, StringComparer.Ordinal);
            return Task.FromResult<PublishedConnectorSnapshot?>(new(Clone(versions[active]), Clone(binding), stamp, secrets, certificates));
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
    private static ConnectorBindingSet Clone(ConnectorBindingSet value) => value with { Endpoints = new Dictionary<string, Uri>(value.Endpoints, StringComparer.Ordinal), SecretResources = new Dictionary<string, ProviderResourceBinding>(value.SecretResources, StringComparer.Ordinal), CertificateResources = new Dictionary<string, ProviderResourceBinding>(value.CertificateResources, StringComparer.Ordinal) };

    private void ValidateCurrentResources(ConnectorBindingSet binding)
    {
        foreach (ProviderResourceBinding resource in binding.SecretResources.Values.Concat(binding.CertificateResources.Values)) _ = RequiredResource(resource);
    }

    private ProviderResourceCatalogRecord RequiredResource(ProviderResourceBinding binding)
    {
        string key = ResourceKey(binding.ProviderId, binding.ResourceId, binding.ResourceType, binding.Version);
        if (!providerResources.TryGetValue(key, out List<ProviderResourceCatalogRecord>? revisions) || revisions.Count == 0) throw new GatewayException("BGW-PROVIDER-RESOURCE-NOT-FOUND", 409);
        ProviderResourceCatalogRecord current = revisions[^1];
        if (current.Status != ProviderResourceStatus.Active || current.Revision != binding.CatalogRevision || !string.Equals(current.ChecksumSha256, binding.CatalogChecksumSha256, StringComparison.Ordinal))
            throw new GatewayException("BGW-PROVIDER-RESOURCE-REVISION-STALE", 409);
        return current;
    }

    private string ResourceStamp(ConnectorBindingSet binding)
    {
        var values = binding.SecretResources.Concat(binding.CertificateResources).OrderBy(value => value.Key, StringComparer.Ordinal)
            .Select(value => new { value.Key, Current = RequiredResource(value.Value).ChecksumSha256 }).ToArray();
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(values)));
    }

    private static void EnsureResourceScope(ProviderResourceCatalogRecord resource, ProviderResourceReference reference, Guid environmentId, string connectorId, IReadOnlyCollection<string> operationIds)
    {
        if (resource.Status != ProviderResourceStatus.Active || resource.EnvironmentId != environmentId || resource.ResourceType != reference.ResourceType ||
            resource.PublicMetadataRevision != reference.PublicMetadataRevision || !string.Equals(resource.ConnectorScope, "*", StringComparison.Ordinal) && !string.Equals(resource.ConnectorScope, connectorId, StringComparison.Ordinal) ||
            operationIds.Any(operationId => !string.Equals(resource.OperationScope, "*", StringComparison.Ordinal) && !string.Equals(resource.OperationScope, operationId, StringComparison.Ordinal)))
            throw new GatewayException("BGW-PROVIDER-RESOURCE-SCOPE", 403);
    }

    private static string ResourceKey(string providerId, string resourceId, ProviderResourceType type, string? version) => $"{providerId}\n{resourceId}\n{type}\n{version}";

    private static string ResourceChecksum(ProviderResourceCatalogRecord resource)
    {
        var canonical = new { resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId, resource.ResourceType, resource.DisplayName, resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope, resource.Status, resource.Version, resource.Revision, resource.PublicMetadataRevision, resource.CertificateMetadata };
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    private static bool SameRegistration(ProviderResourceCatalogRecord current, ProviderResourceCatalogRecord candidate) =>
        current.ProviderDisplayName == candidate.ProviderDisplayName && current.ProviderType == candidate.ProviderType && current.DisplayName == candidate.DisplayName &&
        current.EnvironmentId == candidate.EnvironmentId && current.ConnectorScope == candidate.ConnectorScope && current.OperationScope == candidate.OperationScope &&
        current.ProviderReference == candidate.ProviderReference && current.Status == candidate.Status && current.PublicMetadataRevision == candidate.PublicMetadataRevision && current.CertificateMetadata == candidate.CertificateMetadata;
}

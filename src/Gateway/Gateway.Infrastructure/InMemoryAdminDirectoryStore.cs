using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Development-only administrative catalogue over the in-memory registry.</summary>
public sealed class InMemoryAdminDirectoryStore(InMemoryGatewayRegistry registry) : IAdminDirectoryStore
{
    /// <inheritdoc />
    public Task<AdminPage<TenantRecord>> ListTenantsAsync(int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Tenants.OrderBy(value => value.Code), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<ApplicationRecord>> ListApplicationsAsync(int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Applications.OrderBy(value => value.Code), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<GatewayEnvironmentRecord>> ListEnvironmentsAsync(int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Environments.OrderBy(value => value.Code), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<InstallationRecord>> ListInstallationsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Installations.Where(value => value.TenantId == tenantId).OrderByDescending(value => value.CreatedAt), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<InstallationRecord?> GetInstallationAsync(Guid tenantId, Guid installationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(registry.SnapshotDirectory().Installations.SingleOrDefault(value => value.TenantId == tenantId && value.Id == installationId));
    }

    /// <inheritdoc />
    public Task<AdminPage<InstallationGrantRecord>> ListGrantsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Grants.Where(value => value.TenantId == tenantId).OrderBy(value => value.ConnectorId).ThenBy(value => value.OperationId), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<GatewayAuditEvent>> ListAuditAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Audit.Where(value => value.TenantId == tenantId).OrderByDescending(value => value.OccurredAt), offset, limit, cancellationToken);

    private static Task<AdminPage<T>> Page<T>(IEnumerable<T> source, int offset, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (offset < 0 || limit is < 1 or > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400);
        T[] values = source.ToArray();
        return Task.FromResult(new AdminPage<T>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
    }
}

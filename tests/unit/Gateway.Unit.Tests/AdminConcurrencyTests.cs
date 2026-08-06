using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class AdminConcurrencyTests
{
    [Fact]
    public async Task M5_UT_Tenant_stale_update_and_disable_are_denied_without_success_audit()
    {
        InMemoryGatewayRegistry registry = new(); Guid id = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
        await registry.AddTenantAsync(new(id, "tenant", "Original", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        TenantRecord updated = await registry.UpdateTenantWithAuditAsync(id, "Admin A", 1, Audit(id, "tenant.update"), TestContext.Current.CancellationToken);
        Assert.Equal(2, updated.RowVersion);
        GatewayException staleUpdate = await Assert.ThrowsAsync<GatewayException>(() => registry.UpdateTenantWithAuditAsync(id, "Admin B", 1, Audit(id, "tenant.update"), TestContext.Current.CancellationToken));
        GatewayException staleDisable = await Assert.ThrowsAsync<GatewayException>(() => registry.DisableTenantWithAuditAsync(id, 1, Audit(id, "tenant.disable"), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONCURRENCY-CONFLICT", staleUpdate.Code); Assert.Equal("BGW-CONCURRENCY-CONFLICT", staleDisable.Code);
        (TenantRecord[] tenants, _, _, _, _, GatewayAuditEvent[] audit) = registry.SnapshotDirectory();
        Assert.Equal("Admin A", Assert.Single(tenants).DisplayName); Assert.Single(audit);
    }

    [Fact]
    public async Task M5_UT_Application_stale_update_and_disable_are_denied_without_success_audit()
    {
        InMemoryGatewayRegistry registry = new(); Guid id = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
        await registry.AddApplicationAsync(new(id, "app", "Original", ApplicationStatus.Active, "3.0.0", null, now), TestContext.Current.CancellationToken);
        ApplicationRecord updated = await registry.UpdateApplicationWithAuditAsync(id, "Admin A", "3.1.0", null, 1, Audit(null, "application.update"), TestContext.Current.CancellationToken);
        Assert.Equal(2, updated.RowVersion);
        GatewayException staleUpdate = await Assert.ThrowsAsync<GatewayException>(() => registry.UpdateApplicationWithAuditAsync(id, "Admin B", "4.0.0", null, 1, Audit(null, "application.update"), TestContext.Current.CancellationToken));
        GatewayException staleDisable = await Assert.ThrowsAsync<GatewayException>(() => registry.DisableApplicationWithAuditAsync(id, 1, Audit(null, "application.disable"), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONCURRENCY-CONFLICT", staleUpdate.Code); Assert.Equal("BGW-CONCURRENCY-CONFLICT", staleDisable.Code);
        (_, ApplicationRecord[] applications, _, _, _, GatewayAuditEvent[] audit) = registry.SnapshotDirectory();
        Assert.Equal("Admin A", Assert.Single(applications).DisplayName); Assert.Single(audit);
    }

    private static GatewayAuditEvent Audit(Guid? tenantId, string action) => new(Guid.NewGuid(), DateTimeOffset.UtcNow, tenantId, "administrator", "test", action, "resource", "id", Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>());
}

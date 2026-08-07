using SecureIntegration.M5.DevelopmentSeed;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class AdminLocalDevelopmentTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void M5_ARCH_Local_seed_is_impossible_without_explicit_Development_opt_in()
    {
        Assert.True(DevelopmentSeedBoundary.IsEnabled("Development", "true"));
        Assert.False(DevelopmentSeedBoundary.IsEnabled("Production", "true"));
        Assert.False(DevelopmentSeedBoundary.IsEnabled("Development", null));
        Assert.False(DevelopmentSeedBoundary.IsEnabled("M5Testing", "true"));
    }

    [Fact]
    public void M5_ARCH_Local_proxy_keeps_TLS_validation_and_backend_failures_visible()
    {
        string vite = File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", "vite.config.ts"));
        Assert.Contains("VITE_ADMIN_PROXY_TARGET", vite, StringComparison.Ordinal);
        Assert.Contains("secure: true", vite, StringComparison.Ordinal);
        Assert.DoesNotContain("secure: false", vite, StringComparison.Ordinal);
        Assert.DoesNotContain("https://localhost:8443", vite, StringComparison.Ordinal);
        Assert.Contains("VITE_ADMIN_PROXY_TARGET is required", vite, StringComparison.Ordinal);
        string developmentEnvironment = File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", ".env.development"));
        Assert.Contains("VITE_ADMIN_PROXY_TARGET=https://localhost:5180", developmentEnvironment, StringComparison.Ordinal);
    }

    [Fact]
    public void M5_ARCH_Local_launcher_uses_real_dependencies_and_preserves_the_database_by_default()
    {
        string launcher = File.ReadAllText(Path.Combine(Root, "tools", "m5", "Invoke-M5AdminDev.ps1"));
        Assert.Contains("Gateway.Migrations", launcher, StringComparison.Ordinal);
        Assert.Contains("/health/ready", launcher, StringComparison.Ordinal);
        Assert.Contains("DevelopmentAuth", launcher, StringComparison.Ordinal);
        Assert.Contains("test:local-dev", launcher, StringComparison.Ordinal);
        Assert.Contains("down --remove-orphans", launcher, StringComparison.Ordinal);
        Assert.Contains("if ($Reset)", launcher, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}

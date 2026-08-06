using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class CiSecurityTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void PostgreSql_gate_uses_a_non_superuser_for_admin_store_tests()
    {
        string workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "ci.yml"));

        Assert.Contains("Username=ci_gateway_admin", workflow, StringComparison.Ordinal);
        Assert.Contains("GATEWAY_POSTGRES_MIGRATION_CONNECTION: Host=127.0.0.1;Port=5432;Database=broker_gateway_test;Username=postgres", workflow, StringComparison.Ordinal);
        Assert.Contains("CREATE ROLE ci_gateway_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION", workflow, StringComparison.Ordinal);
        Assert.Contains("GRANT gateway_admin TO ci_gateway_admin", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("GATEWAY_POSTGRES_ADMIN_CONNECTION: Host=127.0.0.1;Port=5432;Database=broker_gateway_test;Username=postgres", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void M4_quickstart_uses_a_distinct_non_superuser_admin_pool()
    {
        string compose = File.ReadAllText(Path.Combine(Root, "deploy", "m4", "docker-compose.m4.yml"));
        string runner = File.ReadAllText(Path.Combine(Root, "tools", "m4", "Invoke-M4Quickstart.ps1"));
        string provisioner = File.ReadAllText(Path.Combine(Root, "tools", "m3", "Provisioner", "Program.cs"));

        Assert.Contains("M4_QUICKSTART_DB_ADMIN_PASSWORD", compose, StringComparison.Ordinal);
        Assert.Contains("ConnectionStrings__GatewayAdminDatabase:", compose, StringComparison.Ordinal);
        Assert.Contains("Username=m5_gateway_admin", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("ConnectionStrings__GatewayAdminDatabase: Host=postgres;Port=5432;Database=broker_gateway_m3;Username=m3_gateway_runtime", compose, StringComparison.Ordinal);
        Assert.Contains("M4_QUICKSTART_DB_ADMIN_PASSWORD", runner, StringComparison.Ordinal);
        Assert.Contains("ALTER ROLE m5_gateway_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION", provisioner, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx")) ||
                File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}

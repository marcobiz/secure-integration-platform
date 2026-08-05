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
        Assert.Contains("CREATE ROLE ci_gateway_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION", workflow, StringComparison.Ordinal);
        Assert.Contains("GRANT gateway_admin TO ci_gateway_admin", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("GATEWAY_POSTGRES_ADMIN_CONNECTION: Host=127.0.0.1;Port=5432;Database=broker_gateway_test;Username=postgres", workflow, StringComparison.Ordinal);
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

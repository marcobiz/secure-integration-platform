using System.Reflection;
using SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class PostgreSqlIsolationPolicyTests
{
    [Fact]
    public void Shared_database_collection_contains_only_PostgreSQL_classes_and_global_parallelism_stays_enabled()
    {
        Assembly assembly = typeof(PostgreSqlIsolationPolicyTests).Assembly;
        string[] actual = assembly.GetTypes()
            .Where(IsInSharedPostgreSqlCollection)
            .Select(type => type.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] expected =
        [
            nameof(AdminApiPostgreSqlSecurityTests),
            nameof(AuthorizedVerticalCapabilityHostedIntegrationTests),
            nameof(ConnectorExecutionSeamHostedIntegrationTests),
            nameof(ConnectorWorkflowContextPostgresTests),
            nameof(PostgresIsolationTests),
            nameof(ProductionComposedSoapRuntimeIntegrationTests),
            nameof(TypedSessionHandshakeHostedIntegrationTests),
            nameof(TypedSessionHandshakePostgresRaceIntegrationTests)
        ];

        Assert.Equal(expected, actual);
        CollectionBehaviorAttribute? behavior = assembly.GetCustomAttribute<CollectionBehaviorAttribute>();
        Assert.False(behavior?.DisableTestParallelization ?? false);
    }

    private static bool IsInSharedPostgreSqlCollection(Type type) =>
        type.GetCustomAttributesData().Any(attribute =>
            attribute.AttributeType == typeof(CollectionAttribute) &&
            attribute.ConstructorArguments.Count == 1 &&
            string.Equals(attribute.ConstructorArguments[0].Value as string, PostgreSqlSharedDatabaseGroup.Name, StringComparison.Ordinal));
}

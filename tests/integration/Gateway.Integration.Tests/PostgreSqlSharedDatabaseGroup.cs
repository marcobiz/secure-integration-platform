using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

// CI intentionally supplies one PostgreSQL database to these opt-in classes.
// Other test classes remain eligible for normal xUnit parallel execution.
[CollectionDefinition(Name)]
public sealed class PostgreSqlSharedDatabaseGroup
{
    public const string Name = "PostgreSQL shared database";
}

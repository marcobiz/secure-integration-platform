using System.Security.Cryptography;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class ConnectorWorkflowContextPostgresTests
{
    private static readonly string[] ExpectedColumns =
    [
        "action_code",
        "application_id",
        "connector_id",
        "connector_version",
        "environment_id",
        "installation_id",
        "operation_profile_checksum_sha256",
        "originating_operation_id",
        "published_context_sha256",
        "purpose_of_use_code",
        "recorded_at",
        "tenant_id",
        "trace_id",
        "workflow_instance_id"
    ];

    [Fact]
    public void FSE2_DUR_Migration_0018_is_additive_closed_and_runtime_only()
    {
        string sql = File.ReadAllText(MigrationPath());
        Assert.Contains("CREATE TABLE IF NOT EXISTS gateway.connector_workflow_context", sql, StringComparison.Ordinal);
        Assert.Contains("FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("GRANT SELECT, INSERT ON TABLE gateway.connector_workflow_context TO gateway_runtime", sql, StringComparison.Ordinal);
        Assert.Contains("FROM PUBLIC, gateway_runtime, gateway_admin, gateway_readonly", sql, StringComparison.Ordinal);
        Assert.Contains("ux_connector_workflow_context_workflow", sql, StringComparison.Ordinal);
        Assert.Contains("ux_connector_workflow_context_trace", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP TABLE", sql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("json", ColumnDefinition(sql), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("payload", ColumnDefinition(sql), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("patient", ColumnDefinition(sql), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FSE2_DUR_DAT_PostgreSQL18_upgrade_from_0017_and_second_apply_are_idempotent()
    {
        string connectionString = RequiredMigrationConnection();
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("18.", owner.PostgreSqlVersion.ToString(), StringComparison.Ordinal);

        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction, "DROP TABLE gateway.connector_workflow_context");
        string migration = await File.ReadAllTextAsync(MigrationPath(), TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction, migration);
        SchemaSnapshot first = await ReadSchemaSnapshotAsync(owner, transaction);
        await ExecuteAsync(owner, transaction, migration);
        SchemaSnapshot second = await ReadSchemaSnapshotAsync(owner, transaction);

        Assert.Equal(first.Columns, second.Columns);
        Assert.Equal(first.UniqueIndexes, second.UniqueIndexes);
        Assert.Equal(first.Policies, second.Policies);
        Assert.Equal(first.RowSecurity, second.RowSecurity);
        Assert.Equal(first.ForcedRowSecurity, second.ForcedRowSecurity);
        Assert.Equal(ExpectedColumns, first.Columns);
        Assert.Equal(
            ["ux_connector_workflow_context_trace", "ux_connector_workflow_context_workflow"],
            first.UniqueIndexes);
        Assert.Equal(["connector_workflow_context_runtime_scope"], first.Policies);
        Assert.True(first.RowSecurity);
        Assert.True(first.ForcedRowSecurity);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task FSE2_DUR_DAT_PostgreSQL18_record_resolve_idempotency_conflict_scope_and_privileges()
    {
        string migrationConnection = RequiredMigrationConnection();
        string adminConnection = RequiredAdminConnection();
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                adminConnection,
                migrationConnection,
                TestContext.Current.CancellationToken);
        await using NpgsqlConnection owner = new(migrationConnection);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        WorkflowDatabaseFixture fixture = await CreateFixtureAsync(owner);

        try
        {
            ConnectorWorkflowContextAuthorityScope authority = new(
                fixture.TenantA,
                fixture.ApplicationA,
                fixture.InstallationA,
                fixture.EnvironmentA,
                fixture.ConnectorId,
                "1.0.0",
                fixture.PublishedContextSha256);
            ConnectorWorkflowContextRecord context = new(
                "create",
                "CREATE",
                "TREATMENT",
                new string('a', 64),
                fixture.WorkflowId,
                fixture.TraceId);
            DateTimeOffset recordedAt = DateTimeOffset.UtcNow;

            await using (NpgsqlDataSource firstDataSource = NpgsqlDataSource.Create(runtimeRole.ConnectionString))
            {
                PostgresConnectorWorkflowContextStore first = new(firstDataSource);
                Assert.Equal(
                    ConnectorWorkflowContextRecordResult.Created,
                    await first.RecordAsync(new(authority, context, recordedAt), TestContext.Current.CancellationToken));
                Assert.Equal(
                    ConnectorWorkflowContextRecordResult.Unchanged,
                    await first.RecordAsync(new(authority, context, recordedAt.AddMinutes(1)), TestContext.Current.CancellationToken));

                ConnectorWorkflowContextRecord different = new(
                    "replace",
                    "UPDATE",
                    "UPDATE",
                    new string('b', 64),
                    fixture.WorkflowId,
                    fixture.TraceId);
                Assert.Equal(
                    ConnectorWorkflowContextRecordResult.Conflict,
                    await first.RecordAsync(new(authority, different, recordedAt.AddMinutes(2)), TestContext.Current.CancellationToken));
                Assert.Equal(
                    ConnectorWorkflowContextRecordResult.Created,
                    await first.RecordAsync(new(
                        authority,
                        new("create", "CREATE", "TREATMENT", new string('a', 64), null, "trace-only-" + fixture.TraceId),
                        recordedAt.AddMinutes(3)), TestContext.Current.CancellationToken));
                Assert.Equal(
                    ConnectorWorkflowContextRecordResult.Created,
                    await first.RecordAsync(new(
                        authority,
                        new("create", "CREATE", "TREATMENT", new string('a', 64), "workflow-only-" + fixture.WorkflowId, null),
                        recordedAt.AddMinutes(4)), TestContext.Current.CancellationToken));
            }

            await using (NpgsqlDataSource restartedDataSource = NpgsqlDataSource.Create(runtimeRole.ConnectionString))
            {
                PostgresConnectorWorkflowContextStore restarted = new(restartedDataSource);
                AuthorizedConnectorWorkflowContext byWorkflow = Assert.IsType<AuthorizedConnectorWorkflowContext>(
                    await restarted.ResolveAsync(
                        authority,
                        new(ConnectorWorkflowIdentifierKind.WorkflowInstanceId, fixture.WorkflowId),
                        TestContext.Current.CancellationToken));
                AuthorizedConnectorWorkflowContext byTrace = Assert.IsType<AuthorizedConnectorWorkflowContext>(
                    await restarted.ResolveAsync(
                        authority,
                        new(ConnectorWorkflowIdentifierKind.TraceId, fixture.TraceId),
                        TestContext.Current.CancellationToken));
                Assert.Equal("create", byWorkflow.OriginatingOperationId);
                Assert.Equal("CREATE", byWorkflow.ActionCode);
                Assert.Equal("TREATMENT", byWorkflow.PurposeOfUseCode);
                Assert.Equal(new string('a', 64), byWorkflow.OperationProfileChecksumSha256);
                Assert.Equal(byWorkflow.RecordedAtUtc, byTrace.RecordedAtUtc);

                ConnectorWorkflowContextAuthorityScope[] deniedAuthorities =
                [
                    authority with { TenantId = fixture.TenantB },
                    authority with { ApplicationId = fixture.ApplicationB },
                    authority with { InstallationId = fixture.InstallationB },
                    authority with { EnvironmentId = fixture.EnvironmentB },
                    authority with { ConnectorId = fixture.ConnectorId + "-other" },
                    authority with { ConnectorVersion = "2.0.0" },
                    authority with { PublishedContextSha256 = new byte[32] }
                ];
                foreach (ConnectorWorkflowContextAuthorityScope denied in deniedAuthorities)
                    Assert.Null(await restarted.ResolveAsync(
                        denied,
                        new(ConnectorWorkflowIdentifierKind.WorkflowInstanceId, fixture.WorkflowId),
                        TestContext.Current.CancellationToken));
            }

            Assert.Equal(1L, await ScalarAsync<long>(
                owner,
                "SELECT count(*) FROM gateway.connector_workflow_context WHERE workflow_instance_id=$1",
                fixture.WorkflowId));
            Assert.Equal("create", await ScalarAsync<string>(
                owner,
                "SELECT originating_operation_id FROM gateway.connector_workflow_context WHERE workflow_instance_id=$1",
                fixture.WorkflowId));
            Assert.Equal(ExpectedColumns, await ReadColumnsAsync(owner, transaction: null));

            string[] privileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"];
            foreach (string privilege in privileges)
            {
                Assert.Equal(privilege is "SELECT" or "INSERT", await HasTablePrivilegeAsync(owner, "gateway_runtime", privilege));
                Assert.False(await HasTablePrivilegeAsync(owner, "gateway_admin", privilege));
                Assert.False(await HasTablePrivilegeAsync(owner, "gateway_readonly", privilege));
            }
            Assert.Equal(0L, await ScalarAsync<long>(owner, """
                SELECT count(*)
                  FROM pg_class c
                  CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) acl
                 WHERE c.oid='gateway.connector_workflow_context'::regclass
                   AND acl.grantee=0
                """));

            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture, "SELECT * FROM gateway.connector_workflow_context");
            await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture, "SELECT * FROM gateway.connector_workflow_context");
            await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture, "UPDATE gateway.connector_workflow_context SET action_code='UPDATE'");
            await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture, "DELETE FROM gateway.connector_workflow_context");
            await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture, "TRUNCATE gateway.connector_workflow_context");

            Assert.Equal(3L, await ScalarAsRuntimeScopeAsync(
                owner,
                fixture.TenantA,
                fixture.InstallationA,
                "SELECT count(*) FROM gateway.connector_workflow_context"));
            Assert.Equal(0L, await ScalarAsRuntimeScopeAsync(
                owner,
                fixture.TenantA,
                fixture.InstallationB,
                "SELECT count(*) FROM gateway.connector_workflow_context"));
            Assert.Equal(0L, await ScalarAsRuntimeScopeAsync(
                owner,
                fixture.TenantB,
                fixture.InstallationA,
                "SELECT count(*) FROM gateway.connector_workflow_context"));
        }
        finally
        {
            await CleanupFixtureAsync(owner, fixture);
        }
    }

    private static string RequiredMigrationConnection() =>
        Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
        ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION")
        ?? Skip<string>("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

    private static string RequiredAdminConnection() =>
        Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION")
        ?? Skip<string>("The dedicated PostgreSQL 18 gate must provide the admin connection.");

    private static T Skip<T>(string reason)
    {
        Assert.Skip(reason);
        throw new InvalidOperationException(reason);
    }

    private static async Task<WorkflowDatabaseFixture> CreateFixtureAsync(NpgsqlConnection owner)
    {
        string suffix = Guid.NewGuid().ToString("N");
        WorkflowDatabaseFixture fixture = new(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "fse2-durable-" + suffix,
            $"workflow-{suffix}",
            $"trace-{suffix}",
            RandomNumberGenerator.GetBytes(32));
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction,
            "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,'FSE2 durable A','active',now()),($3,$4,'FSE2 durable B','active',now())",
            fixture.TenantA, "fse2-ta-" + suffix, fixture.TenantB, "fse2-tb-" + suffix);
        await ExecuteAsync(owner, transaction,
            "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,'FSE2 durable A','active','1.0.0',now()),($3,$4,'FSE2 durable B','active','1.0.0',now())",
            fixture.ApplicationA, "fse2-aa-" + suffix, fixture.ApplicationB, "fse2-ab-" + suffix);
        await ExecuteAsync(owner, transaction,
            "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,'FSE2 durable A',false),($3,$4,'FSE2 durable B',false)",
            fixture.EnvironmentA, "fse2-ea-" + suffix[..20], fixture.EnvironmentB, "fse2-eb-" + suffix[..20]);
        await ExecuteAsync(owner, transaction,
            "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,created_at) VALUES($1,$2,$3,$4,'active',now()),($5,$6,$7,$8,'active',now())",
            fixture.InstallationA, fixture.TenantA, fixture.ApplicationA, fixture.EnvironmentA,
            fixture.InstallationB, fixture.TenantB, fixture.ApplicationB, fixture.EnvironmentB);
        await transaction.CommitAsync(TestContext.Current.CancellationToken);
        return fixture;
    }

    private static async Task CleanupFixtureAsync(NpgsqlConnection owner, WorkflowDatabaseFixture fixture)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(CancellationToken.None);
        await ExecuteAsync(owner, transaction,
            "DELETE FROM gateway.connector_workflow_context WHERE tenant_id IN ($1,$2)",
            fixture.TenantA, fixture.TenantB);
        await ExecuteAsync(owner, transaction,
            "DELETE FROM gateway.installation WHERE id IN ($1,$2)",
            fixture.InstallationA, fixture.InstallationB);
        await ExecuteAsync(owner, transaction,
            "DELETE FROM gateway.environment WHERE id IN ($1,$2)",
            fixture.EnvironmentA, fixture.EnvironmentB);
        await ExecuteAsync(owner, transaction,
            "DELETE FROM gateway.application WHERE id IN ($1,$2)",
            fixture.ApplicationA, fixture.ApplicationB);
        await ExecuteAsync(owner, transaction,
            "DELETE FROM gateway.tenant WHERE id IN ($1,$2)",
            fixture.TenantA, fixture.TenantB);
        await transaction.CommitAsync(CancellationToken.None);
    }

    private static async Task<SchemaSnapshot> ReadSchemaSnapshotAsync(
        NpgsqlConnection owner,
        NpgsqlTransaction transaction)
    {
        string[] columns = await ReadColumnsAsync(owner, transaction);
        string[] indexes = await ReadStringsAsync(owner, transaction, """
            SELECT indexname
              FROM pg_indexes
             WHERE schemaname='gateway' AND tablename='connector_workflow_context'
               AND indexdef LIKE 'CREATE UNIQUE INDEX%'
             ORDER BY indexname
            """);
        string[] policies = await ReadStringsAsync(owner, transaction, """
            SELECT policyname
              FROM pg_policies
             WHERE schemaname='gateway' AND tablename='connector_workflow_context'
             ORDER BY policyname
            """);
        await using NpgsqlCommand flags = new(
            "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='gateway.connector_workflow_context'::regclass",
            owner,
            transaction);
        await using NpgsqlDataReader reader = await flags.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        return new(columns, indexes, policies, reader.GetBoolean(0), reader.GetBoolean(1));
    }

    private static Task<string[]> ReadColumnsAsync(NpgsqlConnection owner, NpgsqlTransaction? transaction) =>
        ReadStringsAsync(owner, transaction, """
            SELECT column_name
              FROM information_schema.columns
             WHERE table_schema='gateway' AND table_name='connector_workflow_context'
             ORDER BY column_name
            """);

    private static async Task<string[]> ReadStringsAsync(
        NpgsqlConnection owner,
        NpgsqlTransaction? transaction,
        string sql)
    {
        await using NpgsqlCommand command = new(sql, owner, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        List<string> result = [];
        while (await reader.ReadAsync(TestContext.Current.CancellationToken)) result.Add(reader.GetString(0));
        return result.ToArray();
    }

    private static async Task<bool> HasTablePrivilegeAsync(NpgsqlConnection owner, string role, string privilege)
    {
        await using NpgsqlCommand command = new(
            "SELECT has_table_privilege($1,'gateway.connector_workflow_context',$2)",
            owner);
        command.Parameters.AddWithValue(role);
        command.Parameters.AddWithValue(privilege);
        return Assert.IsType<bool>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task AssertRoleDeniedAsync(
        NpgsqlConnection owner,
        string role,
        WorkflowDatabaseFixture fixture,
        string sql)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction, $"SET LOCAL ROLE {role}");
        await ExecuteAsync(owner, transaction,
            "SELECT set_config('app.tenant_id',$1,true),set_config('app.installation_id',$2,true)",
            fixture.TenantA.ToString("D"), fixture.InstallationA.ToString("D"));
        await using NpgsqlCommand command = new(sql, owner, transaction);
        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() =>
            command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, failure.SqlState);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<long> ScalarAsRuntimeScopeAsync(
        NpgsqlConnection owner,
        Guid tenantId,
        Guid installationId,
        string sql)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction, "SET LOCAL ROLE gateway_runtime");
        await ExecuteAsync(owner, transaction,
            "SELECT set_config('app.tenant_id',$1,true),set_config('app.installation_id',$2,true)",
            tenantId.ToString("D"), installationId.ToString("D"));
        await using NpgsqlCommand command = new(sql, owner, transaction);
        long result = Assert.IsType<long>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        return result;
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection owner, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, owner);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        return Assert.IsType<T>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        params object[] values)
    {
        await using NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static string MigrationPath() => Path.Combine(
        FindRepositoryRoot(),
        "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations",
        "0018_connector_workflow_context.sql");

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) &&
               !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    private static string ColumnDefinition(string sql)
    {
        int start = sql.IndexOf('(');
        int end = sql.IndexOf(");", start, StringComparison.Ordinal);
        return sql[(start + 1)..end];
    }

    private sealed record WorkflowDatabaseFixture(
        Guid TenantA,
        Guid TenantB,
        Guid ApplicationA,
        Guid ApplicationB,
        Guid EnvironmentA,
        Guid EnvironmentB,
        Guid InstallationA,
        Guid InstallationB,
        string ConnectorId,
        string WorkflowId,
        string TraceId,
        byte[] PublishedContextSha256);

    private sealed record SchemaSnapshot(
        string[] Columns,
        string[] UniqueIndexes,
        string[] Policies,
        bool RowSecurity,
        bool ForcedRowSecurity);
}

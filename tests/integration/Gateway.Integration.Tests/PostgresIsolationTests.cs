using System.Data;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class PostgresIsolationTests
{
    [Fact]
    public async Task IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;

        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("18.", connection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
        await ApplyMigrationAsync(connection);

        Guid tenantA = Guid.NewGuid();
        Guid tenantB = Guid.NewGuid();
        Guid application = Guid.NewGuid();
        Guid environment = Guid.NewGuid();
        Guid installationA = Guid.NewGuid();
        Guid installationB = Guid.NewGuid();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, TestContext.Current.CancellationToken);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,'A','active',now()),($3,$4,'B','active',now())", tenantA, "ta-" + tenantA.ToString("N"), tenantB, "tb-" + tenantB.ToString("N"));
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,'App','active','1.0.0',now())", application, "app-" + application.ToString("N"));
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,'Test',false)", environment, "t-" + environment.ToString("N")[..20]);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,created_at) VALUES($1,$2,$3,$4,'pending',now()),($5,$6,$3,$4,'pending',now())", installationA, tenantA, application, environment, installationB, tenantB);
        await ExecuteAsync(connection, transaction, "SET LOCAL ROLE gateway_runtime");
        await ExecuteAsync(connection, transaction, "SELECT set_config('app.tenant_id',$1,true)", tenantA.ToString("D"));
        await using NpgsqlCommand visible = new("SELECT id FROM gateway.installation ORDER BY id", connection, transaction);
        await using NpgsqlDataReader reader = await visible.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        List<Guid> ids = [];
        while (await reader.ReadAsync(TestContext.Current.CancellationToken)) ids.Add(reader.GetGuid(0));
        await reader.CloseAsync();
        Assert.Equal([installationA], ids);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using NpgsqlDataSource adminDataSource = NpgsqlDataSource.Create(connectionString);
        string runtimeRole = "gateway_test_" + Guid.NewGuid().ToString("N");
        await using (NpgsqlConnection migrationConnection = await adminDataSource.OpenConnectionAsync(TestContext.Current.CancellationToken))
        {
            Assert.StartsWith("18.", migrationConnection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
            await ApplyMigrationAsync(migrationConnection);
            await using NpgsqlCommand createRole = new($"CREATE ROLE {runtimeRole} LOGIN; GRANT gateway_runtime TO {runtimeRole}", migrationConnection);
            await createRole.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        NpgsqlConnectionStringBuilder runtimeConnection = new(connectionString) { Username = runtimeRole, Password = null };
        await using NpgsqlDataSource runtimeDataSource = NpgsqlDataSource.Create(runtimeConnection.ConnectionString);
        PostgresGatewayRegistry adminRegistry = new(adminDataSource);
        PostgresGatewayRegistry registry = new(runtimeDataSource);
        TestClock clock = new(DateTimeOffset.UtcNow);
        byte[] activationKey = SHA256.HashData("postgres-integration-activation"u8);
        EnrollmentSecurityOptions security = new() { ActivationHmacKey = activationKey };
        GatewayProvisioningService provisioningService = new(adminRegistry, clock, security);
        InstallationEnrollmentService enrollmentService = new(registry, new InMemoryEnrollmentChallengeStore(), clock, security);
        Guid suffix = Guid.NewGuid();
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        ProvisionedActivation provisioning = await provisioningService.CreateInstallationAsync(
            new(tenantId, "tenant-" + suffix.ToString("N"), "Tenant", TenantStatus.Active, clock.UtcNow),
            new(applicationId, "app-" + suffix.ToString("N"), "Application", ApplicationStatus.Active, "1.0.0", "2.0.0", clock.UtcNow),
            new(environmentId, "e-" + suffix.ToString("N")[..20], "Test", false), installationId, "integration-test", TestContext.Current.CancellationToken);

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new("CN=postgres-integration", key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        EnrollmentChallengeResponse challenge = await enrollmentService.CreateChallengeAsync(new(provisioning.ActivationCodeId, Convert.ToBase64String(spki)), TestContext.Current.CancellationToken);
        EnrollmentChallenge proofChallenge = new(challenge.ChallengeId, provisioning.ActivationCodeId, Base64Url.Decode(challenge.Challenge), spki, challenge.ExpiresAt);
        byte[] proofSignature = key.SignData(InstallationEnrollmentService.BuildActivationProof(proofChallenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        EnrollmentResult result = await enrollmentService.ActivateAsync(new(challenge.ChallengeId, provisioning.ActivationCode, Convert.ToBase64String(certificate.RawData), Base64Url.Encode(proofSignature), "1.5.0"), TestContext.Current.CancellationToken);
        Assert.Equal(tenantId, result.TenantId);

        RegisteredInstallationIdentity identity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(certificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Credential lookup failed.");
        Assert.Equal(tenantId, identity.TenantId);

        clock.UtcNow = clock.UtcNow.AddDays(61);
        using ECDsa replacementKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest replacementRequest = new("CN=postgres-integration-renewed", replacementKey, HashAlgorithmName.SHA256);
        replacementRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        replacementRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 replacementCertificate = replacementRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] replacementSpki = replacementKey.ExportSubjectPublicKeyInfo();
        byte[] renewalProof = InstallationEnrollmentService.BuildRenewalProof(installationId, identity.CredentialId, SHA256.HashData(replacementSpki));
        byte[] renewalSignature = replacementKey.SignData(renewalProof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await enrollmentService.RenewAsync(identity, new(Convert.ToBase64String(replacementCertificate.RawData), Base64Url.Encode(renewalSignature)), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity replacementIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(replacementCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Replacement credential lookup failed.");
        Assert.Equal(CredentialStatus.Active, replacementIdentity.CredentialStatus);
        RegisteredInstallationIdentity overlapIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(certificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Overlap credential lookup failed.");
        Assert.Equal(CredentialStatus.Overlap, overlapIdentity.CredentialStatus);
        await adminRegistry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, "vendor", "send", true, clock.UtcNow), TestContext.Current.CancellationToken);
        Assert.True(await registry.IsGrantedAsync(installationId, tenantId, "vendor", "send", clock.UtcNow, TestContext.Current.CancellationToken));
        byte[] nonceHash = SHA256.HashData("nonce"u8);
        Assert.True(await registry.TryStoreNonceAsync(installationId, nonceHash, clock.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.False(await registry.TryStoreNonceAsync(installationId, nonceHash, clock.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.True(await adminRegistry.RevokeInstallationAsync(installationId, "integration test", clock.UtcNow, TestContext.Current.CancellationToken));
        RegisteredInstallationIdentity revoked = await registry.FindIdentityByCertificateAsync(SHA256.HashData(replacementCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Revoked credential lookup failed.");
        Assert.Equal(InstallationStatus.Revoked, revoked.InstallationStatus);
        Assert.Equal(CredentialStatus.Revoked, revoked.CredentialStatus);
    }

    [Fact]
    public void IT_DAT_Migration_forces_RLS_and_contains_no_secret_value_columns()
    {
        string sql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0001_gateway_m2.sql"));
        Assert.Contains("ALTER TABLE gateway.installation FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("ALTER TABLE gateway.installation_credential FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("ALTER TABLE gateway.activation_code FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("metadata_redacted jsonb", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("secret_value", sql, StringComparison.OrdinalIgnoreCase);
        string connectorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0002_connector_configuration_m4.sql"));
        Assert.Contains("connector_version_immutable", connectorSql, StringComparison.Ordinal);
        Assert.Contains("state IN ('draft','validated','published','superseded','retired')", connectorSql, StringComparison.Ordinal);
        Assert.DoesNotContain("secret_value", connectorSql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);
        await using (NpgsqlConnection connection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken)) await ApplyMigrationAsync(connection);
        PostgresConnectorConfigurationStore store = new(dataSource);
        PostgresGatewayRegistry registry = new(dataSource);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock);
        Guid suffix = Guid.NewGuid();
        string connectorId = "postgres-" + suffix.ToString("N");
        Guid environmentId = Guid.NewGuid();
        await registry.AddEnvironmentAsync(new(environmentId, "m4-" + suffix.ToString("N")[..20], "M4", false), TestContext.Current.CancellationToken);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));

        async Task<ConnectorVersionResource> ImportPublishAsync(string version, long revision)
        {
            string candidate = source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal).Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal);
            using JsonDocument definition = JsonDocument.Parse(candidate);
            ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, version, imported.RowVersion, "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
            return await admin.PublishAsync(connectorId, version, validated.RowVersion, revision, "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
        }

        ConnectorVersionResource v1 = await ImportPublishAsync("1.0.0", 0);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://key", ["sample-vendor-client-certificate"] = "synthetic://cert" }),
            "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
        GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, "submit", environmentId, TestContext.Current.CancellationToken);
        Assert.Equal("1.0.0", operation.Version);

        ConnectorVersionResource v2 = await ImportPublishAsync("2.0.0", 1);
        ConnectorVersionResource rolledBack = await admin.RollbackAsync(connectorId, new("1.0.0", v2.RowVersion), "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(v1.ChecksumSha256, rolledBack.ChecksumSha256);
        Assert.Equal("1.0.0", (await catalog.GetRequiredAsync(connectorId, "submit", environmentId, TestContext.Current.CancellationToken)).Version);

        await using NpgsqlConnection tamperConnection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand tamper = new("UPDATE gateway.connector_version SET configuration_json='{}'::jsonb WHERE id=$1", tamperConnection);
        tamper.Parameters.AddWithValue((await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken))!.Id);
        PostgresException immutable = await Assert.ThrowsAsync<PostgresException>(() => tamper.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        Assert.Equal("23000", immutable.SqlState);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task ApplyMigrationAsync(NpgsqlConnection connection)
    {
        string directory = Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations");
        foreach (string path in Directory.GetFiles(directory, "*.sql").Order(StringComparer.Ordinal))
        {
            string migration = await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken);
            await using NpgsqlCommand command = new(migration, connection);
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }


    private sealed class TestClock(DateTimeOffset value) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = value;
    }
}

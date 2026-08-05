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
            _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
                new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
                new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://key", ["sample-vendor-client-certificate"] = "synthetic://cert" },
                ConnectorVersion: version), "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
            return await admin.PublishAsync(connectorId, version, validated.RowVersion, revision, "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
        }

        ConnectorVersionResource v1 = await ImportPublishAsync("1.0.0", 0);
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

    [Fact]
    public async Task M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using (NpgsqlConnection migration = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken)) await ApplyMigrationAsync(migration);
        PostgresConnectorConfigurationStore store = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        string connectorId = "atomic-" + Guid.NewGuid().ToString("N");
        await registry.AddEnvironmentAsync(new(environmentId, "a-" + Guid.NewGuid().ToString("N")[..20], "Atomic", false), TestContext.Current.CancellationToken);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, imported.Version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://approved.example.test/" },
            new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://canary", ["sample-vendor-client-certificate"] = "synthetic://certificate" }), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
        byte[] approvedDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        _ = await security.RequestApprovalAsync(stored, approvedDigest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await security.ApproveAsync(stored.Id, stored.ChecksumSha256, approvedDigest, stored.CreatedBy, approver.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(1), TestContext.Current.CancellationToken);

        await using NpgsqlConnection blocker = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlTransaction blockerTransaction = await blocker.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await using (NpgsqlCommand lockVersion = new("SELECT id FROM gateway.connector_version WHERE id=$1 FOR UPDATE", blocker, blockerTransaction))
        {
            lockVersion.Parameters.AddWithValue(stored.Id);
            _ = await lockVersion.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        }
        Task<long> mutation = admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://controlled-attacker.example.test/" },
            new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://canary", ["sample-vendor-client-certificate"] = "synthetic://certificate" }, 1), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        await WaitForVersionLockWaitAsync(adminPool.Value, TestContext.Current.CancellationToken);
        Task<ConnectorVersionRecord> publication = store.PublishApprovedAsync(stored.Id, approvedDigest, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(2), TestContext.Current.CancellationToken);
        await blockerTransaction.CommitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, await mutation);
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => publication);
        Assert.True(denied.Code is "BGW-ADMIN-APPROVAL-STALE" or "BGW-ADMIN-APPROVAL-REQUIRED" or "BGW-CONCURRENCY-CONFLICT", denied.Code);
        ConnectorVersionRecord after = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
        Assert.Equal(ConnectorVersionState.Validated, after.State);
        await using NpgsqlConnection auditConnection = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand audit = new("SELECT count(*) FROM gateway.audit_event WHERE action='connector.publish' AND target_id=$1", auditConnection);
        audit.Parameters.AddWithValue(connectorId + "/" + imported.Version);
        Assert.Equal(0L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));
        byte[] currentDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        _ = await security.RequestApprovalAsync(after, currentDigest, editor.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(3), TestContext.Current.CancellationToken);
        _ = await security.ApproveAsync(after.Id, after.ChecksumSha256, currentDigest, after.CreatedBy, approver.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(4), TestContext.Current.CancellationToken);
        ConnectorVersionRecord published = await store.PublishApprovedAsync(after.Id, currentDigest, after.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, published.State);
        Assert.Equal(1L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_IT_DAT_Fault_injection_rolls_back_admin_state_and_audit_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using (NpgsqlConnection migration = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken)) await ApplyMigrationAsync(migration);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        PostgresGatewayRegistry setupRegistry = new(adminPool.Value);
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid();
        await setupRegistry.AddTenantAsync(new(tenantId, "fault-" + tenantId.ToString("N"), "Fault tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddApplicationAsync(new(applicationId, "fault-" + applicationId.ToString("N"), "Fault app", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddEnvironmentAsync(new(environmentId, "f-" + environmentId.ToString("N")[..20], "Fault environment", false), TestContext.Current.CancellationToken);

        foreach (string point in new[] { "installation.create.after-installation", "installation.create.after-activation" })
        {
            Guid installationId = Guid.NewGuid(); Guid activationId = Guid.NewGuid(); Guid correlationId = Guid.NewGuid();
            PostgresGatewayRegistry faulted = new(adminPool.Value, new ThrowingFaultInjector(point));
            await Assert.ThrowsAsync<InjectedFailureException>(() => faulted.AddInstallationActivationWithAuditAsync(
                new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, now),
                new(activationId, installationId, SHA256.HashData(Guid.NewGuid().ToByteArray()), now.AddHours(1), now, "fault-test"),
                Audit(tenantId, correlationId, "installation.create", installationId.ToString("D"), now), TestContext.Current.CancellationToken));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.installation WHERE id=$1", installationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.activation_code WHERE id=$1", activationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlationId));
        }

        Guid activeInstallation = Guid.NewGuid();
        await setupRegistry.AddInstallationAsync(new(activeInstallation, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, now), TestContext.Current.CancellationToken);
        Guid grantId = Guid.NewGuid(); Guid grantCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedGrant = new(adminPool.Value, new ThrowingFaultInjector("grant.create.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedGrant.AddGrantWithAuditAsync(new(grantId, activeInstallation, tenantId, "fault-connector", "send", true, now), Audit(tenantId, grantCorrelation, "grant.create", grantId.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.installation_connector_grant WHERE id=$1", grantId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", grantCorrelation));

        Guid revokeCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedRevocation = new(adminPool.Value, new ThrowingFaultInjector("installation.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRevocation.RevokeInstallationWithAuditAsync(activeInstallation, "fault test", now, Audit(tenantId, revokeCorrelation, "installation.revoke", activeInstallation.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal("pending", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.installation WHERE id=$1", activeInstallation));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", revokeCorrelation));

        PostgresAdminSecurityStore security = new(adminPool);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord bootstrapPrincipal = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "bootstrap-" + Guid.NewGuid().ToString("N"), "Bootstrap", null), TestContext.Current.CancellationToken);
        Guid bootstrapCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedBootstrap = new(adminPool, new ThrowingFaultInjector("admin.bootstrap.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBootstrap.TryBootstrapSecurityAdministratorAsync(bootstrapPrincipal.Id, bootstrapCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_bootstrap WHERE principal_id=$1", bootstrapPrincipal.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", bootstrapPrincipal.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bootstrapCorrelation));

        Guid roleCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRole = new(adminPool, new ThrowingFaultInjector("admin.role.assign.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRole.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, roleCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", editor.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleCorrelation));
        AdminRoleAssignmentRecord assignment = await security.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid roleRevokeCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRoleRevoke = new(adminPool, new ThrowingFaultInjector("admin.role.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRoleRevoke.RevokeRoleAsync(assignment.Id, approver.Id, roleRevokeCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(1L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE id=$1", assignment.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleRevokeCorrelation));

        ConnectorDefinitionValidator validator = new();
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        string connectorId = "fault-" + Guid.NewGuid().ToString("N");
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ValidatedConnectorDefinition canonical = validator.ValidateRequired(definition.RootElement);
        PostgresConnectorConfigurationStore connectorStore = new(adminPool.Value);
        ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), editor.Id.ToString("D"), now, 0), TestContext.Current.CancellationToken);
        ConnectorVersionRecord validated = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, now, TestContext.Current.CancellationToken);
        Guid approvalCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedApproval = new(adminPool, new ThrowingFaultInjector("connector.approval.request.after-state"));
        byte[] provisionalDigest = SHA256.HashData("provisional"u8);
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApproval.RequestApprovalAsync(validated, provisionalDigest, editor.Id, approvalCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_approval WHERE connector_version_id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approvalCorrelation));

        Guid bindingCorrelation = Guid.NewGuid();
        Dictionary<string, Uri> endpoints = new() { ["sample-vendor-endpoint"] = new("https://vendor.example.test/") };
        Dictionary<string, string> secrets = new() { ["sample-vendor-api-key"] = "synthetic://api-key" };
        Dictionary<string, string> certificates = new() { ["sample-vendor-client-certificate"] = "synthetic://certificate" };
        ConnectorBindingSet binding = new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints, secrets, certificates, 0,
            ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints, secrets, certificates), ConnectorBindingState.Draft, now, editor.Id.ToString("D"));
        PostgresConnectorConfigurationStore faultedBinding = new(adminPool.Value, new ThrowingFaultInjector("connector.binding.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBinding.PutBindingsAsync(binding, null, bindingCorrelation, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_binding_bundle_version WHERE id=$1", binding.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bindingCorrelation));

        ConnectorBindingSet storedBinding = await connectorStore.PutBindingsAsync(binding with { Id = Guid.NewGuid() }, null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] digest = await connectorStore.GetBindingBundleDigestAsync(validated.Id, TestContext.Current.CancellationToken);
        _ = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid approveCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedApprove = new(adminPool, new ThrowingFaultInjector("connector.approval.approve.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApprove.ApproveAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, approveCorrelation, now.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approveCorrelation));
        _ = await security.ApproveAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, Guid.NewGuid(), now.AddSeconds(2), TestContext.Current.CancellationToken);
        _ = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now.AddSeconds(3), TestContext.Current.CancellationToken);
        Guid rejectCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedReject = new(adminPool, new ThrowingFaultInjector("connector.approval.reject.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedReject.RejectAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, "fault", rejectCorrelation, now.AddSeconds(4), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rejectCorrelation));
        _ = await security.ApproveAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, Guid.NewGuid(), now.AddSeconds(5), TestContext.Current.CancellationToken);

        Guid retireCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRetire = new(adminPool.Value, new ThrowingFaultInjector("connector.retire.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRetire.RetireAsync(validated.Id, validated.RowVersion, approver.Id.ToString("D"), retireCorrelation, now.AddSeconds(6), TestContext.Current.CancellationToken));
        Assert.Equal("validated", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", retireCorrelation));
        Guid publishCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedPublish = new(adminPool.Value, new ThrowingFaultInjector("connector.publish.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedPublish.PublishApprovedAsync(validated.Id, digest, validated.RowVersion, 0, approver.Id.ToString("D"), publishCorrelation, now.AddSeconds(7), TestContext.Current.CancellationToken));
        Assert.Equal("validated", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", publishCorrelation));
        Assert.Equal(ConnectorBindingState.Draft, storedBinding.State);

        ConnectorVersionRecord publishedV1 = await connectorStore.PublishApprovedAsync(validated.Id, digest, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), now.AddSeconds(8), TestContext.Current.CancellationToken);
        using JsonDocument definitionV2 = JsonDocument.Parse(definition.RootElement.GetRawText().Replace("\"version\": \"1.0.0\"", "\"version\": \"2.0.0\"", StringComparison.Ordinal));
        ValidatedConnectorDefinition canonicalV2 = validator.ValidateRequired(definitionV2.RootElement);
        ConnectorVersionRecord draftV2 = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonicalV2.Version, canonicalV2.SchemaVersion, ConnectorVersionState.Draft, canonicalV2.CanonicalJson, Convert.FromHexString(canonicalV2.ChecksumSha256), editor.Id.ToString("D"), now.AddSeconds(9), 0), TestContext.Current.CancellationToken);
        ConnectorVersionRecord validatedV2 = await connectorStore.MarkValidatedAsync(draftV2.Id, draftV2.RowVersion, now.AddSeconds(10), TestContext.Current.CancellationToken);
        string bindingV2Checksum = ConnectorBindingDigests.Revision(validatedV2.Id, environmentId, endpoints, secrets, certificates);
        _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), validatedV2.ConnectorId, validatedV2.Id, environmentId, endpoints, secrets, certificates, 0, bindingV2Checksum, ConnectorBindingState.Draft, now.AddSeconds(11), editor.Id.ToString("D")), null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] digestV2 = await connectorStore.GetBindingBundleDigestAsync(validatedV2.Id, TestContext.Current.CancellationToken);
        _ = await security.RequestApprovalAsync(validatedV2, digestV2, editor.Id, Guid.NewGuid(), now.AddSeconds(12), TestContext.Current.CancellationToken);
        _ = await security.ApproveAsync(validatedV2.Id, validatedV2.ChecksumSha256, digestV2, validatedV2.CreatedBy, approver.Id, Guid.NewGuid(), now.AddSeconds(13), TestContext.Current.CancellationToken);
        ConnectorVersionRecord publishedV2 = await connectorStore.PublishApprovedAsync(validatedV2.Id, digestV2, validatedV2.RowVersion, 1, approver.Id.ToString("D"), Guid.NewGuid(), now.AddSeconds(14), TestContext.Current.CancellationToken);
        Guid rollbackCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRollback = new(adminPool.Value, new ThrowingFaultInjector("connector.rollback.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRollback.RollbackAsync(connectorId, publishedV1.Version, publishedV2.RowVersion, approver.Id.ToString("D"), rollbackCorrelation, now.AddSeconds(15), TestContext.Current.CancellationToken));
        Assert.Equal("superseded", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV1.Id));
        Assert.Equal("published", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV2.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rollbackCorrelation));
    }

    [Fact]
    public async Task M5_IT_DAT_Postgres_admin_sessions_are_hashed_expiring_and_revoked_on_privilege_change_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using (NpgsqlConnection migration = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken)) await ApplyMigrationAsync(migration);
        PostgresAdminSecurityStore security = new(adminPool);
        PostgresAdminSessionStore sessions = new(adminPool, security);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminExternalIdentity identity = new("https://session.example.invalid", "session-" + Guid.NewGuid().ToString("N"), "Session test", null);

        (string handle, AdminSessionRecord created) = await sessions.CreateAsync(identity, now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        string storedDigest = await TextScalarAsync(adminPool.Value, "SELECT encode(handle_sha256,'hex') FROM gateway.admin_session WHERE id=$1", created.Id);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(handle))), storedDigest, ignoreCase: true);
        Assert.DoesNotContain(handle, storedDigest, StringComparison.OrdinalIgnoreCase);
        AdminSessionRecord touched = Assert.IsType<AdminSessionRecord>(await sessions.ValidateAsync(handle, now.AddMinutes(10), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        Assert.Equal(now.AddMinutes(30), touched.IdleExpiresAt);

        _ = await security.AssignRoleAsync(created.Principal.Id, AdminRole.Viewer, null, created.Principal.Id, Guid.NewGuid(), now.AddMinutes(11), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(handle, now.AddMinutes(12), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));

        (string idleHandle, AdminSessionRecord idle) = await sessions.CreateAsync(identity, now, TimeSpan.FromHours(8), TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(idleHandle, idle.IdleExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        (string absoluteHandle, AdminSessionRecord absolute) = await sessions.CreateAsync(identity, now, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        Assert.Equal(absolute.AbsoluteExpiresAt, absolute.IdleExpiresAt);
        Assert.Null(await sessions.ValidateAsync(absoluteHandle, absolute.AbsoluteExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
    }

    private static async Task WaitForVersionLockWaitAsync(NpgsqlDataSource dataSource, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 50; attempt++)
        {
            await using NpgsqlConnection observation = await dataSource.OpenConnectionAsync(cancellationToken);
            await using NpgsqlCommand command = new("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT state FROM gateway.connector_version%')", observation);
            if (await command.ExecuteScalarAsync(cancellationToken) is true) return;
            await Task.Delay(50, cancellationToken);
        }
        throw new TimeoutException("Binding mutation did not reach the connector-version lock barrier.");
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static GatewayAuditEvent Audit(Guid tenantId, Guid correlationId, string action, string targetId, DateTimeOffset now) =>
        new(Guid.NewGuid(), now, tenantId, "administrator", "fault-test", action, "test", targetId, correlationId, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());

    private static async Task<long> ScalarAsync(NpgsqlDataSource dataSource, string sql, object value)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new(sql, connection); command.Parameters.AddWithValue(value);
        return Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string> TextScalarAsync(NpgsqlDataSource dataSource, string sql, object value)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new(sql, connection); command.Parameters.AddWithValue(value);
        return (string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
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
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }


    private sealed class TestClock(DateTimeOffset value) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = value;
    }

    private sealed class ThrowingFaultInjector(string point) : IAdminTransactionFaultInjector
    {
        public void Check(string boundary)
        {
            if (string.Equals(boundary, point, StringComparison.Ordinal)) throw new InjectedFailureException(boundary);
        }
    }

    private sealed class InjectedFailureException(string boundary) : Exception(boundary);
}

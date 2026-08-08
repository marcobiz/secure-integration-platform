using System.Data;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class PostgresIsolationTests
{
    [Fact]
    public async Task M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource pool = new(connectionString);
        PostgresGatewayRegistry registry = new(pool.Value);
        DateTimeOffset now = DateTimeOffset.UtcNow; Guid tenantId = Guid.NewGuid();

        await registry.AddTenantWithAuditAsync(new(tenantId, "rls-" + tenantId.ToString("N"), "Created", TenantStatus.Active, now), Audit(tenantId, Guid.NewGuid(), "tenant.create", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        TenantRecord updated = await registry.UpdateTenantWithAuditAsync(tenantId, "Updated", 1, Audit(tenantId, Guid.NewGuid(), "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        TenantRecord disabled = await registry.DisableTenantWithAuditAsync(tenantId, updated.RowVersion, Audit(tenantId, Guid.NewGuid(), "tenant.disable", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        Assert.Equal(3, disabled.RowVersion); Assert.Equal(TenantStatus.Suspended, disabled.Status);
        PostgresAdminDirectoryStore directory = new(pool);
        Assert.Equal(3, (await directory.ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken)).Total);

        await using (NpgsqlConnection connection = await pool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken))
        {
            await using NpgsqlCommand role = new("SELECT r.rolsuper,r.rolbypassrls,c.relforcerowsecurity FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE r.rolname=current_user AND n.nspname='gateway' AND c.relname='audit_event'", connection);
            await using NpgsqlDataReader reader = await role.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken)); Assert.False(reader.GetBoolean(0)); Assert.False(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2));
        }
        await using (NpgsqlConnection connection = await pool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken))
        await using (NpgsqlCommand context = new("SELECT current_setting('app.tenant_id',true)", connection))
            Assert.True(string.IsNullOrEmpty(await context.ExecuteScalarAsync(TestContext.Current.CancellationToken) as string));

        long expected = disabled.RowVersion;
        TaskCompletionSource barrier = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<TenantRecord> Race(string name)
        {
            await barrier.Task.WaitAsync(TestContext.Current.CancellationToken);
            return await registry.UpdateTenantWithAuditAsync(tenantId, name, expected, Audit(tenantId, Guid.NewGuid(), "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        }
        Task<TenantRecord> first = Race("Concurrent A"); Task<TenantRecord> second = Race("Concurrent B"); barrier.SetResult();
        Exception? firstError = await Record.ExceptionAsync(() => first); Exception? secondError = await Record.ExceptionAsync(() => second);
        Assert.True((firstError is null) ^ (secondError is null));
        GatewayException conflict = Assert.IsType<GatewayException>(firstError ?? secondError); Assert.Equal("BGW-CONCURRENCY-CONFLICT", conflict.Code);
        Assert.Equal(4, (await directory.ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken)).Total);

        Guid applicationId = Guid.NewGuid();
        await registry.AddApplicationWithAuditAsync(new(applicationId, "rls-app-" + applicationId.ToString("N"), "Created", ApplicationStatus.Active, "3.0.0", null, now),
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.create", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        ApplicationRecord application = await registry.UpdateApplicationWithAuditAsync(applicationId, "Updated", "3.1.0", null, 1,
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.update", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        application = await registry.DisableApplicationWithAuditAsync(applicationId, application.RowVersion,
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.disable", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        long applicationExpected = application.RowVersion; TaskCompletionSource applicationBarrier = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<ApplicationRecord> RaceApplication(string name)
        {
            await applicationBarrier.Task.WaitAsync(TestContext.Current.CancellationToken);
            return await registry.UpdateApplicationWithAuditAsync(applicationId, name, "3.2.0", null, applicationExpected,
                new(Guid.NewGuid(), now, null, "administrator", "test", "application.update", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        }
        Task<ApplicationRecord> appFirst = RaceApplication("Concurrent A"); Task<ApplicationRecord> appSecond = RaceApplication("Concurrent B"); applicationBarrier.SetResult();
        Exception? appFirstError = await Record.ExceptionAsync(() => appFirst); Exception? appSecondError = await Record.ExceptionAsync(() => appSecond);
        Assert.True((appFirstError is null) ^ (appSecondError is null)); Assert.Equal("BGW-CONCURRENCY-CONFLICT", Assert.IsType<GatewayException>(appFirstError ?? appSecondError).Code);
        Assert.Equal(4L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.audit_event WHERE target_id=$1 AND action LIKE 'application.%'", applicationId.ToString("D")));
    }

    [Fact]
    public async Task IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL migration/admin connection is not configured; the dedicated PostgreSQL gate must provide it.");

        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("18.", connection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
        await ApplyMigrationAsync();

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
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using NpgsqlDataSource adminDataSource = NpgsqlDataSource.Create(connectionString);
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        string runtimeRole = "gateway_test_" + Guid.NewGuid().ToString("N");
        string runtimePassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        await using (NpgsqlConnection migrationConnection = new(migrationConnectionString))
        {
            await migrationConnection.OpenAsync(TestContext.Current.CancellationToken);
            Assert.StartsWith("18.", migrationConnection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
            await ApplyMigrationAsync(migrationConnection);
            await using NpgsqlCommand createRole = new($"CREATE ROLE {runtimeRole} LOGIN PASSWORD '{runtimePassword}'; GRANT gateway_runtime TO {runtimeRole}", migrationConnection);
            await createRole.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        NpgsqlConnectionStringBuilder runtimeConnection = new(connectionString) { Username = runtimeRole, Password = runtimePassword };
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

        Guid directInstallationId = Guid.NewGuid();
        GatewayAuditEvent directCreateAudit = new(Guid.NewGuid(), clock.UtcNow, tenantId, "administrator", "postgres-test", "installation.create", "installation", directInstallationId.ToString("D"), Guid.NewGuid(), "success", "BGW-INSTALLATION-CREATED", new Dictionary<string, string> { ["installationKind"] = InstallationKind.Direct.ToString() });
        ProvisionedActivation directProvisioning = await provisioningService.CreateAdminInstallationAsync(
            new(directInstallationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, clock.UtcNow, InstallationKind: InstallationKind.Direct, UpdatedAt: clock.UtcNow),
            "postgres-test", directCreateAudit, TestContext.Current.CancellationToken);
        using ECDsa directKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest directCertificateRequest = new("CN=postgres-direct-integration", directKey, HashAlgorithmName.SHA256);
        directCertificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        directCertificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 directCertificate = directCertificateRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] directSpki = directKey.ExportSubjectPublicKeyInfo();
        EnrollmentChallengeResponse directChallenge = await enrollmentService.CreateChallengeAsync(new(directProvisioning.ActivationCodeId, Convert.ToBase64String(directSpki)), TestContext.Current.CancellationToken);
        EnrollmentChallenge directProofChallenge = new(directChallenge.ChallengeId, directProvisioning.ActivationCodeId, Base64Url.Decode(directChallenge.Challenge), directSpki, directChallenge.ExpiresAt);
        byte[] directProof = directKey.SignData(InstallationEnrollmentService.BuildActivationProof(directProofChallenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await enrollmentService.ActivateAsync(new(directChallenge.ChallengeId, directProvisioning.ActivationCode, Convert.ToBase64String(directCertificate.RawData), Base64Url.Encode(directProof), ClientVersion: "1.0.0"), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity directIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(directCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Direct credential lookup failed.");
        Assert.Equal(InstallationKind.Direct, directIdentity.InstallationKind);
        Assert.Equal("1.0.0", directIdentity.ClientVersion);
        Assert.Equal(identity.TenantId, directIdentity.TenantId);
        Assert.Equal(identity.ApplicationId, directIdentity.ApplicationId);
        await adminRegistry.AddGrantAsync(new(Guid.NewGuid(), directInstallationId, tenantId, "vendor", "send", true, clock.UtcNow), TestContext.Current.CancellationToken);
        Assert.True(await registry.IsGrantedAsync(directInstallationId, tenantId, "vendor", "send", clock.UtcNow, TestContext.Current.CancellationToken));
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
        string roleRevocationSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0006_admin_role_revocation_m5.sql"));
        Assert.Contains("GRANT DELETE ON gateway.admin_role_assignment TO gateway_admin", roleRevocationSql, StringComparison.Ordinal);
        Assert.DoesNotContain("gateway_runtime", roleRevocationSql, StringComparison.Ordinal);
        string bindingImmutabilitySql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0007_binding_bundle_immutability_m5.sql"));
        Assert.Contains("GRANT UPDATE (state)", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.Contains("connector binding revisions are immutable", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.Contains("binding activation requires a current four-eyes approval", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.DoesNotContain("GRANT UPDATE ON gateway.connector_binding_bundle_version", bindingImmutabilitySql, StringComparison.Ordinal);
        string locatorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0009_runtime_locator_resolution_m5.sql"));
        Assert.Contains("SECURITY DEFINER", locatorSql, StringComparison.Ordinal);
        Assert.Contains("SET search_path = pg_catalog, gateway", locatorSql, StringComparison.Ordinal);
        Assert.Contains("OWNER TO gateway_locator_owner", locatorSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE CREATE ON SCHEMA gateway FROM gateway_locator_owner", locatorSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE ALL ON gateway.provider_resource_locator FROM PUBLIC, gateway_runtime", locatorSql, StringComparison.Ordinal);
        Assert.DoesNotContain("dynamic SQL", locatorSql, StringComparison.OrdinalIgnoreCase);
        string operationLocatorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0010_operation_scoped_locator_m5.sql"));
        Assert.Contains("p_logical_binding_id", operationLocatorSql, StringComparison.Ordinal);
        Assert.Contains("resource.key = p_logical_binding_id", operationLocatorSql, StringComparison.Ordinal);
        Assert.Contains("operation -> 'authentication'", operationLocatorSql, StringComparison.Ordinal);
        string directInstallationSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0011_direct_installation_m55.sql"));
        Assert.Contains("installation_kind IN ('broker','direct')", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("installation_kind = 'direct' AND broker_version IS NULL", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("CREATE OR REPLACE FUNCTION gateway.resolve_installation_client_metadata", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE ALL ON FUNCTION gateway.resolve_installation_client_metadata(bytea) FROM PUBLIC", directInstallationSql, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP FUNCTION", directInstallationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BYPASSRLS", directInstallationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret_value", directInstallationSql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_runtime_locator_is_exactly_granted_and_not_enumerable_when_configured()
    {
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using NpgsqlConnection owner = new(migrationConnection);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);

        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid(); Guid connectorId = Guid.NewGuid(); Guid versionId = Guid.NewGuid();
        Guid bindingId = Guid.NewGuid(); Guid catalogId = Guid.NewGuid();
        string suffix = Guid.NewGuid().ToString("N"); string slug = "locator-" + suffix;
        string resourceLogicalId = "api-key-" + suffix;
        byte[] catalogChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("catalog-" + suffix));
        byte[] bindingChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("binding-" + suffix));
        byte[] definitionChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("definition-" + suffix));
        Guid requesterId = Guid.NewGuid(); Guid approverId = Guid.NewGuid();
        ProviderResourceBinding resource = new("synthetic", "Synthetic", "synthetic", resourceLogicalId, ProviderResourceType.Secret, "API key", environmentId, slug, "submit", null, 1, null, null, Convert.ToHexString(catalogChecksum));
        string secretJson = JsonSerializer.Serialize(new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-api-key"] = resource });

        await using (NpgsqlTransaction setup = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,$3,'active',now())", tenantId, "t-" + suffix, "Locator tenant");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,$3,'active','3.0.0',now())", applicationId, "a-" + suffix, "Locator app");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,$3,false)", environmentId, "e-" + suffix[..20], "Locator env");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$3,'active',now(),'test')", connectorId, slug, "Locator connector");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_version(id,connector_id,version,schema_version,state,configuration_json,checksum_sha256,created_by,created_at,published_at) VALUES($1,$2,'1.0.0','1.0','published',$3::jsonb,$4,'test',now(),now())", versionId, connectorId, "{\"operations\":[{\"operationId\":\"submit\",\"authentication\":{\"kind\":\"apiKey\",\"secretBinding\":\"sample-vendor-api-key\"}},{\"operationId\":\"other-operation\",\"authentication\":{\"kind\":\"apiKey\",\"secretBinding\":\"other-operation-secret\"}}]}", definitionChecksum);
            await ExecuteAsync(owner, setup, "UPDATE gateway.connector_definition SET active_version_id=$2 WHERE id=$1", connectorId, versionId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.provider_resource_catalog_version(id,provider_id,provider_display_name,provider_type,resource_id,resource_type,display_name,environment_id,connector_scope,operation_scope,status,revision,checksum_sha256,created_at) VALUES($1,'synthetic','Synthetic','synthetic',$2,'secret','API key',$3,$4,'*','active',1,$5,now())", catalogId, resourceLogicalId, environmentId, slug, catalogChecksum);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.provider_resource_locator(provider_resource_catalog_id,provider_reference) VALUES($1,$2)", catalogId, "synthetic://controlled-" + suffix);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_binding_bundle_version(id,connector_id,connector_version_id,environment_id,revision,state,endpoints_json,secret_references_json,certificate_references_json,checksum_sha256,created_at,created_by) VALUES($1,$2,$3,$4,1,'draft','{}'::jsonb,$5::jsonb,'{}'::jsonb,$6,now(),'test')", bindingId, connectorId, versionId, environmentId, secretJson, bindingChecksum);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.admin_principal(id,issuer,subject,display_name,created_at,last_login_at) VALUES($1,'https://locator.invalid',$2,'Requester',now(),now()),($3,'https://locator.invalid',$4,'Approver',now(),now())", requesterId, "requester-" + suffix, approverId, "approver-" + suffix);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_approval(id,connector_version_id,checksum_sha256,binding_digest_sha256,requested_by,approved_by,status,requested_at,approved_at) VALUES($1,$2,$3,$4,$5,$6,'approved',now(),now())", Guid.NewGuid(), versionId, definitionChecksum, bindingChecksum, requesterId, approverId);
            await ExecuteAsync(owner, setup, "UPDATE gateway.connector_binding_bundle_version SET state='active' WHERE id=$1", bindingId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,broker_version,created_at) VALUES($1,$2,$3,$4,'active','3.0.0',now())", installationId, tenantId, applicationId, environmentId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.installation_connector_grant(id,installation_id,tenant_id,connector_id,operation_id,enabled,valid_from) VALUES($1,$2,$3,$4,'submit',true,now()-interval '1 minute')", Guid.NewGuid(), installationId, tenantId, connectorId);
            await setup.CommitAsync(TestContext.Current.CancellationToken);
        }

        await using (NpgsqlTransaction denied = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await ExecuteAsync(owner, denied, "SET LOCAL ROLE gateway_runtime");
            PostgresException direct = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(owner, denied, "SELECT provider_reference FROM gateway.provider_resource_locator"));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, direct.SqlState);
            await denied.RollbackAsync(TestContext.Current.CancellationToken);
        }

        async Task<string?> ResolveAsync(string operation, string logicalBindingId, Guid environment, Guid resourceId, long revision = 1)
        {
            await using NpgsqlTransaction runtime = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await ExecuteAsync(owner, runtime, "SET LOCAL ROLE gateway_runtime");
            await using NpgsqlCommand command = new("SELECT gateway.resolve_published_provider_locator($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", owner, runtime);
            foreach (object value in new object[] { resourceId, slug, operation, logicalBindingId, environment, bindingId, revision, bindingChecksum, installationId, tenantId, applicationId }) command.Parameters.AddWithValue(value);
            object? result = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
            await runtime.RollbackAsync(TestContext.Current.CancellationToken);
            return result is DBNull or null ? null : (string)result;
        }

        Assert.Equal("synthetic://controlled-" + suffix, await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId));
        Assert.Null(await ResolveAsync("other-operation", "sample-vendor-api-key", environmentId, catalogId));
        Assert.Null(await ResolveAsync("submit", "other-operation-secret", environmentId, catalogId));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", Guid.NewGuid(), catalogId));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, Guid.NewGuid()));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId, 2));

        await using (NpgsqlCommand disable = new("UPDATE gateway.provider_resource_catalog_version SET status='disabled' WHERE id=$1", owner))
        {
            disable.Parameters.AddWithValue(catalogId); _ = await disable.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId));
        await ApplyMigrationAsync(owner);
        await using NpgsqlTransaction replay = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, replay, "SET LOCAL ROLE gateway_runtime");
        Assert.Equal(false, await new NpgsqlCommand("SELECT has_table_privilege('gateway_runtime','gateway.provider_resource_locator','SELECT')", owner, replay).ExecuteScalarAsync(TestContext.Current.CancellationToken));
        await replay.RollbackAsync(TestContext.Current.CancellationToken);
        Assert.Equal(false, await new NpgsqlCommand("SELECT has_schema_privilege('gateway_locator_owner','gateway','CREATE')", owner).ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_admin_pagination_has_total_order_and_empty_page_count_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource pool = new(connectionString);
        PostgresGatewayRegistry registry = new(pool.Value);
        PostgresAdminDirectoryStore directory = new(pool);
        DateTimeOffset tiedCreatedAt = DateTimeOffset.UtcNow;
        string prefix = "page-" + Guid.NewGuid().ToString("N");
        Guid foreignTenantId = Guid.NewGuid();
        Guid foreignApplicationId = Guid.NewGuid();
        Guid[] tenantIds = Enumerable.Range(0, 101).Select(_ => Guid.NewGuid()).ToArray();
        Guid[] applicationIds = Enumerable.Range(0, 101).Select(_ => Guid.NewGuid()).ToArray();
        List<Guid> createdTenantIds = [];
        List<Guid> createdApplicationIds = [];
        bool foreignTenantCreated = false;
        bool foreignApplicationCreated = false;
        try
        {
            await registry.AddTenantAsync(new(foreignTenantId, $"{prefix}-z-foreign-tenant", "Foreign tenant", TenantStatus.Active, tiedCreatedAt), TestContext.Current.CancellationToken);
            foreignTenantCreated = true;
            await registry.AddApplicationAsync(new(foreignApplicationId, $"{prefix}-z-foreign-application", "Foreign application", ApplicationStatus.Active, "1.0.0", null, tiedCreatedAt), TestContext.Current.CancellationToken);
            foreignApplicationCreated = true;

            for (int index = 0; index < 101; index++)
            {
                await registry.AddTenantAsync(new(tenantIds[index], $"{prefix}-t-{index:D3}", $"Tenant {index:D3}", TenantStatus.Active, tiedCreatedAt), TestContext.Current.CancellationToken);
                createdTenantIds.Add(tenantIds[index]);
                await registry.AddApplicationAsync(new(applicationIds[index], $"{prefix}-a-{index:D3}", $"Application {index:D3}", ApplicationStatus.Active, "1.0.0", null, tiedCreatedAt), TestContext.Current.CancellationToken);
                createdApplicationIds.Add(applicationIds[index]);
            }

            Assert.Equal(101, createdTenantIds.Count);
            Assert.Equal(101, createdApplicationIds.Count);
            await AssertOwnedPaginationAsync(directory.ListTenantsAsync, record => record.Id, tenantIds, foreignTenantId, TestContext.Current.CancellationToken);
            await AssertOwnedPaginationAsync(directory.ListApplicationsAsync, record => record.Id, applicationIds, foreignApplicationId, TestContext.Current.CancellationToken);

            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=ANY($1)", TestContext.Current.CancellationToken, createdTenantIds.ToArray());
            createdTenantIds.Clear();
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=ANY($1)", TestContext.Current.CancellationToken, createdApplicationIds.ToArray());
            createdApplicationIds.Clear();
            Assert.Equal(1L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.tenant WHERE id=$1", foreignTenantId));
            Assert.Equal(1L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.application WHERE id=$1", foreignApplicationId));
        }
        finally
        {
            try
            {
                if (createdTenantIds.Count > 0)
                    await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=ANY($1)", CancellationToken.None, createdTenantIds.ToArray());
            }
            finally
            {
                try
                {
                    if (createdApplicationIds.Count > 0)
                        await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=ANY($1)", CancellationToken.None, createdApplicationIds.ToArray());
                }
                finally
                {
                    try
                    {
                        if (foreignTenantCreated)
                            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=$1", CancellationToken.None, foreignTenantId);
                    }
                    finally
                    {
                        if (foreignApplicationCreated)
                            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=$1", CancellationToken.None, foreignApplicationId);
                    }
                }
            }
        }
    }

    [Fact]
    public async Task M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        NpgsqlDataSource dataSource = adminPool.Value;
        await ApplyMigrationAsync();
        PostgresConnectorConfigurationStore store = new(dataSource);
        PostgresGatewayRegistry registry = new(dataSource);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://m4-postgres.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://m4-postgres.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        Guid suffix = Guid.NewGuid();
        string connectorId = "postgres-" + suffix.ToString("N");
        Guid environmentId = Guid.NewGuid();
        await registry.AddEnvironmentAsync(new(environmentId, "m4-" + suffix.ToString("N")[..20], "M4", false), TestContext.Current.CancellationToken);
        TestProviderResources resources = await RegisterTestResourcesAsync(store, environmentId, connectorId, clock.UtcNow);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));

        async Task<ConnectorVersionResource> ImportPublishAsync(string version, long revision)
        {
            string candidate = source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal).Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal);
            using JsonDocument definition = JsonDocument.Parse(candidate);
            ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
                new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, null,
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }, version), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, version, TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Imported version missing.");
            byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
            ConnectorApprovalRecord request = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
            _ = await store.ApproveCanonicalAsync(security, request.Id, stored.Id, Convert.ToHexString(digest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken);
            return await admin.PublishAsync(connectorId, version, validated.RowVersion, revision, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
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
    public async Task W1_IT_DAT_PostgreSQL18_OAuth_validation_approval_publication_and_operation_locator_resolution_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(connectionString);
        PostgresConnectorConfigurationStore store = new(adminPool.Value);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        string suffix = Guid.NewGuid().ToString("N");
        string connectorId = "oauth-pg-" + suffix;
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        await registry.AddTenantAsync(new(tenantId, "ow1-t-" + suffix, "OAuth tenant", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "ow1-a-" + suffix, "OAuth application", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "ow1-e-" + suffix[..20], "OAuth environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorId, "invoke", true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        ProviderResourceCatalogRecord registered = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "oauth-secret-" + suffix,
            ProviderResourceType.Secret, "OAuth client secret", environmentId, connectorId, "invoke", "synthetic://oauth-controlled-" + suffix,
            ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        using JsonDocument definition = JsonDocument.Parse($$"""
        {
          "schemaVersion":"1.0","connectorId":"{{connectorId}}","version":"1.0.0","displayName":"OAuth PostgreSQL path",
          "bindings":{"endpoints":[{"name":"protected-api"},{"name":"oauth-authorize"},{"name":"oauth-token"}],"secrets":[{"name":"oauth-client-secret","kind":"opaque"}]},
          "operations":[
            {"operationId":"invoke","endpointBinding":"protected-api","method":"GET","path":"/resource","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"oauthAuthorizationCode","profileId":"postgres.oauth","authorizationEndpointBinding":"oauth-authorize","tokenEndpointBinding":"oauth-token","clientId":"postgres-client","clientAuthMethod":"client_secret_basic","secretBinding":"oauth-client-secret","scopes":["read"],"redirectUri":"https://gateway.example.test/callback","pkcePolicy":"S256_REQUIRED"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://oauth-pg.invalid", "editor-" + suffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://oauth-pg.invalid", "approver-" + suffix, "Approver", null), TestContext.Current.CancellationToken);
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, "1.0.0", imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string>
            {
                ["protected-api"] = "https://api.example.test/",
                ["oauth-authorize"] = "https://identity.example.test/authorize",
                ["oauth-token"] = "https://identity.example.test/token"
            },
            new Dictionary<string, ProviderResourceReference> { ["oauth-client-secret"] = new(registered.ProviderId, registered.ResourceId, registered.ResourceType) }, null, null, "1.0.0"),
            editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("OAuth version missing.");
        ConnectorBindingSet binding = Assert.Single((await store.ListBindingsPageAsync(stored.Id, 0, 10, environmentId, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        Assert.Equal(["oauth-authorize", "oauth-token"], Assert.Single(review.Artifact.Operations).BindingDependencies.AuthorityEndpointBindingIds);
        byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        Assert.Equal(review.DigestSha256, Convert.ToHexString(digest));
        ConnectorApprovalRecord request = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await store.ApproveCanonicalAsync(security, request.Id, stored.Id, review.DigestSha256, stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken);
        _ = await admin.PublishAsync(connectorId, "1.0.0", validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);

        PublishedConnectorAccessContext access = new(installationId, tenantId, applicationId, "invoke");
        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, access, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published OAuth snapshot missing.");
        Assert.Equal("synthetic://oauth-controlled-" + suffix, Assert.Single(snapshot.SecretProviderReferences).Value);
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
            Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "3.0.0", null);
        PublishedOAuthAuthorityResolver resolver = new(store, new NeverReadSecretProvider(), clock);
        OAuthResolvedExecutionContext resolved = await resolver.ResolveAsync(new OAuthAuthorizedInvocation(new GatewayClientPrincipal(identity, Guid.NewGuid()), connectorId, "invoke"),
            new OAuthAuthorityRequest("postgres.oauth"), TestContext.Current.CancellationToken);
        Assert.Equal("postgres.oauth", resolved.ProfileId);
        Assert.Equal(connectorId, resolved.ConnectorId);
    }

    [Fact]
    public async Task M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await ApplyMigrationAsync();
        PostgresConnectorConfigurationStore store = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new DevelopmentConnectorApprovalPolicy());
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        string connectorId = "atomic-" + Guid.NewGuid().ToString("N");
        await registry.AddEnvironmentAsync(new(environmentId, "a-" + Guid.NewGuid().ToString("N")[..20], "Atomic", false), TestContext.Current.CancellationToken);
        TestProviderResources resources = await RegisterTestResourcesAsync(store, environmentId, connectorId, clock.UtcNow);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, imported.Version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://approved.example.test/" },
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, null,
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
        byte[] approvedDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approvalRequest = await security.RequestApprovalAsync(stored, approvedDigest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord previousResource = await store.ResolveProviderResourceAsync(resources.SecretReference, environmentId, connectorId, ["submit"], TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord rotatedResource = await store.RegisterProviderResourceAsync(previousResource with { Id = Guid.NewGuid(), ProviderReference = "synthetic://rotated-api-key", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = clock.UtcNow.AddMilliseconds(1) }, TestContext.Current.CancellationToken);
        GatewayException staleReview = await Assert.ThrowsAsync<GatewayException>(() => store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, Convert.ToHexString(approvedDigest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", staleReview.Code);
        Dictionary<string, ProviderResourceBinding> refreshedSecrets = new() { ["sample-vendor-api-key"] = Binding(rotatedResource) };
        _ = await store.PutBindingsAsync(new(Guid.NewGuid(), stored.ConnectorId, stored.Id, environmentId,
            new Dictionary<string, Uri> { ["sample-vendor-endpoint"] = new("https://approved.example.test/") }, refreshedSecrets,
            new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-client-certificate"] = resources.CertificateBinding }, 0,
            ConnectorBindingDigests.Revision(stored.Id, environmentId, new Dictionary<string, Uri> { ["sample-vendor-endpoint"] = new("https://approved.example.test/") }, refreshedSecrets, new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-client-certificate"] = resources.CertificateBinding }),
            ConnectorBindingState.Draft, clock.UtcNow.AddSeconds(1), editor.Id.ToString("D")), 1, Guid.NewGuid(), TestContext.Current.CancellationToken);
        approvedDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        approvalRequest = await security.RequestApprovalAsync(stored, approvedDigest, editor.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(1), TestContext.Current.CancellationToken);
        _ = await store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, Convert.ToHexString(approvedDigest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(2), TestContext.Current.CancellationToken);

        await using NpgsqlConnection blocker = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlTransaction blockerTransaction = await blocker.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await using (NpgsqlCommand lockVersion = new("SELECT id FROM gateway.connector_version WHERE id=$1 FOR UPDATE", blocker, blockerTransaction))
        {
            lockVersion.Parameters.AddWithValue(stored.Id);
            _ = await lockVersion.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        }
        Task<long> mutation = admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://controlled-attacker.example.test/" },
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, 2,
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        await WaitForVersionLockWaitAsync(adminPool.Value, TestContext.Current.CancellationToken);
        Task<ConnectorVersionRecord> publication = store.PublishApprovedAsync(stored.Id, approvedDigest, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(2), TestContext.Current.CancellationToken);
        await blockerTransaction.CommitAsync(TestContext.Current.CancellationToken);

        long? mutationRevision = null;
        ConnectorVersionRecord? firstPublication = null;
        Exception? mutationFailure = null;
        Exception? publicationFailure = null;
        try { mutationRevision = await mutation; } catch (Exception exception) { mutationFailure = exception; }
        try { firstPublication = await publication; } catch (Exception exception) { publicationFailure = exception; }
        Assert.NotEqual(mutationFailure is null, publicationFailure is null);

        await using NpgsqlConnection auditConnection = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand audit = new("SELECT count(*) FROM gateway.audit_event WHERE action='connector.publish' AND target_id=$1", auditConnection);
        audit.Parameters.AddWithValue(connectorId + "/" + imported.Version);
        ConnectorVersionRecord published;
        string expectedEndpoint;
        if (mutationFailure is null)
        {
            Assert.Equal(3, mutationRevision);
            GatewayException denied = Assert.IsType<GatewayException>(publicationFailure);
            Assert.True(denied.Code is "BGW-ADMIN-APPROVAL-STALE" or "BGW-ADMIN-APPROVAL-REQUIRED" or "BGW-CONCURRENCY-CONFLICT", denied.Code);
            ConnectorVersionRecord after = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
            Assert.Equal(ConnectorVersionState.Validated, after.State);
            Assert.Equal(0L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));
            byte[] currentDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
            ConnectorApprovalRecord currentRequest = await security.RequestApprovalAsync(after, currentDigest, editor.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(3), TestContext.Current.CancellationToken);
            _ = await store.ApproveCanonicalAsync(security, currentRequest.Id, after.Id, Convert.ToHexString(currentDigest), after.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(4), TestContext.Current.CancellationToken);
            published = await store.PublishApprovedAsync(after.Id, currentDigest, after.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(5), TestContext.Current.CancellationToken);
            expectedEndpoint = "https://controlled-attacker.example.test/";
        }
        else
        {
            GatewayException denied = Assert.IsType<GatewayException>(mutationFailure);
            Assert.Equal("BGW-CONCURRENCY-CONFLICT", denied.Code);
            Assert.Null(publicationFailure);
            published = Assert.IsType<ConnectorVersionRecord>(firstPublication);
            expectedEndpoint = "https://approved.example.test/";
        }
        Assert.Equal(ConnectorVersionState.Published, published.State);
        Assert.Equal(1L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));

        AdminPage<ConnectorBindingSet> bindingPage = await store.ListBindingsPageAsync(published.Id, 0, 10, environmentId, TestContext.Current.CancellationToken);
        ConnectorBindingSet activeBinding = Assert.Single(bindingPage.Items, value => value.State == ConnectorBindingState.Active);
        await using NpgsqlConnection tamperConnection = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using (NpgsqlCommand roleCheck = new("SELECT rolsuper FROM pg_roles WHERE rolname=current_user", tamperConnection))
            Assert.False((bool)(await roleCheck.ExecuteScalarAsync(TestContext.Current.CancellationToken))!);

        async Task AssertBindingTamperDeniedAsync(string assignment, object value)
        {
            await using NpgsqlCommand command = new($"UPDATE gateway.connector_binding_bundle_version SET {assignment}=$2 WHERE id=$1", tamperConnection);
            command.Parameters.AddWithValue(activeBinding.Id);
            command.Parameters.AddWithValue(value);
            _ = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        }

        await AssertBindingTamperDeniedAsync("endpoints_json", JsonSerializer.Serialize(new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://tamper.invalid/" }));
        await AssertBindingTamperDeniedAsync("checksum_sha256", RandomNumberGenerator.GetBytes(32));
        await AssertBindingTamperDeniedAsync("connector_id", "tampered-connector");
        await AssertBindingTamperDeniedAsync("environment_id", Guid.NewGuid());
        await AssertBindingTamperDeniedAsync("revision", activeBinding.Revision + 1);
        await AssertBindingTamperDeniedAsync("state", "draft");

        PublishedConnectorSnapshot unchanged = await store.GetPublishedSnapshotAsync(connectorId, environmentId, null, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published snapshot disappeared after a rejected tamper attempt.");
        Assert.Equal(expectedEndpoint, unchanged.Bindings.Endpoints["sample-vendor-endpoint"].AbsoluteUri);
        Assert.Equal(activeBinding.Revision, unchanged.Bindings.Revision);
        Assert.Equal(activeBinding.ChecksumSha256, unchanged.Bindings.ChecksumSha256);
    }

    [Fact]
    public async Task M5_IT_DAT_Fault_injection_rolls_back_admin_state_and_audit_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        await using AdminPostgresDataSource adminPool = new(migrationConnectionString);
        await using AdminPostgresDataSource storePool = new(connectionString);
        await ApplyMigrationAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        PostgresGatewayRegistry setupRegistry = new(storePool.Value);
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid();
        await setupRegistry.AddTenantAsync(new(tenantId, "fault-" + tenantId.ToString("N"), "Fault tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddApplicationAsync(new(applicationId, "fault-" + applicationId.ToString("N"), "Fault app", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddEnvironmentAsync(new(environmentId, "f-" + environmentId.ToString("N")[..20], "Fault environment", false), TestContext.Current.CancellationToken);

        Guid failedTenantId = Guid.NewGuid(); Guid failedTenantCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedTenant = new(storePool.Value, new ThrowingFaultInjector("tenant.create.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedTenant.AddTenantWithAuditAsync(new(failedTenantId, "failed-" + failedTenantId.ToString("N"), "Failed tenant", TenantStatus.Active, now), Audit(failedTenantId, failedTenantCorrelation, "tenant.create", failedTenantId.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.tenant WHERE id=$1", failedTenantId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedTenantCorrelation));

        Guid failedApplicationId = Guid.NewGuid(); Guid failedApplicationCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedApplication = new(storePool.Value, new ThrowingFaultInjector("application.create.after-state"));
        GatewayAuditEvent applicationAudit = new(Guid.NewGuid(), now, null, "administrator", "fault-test", "application.create", "application", failedApplicationId.ToString("D"), failedApplicationCorrelation, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApplication.AddApplicationWithAuditAsync(new(failedApplicationId, "failed-" + failedApplicationId.ToString("N"), "Failed application", ApplicationStatus.Active, "1.0.0", null, now), applicationAudit, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.application WHERE id=$1", failedApplicationId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedApplicationCorrelation));

        foreach (string point in new[] { "tenant.update.after-state", "tenant.disable.after-state" })
        {
            Guid correlation = Guid.NewGuid(); PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
            Task mutation = point.Contains("update", StringComparison.Ordinal)
                ? faulted.UpdateTenantWithAuditAsync(tenantId, "Tampered tenant", 1, Audit(tenantId, correlation, "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken)
                : faulted.DisableTenantWithAuditAsync(tenantId, 1, Audit(tenantId, correlation, "tenant.disable", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<InjectedFailureException>(() => mutation);
            Assert.Equal("Fault tenant", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal("active", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlation));
        }

        foreach (string point in new[] { "application.update.after-state", "application.disable.after-state" })
        {
            Guid correlation = Guid.NewGuid(); PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
            GatewayAuditEvent eventValue = new(Guid.NewGuid(), now, null, "administrator", "fault-test", point.Replace(".after-state", "", StringComparison.Ordinal), "application", applicationId.ToString("D"), correlation, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());
            Task mutation = point.Contains("update", StringComparison.Ordinal)
                ? faulted.UpdateApplicationWithAuditAsync(applicationId, "Tampered app", "9.0.0", null, 1, eventValue, TestContext.Current.CancellationToken)
                : faulted.DisableApplicationWithAuditAsync(applicationId, 1, eventValue, TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<InjectedFailureException>(() => mutation);
            Assert.Equal("Fault app", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.application WHERE id=$1", applicationId));
            Assert.Equal("active", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.application WHERE id=$1", applicationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlation));
        }

        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel(); Guid cancellationCorrelation = Guid.NewGuid();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setupRegistry.UpdateTenantWithAuditAsync(tenantId, "Cancelled tenant", 1, Audit(tenantId, cancellationCorrelation, "tenant.update", tenantId.ToString("D"), now), cancelled.Token));
            Assert.Equal("Fault tenant", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", cancellationCorrelation));
        }

        foreach (string point in new[] { "installation.create.after-installation", "installation.create.after-activation" })
        {
            Guid installationId = Guid.NewGuid(); Guid activationId = Guid.NewGuid(); Guid correlationId = Guid.NewGuid();
            PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
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
        PostgresGatewayRegistry faultedGrant = new(storePool.Value, new ThrowingFaultInjector("grant.create.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedGrant.AddGrantWithAuditAsync(new(grantId, activeInstallation, tenantId, "fault-connector", "send", true, now), Audit(tenantId, grantCorrelation, "grant.create", grantId.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.installation_connector_grant WHERE id=$1", grantId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", grantCorrelation));

        Guid revokeCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedRevocation = new(storePool.Value, new ThrowingFaultInjector("installation.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRevocation.RevokeInstallationWithAuditAsync(activeInstallation, "fault test", now, Audit(tenantId, revokeCorrelation, "installation.revoke", activeInstallation.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal("pending", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.installation WHERE id=$1", activeInstallation));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", revokeCorrelation));

        PostgresAdminSecurityStore security = new(storePool);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord bootstrapPrincipal = await security.EnsurePrincipalAsync(new("https://fault.example.invalid", "bootstrap-" + Guid.NewGuid().ToString("N"), "Bootstrap", null), TestContext.Current.CancellationToken);
        Guid bootstrapCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedBootstrap = new(storePool, new ThrowingFaultInjector("admin.bootstrap.after-state"));
        await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_bootstrap", TestContext.Current.CancellationToken);
        try
        {
            await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBootstrap.TryBootstrapSecurityAdministratorAsync(bootstrapPrincipal.Id, bootstrapCorrelation, now, TestContext.Current.CancellationToken));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_bootstrap WHERE principal_id=$1", bootstrapPrincipal.Id));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", bootstrapPrincipal.Id));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bootstrapCorrelation));
        }
        finally
        {
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_role_assignment WHERE principal_id=$1", CancellationToken.None, bootstrapPrincipal.Id);
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_bootstrap WHERE principal_id=$1", CancellationToken.None, bootstrapPrincipal.Id);
        }

        Guid roleCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRole = new(storePool, new ThrowingFaultInjector("admin.role.assign.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRole.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, roleCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", editor.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleCorrelation));
        AdminRoleAssignmentRecord assignment = await security.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid roleRevokeCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRoleRevoke = new(storePool, new ThrowingFaultInjector("admin.role.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRoleRevoke.RevokeRoleAsync(assignment.Id, approver.Id, roleRevokeCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(1L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE id=$1", assignment.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleRevokeCorrelation));

        ConnectorDefinitionValidator validator = new();
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        string connectorId = "fault-" + Guid.NewGuid().ToString("N");
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ValidatedConnectorDefinition canonical = validator.ValidateRequired(definition.RootElement);
        PostgresConnectorConfigurationStore connectorStore = new(storePool.Value);
        Guid failedImportCorrelation = Guid.NewGuid(); Guid failedDraftId = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedImport = new(storePool.Value, new ThrowingFaultInjector("connector.import.after-state"));
        GatewayAuditEvent importAudit = new(Guid.NewGuid(), now, null, "administrator", editor.Id.ToString("D"), "connector.import", "connectorVersion", connectorId + "/" + canonical.Version, failedImportCorrelation, "success", "BGW-CONNECTOR-IMPORTED", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedImport.CreateDraftWithAuditAsync(new(failedDraftId, Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), editor.Id.ToString("D"), now, 0), importAudit, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_version WHERE id=$1", failedDraftId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedImportCorrelation));
        ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), editor.Id.ToString("D"), now, 0), TestContext.Current.CancellationToken);
        Guid failedValidationCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedValidation = new(storePool.Value, new ThrowingFaultInjector("connector.validate.after-state"));
        GatewayAuditEvent validationAudit = new(Guid.NewGuid(), now, null, "administrator", editor.Id.ToString("D"), "connector.validate", "connectorVersion", connectorId + "/" + canonical.Version, failedValidationCorrelation, "success", "BGW-CONNECTOR-VALIDATED", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedValidation.MarkValidatedWithAuditAsync(draft.Id, draft.RowVersion, now, validationAudit, TestContext.Current.CancellationToken));
        Assert.Equal("draft", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", draft.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedValidationCorrelation));
        ConnectorVersionRecord validated = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, now, TestContext.Current.CancellationToken);
        Guid approvalCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedApproval = new(storePool, new ThrowingFaultInjector("connector.approval.request.after-state"));
        byte[] provisionalDigest = SHA256.HashData("provisional"u8);
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApproval.RequestApprovalAsync(validated, provisionalDigest, editor.Id, approvalCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_approval WHERE connector_version_id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approvalCorrelation));

        Guid bindingCorrelation = Guid.NewGuid();
        Dictionary<string, Uri> endpoints = new() { ["sample-vendor-endpoint"] = new("https://vendor.example.test/") };
        TestProviderResources resources = await RegisterTestResourcesAsync(connectorStore, environmentId, connectorId, now);
        Dictionary<string, ProviderResourceBinding> secrets = new() { ["sample-vendor-api-key"] = resources.SecretBinding };
        Dictionary<string, ProviderResourceBinding> certificates = new() { ["sample-vendor-client-certificate"] = resources.CertificateBinding };
        ConnectorBindingSet binding = new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints, secrets, certificates, 0,
            ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints, secrets, certificates), ConnectorBindingState.Draft, now, editor.Id.ToString("D"));
        PostgresConnectorConfigurationStore faultedBinding = new(storePool.Value, new ThrowingFaultInjector("connector.binding.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBinding.PutBindingsAsync(binding, null, bindingCorrelation, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_binding_bundle_version WHERE id=$1", binding.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bindingCorrelation));

        ConnectorBindingSet storedBinding = await connectorStore.PutBindingsAsync(binding with { Id = Guid.NewGuid() }, null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] digest = await connectorStore.GetBindingBundleDigestAsync(validated.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord firstApprovalRequest = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid approveCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedApprove = new(storePool.Value, new ThrowingFaultInjector("connector.approval.approve.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApprove.ApproveCanonicalAsync(security, firstApprovalRequest.Id, validated.Id, Convert.ToHexString(digest), validated.CreatedBy, approver.Id, null, approveCorrelation, now.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approveCorrelation));
        _ = await connectorStore.ApproveCanonicalAsync(security, firstApprovalRequest.Id, validated.Id, Convert.ToHexString(digest), validated.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(2), TestContext.Current.CancellationToken);
        ConnectorApprovalRecord secondApprovalRequest = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now.AddSeconds(3), TestContext.Current.CancellationToken);
        Guid rejectCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedReject = new(storePool, new ThrowingFaultInjector("connector.approval.reject.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedReject.RejectAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, "fault", rejectCorrelation, now.AddSeconds(4), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rejectCorrelation));
        _ = await security.ApproveAsync(secondApprovalRequest.Id, validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(5), TestContext.Current.CancellationToken);

        Guid retireCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRetire = new(storePool.Value, new ThrowingFaultInjector("connector.retire.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRetire.RetireAsync(validated.Id, validated.RowVersion, approver.Id.ToString("D"), retireCorrelation, now.AddSeconds(6), TestContext.Current.CancellationToken));
        Assert.Equal("validated", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", retireCorrelation));
        Guid publishCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedPublish = new(storePool.Value, new ThrowingFaultInjector("connector.publish.after-state"));
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
        ConnectorApprovalRecord approvalRequestV2 = await security.RequestApprovalAsync(validatedV2, digestV2, editor.Id, Guid.NewGuid(), now.AddSeconds(12), TestContext.Current.CancellationToken);
        _ = await security.ApproveAsync(approvalRequestV2.Id, validatedV2.Id, validatedV2.ChecksumSha256, digestV2, validatedV2.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(13), TestContext.Current.CancellationToken);
        ConnectorVersionRecord publishedV2 = await connectorStore.PublishApprovedAsync(validatedV2.Id, digestV2, validatedV2.RowVersion, 1, approver.Id.ToString("D"), Guid.NewGuid(), now.AddSeconds(14), TestContext.Current.CancellationToken);
        Guid rollbackCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRollback = new(storePool.Value, new ThrowingFaultInjector("connector.rollback.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRollback.RollbackAsync(connectorId, publishedV1.Version, publishedV2.RowVersion, approver.Id.ToString("D"), rollbackCorrelation, now.AddSeconds(15), TestContext.Current.CancellationToken));
        Assert.Equal("superseded", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV1.Id));
        Assert.Equal("published", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV2.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rollbackCorrelation));
    }

    [Fact]
    public async Task M5_IT_DAT_Postgres_admin_sessions_are_hashed_expiring_and_revoked_on_privilege_change_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await ApplyMigrationAsync();
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

    private static async Task<TestProviderResources> RegisterTestResourcesAsync(PostgresConnectorConfigurationStore store, Guid environmentId, string connectorId, DateTimeOffset now)
    {
        string suffix = environmentId.ToString("N");
        string secretId = "api-" + suffix;
        string certificateId = "cert-" + suffix;
        CertificatePublicMetadata metadata = new(new string('A', 64), "CN=test-client", "CN=test-ca", now.AddDays(-1), now.AddDays(90), "ECDSA", 256, "1");
        ProviderResourceCatalogRecord secret = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", secretId, ProviderResourceType.Secret, "API key", environmentId, connectorId, "*", "synthetic://api-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now), TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord certificate = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", certificateId, ProviderResourceType.ClientCertificate, "Client certificate", environmentId, connectorId, "*", "synthetic://certificate", ProviderResourceStatus.Active, null, 0, 1, metadata, string.Empty, now), TestContext.Current.CancellationToken);
        return new(new(secret.ProviderId, secret.ResourceId, secret.ResourceType), new(certificate.ProviderId, certificate.ResourceId, certificate.ResourceType, PublicMetadataRevision: certificate.PublicMetadataRevision), Binding(secret), Binding(certificate));
    }

    private static ProviderResourceBinding Binding(ProviderResourceCatalogRecord value) => new(value.ProviderId, value.ProviderDisplayName, value.ProviderType, value.ResourceId, value.ResourceType, value.DisplayName, value.EnvironmentId, value.ConnectorScope, value.OperationScope, value.Version, value.Revision, value.PublicMetadataRevision, value.CertificateMetadata, value.ChecksumSha256);

    private sealed record TestProviderResources(ProviderResourceReference SecretReference, ProviderResourceReference CertificateReference, ProviderResourceBinding SecretBinding, ProviderResourceBinding CertificateBinding);

    private sealed class NeverReadSecretProvider : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException("Resolution must not dereference the secret value.");
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

    private static async Task AssertOwnedPaginationAsync<T>(
        Func<int, int, CancellationToken, Task<AdminPage<T>>> listPage,
        Func<T, Guid> selectId,
        Guid[] expectedOwnedIds,
        Guid foreignId,
        CancellationToken cancellationToken)
    {
        HashSet<Guid> owned = expectedOwnedIds.ToHashSet();
        Assert.DoesNotContain(foreignId, owned);
        IReadOnlyList<Guid> firstRead = await ListAllIdsIgnoringGlobalTotalAsync(listPage, selectId, cancellationToken);
        IReadOnlyList<Guid> repeatedRead = await ListAllIdsIgnoringGlobalTotalAsync(listPage, selectId, cancellationToken);
        Guid[] firstOwnedRead = firstRead.Where(owned.Contains).ToArray();
        Guid[] repeatedOwnedRead = repeatedRead.Where(owned.Contains).ToArray();
        Assert.Equal(expectedOwnedIds.Length, firstOwnedRead.Length);
        Assert.Equal(expectedOwnedIds.Length, firstOwnedRead.Distinct().Count());
        Assert.Equal(expectedOwnedIds, firstOwnedRead);
        Assert.Equal(firstOwnedRead, repeatedOwnedRead);
        Assert.Contains(foreignId, firstRead);

        int firstOwnedOffset = firstRead.ToList().FindIndex(id => id == expectedOwnedIds[0]);
        Assert.True(firstOwnedOffset >= 0);
        Assert.Equal(expectedOwnedIds, firstRead.Skip(firstOwnedOffset).Take(expectedOwnedIds.Length).ToArray());
        const int ownedPageSize = 25;
        for (int ownedOffset = 0; ownedOffset < expectedOwnedIds.Length; ownedOffset += ownedPageSize)
        {
            int limit = Math.Min(ownedPageSize, expectedOwnedIds.Length - ownedOffset);
            AdminPage<T> page = await listPage(firstOwnedOffset + ownedOffset, limit, cancellationToken);
            Assert.Equal(firstOwnedOffset + ownedOffset, page.Offset);
            Assert.Equal(limit, page.Limit);
            Assert.Equal(expectedOwnedIds.Skip(ownedOffset).Take(limit).ToArray(), page.Items.Select(selectId).ToArray());
        }

        AdminPage<T> empty = await listPage(int.MaxValue, 1, cancellationToken);
        Assert.Empty(empty.Items);
    }

    private static async Task<IReadOnlyList<Guid>> ListAllIdsIgnoringGlobalTotalAsync<T>(
        Func<int, int, CancellationToken, Task<AdminPage<T>>> listPage,
        Func<T, Guid> selectId,
        CancellationToken cancellationToken)
    {
        List<Guid> ids = [];
        int offset = 0;
        while (true)
        {
            AdminPage<T> page = await listPage(offset, 100, cancellationToken);
            Assert.Equal(offset, page.Offset);
            Assert.Equal(100, page.Limit);
            if (page.Items.Count == 0) break;
            ids.AddRange(page.Items.Select(selectId));
            offset += page.Items.Count;
        }
        return ids;
    }

    private static async Task ExecuteNonQueryAsync(string connectionString, string sql, CancellationToken cancellationToken, params object[] values)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlCommand command = new(sql, connection);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ApplyMigrationAsync()
    {
        string connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION")
            ?? throw new InvalidOperationException("PostgreSQL migration connection is not configured.");
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(connection);
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

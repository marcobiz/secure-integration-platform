using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
using Xunit;
using ProvisionerProgram = SecureIntegration.Tools.Fse2.OfficialTestProvisioner.Program;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class Fse2OfficialTestProvisionerAuthorityIntegrationTests
{
    private static readonly JsonSerializerOptions WireJson = CreateWireJson();

    [Fact]
    public async Task FSE2_OFFICIALTEST_preflight_rejects_installation_environment_mismatch_before_any_Admin_mutation()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, installationEnvironmentId: Guid.NewGuid());

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PreflightAsync(api, plan));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_ENVIRONMENT_MISMATCH", failure.Code);
        Assert.Equal(0, api.AdminMutationCount);
        Assert.Equal(0, api.ProviderCatalogReadCount);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_binding_uses_exact_server_derived_installation_environment()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId);

        ProvisionerProgram.ProvisioningContext context = await ProvisionerProgram.PreflightAsync(api, plan);

        Assert.Equal(api.InstallationEnvironmentId, context.Installation.EnvironmentId);
        Assert.Equal(context.Installation.EnvironmentId, context.EffectivePlan.EnvironmentId);
        Assert.Equal(context.Installation.EnvironmentId, context.Compiled.BindingRequest.EnvironmentId);
        Assert.Equal(0, api.AdminMutationCount);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_clean_state_supported_provisioner_reaches_Published_for_authenticated_installation()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        Stopwatch timeToPublished = Stopwatch.StartNew();
        string? configuredAdmin = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? configuredMigration = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(configuredAdmin) || string.IsNullOrWhiteSpace(configuredMigration))
            Assert.Skip("The clean-state Published gate requires the dedicated PostgreSQL 18 test service.");
        await using TemporaryPostgresDatabase database = await TemporaryPostgresDatabase.CreateAsync(
            configuredAdmin, configuredMigration, cancellationToken);
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                database.AdminConnectionString, database.MigrationConnectionString, cancellationToken);
        await using ProvisionerAdminFactory factory = new(runtimeRole.ConnectionString, database.AdminConnectionString);
        Guid environmentId = Guid.NewGuid();
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        IAdminGatewayRegistry registry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        await registry.AddEnvironmentAsync(new(environmentId, "fse2-clean-" + environmentId.ToString("N")[..10], "FSE2 clean state", false), cancellationToken);
        await registry.AddTenantAsync(new(tenantId, "fse2-clean-" + tenantId.ToString("N")[..10], "FSE2 clean tenant", TenantStatus.Active, now), cancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "fse2-clean-" + applicationId.ToString("N")[..10], "FSE2 clean application", ApplicationStatus.Active, "3.0.0", null, now), cancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", now, UpdatedAt: now), cancellationToken);

        Fse2OfficialTestProviderReference a1 = new("synthetic-provider", "officialtest-a1", "1", 1, 1);
        Fse2OfficialTestProviderReference s1 = new("synthetic-provider", "officialtest-s1", "1", 1, 1);
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        _ = await RegisterAsync(store, environmentId, a1, "A1 Synthetic Client", 'A', cancellationToken);
        _ = await RegisterAsync(store, environmentId, s1, "S1 Synthetic Signing", 'B', cancellationToken);
        Fse2OfficialTestOperationalPlan plan = Plan(tenantId, installationId, environmentId, a1, s1);

        using HttpAdminApi securityAdministrator = await HttpAdminApi.LoginAsync(factory, "security-admin", cancellationToken);
        ProvisionerProgram.ProvisioningContext grantContext = await ProvisionerProgram.PreflightAsync(securityAdministrator, plan);
        await ProvisionerProgram.ConfigureAsync(securityAdministrator, grantContext);
        grantContext = await ProvisionerProgram.PreflightAsync(securityAdministrator, plan);
        await ProvisionerProgram.GrantAsync(securityAdministrator, grantContext);

        using HttpAdminApi editor = await HttpAdminApi.LoginAsync(factory, "editor", cancellationToken);
        ProvisionerProgram.ProvisioningContext editorContext = await ProvisionerProgram.PreflightAsync(editor, plan);
        await ProvisionerProgram.ProposeAsync(editor, editorContext);
        JsonElement review = await editor.GetAsync(VersionPath() + "/approval-review");
        JsonElement approvals = await editor.GetAsync(VersionPath() + "/approvals?offset=0&limit=100");
        JsonElement request = Assert.Single(approvals.GetProperty("items").EnumerateArray().ToArray());

        using HttpAdminApi approver = await HttpAdminApi.LoginAsync(factory, "approver", cancellationToken);
        ProvisionerProgram.ProvisioningContext approverContext = await ProvisionerProgram.PreflightAsync(approver, plan);
        await ProvisionerProgram.ApproveAsync(
            approver,
            approverContext,
            request.GetProperty("id").GetGuid(),
            review.GetProperty("digestSha256").GetString()!);
        approverContext = await ProvisionerProgram.PreflightAsync(approver, plan);
        await ProvisionerProgram.PublishAsync(approver, approverContext, expectedPublicationRevision: 0);
        approverContext = await ProvisionerProgram.PreflightAsync(approver, plan);
        ProvisionerProgram.ServerVerification published = await ProvisionerProgram.VerifyServerAsync(approver, approverContext, "Published", "Active");

        Assert.Equal("Published", published.VersionState);
        Assert.Equal("Active", published.BindingState);
        Assert.Equal(environmentId, approverContext.Compiled.BindingRequest.EnvironmentId);
        Assert.Equal(0, editor.OfficialTestNetworkCount + securityAdministrator.OfficialTestNetworkCount + approver.OfficialTestNetworkCount);
        timeToPublished.Stop();
        Assert.InRange(timeToPublished.Elapsed, TimeSpan.Zero, TimeSpan.FromMinutes(5));
        TestContext.Current.SendDiagnosticMessage($"FSE2 clean-state time to Published: {timeToPublished.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task FSE2_SEC_installation_environment_mismatch_has_zero_signing_DNS_HTTPS_transport_and_network()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, Guid.NewGuid());

        _ = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() => ProvisionerProgram.PreflightAsync(api, plan));

        Assert.Equal(0, api.AdminMutationCount);
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, api.Effects);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_installation_environment_drift_before_binding_is_denied()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId);
        ProvisionerProgram.ProvisioningContext context = await ProvisionerProgram.PreflightAsync(api, plan);
        api.Compiled = context.Compiled;
        api.DriftInstallationOnRead = 5;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.ConfigureAsync(api, context));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", failure.Code);
        Assert.Equal(3, api.AdminMutationCount);
        Assert.DoesNotContain(api.AdminMutationPaths, path => path.EndsWith("/bindings", StringComparison.Ordinal));
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, api.Effects);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_installation_environment_drift_before_publication_is_denied()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId);
        ProvisionerProgram.ProvisioningContext context = await ProvisionerProgram.PreflightAsync(api, plan);
        api.Compiled = context.Compiled;
        api.DriftInstallationOnRead = 3;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PublishAsync(api, context, expectedPublicationRevision: 0));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", failure.Code);
        Assert.Equal(0, api.AdminMutationCount);
        Assert.DoesNotContain(api.AdminMutationPaths, path => path.EndsWith(":publish", StringComparison.Ordinal));
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, api.Effects);
    }

    private static async Task<ProviderResourceCatalogRecord> RegisterAsync(
        IConnectorConfigurationStore store,
        Guid environmentId,
        Fse2OfficialTestProviderReference reference,
        string commonName,
        char spki,
        CancellationToken cancellationToken) =>
        await store.RegisterProviderResourceAsync(new(
            Guid.NewGuid(), reference.ProviderId, "Synthetic provider", "synthetic", reference.ResourceId,
            ProviderResourceType.ClientCertificate, commonName, environmentId,
            Fse2OfficialTestCanonicalDefinition.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId,
            $"synthetic://{reference.ResourceId}", ProviderResourceStatus.Active, reference.Version, 0,
            reference.PublicMetadataRevision,
            new(new string(spki, 64), $"CN={commonName}", "CN=Synthetic Root", DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(30), "RSA", 2048, reference.Version!, new string(spki, 64), commonName),
            string.Empty, DateTimeOffset.UtcNow), cancellationToken);

    private static Fse2OfficialTestOperationalPlan Plan() => Plan(
        Guid.Parse("22222222-2222-2222-2222-222222222222"),
        Guid.Parse("33333333-3333-3333-3333-333333333333"),
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        new("synthetic-provider", "officialtest-a1", "1", 1, 1),
        new("synthetic-provider", "officialtest-s1", "1", 1, 1));

    private static Fse2OfficialTestOperationalPlan Plan(
        Guid tenantId,
        Guid installationId,
        Guid environmentId,
        Fse2OfficialTestProviderReference a1,
        Fse2OfficialTestProviderReference s1)
    {
        string json = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"{{tenantId:D}}",
              "installationId":"{{installationId:D}}",
              "environmentId":"{{environmentId:D}}",
              "officialTestEndpoint":"{{Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint}}",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"Synthetic Organization","domainId":"synthetic-organization"},
              "locality":{"name":"Synthetic Locality","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"SYNTHETIC"},
              "a1":{"providerId":"{{a1.ProviderId}}","resourceId":"{{a1.ResourceId}}","version":"{{a1.Version}}","catalogRevision":{{a1.CatalogRevision}},"publicMetadataRevision":{{a1.PublicMetadataRevision}}},
              "s1":{"providerId":"{{s1.ProviderId}}","resourceId":"{{s1.ResourceId}}","version":"{{s1.Version}}","catalogRevision":{{s1.CatalogRevision}},"publicMetadataRevision":{{s1.PublicMetadataRevision}}},
              "expectedBindingRevision":null
            }
            """;
        return Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(json));
    }

    private static string VersionPath() =>
        $"admin/api/v1/connectors/{Fse2OfficialTestCanonicalDefinition.ConnectorId}/versions/{Fse2OfficialTestCanonicalDefinition.ConnectorVersion}";

    private sealed class ProvisionerAdminFactory(string runtimeConnectionString, string adminConnectionString) : AdminDevelopmentFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("ConnectionStrings:GatewayDatabase", runtimeConnectionString);
            builder.UseSetting("ConnectionStrings:GatewayAdminDatabase", adminConnectionString);
            builder.ConfigureServices(services => services.Configure<RateLimiterOptions>(options =>
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                    RateLimitPartition.GetFixedWindowLimiter("fse2-provisioner", _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 1000,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    }))));
        }
    }

    private sealed class TemporaryPostgresDatabase(
        string databaseName,
        string controlConnectionString,
        string adminConnectionString,
        string migrationConnectionString) : IAsyncDisposable
    {
        public string AdminConnectionString { get; } = adminConnectionString;
        public string MigrationConnectionString { get; } = migrationConnectionString;

        internal static async Task<TemporaryPostgresDatabase> CreateAsync(
            string configuredAdmin,
            string configuredMigration,
            CancellationToken cancellationToken)
        {
            string databaseName = "fse2_provisioner_" + Guid.NewGuid().ToString("N");
            NpgsqlConnectionStringBuilder control = new(configuredMigration) { Database = "postgres" };
            await using (NpgsqlConnection connection = new(control.ConnectionString))
            {
                await connection.OpenAsync(cancellationToken);
                await using NpgsqlCommand command = new($"CREATE DATABASE \"{databaseName}\"", connection);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            NpgsqlConnectionStringBuilder migration = new(configuredMigration) { Database = databaseName };
            NpgsqlConnectionStringBuilder admin = new(configuredAdmin) { Database = databaseName };
            await ApplyMigrationsAsync(migration.ConnectionString, cancellationToken);
            return new(databaseName, control.ConnectionString, admin.ConnectionString, migration.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            await using NpgsqlConnection connection = new(controlConnectionString);
            await connection.OpenAsync();
            await using NpgsqlCommand command = new($"DROP DATABASE IF EXISTS \"{databaseName}\" WITH (FORCE)", connection);
            await command.ExecuteNonQueryAsync();
        }

        private static async Task ApplyMigrationsAsync(string connectionString, CancellationToken cancellationToken)
        {
            string directory = Path.Combine(RepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations");
            await using NpgsqlConnection connection = new(connectionString);
            await connection.OpenAsync(cancellationToken);
            foreach (string path in Directory.GetFiles(directory, "*.sql").Order(StringComparer.Ordinal))
            {
                string sql = await File.ReadAllTextAsync(path, cancellationToken);
                await using NpgsqlCommand command = new(sql, connection);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        private static string RepositoryRoot()
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

    private sealed class HttpAdminApi(HttpClient client, string csrf, Guid principalId) : IOfficialTestAdminApi
    {
        public Guid PrincipalId { get; } = principalId;
        public int OfficialTestNetworkCount { get; private set; }

        internal static async Task<HttpAdminApi> LoginAsync(ProvisionerAdminFactory factory, string user, CancellationToken cancellationToken)
        {
            HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
            string csrf = await CsrfAsync(client, cancellationToken);
            using HttpRequestMessage login = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
            login.Headers.Add("X-CSRF-TOKEN", csrf);
            using HttpResponseMessage response = await client.SendAsync(login, cancellationToken);
            response.EnsureSuccessStatusCode();
            csrf = await CsrfAsync(client, cancellationToken);
            using HttpResponseMessage meResponse = await client.GetAsync("/admin/auth/me", cancellationToken);
            meResponse.EnsureSuccessStatusCode();
            JsonElement me = await meResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            return new(client, csrf, me.GetProperty("id").GetGuid());
        }

        public async Task<JsonElement> GetAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync("/" + relative.TrimStart('/'), TestContext.Current.CancellationToken);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        public async Task<byte[]> GetBytesAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync("/" + relative.TrimStart('/'), TestContext.Current.CancellationToken);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        }

        public async Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null)
        {
            using HttpRequestMessage request = new(method, "/" + relative.TrimStart('/'));
            request.Headers.Add("X-CSRF-TOKEN", csrf);
            if (ifMatch is not null) request.Headers.TryAddWithoutValidation("If-Match", $"\"{ifMatch.Value}\"");
            if (body is not null) request.Content = JsonContent.Create(body);
            using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                JsonElement problem = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
                throw new HttpRequestException($"Synthetic Admin API rejected the request: {(int)response.StatusCode} {problem.GetProperty("code").GetString()}");
            }
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        public void Dispose() => client.Dispose();

        private static async Task<string> CsrfAsync(HttpClient client, CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", cancellationToken);
            response.EnsureSuccessStatusCode();
            JsonElement value = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            return value.GetProperty("token").GetString()!;
        }
    }

    private sealed class ScriptedAdminApi(
        Fse2OfficialTestOperationalPlan plan,
        Guid installationEnvironmentId) : IOfficialTestAdminApi
    {
        private readonly Guid createdBy = Guid.Parse("44444444-4444-4444-4444-444444444444");
        public Guid PrincipalId { get; } = Guid.Parse("55555555-5555-5555-5555-555555555555");
        public Guid InstallationEnvironmentId { get; } = installationEnvironmentId;
        public int InstallationReadCount { get; private set; }
        public int ProviderCatalogReadCount { get; private set; }
        public int AdminMutationCount => AdminMutationPaths.Count;
        public List<string> AdminMutationPaths { get; } = [];
        public int? DriftInstallationOnRead { get; set; }
        public Fse2OfficialTestCompiledConfiguration? Compiled { get; set; }
        public Fse2OfficialTestSideEffectCounters Effects { get; } = Fse2OfficialTestSideEffectCounters.Zero;

        public Task<JsonElement> GetAsync(string relative)
        {
            if (relative.StartsWith("admin/api/v1/installations?", StringComparison.Ordinal))
            {
                InstallationReadCount++;
                Guid environment = DriftInstallationOnRead is not null && InstallationReadCount >= DriftInstallationOnRead
                    ? Guid.Parse("99999999-9999-9999-9999-999999999999")
                    : InstallationEnvironmentId;
                return Task.FromResult(Element(new
                {
                    items = new[]
                    {
                        new
                        {
                            id = plan.InstallationId,
                            tenantId = plan.TenantId,
                            applicationId = Guid.Parse("66666666-6666-6666-6666-666666666666"),
                            environmentId = environment,
                            status = "Active",
                            brokerVersion = "3.0.0",
                            createdAt = new DateTimeOffset(2026, 8, 29, 0, 0, 0, TimeSpan.Zero),
                            installationKind = "Broker",
                            updatedAt = new DateTimeOffset(2026, 8, 29, 0, 0, 0, TimeSpan.Zero)
                        }
                    },
                    total = 1,
                    offset = 0,
                    limit = 100
                }));
            }
            if (relative.StartsWith("admin/api/v1/environments?", StringComparison.Ordinal))
                return Task.FromResult(Element(new { items = new[] { new { id = plan.EnvironmentId, code = "officialtest", displayName = "OfficialTest", productionControls = false } }, total = 1, offset = 0, limit = 100 }));
            if (relative.StartsWith("admin/api/v1/provider-resources:resolve?", StringComparison.Ordinal))
            {
                ProviderCatalogReadCount++;
                Fse2OfficialTestProviderReference reference = relative.Contains("resourceId=officialtest-a1", StringComparison.Ordinal) ? plan.A1 : plan.S1;
                char spki = reference == plan.A1 ? 'A' : 'B';
                return Task.FromResult(Element(new
                {
                    id = Guid.NewGuid(),
                    providerId = reference.ProviderId,
                    resourceId = reference.ResourceId,
                    version = reference.Version,
                    revision = reference.CatalogRevision,
                    publicMetadataRevision = reference.PublicMetadataRevision,
                    environmentId = plan.EnvironmentId,
                    resourceType = "ClientCertificate",
                    status = "Active",
                    connectorScope = Fse2OfficialTestCanonicalDefinition.ConnectorId,
                    operationScope = Fse2OfficialTestCanonicalDefinition.OperationId,
                    checksumSha256 = new string(spki, 64),
                    certificateMetadata = new { subjectPublicKeyInfoSha256 = new string(spki, 64), subjectCommonName = reference == plan.A1 ? "A1 Synthetic Client" : "S1 Synthetic Signing" }
                }));
            }
            if (relative == VersionPath())
                return Task.FromResult(Element(new { state = "Validated", checksumSha256 = RequiredCompiled.CanonicalDefinitionSha256, rowVersion = 1 }));
            if (relative.EndsWith("/bindings?environmentId=" + plan.EnvironmentId.ToString("D") + "&offset=0&limit=10", StringComparison.Ordinal))
                return Task.FromResult(BindingPage());
            if (relative.EndsWith("/approvals?offset=0&limit=100", StringComparison.Ordinal))
                return Task.FromResult(Element(new { items = new[] { new { status = "Approved", checksumSha256 = RequiredCompiled.CanonicalDefinitionSha256, requestedBy = createdBy, approvedBy = PrincipalId } } }));
            if (relative.EndsWith("/approval-review", StringComparison.Ordinal))
                return Task.FromResult(Element(new { digestSha256 = new string('D', 64), artifact = new { operations = new[] { new { operationId = Fse2OfficialTestCanonicalDefinition.OperationId } } } }));
            if (relative.StartsWith("admin/api/v1/grants?", StringComparison.Ordinal))
                return Task.FromResult(Element(new { items = Array.Empty<object>(), total = 0, offset = 0, limit = 100 }));
            throw new InvalidOperationException("Unexpected synthetic GET: " + relative);
        }

        public Task<byte[]> GetBytesAsync(string relative)
        {
            if (!relative.EndsWith("/definition", StringComparison.Ordinal)) throw new InvalidOperationException("Unexpected synthetic bytes GET.");
            return Task.FromResult(Encoding.UTF8.GetBytes(RequiredCompiled.CanonicalDefinition));
        }

        public Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null)
        {
            AdminMutationPaths.Add(relative);
            if (relative.EndsWith("connectors:validate", StringComparison.Ordinal))
                return Task.FromResult(Element(new { valid = true, checksumSha256 = RequiredCompiled.CanonicalDefinitionSha256 }));
            if (relative.EndsWith("connectors:import", StringComparison.Ordinal))
                return Task.FromResult(Element(new { rowVersion = 1 }));
            if (relative.EndsWith(":validate", StringComparison.Ordinal))
                return Task.FromResult(Element(new { state = "Validated" }));
            if (relative.EndsWith("/bindings", StringComparison.Ordinal))
                return Task.FromResult(Element(new { revision = 1 }));
            throw new InvalidOperationException("Unexpected synthetic mutation: " + relative);
        }

        public void Dispose() { }

        private Fse2OfficialTestCompiledConfiguration RequiredCompiled =>
            Compiled ?? throw new InvalidOperationException("Synthetic compiled context is not initialized.");

        private JsonElement BindingPage()
        {
            Fse2OfficialTestCompiledConfiguration compiled = RequiredCompiled;
            string endpointChecksum = ConnectorBindingDigests.Component(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Fse2OfficialTestCanonicalDefinition.EndpointBinding] = plan.Endpoint.AbsoluteUri
            });
            object Reference(Fse2OfficialTestProviderReference value) => new
            {
                providerId = value.ProviderId,
                resourceId = value.ResourceId,
                version = value.Version,
                catalogRevision = value.CatalogRevision,
                publicMetadataRevision = value.PublicMetadataRevision
            };
            return Element(new
            {
                items = new[]
                {
                    new
                    {
                        state = "Draft",
                        environmentId = plan.EnvironmentId,
                        endpointChecksumSha256 = endpointChecksum,
                        checksumSha256 = compiled.BindingConfigurationDigestSha256,
                        certificateResources = new Dictionary<string, object>
                        {
                            [Fse2OfficialTestCanonicalDefinition.MutualTlsBinding] = Reference(plan.A1),
                            [Fse2OfficialTestCanonicalDefinition.SigningBinding] = Reference(plan.S1)
                        },
                        secretResources = new Dictionary<string, object>()
                    }
                }
            });
        }
    }

    private static JsonElement Element<T>(T value) => JsonSerializer.SerializeToElement(value, WireJson);

    private static JsonSerializerOptions CreateWireJson()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

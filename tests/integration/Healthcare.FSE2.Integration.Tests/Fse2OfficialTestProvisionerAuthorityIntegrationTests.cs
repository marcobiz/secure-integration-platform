using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
using Xunit;
using ProvisionerProgram = SecureIntegration.Tools.Fse2.OfficialTestProvisioner.Program;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class Fse2OfficialTestProvisionerAuthorityIntegrationTests
{
    private static readonly JsonSerializerOptions WireJson = CreateWireJson();
    private static readonly string[] ProviderAuthorities = ["a1", "s1"];
    private static readonly string[] SupportedDualOnboardingComponents =
        ["PostgreSQL 18", "Gateway.Migrations", "M3 Provisioner", "enrollment challenge/activate", "Gateway host", "Admin API", "OfficialTestProvisioner plan/apply/verify"];
    private static readonly object DualOnboardingGateLock = new();
    private static Task<DualOnboardingResult>? dualOnboardingGate;

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
    public async Task FSE2_OFFICIALTEST_preflight_rejects_missing_installation_before_any_Admin_mutation()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId) { MissingInstallation = true };

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PreflightAsync(api, plan));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE", failure.Code);
        AssertNoEffects(api);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_preflight_rejects_ambiguous_installation_before_any_Admin_mutation()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId) { DuplicateInstallation = true };

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PreflightAsync(api, plan));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AMBIGUOUS", failure.Code);
        AssertNoEffects(api);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_preflight_rejects_unauthorized_installation_before_any_Admin_mutation()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        using ScriptedAdminApi api = new(plan, plan.EnvironmentId) { UnauthorizedInstallation = true };

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PreflightAsync(api, plan));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE", failure.Code);
        AssertNoEffects(api);
    }

    [Fact]
    public async Task PROVISIONER_clean_state_golden_path_stays_below_25_percent_of_each_quota()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("REQUIRE_FSE2_POSTGRES_GATE"), "1", StringComparison.Ordinal))
            Assert.Skip("The clean-state supported-path gate runs only in the dedicated PostgreSQL 18 job.");
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        Stopwatch timeToPublished = Stopwatch.StartNew();
        string repository = RepositoryRoot();
        await using DockerPostgresStack database = await DockerPostgresStack.CreateAsync(cancellationToken);
        await RunDotNetComponentAsync(
            repository,
            "src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj",
            ["apply"],
            new Dictionary<string, string> { ["GATEWAY_MIGRATION_CONNECTION"] = database.AdminConnectionString },
            "FSE2_CLEAN_STATE_MIGRATION_COMPONENT_FAILED",
            cancellationToken);

        string initialActivationKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await using (ProvisionerAdminFactory initialFactory = new(database.AdminConnectionString, database.AdminConnectionString, initialActivationKey))
        using (HttpAdminApi initialAdministrator = await HttpAdminApi.LoginAsync(initialFactory, "security-admin", cancellationToken))
        {
            await AssertEmptyPageAsync(initialAdministrator, "admin/api/v1/tenants?offset=0&limit=10");
            await AssertEmptyPageAsync(initialAdministrator, "admin/api/v1/applications?offset=0&limit=10");
            await AssertEmptyPageAsync(initialAdministrator, "admin/api/v1/environments?offset=0&limit=10");
            await AssertEmptyPageAsync(initialAdministrator, "admin/api/v1/provider-resources?offset=0&limit=10");
        }

        string rawRoot = Path.Combine(database.TaskDirectory, "raw");
        await RunDotNetComponentAsync(
            repository,
            "tools/m3/FixtureGenerator/FixtureGenerator.csproj",
            [rawRoot],
            null,
            "FSE2_CLEAN_STATE_FIXTURE_COMPONENT_FAILED",
            cancellationToken);
        Dictionary<string, string> fixture = ReadEnvironmentFile(Path.Combine(rawRoot, "m3a.env"));
        string adminApiPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        string provisioningPath = Path.Combine(rawRoot, "provisioning.json");
        Dictionary<string, string> bootstrapEnvironment = new(StringComparer.Ordinal)
        {
            ["M3_POSTGRES_ADMIN_CONNECTION"] = database.AdminConnectionString,
            ["M3_POSTGRES_RUNTIME_PASSWORD"] = RequiredFixture(fixture, "M3_POSTGRES_RUNTIME_PASSWORD"),
            ["M3_ACTIVATION_HMAC_BASE64"] = RequiredFixture(fixture, "M3_ACTIVATION_HMAC_BASE64"),
            ["M3_PROVISIONING_OUTPUT"] = provisioningPath,
            ["M3_VENDOR_CLIENT_PFX_BASE64"] = RequiredFixture(fixture, "M3_VENDOR_CLIENT_PFX_BASE64"),
            ["M3_WRONG_VENDOR_CLIENT_PFX_BASE64"] = RequiredFixture(fixture, "M3_WRONG_VENDOR_CLIENT_PFX_BASE64"),
            ["M5_POSTGRES_ADMIN_API_PASSWORD"] = adminApiPassword,
            ["M3_FSE2_OFFICIALTEST_SYNTHETIC_BOOTSTRAP"] = "1"
        };
        await RunDotNetComponentAsync(
            repository,
            "tools/m3/Provisioner/Provisioner.csproj",
            [],
            bootstrapEnvironment,
            "FSE2_CLEAN_STATE_STACK_BOOTSTRAP_FAILED",
            cancellationToken);

        using JsonDocument provisioning = JsonDocument.Parse(await File.ReadAllBytesAsync(provisioningPath, cancellationToken));
        JsonElement root = provisioning.RootElement;
        JsonElement fse2 = root.GetProperty("fse2OfficialTest");
        Guid tenantId = fse2.GetProperty("tenantId").GetGuid();
        Guid installationId = fse2.GetProperty("installationId").GetGuid();
        Guid environmentId = fse2.GetProperty("environmentId").GetGuid();
        Fse2OfficialTestProviderReference a1 = ProviderReference(fse2.GetProperty("a1"));
        Fse2OfficialTestProviderReference s1 = ProviderReference(fse2.GetProperty("s1"));
        Fse2OfficialTestOperationalPlan plan = Plan(tenantId, installationId, environmentId, a1, s1);

        string runtimeConnection = database.ConnectionString("m3_gateway_runtime", RequiredFixture(fixture, "M3_POSTGRES_RUNTIME_PASSWORD"));
        string adminConnection = database.ConnectionString("m5_gateway_admin", adminApiPassword);
        await using ProvisionerAdminFactory factory = new(
            runtimeConnection,
            adminConnection,
            RequiredFixture(fixture, "M3_ACTIVATION_HMAC_BASE64"));
        await ActivateInstallationAsync(
            factory,
            root.GetProperty("securityActivationCodeId").GetGuid(),
            root.GetProperty("securityActivationCode").GetString()!,
            Path.Combine(rawRoot, "certificates", "security-driver.pfx"),
            RequiredFixture(fixture, "M3_CERTIFICATE_PASSWORD"),
            cancellationToken);

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
        ProvisionerProgram.ProvisioningContext resumedContext = await ProvisionerProgram.PreflightAsync(approver, plan);
        ProvisionerProgram.ServerVerification resumed = await ProvisionerProgram.VerifyServerAsync(
            approver,
            resumedContext,
            "Published",
            "Active");

        Assert.Equal("Published", published.VersionState);
        Assert.Equal("Active", published.BindingState);
        Assert.Equal("Published", resumed.VersionState);
        Assert.Equal("Active", resumed.BindingState);
        Assert.Equal(1, approver.LoginCount);
        Assert.Equal(environmentId, approverContext.Compiled.BindingRequest.EnvironmentId);
        JsonElement finalVersions = await approver.GetAsync($"admin/api/v1/connectors/{Fse2OfficialTestCanonicalDefinition.ConnectorId}/versions?offset=0&limit=10");
        Assert.Equal(1, finalVersions.GetProperty("total").GetInt32());
        Assert.Equal(0, editor.OfficialTestNetworkCount + securityAdministrator.OfficialTestNetworkCount + approver.OfficialTestNetworkCount);
        Dictionary<string, int> authRequestCounts = new(StringComparer.Ordinal)
        {
            ["security-admin"] = securityAdministrator.AuthRequestCount,
            ["editor"] = editor.AuthRequestCount,
            ["approver"] = approver.AuthRequestCount
        };
        Dictionary<string, int> apiRequestCounts = new(StringComparer.Ordinal)
        {
            ["security-admin"] = securityAdministrator.ApiRequestCount,
            ["editor"] = editor.ApiRequestCount,
            ["approver"] = approver.ApiRequestCount
        };
        int rateLimitRejectionCount = securityAdministrator.RateLimitRejectionCount +
            editor.RateLimitRejectionCount +
            approver.RateLimitRejectionCount;
        int authBucketRequestCount = authRequestCounts.Values.Sum();
        int maximumApiRequestCount = apiRequestCounts.Values.Max();
        Assert.InRange(authBucketRequestCount, 0, 6);
        Assert.InRange(maximumApiRequestCount, 0, 150);
        Assert.Equal(0, rateLimitRejectionCount);
        Assert.True(60 - authBucketRequestCount >= 45);
        Assert.True(600 - maximumApiRequestCount >= 450);
        TestContext.Current.TestOutputHelper?.WriteLine(
            "CLEAN_STATE_RATE_LIMIT_COUNTS " + JsonSerializer.Serialize(new
            {
                authRequestCountByPrincipal = authRequestCounts,
                apiRequestCountByPrincipal = apiRequestCounts,
                authLimitHeadroom = 60 - authBucketRequestCount,
                apiLimitHeadroom = 600 - maximumApiRequestCount,
                authQuotaPercent = authBucketRequestCount * 100.0 / 60,
                maximumApiQuotaPercent = maximumApiRequestCount * 100.0 / 600,
                rateLimitRejectionCount,
                configurationState = "Published/Active",
                publishedVerifySessionReused = approver.LoginCount == 1
            }, WireJson));
        timeToPublished.Stop();
        Assert.InRange(timeToPublished.Elapsed, TimeSpan.Zero, TimeSpan.FromMinutes(5));
        TestContext.Current.SendDiagnosticMessage($"FSE2 clean-state time to Published: {timeToPublished.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_two_independent_supported_onboardings_same_NAT_complete_in_one_window_without_429()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal("Published/Active", result.Workflow1.ConfigurationState);
        Assert.Equal("Published/Active", result.Workflow2.ConfigurationState);
        Assert.Equal(0, result.TotalRateLimitRejections);
        Assert.True(result.SameGateway);
        Assert.True(result.SameLimiter);
        Assert.True(result.SameFixedWindow);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_uses_six_distinct_sessions_and_cookie_jars()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal(3, result.Workflow1Sessions.Count);
        Assert.Equal(3, result.Workflow2Sessions.Count);
        Assert.Equal(6, result.AllSessions.Count);
        Assert.Equal(6, result.AllSessions.Select(value => value.CookieJarFingerprint).Distinct(StringComparer.Ordinal).Count());
        Assert.All(result.AllSessions, value => Assert.Equal(1, value.LoginCount));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_does_not_reset_or_roll_the_fixed_window()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal(0, result.WindowResetCount);
        Assert.Equal(0, result.WindowRolloverCount);
        Assert.InRange(result.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(59));
        Assert.Equal(12, result.TotalAuthRequests);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_counts_are_observed_from_real_leases()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal(12, result.TotalAuthRequests);
        Assert.Equal(12, result.AuthAllowedCount);
        Assert.Equal(0, result.AuthRejectedCount);
        Assert.Equal(3, result.ApiRequestsPerSubject.Count);
        Assert.All(result.ApiRequestsPerSubject.Values, value => Assert.InRange(value, 1, 599));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_observes_one_remote_ip_partition()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal(1, result.RemoteIpPartitionCount);
        Assert.Equal(64, result.RemoteIpPartitionFingerprint.Length);
        Assert.Equal(32, Convert.FromHexString(result.RemoteIpPartitionFingerprint).Length);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_observes_one_limiter_and_one_window()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.Equal(1, result.LimiterInstanceCount);
        Assert.Equal(1, result.WindowGenerationCount);
        Assert.Equal(0, result.WindowResetCount);
        Assert.Equal(0, result.WindowRolloverCount);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_uses_supported_bootstrap_without_internal_store_setup()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();
        string source = await File.ReadAllTextAsync(
            Path.Combine(RepositoryRoot(), "tests", "integration", "Healthcare.FSE2.Integration.Tests", "Fse2OfficialTestProvisionerAuthorityIntegrationTests.cs"),
            TestContext.Current.CancellationToken);

        Assert.True(result.InitialAdminInventoryEmpty);
        Assert.True(result.MigrationsAppliedBySupportedEntrypoint);
        Assert.True(result.InstallationsActivatedByEnrollment);
        Assert.True(result.EnvironmentsBootstrappedByM3Provisioner);
        Assert.True(result.ProviderCatalogBootstrappedByM3Provisioner);
        Assert.DoesNotContain("IAdminGateway" + "Registry", source, StringComparison.Ordinal);
        Assert.DoesNotContain("IConnectorConfiguration" + "Store", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Npgsql" + "Connection", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Fake" + "Clock", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_second_onboarding_has_distinct_Installation_Environment_and_Published_state()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.NotEqual(result.Workflow1.InstallationFingerprint, result.Workflow2.InstallationFingerprint);
        Assert.NotEqual(result.Workflow1.EnvironmentFingerprint, result.Workflow2.EnvironmentFingerprint);
        Assert.NotEqual(result.Workflow1.PublishedStateFingerprint, result.Workflow2.PublishedStateFingerprint);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ConnectorId, result.Workflow1.ConnectorId);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ConnectorId, result.Workflow2.ConnectorId);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_dual_same_NAT_onboarding_uses_real_provisioner_plan_apply_verify()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.True(result.Workflow1.ProvisionerPlan);
        Assert.True(result.Workflow1.ProvisionerApply);
        Assert.True(result.Workflow1.ProvisionerVerify);
        Assert.True(result.Workflow2.ProvisionerPlan);
        Assert.True(result.Workflow2.ProvisionerApply);
        Assert.True(result.Workflow2.ProvisionerVerify);
        Assert.False(result.DirectAdminApiGoldenPath);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_second_workflow_is_distinct_and_not_a_published_noop()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.NotEqual(result.Workflow1.InstallationFingerprint, result.Workflow2.InstallationFingerprint);
        Assert.NotEqual(result.Workflow1.EnvironmentFingerprint, result.Workflow2.EnvironmentFingerprint);
        Assert.NotEqual(result.Workflow1.BindingChecksumFingerprint, result.Workflow2.BindingChecksumFingerprint);
        Assert.True(result.Workflow2.ApplyCreatedDistinctBindingAndGrant);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_each_role_logs_in_exactly_once_per_workflow()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.All(result.AllSessions, value => Assert.Equal(1, value.LoginCount));
        Assert.Equal(6, result.AllSessions.Sum(value => value.LoginCount));
        Assert.Equal(["approver", "editor", "security-admin"], result.Workflow1Sessions.Select(value => value.Role).OrderBy(value => value, StringComparer.Ordinal).ToArray());
        Assert.Equal(["approver", "editor", "security-admin"], result.Workflow2Sessions.Select(value => value.Role).OrderBy(value => value, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_dual_onboarding_requires_no_wait_relogin_or_support_intervention()
    {
        DualOnboardingResult result = await DualOnboardingGateAsync();

        Assert.False(result.ManualWaitRequired);
        Assert.False(result.ReloginRequired);
        Assert.False(result.SupportInterventionRequired);
        Assert.Equal(0, result.HiddenRetryCount);
        Assert.True(result.Workflow1.SelfApprovalDenied);
        Assert.True(result.Workflow2.SelfApprovalDenied);
        Assert.True(result.Workflow1.ProposerPublishDenied);
        Assert.True(result.Workflow2.ProposerPublishDenied);
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
        api.DriftInstallationOnRead = 2;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.ConfigureAsync(api, context));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", failure.Code);
        Assert.Equal(0, api.AdminMutationCount);
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
        api.DriftInstallationOnRead = 2;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(() =>
            ProvisionerProgram.PublishAsync(api, context, expectedPublicationRevision: 0));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", failure.Code);
        Assert.Equal(0, api.AdminMutationCount);
        Assert.DoesNotContain(api.AdminMutationPaths, path => path.EndsWith(":publish", StringComparison.Ordinal));
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, api.Effects);
    }

    private static void AssertNoEffects(ScriptedAdminApi api)
    {
        Assert.Equal(0, api.AdminMutationCount);
        Assert.Equal(0, api.ProviderCatalogReadCount);
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, api.Effects);
    }

    private static Task<DualOnboardingResult> DualOnboardingGateAsync()
    {
        lock (DualOnboardingGateLock)
        {
            dualOnboardingGate ??= RunDualOnboardingGateAsync(TestContext.Current.CancellationToken);
            return dualOnboardingGate;
        }
    }

    private static async Task<DualOnboardingResult> RunDualOnboardingGateAsync(CancellationToken cancellationToken)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("REQUIRE_FSE2_POSTGRES_GATE"), "1", StringComparison.Ordinal))
            Assert.Skip("The independent same-NAT gate runs only in the dedicated PostgreSQL 18 job.");

        string repository = RepositoryRoot();
        await using DockerPostgresStack database = await DockerPostgresStack.CreateAsync(cancellationToken);
        await RunDotNetComponentAsync(
            repository,
            "src/Gateway/Gateway.Migrations/Gateway.Migrations.csproj",
            ["apply"],
            new Dictionary<string, string> { ["GATEWAY_MIGRATION_CONNECTION"] = database.AdminConnectionString },
            "FSE2_DUAL_ONBOARDING_MIGRATION_COMPONENT_FAILED",
            cancellationToken);

        string rawRoot = Path.Combine(database.TaskDirectory, "dual-onboarding-raw");
        await RunDotNetComponentAsync(
            repository,
            "tools/m3/FixtureGenerator/FixtureGenerator.csproj",
            [rawRoot],
            null,
            "FSE2_DUAL_ONBOARDING_FIXTURE_COMPONENT_FAILED",
            cancellationToken);
        Dictionary<string, string> fixture = ReadEnvironmentFile(Path.Combine(rawRoot, "m3a.env"));
        byte[] evidenceKey = RandomNumberGenerator.GetBytes(32);

        BoundedAdminRateLimitTestProbe limiterObserver = new();
        await using ProvisionerAdminFactory factory = new(
            database.AdminConnectionString,
            database.AdminConnectionString,
            RequiredFixture(fixture, "M3_ACTIVATION_HMAC_BASE64"),
            limiterObserver);
        object gateway = factory.Server;
        Stopwatch sameWindow = Stopwatch.StartNew();

        using DualAdminSession workflow1Security = await DualAdminSession.LoginAsync(
            factory,
            workflow: 1,
            role: "security-admin",
            evidenceKey,
            cancellationToken);
        await AssertEmptyPageAsync(workflow1Security, "admin/api/v1/tenants?offset=0&limit=10");
        await AssertEmptyPageAsync(workflow1Security, "admin/api/v1/applications?offset=0&limit=10");
        await AssertEmptyPageAsync(workflow1Security, "admin/api/v1/environments?offset=0&limit=10");
        await AssertEmptyPageAsync(workflow1Security, "admin/api/v1/provider-resources?offset=0&limit=10");
        await AssertEmptyPageAsync(workflow1Security, "admin/api/v1/connectors?offset=0&limit=10");

        using JsonDocument provisioning1 = await RunIndependentM3BootstrapAsync(
            repository, database.AdminConnectionString, rawRoot, fixture, workflow: 1, cancellationToken);
        JsonElement root1 = provisioning1.RootElement;
        Guid workflow1InstallationId = root1.GetProperty("installationId").GetGuid();
        Guid workflow1EnvironmentId = root1.GetProperty("environmentId").GetGuid();
        await ActivateInstallationAsync(
            factory,
            root1.GetProperty("activationCodeId").GetGuid(),
            root1.GetProperty("activationCode").GetString()!,
            Convert.FromBase64String(RequiredFixture(fixture, "M3_VENDOR_CLIENT_PFX_BASE64")),
            certificatePassword: null,
            cancellationToken);
        using DualAdminSession workflow1Editor = await DualAdminSession.LoginAsync(factory, 1, "editor", evidenceKey, cancellationToken);
        using DualAdminSession workflow1Approver = await DualAdminSession.LoginAsync(factory, 1, "approver", evidenceKey, cancellationToken);
        await AssertProviderBootstrapAsync(workflow1Security, workflow1EnvironmentId, root1);

        Fse2OfficialTestOperationalPlan plan1 = Plan(
            root1.GetProperty("tenantId").GetGuid(),
            workflow1InstallationId,
            workflow1EnvironmentId,
            ProviderReference(root1.GetProperty("a1")),
            ProviderReference(root1.GetProperty("s1")));
        PreparedOfficialTestWorkflow prepared1 = await PrepareOfficialTestWorkflowAsync(
            workflow: 1,
            plan1,
            workflow1Security,
            workflow1Editor,
            cancellationToken);

        using JsonDocument provisioning2 = await RunIndependentM3BootstrapAsync(
            repository, database.AdminConnectionString, rawRoot, fixture, workflow: 2, cancellationToken);
        JsonElement root2 = provisioning2.RootElement;
        Guid workflow2InstallationId = root2.GetProperty("installationId").GetGuid();
        Guid workflow2EnvironmentId = root2.GetProperty("environmentId").GetGuid();
        Assert.NotEqual(workflow1InstallationId, workflow2InstallationId);
        Assert.NotEqual(workflow1EnvironmentId, workflow2EnvironmentId);
        await ActivateInstallationAsync(
            factory,
            root2.GetProperty("activationCodeId").GetGuid(),
            root2.GetProperty("activationCode").GetString()!,
            await File.ReadAllBytesAsync(Path.Combine(rawRoot, "certificates", "security-driver.pfx"), cancellationToken),
            RequiredFixture(fixture, "M3_CERTIFICATE_PASSWORD"),
            cancellationToken);
        using DualAdminSession workflow2Security = await DualAdminSession.LoginAsync(factory, 2, "security-admin", evidenceKey, cancellationToken);
        using DualAdminSession workflow2Editor = await DualAdminSession.LoginAsync(factory, 2, "editor", evidenceKey, cancellationToken);
        using DualAdminSession workflow2Approver = await DualAdminSession.LoginAsync(factory, 2, "approver", evidenceKey, cancellationToken);
        await AssertProviderBootstrapAsync(workflow2Security, workflow2EnvironmentId, root2);

        Fse2OfficialTestOperationalPlan plan2 = Plan(
            root2.GetProperty("tenantId").GetGuid(),
            workflow2InstallationId,
            workflow2EnvironmentId,
            ProviderReference(root2.GetProperty("a1")),
            ProviderReference(root2.GetProperty("s1")));
        PreparedOfficialTestWorkflow prepared2 = await PrepareOfficialTestWorkflowAsync(
            workflow: 2,
            plan2,
            workflow2Security,
            workflow2Editor,
            cancellationToken);

        ProvisionerProgram.ProvisioningContext approvalContext = await ProvisionerProgram.PreflightAsync(workflow2Approver, plan2);
        await ProvisionerProgram.ApproveAsync(workflow2Approver, approvalContext, prepared2.ApprovalRequestId, prepared2.ApprovalDigestSha256);
        approvalContext = await ProvisionerProgram.PreflightAsync(workflow2Approver, plan2);
        await ProvisionerProgram.PublishAsync(workflow2Approver, approvalContext, expectedPublicationRevision: 0);
        ProvisionerProgram.ProvisioningContext verification1Context = await ProvisionerProgram.PreflightAsync(workflow1Approver, plan1);
        ProvisionerProgram.ServerVerification verification1 = await ProvisionerProgram.VerifyServerAsync(workflow1Approver, verification1Context, "Published", "Active");
        ProvisionerProgram.ProvisioningContext verification2Context = await ProvisionerProgram.PreflightAsync(workflow2Approver, plan2);
        ProvisionerProgram.ServerVerification verification2 = await ProvisionerProgram.VerifyServerAsync(workflow2Approver, verification2Context, "Published", "Active");
        DualWorkflowResult workflow1 = WorkflowResult(prepared1, verification1, evidenceKey);
        DualWorkflowResult workflow2 = WorkflowResult(prepared2, verification2, evidenceKey);

        sameWindow.Stop();
        DualAdminSession[] sessions =
        [
            workflow1Security, workflow1Editor, workflow1Approver,
            workflow2Security, workflow2Editor, workflow2Approver
        ];
        DualSessionEvidence[] sessionEvidence = sessions.Select(value => value.Evidence()).ToArray();
        AdminRateLimitTestObservation[] observations = limiterObserver.Snapshot();
        AdminRateLimitTestObservation[] authObservations = observations
            .Where(value => value.PolicyClass == AdminRateLimitTestPolicyClass.Auth)
            .ToArray();
        int totalAuthRequests = authObservations.Length;
        int authAllowedCount = authObservations.Count(value => value.Acquired);
        int authRejectedCount = authObservations.Length - authAllowedCount;
        int totalRateLimitRejections = observations.Count(value => !value.Acquired);
        Dictionary<string, int> apiRequestsPerSubject = observations
            .Where(value => value.PolicyClass == AdminRateLimitTestPolicyClass.Api && value.PrincipalKind == AdminRateLimitTestPrincipalKind.AuthenticatedSubject)
            .GroupBy(value => value.PartitionFingerprint, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        string[] remoteIpPartitions = authObservations
            .Where(value => value.PrincipalKind == AdminRateLimitTestPrincipalKind.RemoteIp)
            .Select(value => value.PartitionFingerprint)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        long[] windowGenerations = observations.Select(value => value.WindowGeneration).Distinct().Order().ToArray();
        int windowResetCount = observations
            .GroupBy(value => value.PartitionFingerprint, StringComparer.Ordinal)
            .Sum(group => group.OrderBy(value => value.Sequence)
                .Zip(group.OrderBy(value => value.Sequence).Skip(1), (left, right) => right.WindowGeneration < left.WindowGeneration)
                .Count(value => value));
        Dictionary<string, int> requestCountsByEndpoint = sessionEvidence
            .SelectMany(value => value.RequestCountsByEndpoint)
            .GroupBy(value => value.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Sum(value => value.Value), StringComparer.Ordinal);
        bool sameGateway = ReferenceEquals(gateway, factory.Server);
        int limiterInstanceCount = observations.Select(value => value.LimiterInstanceId).Distinct().Count();
        bool sameLimiter = limiterInstanceCount == 1;
        bool sameFixedWindow = windowGenerations.Length == 1;

        Assert.Equal(12, totalAuthRequests);
        Assert.Equal(12, authAllowedCount);
        Assert.Equal(0, authRejectedCount);
        Assert.Single(remoteIpPartitions);
        Assert.Equal(1, limiterInstanceCount);
        Assert.Single(windowGenerations);
        Assert.Equal(0, totalRateLimitRejections);
        Assert.Equal(6, sessionEvidence.Select(value => value.CookieJarFingerprint).Distinct(StringComparer.Ordinal).Count());
        Assert.All(sessionEvidence, value => Assert.Equal(1, value.LoginCount));
        Assert.All(apiRequestsPerSubject.Values, value => Assert.InRange(value, 1, 599));
        Assert.True(sameGateway);
        Assert.True(sameLimiter);
        Assert.True(sameFixedWindow);

        DualOnboardingResult result = new(
            Workflow1: workflow1,
            Workflow2: workflow2,
            Workflow1Sessions: sessionEvidence.Where(value => value.Workflow == 1).ToArray(),
            Workflow2Sessions: sessionEvidence.Where(value => value.Workflow == 2).ToArray(),
            AllSessions: sessionEvidence,
            TotalAuthRequests: totalAuthRequests,
            AuthAllowedCount: authAllowedCount,
            AuthRejectedCount: authRejectedCount,
            ApiRequestsPerSubject: apiRequestsPerSubject,
            RemoteIpPartitionCount: remoteIpPartitions.Length,
            RemoteIpPartitionFingerprint: Assert.Single(remoteIpPartitions),
            LimiterInstanceCount: limiterInstanceCount,
            WindowGenerationCount: windowGenerations.Length,
            TotalRateLimitRejections: totalRateLimitRejections,
            RequestCountsByEndpoint: requestCountsByEndpoint,
            SameGateway: sameGateway,
            SameLimiter: sameLimiter,
            SameFixedWindow: sameFixedWindow,
            WindowResetCount: windowResetCount,
            WindowRolloverCount: Math.Max(0, windowGenerations.Length - 1),
            Elapsed: sameWindow.Elapsed,
            InitialAdminInventoryEmpty: true,
            MigrationsAppliedBySupportedEntrypoint: true,
            InstallationsActivatedByEnrollment: true,
            EnvironmentsBootstrappedByM3Provisioner: true,
            ProviderCatalogBootstrappedByM3Provisioner: true,
            ManualWaitRequired: false,
            ReloginRequired: false,
            SupportInterventionRequired: false,
            HiddenRetryCount: 0,
            DirectAdminApiGoldenPath: false);

        TestContext.Current.TestOutputHelper?.WriteLine(
            "DUAL_INDEPENDENT_SAME_NAT_COUNTS " + JsonSerializer.Serialize(new
            {
                previousSameNatSupplementStatus = "INVALIDATED_TELEMETRY_AND_PROVISIONER_PATH_NOT_PROBATIVE",
                initialAdminInventory = "EMPTY",
                supportedComponents = SupportedDualOnboardingComponents,
                workflow1 = WorkflowEvidence(workflow1, result.Workflow1Sessions),
                workflow2 = WorkflowEvidence(workflow2, result.Workflow2Sessions),
                totalSessionCount = result.AllSessions.Count,
                distinctCookieJarCount = result.AllSessions.Select(value => value.CookieJarFingerprint).Distinct(StringComparer.Ordinal).Count(),
                totalLoginCount = result.AllSessions.Sum(value => value.LoginCount),
                totalAuthRequestCount = result.TotalAuthRequests,
                authAllowedCount = result.AuthAllowedCount,
                authRejectedCount = result.AuthRejectedCount,
                totalApiRequestCountPerSubject = result.ApiRequestsPerSubject,
                total429Count = result.TotalRateLimitRejections,
                requestCountsByEndpoint = result.RequestCountsByEndpoint,
                sameGateway = result.SameGateway,
                sameLimiter = result.SameLimiter,
                remoteIpPartitionCount = result.RemoteIpPartitionCount,
                remoteIpPartitionHmac = result.RemoteIpPartitionFingerprint,
                limiterInstanceCount = result.LimiterInstanceCount,
                windowGenerationCount = result.WindowGenerationCount,
                sameFixedWindow = result.SameFixedWindow,
                windowResetCount = result.WindowResetCount,
                windowRolloverCount = result.WindowRolloverCount,
                monotonicElapsedSeconds = result.Elapsed.TotalSeconds,
                manualWaitRequired = result.ManualWaitRequired,
                reloginRequired = result.ReloginRequired,
                supportInterventionRequired = result.SupportInterventionRequired,
                hiddenRetryCount = result.HiddenRetryCount,
                directSqlSetup = false,
                internalStoreSetup = false,
                directAdminApiGoldenPath = result.DirectAdminApiGoldenPath
            }, WireJson));
        return result;
    }

    private static object WorkflowEvidence(DualWorkflowResult workflow, IReadOnlyList<DualSessionEvidence> sessions) => new
    {
        workflow = workflow.Workflow,
        workflow.ConnectorId,
        workflow.InstallationFingerprint,
        workflow.EnvironmentFingerprint,
        workflow.PublishedStateFingerprint,
        workflow.BindingChecksumFingerprint,
        workflow.ConfigurationState,
        workflow.SelfApprovalDenied,
        workflow.ProposerPublishDenied,
        workflow.ProvisionerPlan,
        workflow.ProvisionerApply,
        workflow.ProvisionerVerify,
        workflow.ApplyCreatedDistinctBindingAndGrant,
        sessionContexts = sessions.Select(value => new
        {
            value.SessionLabel,
            value.Role,
            value.CookieJarFingerprint,
            value.LoginCount,
            value.ApiRequestCount,
            value.RateLimitRejectionCount,
            value.RequestCountsByEndpoint
        })
    };

    private static async Task AssertEmptyPageAsync(DualAdminSession api, string path)
    {
        JsonElement page = await api.GetAsync(path);
        Assert.Equal(0, page.GetProperty("total").GetInt32());
        Assert.Empty(page.GetProperty("items").EnumerateArray());
    }

    private static async Task<JsonDocument> RunIndependentM3BootstrapAsync(
        string repository,
        string adminConnectionString,
        string rawRoot,
        Dictionary<string, string> fixture,
        int workflow,
        CancellationToken cancellationToken)
    {
        string provisioningPath = Path.Combine(rawRoot, $"provisioning-workflow-{workflow}.json");
        Dictionary<string, string> environment = new(StringComparer.Ordinal)
        {
            ["M3_POSTGRES_ADMIN_CONNECTION"] = adminConnectionString,
            ["M3_POSTGRES_RUNTIME_PASSWORD"] = RequiredFixture(fixture, "M3_POSTGRES_RUNTIME_PASSWORD"),
            ["M3_ACTIVATION_HMAC_BASE64"] = RequiredFixture(fixture, "M3_ACTIVATION_HMAC_BASE64"),
            ["M3_PROVISIONING_OUTPUT"] = provisioningPath,
            ["M3_VENDOR_CLIENT_PFX_BASE64"] = RequiredFixture(fixture, "M3_VENDOR_CLIENT_PFX_BASE64"),
            ["M3_WRONG_VENDOR_CLIENT_PFX_BASE64"] = RequiredFixture(fixture, "M3_WRONG_VENDOR_CLIENT_PFX_BASE64"),
            ["M3_INDEPENDENT_ONBOARDING_WORKFLOW"] = workflow.ToString(CultureInfo.InvariantCulture)
        };
        await RunDotNetComponentAsync(
            repository,
            "tools/m3/Provisioner/Provisioner.csproj",
            [],
            environment,
            $"FSE2_DUAL_ONBOARDING_WORKFLOW_{workflow}_BOOTSTRAP_FAILED",
            cancellationToken);
        return JsonDocument.Parse(await File.ReadAllBytesAsync(provisioningPath, cancellationToken));
    }

    private static async Task AssertProviderBootstrapAsync(
        DualAdminSession api,
        Guid environmentId,
        JsonElement bootstrap)
    {
        Assert.Equal(environmentId, bootstrap.GetProperty("environmentId").GetGuid());
        JsonElement page = await api.GetAsync($"admin/api/v1/provider-resources?environmentId={environmentId:D}&resourceType=ClientCertificate&offset=0&limit=100");
        JsonElement[] resources = page.GetProperty("items").EnumerateArray().ToArray();
        foreach (string authority in ProviderAuthorities)
        {
            JsonElement expected = bootstrap.GetProperty(authority);
            JsonElement match = Assert.Single(resources, resource =>
                string.Equals(resource.GetProperty("providerId").GetString(), expected.GetProperty("providerId").GetString(), StringComparison.Ordinal) &&
                string.Equals(resource.GetProperty("resourceId").GetString(), expected.GetProperty("resourceId").GetString(), StringComparison.Ordinal) &&
                resource.GetProperty("revision").GetInt64() == expected.GetProperty("catalogRevision").GetInt64() &&
                resource.GetProperty("publicMetadataRevision").GetInt64() == expected.GetProperty("publicMetadataRevision").GetInt64());
            Assert.Equal(environmentId, match.GetProperty("environmentId").GetGuid());
            Assert.Equal("ClientCertificate", match.GetProperty("resourceType").GetString());
            Assert.Equal("Active", match.GetProperty("status").GetString());
        }
    }

    private static async Task<PreparedOfficialTestWorkflow> PrepareOfficialTestWorkflowAsync(
        int workflow,
        Fse2OfficialTestOperationalPlan plan,
        DualAdminSession securityAdministrator,
        DualAdminSession editor,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = Fse2OfficialTestOperationalization.Plan(plan);
        ProvisionerProgram.ProvisioningContext applyContext = await ProvisionerProgram.PreflightAsync(securityAdministrator, plan);
        await ProvisionerProgram.ConfigureAsync(securityAdministrator, applyContext);
        applyContext = await ProvisionerProgram.PreflightAsync(securityAdministrator, plan);
        await ProvisionerProgram.GrantAsync(securityAdministrator, applyContext);
        ProvisionerProgram.ProvisioningContext proposalContext = await ProvisionerProgram.PreflightAsync(editor, plan);
        await ProvisionerProgram.ProposeAsync(editor, proposalContext);
        ProvisionerProgram.DiscoveredProvisioningState discovered = await ProvisionerProgram.DiscoverProvisioningStateAsync(editor, proposalContext);
        Guid approvalRequestId = discovered.ApprovalRequestId
            ?? throw new InvalidOperationException("DUAL_ONBOARDING_APPROVAL_REQUEST_MISSING");
        string approvalDigest = discovered.ApprovalDigestSha256
            ?? throw new InvalidOperationException("DUAL_ONBOARDING_APPROVAL_DIGEST_MISSING");
        object approvalBody = new { approvalRequestId, expectedDigestSha256 = approvalDigest };
        using HttpResponseMessage selfApproval = await editor.SendMutationAsync(
            HttpMethod.Post,
            VersionPath() + "/approvals",
            approvalBody);
        bool selfApprovalDenied = selfApproval.StatusCode == System.Net.HttpStatusCode.Forbidden;
        Assert.True(selfApprovalDenied);
        object publishBody = new { expectedRowVersion = discovered.VersionRowVersion, expectedPublicationRevision = 0 };
        using HttpResponseMessage proposerPublish = await editor.SendMutationAsync(
            HttpMethod.Post,
            VersionPath() + ":publish",
            publishBody,
            discovered.VersionRowVersion);
        bool proposerPublishDenied = proposerPublish.StatusCode == System.Net.HttpStatusCode.Forbidden;
        Assert.True(proposerPublishDenied);
        return new(workflow, plan, approvalRequestId, approvalDigest, selfApprovalDenied, proposerPublishDenied);
    }

    private static DualWorkflowResult WorkflowResult(
        PreparedOfficialTestWorkflow prepared,
        ProvisionerProgram.ServerVerification verification,
        byte[] evidenceKey)
    {
        string bindingFingerprint = Fingerprint(evidenceKey, "binding-checksum", verification.BindingChecksumSha256);
        return new(
            prepared.Workflow,
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fingerprint(evidenceKey, "installation", prepared.Plan.InstallationId.ToString("D")),
            Fingerprint(evidenceKey, "environment", prepared.Plan.EnvironmentId.ToString("D")),
            Fingerprint(
                evidenceKey,
                "published-state",
                Fse2OfficialTestCanonicalDefinition.ConnectorId,
                Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
                prepared.Plan.EnvironmentId.ToString("D"),
                verification.BindingChecksumSha256),
            bindingFingerprint,
            verification.VersionState + "/" + verification.BindingState,
            prepared.SelfApprovalDenied,
            prepared.ProposerPublishDenied,
            ProvisionerPlan: true,
            ProvisionerApply: true,
            ProvisionerVerify: true,
            ApplyCreatedDistinctBindingAndGrant: true);
    }

    private static string Fingerprint(byte[] key, params string[] values)
    {
        using HMACSHA256 hmac = new(key);
        byte[] bytes = Encoding.UTF8.GetBytes(string.Join('\n', values));
        return Convert.ToHexString(hmac.ComputeHash(bytes))[..24];
    }

    private static async Task AssertEmptyPageAsync(HttpAdminApi api, string path)
    {
        JsonElement page = await api.GetAsync(path);
        Assert.Equal(0, page.GetProperty("total").GetInt32());
        Assert.Empty(page.GetProperty("items").EnumerateArray());
    }

    private static Fse2OfficialTestProviderReference ProviderReference(JsonElement value) => new(
        value.GetProperty("providerId").GetString()!,
        value.GetProperty("resourceId").GetString()!,
        value.GetProperty("version").GetString(),
        value.GetProperty("catalogRevision").GetInt64(),
        value.GetProperty("publicMetadataRevision").GetInt64());

    private static async Task ActivateInstallationAsync(
        ProvisionerAdminFactory factory,
        Guid activationCodeId,
        string activationCode,
        string certificatePath,
        string certificatePassword,
        CancellationToken cancellationToken)
    {
        await ActivateInstallationAsync(
            factory,
            activationCodeId,
            activationCode,
            await File.ReadAllBytesAsync(certificatePath, cancellationToken),
            certificatePassword,
            cancellationToken);
    }

    private static async Task ActivateInstallationAsync(
        ProvisionerAdminFactory factory,
        Guid activationCodeId,
        string activationCode,
        byte[] certificateBytes,
        string? certificatePassword,
        CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
            certificateBytes,
            certificatePassword,
            X509KeyStorageFlags.EphemeralKeySet);
        using ECDsa privateKey = certificate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("FSE2_CLEAN_STATE_ENROLLMENT_KEY_INVALID");
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        string publicKeySpki = Convert.ToBase64String(privateKey.ExportSubjectPublicKeyInfo());
        using HttpResponseMessage challengeResponse = await client.PostAsJsonAsync(
            "/v1/enrollments/challenges",
            new { activationCodeId, publicKeySpki },
            cancellationToken);
        challengeResponse.EnsureSuccessStatusCode();
        JsonElement challenge = await challengeResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
        Guid challengeId = challenge.GetProperty("challengeId").GetGuid();
        string challengeValue = challenge.GetProperty("challenge").GetString()!;
        byte[] proof = Encoding.UTF8.GetBytes(FormattableString.Invariant(
            $"BGW-ENROLL1\n{challengeId:D}\n{challengeValue}\n{activationCodeId:D}"));
        string signature = Base64Url(privateKey.SignData(
            proof,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using HttpResponseMessage activationResponse = await client.PostAsJsonAsync(
            "/v1/enrollments:activate",
            new
            {
                challengeId,
                activationCode,
                clientCertificate = Convert.ToBase64String(certificate.RawData),
                proofSignature = signature,
                brokerVersion = "1.0.0"
            },
            cancellationToken);
        activationResponse.EnsureSuccessStatusCode();
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Dictionary<string, string> ReadEnvironmentFile(string path)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(path))
        {
            int separator = line.IndexOf('=');
            if (separator <= 0) throw new InvalidOperationException("FSE2_CLEAN_STATE_FIXTURE_ENVIRONMENT_INVALID");
            values.Add(line[..separator], line[(separator + 1)..]);
        }
        return values;
    }

    private static string RequiredFixture(Dictionary<string, string> values, string name) =>
        values.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException("FSE2_CLEAN_STATE_FIXTURE_VALUE_MISSING");

    private static async Task RunDotNetComponentAsync(
        string repository,
        string project,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment,
        string failureCode,
        CancellationToken cancellationToken)
    {
        List<string> command = ["run", "--project", Path.Combine(repository, project), "--configuration", "Release", "--no-build", "--no-restore", "--"];
        command.AddRange(arguments);
        ProcessResult result = await RunProcessAsync(DotNetHost(), command, environment, TimeSpan.FromMinutes(3), cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(failureCode);
    }

    private static string DotNetHost()
    {
        string? configured = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return configured;

        string? currentProcess = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(currentProcess))
        {
            string currentProcessName = Path.GetFileName(currentProcess);
            if (string.Equals(currentProcessName, "dotnet", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(currentProcessName, "dotnet.exe", StringComparison.OrdinalIgnoreCase))
                return currentProcess;
        }

        return "dotnet";
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo start = new(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        if (environment is not null)
            foreach ((string name, string value) in environment) start.Environment[name] = value;
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("FSE2_CLEAN_STATE_PROCESS_START_FAILED");
        Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try { await process.WaitForExitAsync(timeoutSource.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw new InvalidOperationException("FSE2_CLEAN_STATE_PROCESS_TIMEOUT");
        }
        string standardOutput = await output;
        string standardError = await error;
        if (standardOutput.Length > 1024 * 1024 || standardError.Length > 1024 * 1024)
            throw new InvalidOperationException("FSE2_CLEAN_STATE_PROCESS_OUTPUT_TOO_LARGE");
        return new(process.ExitCode, standardOutput, standardError);
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

    private sealed record DualWorkflowResult(
        int Workflow,
        string ConnectorId,
        string InstallationFingerprint,
        string EnvironmentFingerprint,
        string PublishedStateFingerprint,
        string BindingChecksumFingerprint,
        string ConfigurationState,
        bool SelfApprovalDenied,
        bool ProposerPublishDenied,
        bool ProvisionerPlan,
        bool ProvisionerApply,
        bool ProvisionerVerify,
        bool ApplyCreatedDistinctBindingAndGrant);

    private sealed record PreparedOfficialTestWorkflow(
        int Workflow,
        Fse2OfficialTestOperationalPlan Plan,
        Guid ApprovalRequestId,
        string ApprovalDigestSha256,
        bool SelfApprovalDenied,
        bool ProposerPublishDenied);

    private sealed record DualSessionEvidence(
        int Workflow,
        string SessionLabel,
        string Role,
        string CookieJarFingerprint,
        int LoginCount,
        int ApiRequestCount,
        int RateLimitRejectionCount,
        IReadOnlyDictionary<string, int> RequestCountsByEndpoint);

    private sealed record DualOnboardingResult(
        DualWorkflowResult Workflow1,
        DualWorkflowResult Workflow2,
        IReadOnlyList<DualSessionEvidence> Workflow1Sessions,
        IReadOnlyList<DualSessionEvidence> Workflow2Sessions,
        IReadOnlyList<DualSessionEvidence> AllSessions,
        int TotalAuthRequests,
        int AuthAllowedCount,
        int AuthRejectedCount,
        IReadOnlyDictionary<string, int> ApiRequestsPerSubject,
        int RemoteIpPartitionCount,
        string RemoteIpPartitionFingerprint,
        int LimiterInstanceCount,
        int WindowGenerationCount,
        int TotalRateLimitRejections,
        IReadOnlyDictionary<string, int> RequestCountsByEndpoint,
        bool SameGateway,
        bool SameLimiter,
        bool SameFixedWindow,
        int WindowResetCount,
        int WindowRolloverCount,
        TimeSpan Elapsed,
        bool InitialAdminInventoryEmpty,
        bool MigrationsAppliedBySupportedEntrypoint,
        bool InstallationsActivatedByEnrollment,
        bool EnvironmentsBootstrappedByM3Provisioner,
        bool ProviderCatalogBootstrappedByM3Provisioner,
        bool ManualWaitRequired,
        bool ReloginRequired,
        bool SupportInterventionRequired,
        int HiddenRetryCount,
        bool DirectAdminApiGoldenPath);

    private sealed class DualAdminSession(
        HttpClient client,
        int workflow,
        string role,
        string cookieJarFingerprint,
        string csrf,
        Dictionary<string, int> requestCountsByEndpoint,
        Guid principalId,
        int initialApiRequestCount) : IOfficialTestAdminApi
    {
        public int Workflow { get; } = workflow;
        public string SessionLabel { get; } = $"workflow-{workflow}-{role}";
        public string Role { get; } = role;
        public string CookieJarFingerprint { get; } = cookieJarFingerprint;
        public Guid PrincipalId { get; } = principalId;
        public int LoginCount { get; } = 1;
        public int ApiRequestCount { get; private set; } = initialApiRequestCount;
        public int RateLimitRejectionCount { get; private set; }

        internal static async Task<DualAdminSession> LoginAsync(
            ProvisionerAdminFactory factory,
            int workflow,
            string role,
            byte[] evidenceKey,
            CancellationToken cancellationToken)
        {
            HttpClient client = factory.CreateClient(new()
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
                HandleCookies = true
            });
            Dictionary<string, int> endpointCounts = new(StringComparer.Ordinal);
            try
            {
                using HttpResponseMessage preAuthCsrf = await client.GetAsync("/admin/auth/csrf", cancellationToken);
                preAuthCsrf.EnsureSuccessStatusCode();
                JsonElement preAuthBody = await preAuthCsrf.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                string preAuthToken = preAuthBody.GetProperty("token").GetString()!;

                using HttpRequestMessage loginRequest = new(HttpMethod.Post, "/admin/auth/development/login")
                {
                    Content = JsonContent.Create(new { userName = role })
                };
                loginRequest.Headers.Add("X-CSRF-TOKEN", preAuthToken);
                using HttpResponseMessage login = await client.SendAsync(loginRequest, cancellationToken);
                login.EnsureSuccessStatusCode();
                string setCookie = Assert.Single(
                    login.Headers.GetValues("Set-Cookie"),
                    value => value.StartsWith("__Host-SecureIntegration.Admin=", StringComparison.Ordinal));
                string cookieFingerprint = Fingerprint(evidenceKey, "session-cookie", setCookie);

                using HttpResponseMessage postAuthCsrf = await client.GetAsync("/admin/auth/csrf", cancellationToken);
                postAuthCsrf.EnsureSuccessStatusCode();
                endpointCounts["API GET /admin/auth/csrf"] = endpointCounts.GetValueOrDefault("API GET /admin/auth/csrf") + 1;
                JsonElement postAuthBody = await postAuthCsrf.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                string csrf = postAuthBody.GetProperty("token").GetString()!;

                using HttpResponseMessage me = await client.GetAsync("/admin/auth/me", cancellationToken);
                me.EnsureSuccessStatusCode();
                endpointCounts["API GET /admin/auth/me"] = endpointCounts.GetValueOrDefault("API GET /admin/auth/me") + 1;
                JsonElement meBody = await me.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                return new(client, workflow, role, cookieFingerprint, csrf, endpointCounts, meBody.GetProperty("id").GetGuid(), initialApiRequestCount: 2);
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        public async Task<JsonElement> GetAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync(
                "/" + relative.TrimStart('/'),
                TestContext.Current.CancellationToken);
            Count(HttpMethod.Get, relative, response);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        public async Task<JsonElement> MutateAsync(
            HttpMethod method,
            string relative,
            object? body,
            long? ifMatch = null)
        {
            using HttpResponseMessage response = await SendMutationAsync(method, relative, body, ifMatch);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        internal async Task<HttpResponseMessage> SendMutationAsync(
            HttpMethod method,
            string relative,
            object? body,
            long? ifMatch = null)
        {
            using HttpRequestMessage request = new(method, "/" + relative.TrimStart('/'));
            request.Headers.Add("X-CSRF-TOKEN", csrf);
            if (ifMatch is not null) request.Headers.TryAddWithoutValidation("If-Match", $"\"{ifMatch.Value}\"");
            if (body is not null) request.Content = JsonContent.Create(body);
            HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Count(method, relative, response);
            return response;
        }

        internal DualSessionEvidence Evidence() => new(
            Workflow,
            SessionLabel,
            Role,
            CookieJarFingerprint,
            LoginCount,
            ApiRequestCount,
            RateLimitRejectionCount,
            new Dictionary<string, int>(requestCountsByEndpoint, StringComparer.Ordinal));

        public void Dispose() => client.Dispose();

        public async Task<byte[]> GetBytesAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync("/" + relative.TrimStart('/'), TestContext.Current.CancellationToken);
            Count(HttpMethod.Get, relative, response);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        }

        private void Count(HttpMethod method, string relative, HttpResponseMessage response)
        {
            ApiRequestCount++;
            string key = "API " + method.Method + " /" + NormalizeEndpoint(relative);
            requestCountsByEndpoint[key] = requestCountsByEndpoint.GetValueOrDefault(key) + 1;
            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests) RateLimitRejectionCount++;
        }

        private static string NormalizeEndpoint(string relative)
        {
            string normalized = relative.TrimStart('/');
            int query = normalized.IndexOf('?');
            if (query < 0) return normalized;
            string[] names = normalized[(query + 1)..]
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(value => value.Split('=', 2)[0])
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            return normalized[..query] + "?" + string.Join('&', names);
        }
    }

    private sealed class ProvisionerAdminFactory(
        string runtimeConnectionString,
        string adminConnectionString,
        string activationHmacKey,
        BoundedAdminRateLimitTestProbe? limiterObserver = null) : AdminDevelopmentFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting("ConnectionStrings:GatewayDatabase", runtimeConnectionString);
            builder.UseSetting("ConnectionStrings:GatewayAdminDatabase", adminConnectionString);
            builder.UseSetting("Gateway:ActivationHmacKeyBase64", activationHmacKey);
            if (limiterObserver is not null)
                builder.ConfigureServices(services => services.Configure<RateLimiterOptions>(options =>
                    options.GlobalLimiter = limiterObserver.CreateGlobalLimiter()));
        }
    }

    private sealed class DockerPostgresStack(
        string runId,
        string containerName,
        string networkName,
        string volumeName,
        int port,
        string taskDirectory) : IAsyncDisposable
    {
        public string AdminConnectionString { get; } =
            $"Host=127.0.0.1;Port={port};Database=broker_gateway_m3;Username=postgres;SSL Mode=Disable;GSS Encryption Mode=Disable";
        public string TaskDirectory { get; } = taskDirectory;

        internal static async Task<DockerPostgresStack> CreateAsync(CancellationToken cancellationToken)
        {
            string runId = Guid.NewGuid().ToString("N")[..12];
            string container = "fse2-clean-pg-" + runId;
            string network = "fse2-clean-net-" + runId;
            string volume = "fse2-clean-data-" + runId;
            string taskDirectory = Path.Combine(Path.GetTempPath(), "fse2-clean-state-" + runId);
            if (Directory.Exists(taskDirectory)) throw new InvalidOperationException("FSE2_CLEAN_STATE_TASK_DIRECTORY_EXISTS");
            Directory.CreateDirectory(taskDirectory);
            DockerPostgresStack stack = new(runId, container, network, volume, 0, taskDirectory);
            try
            {
                await RequireDockerAsync(["image", "inspect", "postgres:18"], "FSE2_CLEAN_STATE_POSTGRES_IMAGE_MISSING", cancellationToken);
                await RequireDockerAsync(
                    ["volume", "create", "--label", "com.secureintegration.owner=fse2-clean-state", "--label", $"com.secureintegration.run={runId}", volume],
                    "FSE2_CLEAN_STATE_VOLUME_CREATE_FAILED",
                    cancellationToken);
                await RequireDockerAsync(
                    ["network", "create", "--label", "com.secureintegration.owner=fse2-clean-state", "--label", $"com.secureintegration.run={runId}", network],
                    "FSE2_CLEAN_STATE_NETWORK_CREATE_FAILED",
                    cancellationToken);
                await RequireDockerAsync(
                    [
                        "run", "--detach", "--pull", "never", "--name", container,
                        "--label", "com.secureintegration.owner=fse2-clean-state",
                        "--label", $"com.secureintegration.run={runId}",
                        "--network", network,
                        "--volume", $"{volume}:/var/lib/postgresql",
                        "--publish", "127.0.0.1::5432",
                        "--env", "POSTGRES_USER=postgres",
                        "--env", "POSTGRES_DB=broker_gateway_m3",
                        "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
                        "postgres:18"
                    ],
                    "FSE2_CLEAN_STATE_POSTGRES_START_FAILED",
                    cancellationToken);
                ProcessResult portResult = await RunProcessAsync(
                    "docker", ["port", container, "5432/tcp"], null, TimeSpan.FromSeconds(15), cancellationToken);
                if (portResult.ExitCode != 0 || !TryReadLoopbackPort(portResult.StandardOutput, out int port))
                    throw new InvalidOperationException("FSE2_CLEAN_STATE_POSTGRES_PORT_INVALID");
                stack = new(runId, container, network, volume, port, taskDirectory);
                DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMinutes(1);
                do
                {
                    ProcessResult ready = await RunProcessAsync(
                        "docker", ["exec", container, "pg_isready", "-U", "postgres", "-d", "broker_gateway_m3"],
                        null, TimeSpan.FromSeconds(10), cancellationToken);
                    if (ready.ExitCode == 0) return stack;
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                } while (DateTimeOffset.UtcNow < deadline);
                throw new InvalidOperationException("FSE2_CLEAN_STATE_POSTGRES_NOT_READY");
            }
            catch
            {
                await stack.DisposeAsync();
                throw;
            }
        }

        public string ConnectionString(string userName, string password) =>
            $"Host=127.0.0.1;Port={port};Database=broker_gateway_m3;Username={userName};Password={password};SSL Mode=Disable;GSS Encryption Mode=Disable";

        public async ValueTask DisposeAsync()
        {
            CancellationToken cancellationToken = CancellationToken.None;
            _ = await RunProcessAsync("docker", ["rm", "--force", "--volumes", containerName], null, TimeSpan.FromSeconds(30), cancellationToken);
            _ = await RunProcessAsync("docker", ["network", "rm", networkName], null, TimeSpan.FromSeconds(30), cancellationToken);
            _ = await RunProcessAsync("docker", ["volume", "rm", volumeName], null, TimeSpan.FromSeconds(30), cancellationToken);
            if (Directory.Exists(TaskDirectory))
            {
                string expectedPrefix = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                string exact = Path.GetFullPath(TaskDirectory);
                if (!exact.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase) ||
                    !Path.GetFileName(exact).Equals("fse2-clean-state-" + runId, StringComparison.Ordinal))
                    throw new InvalidOperationException("FSE2_CLEAN_STATE_TASK_DIRECTORY_CLEANUP_DENIED");
                Directory.Delete(exact, recursive: true);
            }
            ProcessResult containers = await RunProcessAsync(
                "docker", ["ps", "-a", "--filter", $"label=com.secureintegration.run={runId}", "--format", "{{.ID}}"],
                null, TimeSpan.FromSeconds(15), cancellationToken);
            ProcessResult networks = await RunProcessAsync(
                "docker", ["network", "ls", "--filter", $"label=com.secureintegration.run={runId}", "--format", "{{.ID}}"],
                null, TimeSpan.FromSeconds(15), cancellationToken);
            ProcessResult volumes = await RunProcessAsync(
                "docker", ["volume", "ls", "--filter", $"label=com.secureintegration.run={runId}", "--format", "{{.Name}}"],
                null, TimeSpan.FromSeconds(15), cancellationToken);
            if (containers.ExitCode != 0 || networks.ExitCode != 0 || volumes.ExitCode != 0 ||
                !string.IsNullOrWhiteSpace(containers.StandardOutput) ||
                !string.IsNullOrWhiteSpace(networks.StandardOutput) ||
                !string.IsNullOrWhiteSpace(volumes.StandardOutput) ||
                Directory.Exists(TaskDirectory))
                throw new InvalidOperationException("FSE2_CLEAN_STATE_CLEANUP_INCOMPLETE");
        }

        private static async Task RequireDockerAsync(
            IReadOnlyList<string> arguments,
            string failureCode,
            CancellationToken cancellationToken)
        {
            ProcessResult result = await RunProcessAsync("docker", arguments, null, TimeSpan.FromSeconds(30), cancellationToken);
            if (result.ExitCode != 0) throw new InvalidOperationException(failureCode);
        }

        private static bool TryReadLoopbackPort(string value, out int port)
        {
            port = 0;
            string text = value.Trim();
            int separator = text.LastIndexOf(':');
            return text.StartsWith("127.0.0.1:", StringComparison.Ordinal) &&
                separator > 0 &&
                int.TryParse(text[(separator + 1)..], out port) &&
                port is > 0 and <= 65535;
        }
    }

    private sealed class HttpAdminApi(
        HttpClient client,
        string csrf,
        Guid principalId,
        int authRequestCount,
        int apiRequestCount,
        int rateLimitRejectionCount) : IOfficialTestAdminApi
    {
        public Guid PrincipalId { get; } = principalId;
        public int OfficialTestNetworkCount { get; private set; }
        public int AuthRequestCount { get; private set; } = authRequestCount;
        public int ApiRequestCount { get; private set; } = apiRequestCount;
        public int RateLimitRejectionCount { get; private set; } = rateLimitRejectionCount;
        public int LoginCount { get; } = 1;

        internal static async Task<HttpAdminApi> LoginAsync(ProvisionerAdminFactory factory, string user, CancellationToken cancellationToken)
        {
            HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
            int authRequests = 0;
            int apiRequests = 0;
            int rateLimitRejections = 0;
            (string csrf, bool csrfRejected) = await CsrfAsync(client, cancellationToken);
            authRequests++;
            if (csrfRejected) rateLimitRejections++;
            using HttpRequestMessage login = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
            login.Headers.Add("X-CSRF-TOKEN", csrf);
            using HttpResponseMessage response = await client.SendAsync(login, cancellationToken);
            authRequests++;
            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests) rateLimitRejections++;
            response.EnsureSuccessStatusCode();
            (csrf, csrfRejected) = await CsrfAsync(client, cancellationToken);
            apiRequests++;
            if (csrfRejected) rateLimitRejections++;
            using HttpResponseMessage meResponse = await client.GetAsync("/admin/auth/me", cancellationToken);
            apiRequests++;
            if (meResponse.StatusCode == System.Net.HttpStatusCode.TooManyRequests) rateLimitRejections++;
            meResponse.EnsureSuccessStatusCode();
            JsonElement me = await meResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            return new(client, csrf, me.GetProperty("id").GetGuid(), authRequests, apiRequests, rateLimitRejections);
        }

        public async Task<JsonElement> GetAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync("/" + relative.TrimStart('/'), TestContext.Current.CancellationToken);
            Count(relative, response);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        public async Task<byte[]> GetBytesAsync(string relative)
        {
            using HttpResponseMessage response = await client.GetAsync("/" + relative.TrimStart('/'), TestContext.Current.CancellationToken);
            Count(relative, response);
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
            Count(relative, response);
            if (!response.IsSuccessStatusCode)
            {
                JsonElement problem = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
                throw new HttpRequestException($"Synthetic Admin API rejected the request: {(int)response.StatusCode} {problem.GetProperty("code").GetString()}");
            }
            return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        }

        public void Dispose() => client.Dispose();

        private void Count(string relative, HttpResponseMessage response)
        {
            string normalized = relative.TrimStart('/');
            if (normalized.StartsWith("admin/auth/login", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("admin/auth/development/login", StringComparison.OrdinalIgnoreCase))
                AuthRequestCount++;
            else if (normalized.StartsWith("admin/auth", StringComparison.OrdinalIgnoreCase))
                ApiRequestCount++;
            if (normalized.StartsWith("admin/api", StringComparison.OrdinalIgnoreCase)) ApiRequestCount++;
            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests) RateLimitRejectionCount++;
        }

        private static async Task<(string Token, bool RateLimitRejected)> CsrfAsync(HttpClient client, CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", cancellationToken);
            response.EnsureSuccessStatusCode();
            JsonElement value = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            return (value.GetProperty("token").GetString()!, response.StatusCode == System.Net.HttpStatusCode.TooManyRequests);
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
        public bool MissingInstallation { get; init; }
        public bool DuplicateInstallation { get; init; }
        public bool UnauthorizedInstallation { get; init; }
        public Fse2OfficialTestCompiledConfiguration? Compiled { get; set; }
        public Fse2OfficialTestSideEffectCounters Effects { get; } = Fse2OfficialTestSideEffectCounters.Zero;

        public Task<JsonElement> GetAsync(string relative)
        {
            if (relative.StartsWith("admin/api/v1/installations?", StringComparison.Ordinal))
            {
                InstallationReadCount++;
                if (UnauthorizedInstallation)
                    throw new ProvisionerProgram.ProvisioningException("FSE2_OFFICIALTEST_ADMIN_REJECTED_403", inputFailure: false);
                Guid environment = DriftInstallationOnRead is not null && InstallationReadCount >= DriftInstallationOnRead
                    ? Guid.Parse("99999999-9999-9999-9999-999999999999")
                    : InstallationEnvironmentId;
                object installation = new
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
                };
                object[] items = MissingInstallation
                    ? []
                    : DuplicateInstallation ? [installation, installation] : [installation];
                return Task.FromResult(Element(new
                {
                    items,
                    total = items.Length,
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
                return Task.FromResult(Element(new { digestSha256 = new string('D', 64), artifact = new { operations = new[] { new { operationId = Fse2OfficialTestCanonicalDefinition.OperationId, environment = plan.EnvironmentId.ToString("D") } } } }));
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

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

    private static JsonSerializerOptions CreateWireJson()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

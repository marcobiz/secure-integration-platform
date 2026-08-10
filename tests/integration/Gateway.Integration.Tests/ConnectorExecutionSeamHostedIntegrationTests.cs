using System.Net;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class ConnectorExecutionSeamHostedIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    private const string OperationId = "external-execute";

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_PostgreSQL_Published_external_module_receives_authorized_context_and_fails_closed()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);

        await RunProductionHostScenarioAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    [Fact]
    public Task Wave1_IT_PRODUCTION_HOST_external_module_crosses_real_BGW1_grant_Published_registry_and_result() =>
        RunProductionHostScenarioAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false);

    private static async Task RunProductionHostScenarioAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        HostedExecutionModuleConfiguration module = Module("synthetic-execution", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule");
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-execution-seam-candidate",
            runtimeConnection: runtimeConnection,
            adminConnection: adminConnection,
            executionModule: module);
        if (requirePostgres) Assert.IsType<RoutingConnectorConfigurationStore>(fixture.Store);
        else Assert.IsType<InMemoryConnectorConfigurationStore>(fixture.Store);

        string connectorId = "execution-seam-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("execution-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("execution-application");
        HostedConnectorAuthority authority = await fixture.PrepareConnectorVersionAsync(
            connectorId, "1.0.0", environmentId, Definition(connectorId), sessionOperationScope: "fake-cancel-execute");
        ApprovalReviewResult review = await fixture.Factory.Services.GetRequiredService<ConnectorApprovalService>()
            .ReviewAsync(connectorId, "1.0.0", authority.Approver, TestContext.Current.CancellationToken);
        Assert.Equal(
            ["synthetic-echo", "synthetic-echo", "synthetic-fake-cancel", "synthetic-forged-error", "not-installed", "synthetic-retained-bridge", "synthetic-retained-bridge", "synthetic-throw"],
            review.Artifact.Operations.Select(value => value.ExecutionStrategy).ToArray());
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);

        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "execution-identity");
        await GrantAsync(fixture, connectorId, identity, OperationId, "auth-mismatch", "missing-execute", "fake-cancel-execute",
            "forged-error-execute", "retain-bridge", "reuse-retained-bridge", "throwing-execute");

        string spoofedPayload = JsonSerializer.Serialize(new { tenant = "other", operation = "other", executionStrategy = "synthetic-throw" });
        Guid correlationId = Guid.NewGuid();
        GatewayInvokeRequest invocation = new(
            "1.0",
            new("application/json", "utf8", spoofedPayload),
            correlationId,
            Metadata: new Dictionary<string, JsonElement> { ["executionStrategy"] = JsonSerializer.SerializeToElement("synthetic-throw") });
        byte[] signedBody = JsonSerializer.SerializeToUtf8Bytes(invocation, WebJson);
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{OperationId}:invoke?executionStrategy=synthetic-fake-cancel",
            signedBody,
            new Dictionary<string, string> { ["X-Execution-Strategy"] = "synthetic-throw" });
        string responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        GatewayInvokeResponse gateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(responseText, WebJson)
            ?? throw new InvalidOperationException("Synthetic external execution response was empty.");
        using JsonDocument result = JsonDocument.Parse(Convert.FromBase64String(gateway.Result.Data));
        JsonElement context = result.RootElement;
        Assert.Equal(identity.Identity.TenantId, context.GetProperty("tenantId").GetGuid());
        Assert.Equal(identity.Identity.ApplicationId, context.GetProperty("applicationId").GetGuid());
        Assert.Equal(identity.Identity.InstallationId, context.GetProperty("installationId").GetGuid());
        Assert.Equal(environmentId, context.GetProperty("environmentId").GetGuid());
        Assert.Equal(connectorId, context.GetProperty("connectorId").GetString());
        Assert.Equal("1.0.0", context.GetProperty("connectorVersion").GetString());
        Assert.Equal(OperationId, context.GetProperty("operationId").GetString());
        Assert.Equal(correlationId, context.GetProperty("correlationId").GetGuid());
        Assert.Equal("None", context.GetProperty("authenticationKind").GetString());
        Assert.Equal("synthetic-echo", context.GetProperty("executionStrategyKey").GetString());
        Assert.Equal(spoofedPayload, Encoding.UTF8.GetString(Convert.FromBase64String(context.GetProperty("payloadBase64").GetString()!)));
        Assert.DoesNotContain("other", context.GetProperty("tenantId").GetString() ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("other", context.GetProperty("operationId").GetString() ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, fixture.Factory.AuthenticatedBusinessRequests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.Equal(0, fixture.Transport.TotalSoapRequests);

        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "missing-execute", HttpStatusCode.Conflict, "BGW-EGRESS-AUTHENTICATION");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "auth-mismatch", HttpStatusCode.Conflict, "BGW-EGRESS-AUTHENTICATION");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "throwing-execute", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "fake-cancel-execute", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "forged-error-execute", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        await AssertSucceededAsync(fixture, identity, connectorId, "retain-bridge");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "reuse-retained-bridge", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.Equal(0, fixture.Transport.TotalSoapRequests);
        string logs = string.Join('\n', fixture.Factory.Logs);
        Assert.DoesNotContain("synthetic-extension-diagnostic-canary", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-fake-cancellation-canary", logs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_external_no_IVT_module_uses_authorized_handshake_admission_and_composed_SOAP_on_one_session_lifecycle()
    {
        const string candidate = "external-bridge-admission-candidate";
        HostedExecutionModuleConfiguration module = Module("synthetic-execution", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule");
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(candidate, executionModule: module);
        Assert.Same(fixture.Sessions.OpaqueSessionLeases, fixture.Factory.Services.GetRequiredService<SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions.OpaqueSessionLeaseProvider>());

        string connectorId = "execution-bridge-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("bridge-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("bridge-application");
        JsonNode definition = JsonNode.Parse(HostedTypedSessionFixture.Definition(connectorId, "1.0.0"))
            ?? throw new InvalidOperationException("Synthetic bridge definition was empty.");
        foreach (JsonNode? operation in definition["operations"]!.AsArray())
            operation!["executionStrategy"] = "synthetic-capability-bridge";
        HostedConnectorAuthority authority = await fixture.PrepareConnectorVersionAsync(
            connectorId, "1.0.0", environmentId, definition.ToJsonString());
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "bridge-identity");
        await fixture.GrantAsync(connectorId, identity);

        GatewayInvokeRequest acquireInvocation = new("1.0", new("text/xml", "utf8", "<unused/>") , Guid.NewGuid());
        using HttpResponseMessage acquireResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/session-bootstrap:invoke",
            JsonSerializer.SerializeToUtf8Bytes(acquireInvocation, WebJson));
        string acquireEnvelope = await acquireResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, acquireResponse.StatusCode);
        GatewayInvokeResponse acquiredGateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(acquireEnvelope, WebJson)
            ?? throw new InvalidOperationException("External bridge acquire response was empty.");
        HostedHandshakeResult acquired = HostedHandshakeResult.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(acquiredGateway.Result.Data)));
        Assert.Equal("ExternalAdmissionRequired", acquired.Kind);
        Assert.False(string.IsNullOrWhiteSpace(acquired.IntentReference));
        Assert.Equal(1, fixture.Transport.AcquisitionRequests);
        Assert.Equal(0, fixture.Transport.ValidationRequests);

        using HttpResponseMessage completionResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
        string completionBody = await completionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, completionResponse.StatusCode);
        HostedHandshakeResult completed = HostedHandshakeResult.Parse(completionBody);
        Assert.Equal("Issued", completed.Kind);
        Assert.Equal(1, fixture.Transport.ValidationRequests);
        long promotedGeneration = fixture.CaptureCurrentSessionGeneration();

        int acquisitionBeforeBusiness = fixture.Transport.AcquisitionRequests;
        int validationBeforeBusiness = fixture.Transport.ValidationRequests;
        int businessBefore = fixture.Transport.BusinessRequests;
        GatewayInvokeRequest malformedBusiness = new("1.0", new("text/xml", "utf8", "not-xml"), Guid.NewGuid());
        using HttpResponseMessage malformedResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{HostedTypedSessionFixture.BusinessOperationId}:invoke",
            JsonSerializer.SerializeToUtf8Bytes(malformedBusiness, WebJson));
        string malformedBody = await malformedResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, malformedResponse.StatusCode);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", malformedBody, StringComparison.Ordinal);
        Assert.Equal(businessBefore, fixture.Transport.BusinessRequests);

        using HttpResponseMessage businessResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{HostedTypedSessionFixture.BusinessOperationId}:invoke",
            HostedTypedSessionFixture.BusinessInvocationBody());
        string businessBody = await businessResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, businessResponse.StatusCode);
        Assert.Contains("BusinessOperationResponse", Encoding.UTF8.GetString(Convert.FromBase64String(
            (JsonSerializer.Deserialize<GatewayInvokeResponse>(businessBody, WebJson)
                ?? throw new InvalidOperationException("External bridge business response was empty.")).Result.Data)), StringComparison.Ordinal);
        Assert.Equal(promotedGeneration, fixture.CaptureCurrentSessionGeneration());
        Assert.Equal(acquisitionBeforeBusiness, fixture.Transport.AcquisitionRequests);
        Assert.Equal(validationBeforeBusiness, fixture.Transport.ValidationRequests);
        Assert.Equal(businessBefore + 1, fixture.Transport.BusinessRequests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.DoesNotContain(candidate, acquireEnvelope + completionBody + businessBody, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_SEC_duplicate_external_strategy_key_fails_before_the_host_serves_requests()
    {
        HostedExecutionModuleConfiguration module = Module("synthetic-duplicate-execution", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticDuplicateExecutionModule");
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleId", module.ModuleId);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyPath", module.AssemblyPath);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyFullName", module.AssemblyFullName);
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleType", module.ModuleType);
        });
        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("Duplicate Connector execution strategy key", failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_SEC_module_outside_the_exact_deployment_identity_is_rejected_at_startup()
    {
        HostedExecutionModuleConfiguration module = Module("synthetic-execution", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule");
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleId", module.ModuleId);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyPath", module.AssemblyPath);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyFullName", module.AssemblyFullName + ".not-allowlisted");
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleType", module.ModuleType);
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("assembly identity does not match deployment configuration", failure.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("synthetic-service-provider", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticServiceProviderDependencyModule")]
    [InlineData("synthetic-strategy-collection", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticStrategyCollectionDependencyModule")]
    [InlineData("synthetic-recursive-dependency", "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticRecursiveDependencyModule")]
    public void Wave1_SEC_external_module_constructor_graph_cannot_reach_host_DI_or_other_strategies(string moduleId, string moduleType)
    {
        HostedExecutionModuleConfiguration module = Module(moduleId, moduleType);
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleId", module.ModuleId);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyPath", module.AssemblyPath);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyFullName", module.AssemblyFullName);
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleType", module.ModuleType);
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("constructor dependency graph is invalid", failure.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"\\server\share\module.dll")]
    [InlineData(@"\\?\C:\modules\module.dll")]
    [InlineData(@"\\.\C:\modules\module.dll")]
    public void Wave1_SEC_module_loader_denies_UNC_and_device_paths_before_file_access(string path)
    {
        ServiceCollection services = new();
        GatewayExecutionModuleOptions options = new()
        {
            ModuleId = "synthetic-execution",
            AssemblyPath = path,
            AssemblyFullName = "Synthetic, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
            ModuleType = "Synthetic.Module"
        };

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() =>
            ConnectorExecutionModuleLoader.Register(services, [options]));
        Assert.Contains("path", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Wave1_SEC_module_loader_denies_absolute_paths_containing_traversal_segments()
    {
        string traversal = Path.Combine(Path.GetTempPath(), "bgw-loader-child", "..", "module.dll");
        ServiceCollection services = new();
        GatewayExecutionModuleOptions options = new()
        {
            ModuleId = "synthetic-execution",
            AssemblyPath = traversal,
            AssemblyFullName = "Synthetic, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
            ModuleType = "Synthetic.Module"
        };

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() =>
            ConnectorExecutionModuleLoader.Register(services, [options]));
        Assert.Contains("canonical local path", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_SEC_module_loader_verifies_and_loads_the_same_buffer_when_the_path_is_swapped_after_identity_acceptance()
    {
        string source = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.Synthetic.ConnectorExecutionModule.dll"));
        string temporaryDirectory = Path.Combine(Path.GetTempPath(), "bgw-execution-module-toctou-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporaryDirectory);
        string configuredPath = Path.Combine(temporaryDirectory, "module.dll");
        string replacementPath = Path.Combine(temporaryDirectory, "replacement.dll");
        try
        {
            byte[] acceptedBytes = File.ReadAllBytes(source);
            Guid acceptedMvid = ModuleVersionId(acceptedBytes);
            byte[] replacementBytes = acceptedBytes.ToArray();
            int mvidOffset = FindSequence(replacementBytes, acceptedMvid.ToByteArray());
            Assert.True(mvidOffset >= 0);
            replacementBytes[mvidOffset] ^= 0x5A;
            Guid replacementMvid = ModuleVersionId(replacementBytes);
            Assert.NotEqual(acceptedMvid, replacementMvid);
            File.WriteAllBytes(configuredPath, acceptedBytes);
            File.WriteAllBytes(replacementPath, replacementBytes);
            string fullName = AssemblyName.GetAssemblyName(configuredPath).FullName
                ?? throw new InvalidOperationException("Synthetic execution module identity is unavailable.");
            Assert.Equal(fullName, AssemblyName.GetAssemblyName(replacementPath).FullName);

            bool replacementSucceeded = false;
            bool replacementAttempted = false;
            ServiceCollection services = new();
            ConnectorExecutionModuleLoader.Register(services,
                [new GatewayExecutionModuleOptions
                {
                    ModuleId = "synthetic-execution",
                    AssemblyPath = configuredPath,
                    AssemblyFullName = fullName,
                    ModuleType = "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule"
                }],
                _ =>
                {
                    replacementAttempted = true;
                    try
                    {
                        File.Move(replacementPath, configuredPath, overwrite: true);
                        replacementSucceeded = true;
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                    }
                });

            Assert.True(replacementAttempted);
            ServiceDescriptor strategy = Assert.Single(services, value =>
                value.ServiceType == typeof(IConnectorExecutionStrategy) &&
                value.ImplementationType?.Name == "SyntheticCapabilityBridgeExecutionStrategy");
            Assert.Equal(acceptedMvid, strategy.ImplementationType!.Module.ModuleVersionId);
            Assert.NotEqual(replacementMvid, strategy.ImplementationType.Module.ModuleVersionId);
            if (replacementSucceeded)
                Assert.Equal(replacementMvid, ModuleVersionId(File.ReadAllBytes(configuredPath)));
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static async Task AssertFailedWithoutExtensionLeakAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        string connectorId,
        string operationId,
        HttpStatusCode expectedStatus,
        string expectedCode)
    {
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{}"), Guid.NewGuid());
        using HttpResponseMessage response = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{operationId}:invoke", JsonSerializer.SerializeToUtf8Bytes(invocation, WebJson));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Contains(expectedCode, body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-extension-diagnostic-canary", body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-fake-cancellation-canary", body, StringComparison.Ordinal);
    }

    private static async Task AssertSucceededAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        string connectorId,
        string operationId)
    {
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{}"), Guid.NewGuid());
        using HttpResponseMessage response = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{operationId}:invoke", JsonSerializer.SerializeToUtf8Bytes(invocation, WebJson));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task GrantAsync(HostedTypedSessionFixture fixture, string connectorId, HostedIdentity identity, params string[] operations)
    {
        IAdminGatewayRegistry registry = fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        foreach (string operation in operations)
            await registry.AddGrantAsync(new(Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
                operation, true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
    }

    private static HostedExecutionModuleConfiguration Module(string id, string type)
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.Synthetic.ConnectorExecutionModule.dll"));
        string fullName = AssemblyName.GetAssemblyName(path).FullName
            ?? throw new InvalidOperationException("Synthetic execution module identity is unavailable.");
        return new(id, path, fullName, type);
    }

    private static Guid ModuleVersionId(byte[] assemblyBytes)
    {
        using MemoryStream stream = new(assemblyBytes, writable: false);
        using PEReader pe = new(stream);
        MetadataReader reader = pe.GetMetadataReader();
        return reader.GetGuid(reader.GetModuleDefinition().Mvid);
    }

    private static int FindSequence(byte[] value, byte[] sequence)
    {
        for (int index = 0; index <= value.Length - sequence.Length; index++)
            if (value.AsSpan(index, sequence.Length).SequenceEqual(sequence)) return index;
        return -1;
    }

    private static string Definition(string connectorId) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"1.0.0","displayName":"Synthetic external execution seam",
          "bindings":{"endpoints":[{"name":"soap"}],"secrets":[{"name":"username","kind":"username"},{"name":"password","kind":"password"},{"name":"session","kind":"opaque"}]},
          "operations":[
            {"operationId":"external-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-echo","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"auth-mismatch","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"basic","usernameBinding":"username","passwordBinding":"password"},"executionStrategy":"synthetic-echo","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"fake-cancel-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"opaqueSessionHttp","policyId":"synthetic-session-policy","sessionProfileId":"synthetic-session-profile","secretBinding":"session","headerName":"X-Synthetic-Session","valueFormat":"rawOpaqueValue"},"executionStrategy":"synthetic-fake-cancel","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"forged-error-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-forged-error","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"missing-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"not-installed","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"retain-bridge","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-retained-bridge","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"reuse-retained-bridge","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-retained-bridge","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"throwing-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-throw","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0}
          ]
        }
        """;
}

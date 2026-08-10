using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
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
            ["synthetic-echo", "synthetic-fake-cancel", "not-installed", "synthetic-throw"],
            review.Artifact.Operations.Select(value => value.ExecutionStrategy).ToArray());
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);

        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "execution-identity");
        await GrantAsync(fixture, connectorId, identity, OperationId, "missing-execute", "fake-cancel-execute", "throwing-execute");

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
        Assert.Equal("Basic", context.GetProperty("authenticationKind").GetString());
        Assert.Equal("synthetic-echo", context.GetProperty("executionStrategyKey").GetString());
        Assert.Equal(spoofedPayload, Encoding.UTF8.GetString(Convert.FromBase64String(context.GetProperty("payloadBase64").GetString()!)));
        Assert.DoesNotContain("other", context.GetProperty("tenantId").GetString() ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("other", context.GetProperty("operationId").GetString() ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, fixture.Factory.AuthenticatedBusinessRequests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.Equal(0, fixture.Transport.TotalSoapRequests);

        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "missing-execute", HttpStatusCode.Conflict, "BGW-EGRESS-AUTHENTICATION");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "throwing-execute", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        await AssertFailedWithoutExtensionLeakAsync(fixture, identity, connectorId, "fake-cancel-execute", HttpStatusCode.BadGateway, "BGW-EGRESS-UPSTREAM-REJECTED");
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.Equal(0, fixture.Transport.TotalSoapRequests);
        string logs = string.Join('\n', fixture.Factory.Logs);
        Assert.DoesNotContain("synthetic-extension-diagnostic-canary", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-fake-cancellation-canary", logs, StringComparison.Ordinal);
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

    private static string Definition(string connectorId) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"1.0.0","displayName":"Synthetic external execution seam",
          "bindings":{"endpoints":[{"name":"soap"}],"secrets":[{"name":"username","kind":"username"},{"name":"password","kind":"password"},{"name":"session","kind":"opaque"}]},
          "operations":[
            {"operationId":"external-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"basic","usernameBinding":"username","passwordBinding":"password"},"executionStrategy":"synthetic-echo","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"fake-cancel-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"opaqueSessionHttp","policyId":"synthetic-session-policy","sessionProfileId":"synthetic-session-profile","secretBinding":"session","headerName":"X-Synthetic-Session","valueFormat":"rawOpaqueValue"},"executionStrategy":"synthetic-fake-cancel","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"missing-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"not-installed","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"throwing-execute","endpointBinding":"soap","method":"POST","path":"/unused","request":{"contentType":"application/json","maximumBytes":32768},"response":{"maximumBytes":32768},"authentication":{"kind":"none"},"executionStrategy":"synthetic-throw","timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0}
          ]
        }
        """;
}

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class GatewayApiTests : IClassFixture<GatewayApiFactory>
{
    private readonly HttpClient client;
    private readonly GatewayApiFactory factory;

    public GatewayApiTests(GatewayApiFactory factory)
    {
        this.factory = factory;
        client = factory.CreateClient();
    }

    [Fact]
    public async Task IT_GTW_Liveness_and_readiness_are_available()
    {
        using HttpResponseMessage live = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);
        using HttpResponseMessage ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
    }

    [Fact]
    public async Task IT_GTW_Runtime_without_client_certificate_returns_sanitized_problem()
    {
        using HttpResponseMessage response = await client.GetAsync("/v1/broker-policy", TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("BGW-AUTHN-CERTIFICATE-REQUIRED", body, StringComparison.Ordinal);
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GatewayException", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details()
    {
        const string canary = "M2_SECRET_CANARY_NEVER_ECHO";
        using HttpResponseMessage response = await client.PostAsJsonAsync("/v1/enrollments/challenges", new { activationCodeId = Guid.NewGuid(), publicKeySpki = "AA", unexpected = canary }, TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonException", body, StringComparison.Ordinal);
        Assert.Contains("BGW-PROTOCOL", body, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, string.Join('\n', factory.Logs), StringComparison.Ordinal);
    }

    [Fact]
    public async Task M4_IT_Admin_API_requires_key_and_supports_import_validate_publish_export_and_test()
    {
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Samples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        string connectorId = "sample-" + Guid.NewGuid().ToString("N");
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ConnectorImportRequest importRequest = new(definition.RootElement.Clone());

        using HttpResponseMessage unauthenticated = await client.PostAsJsonAsync("/admin/v1/connectors:validate", importRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        client.DefaultRequestHeaders.Add("X-Admin-Key", GatewayApiFactory.AdminKey);
        client.DefaultRequestHeaders.Add("X-Admin-Actor", "m4-integration-test");
        using HttpResponseMessage validation = await client.PostAsJsonAsync("/admin/v1/connectors:validate", importRequest, TestContext.Current.CancellationToken);
        ConnectorValidationResult validationResult = (await validation.Content.ReadFromJsonAsync<ConnectorValidationResult>(cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.True(validationResult.Valid);

        using HttpResponseMessage importedResponse = await client.PostAsJsonAsync("/admin/v1/connectors:import", importRequest with { ExpectedChecksumSha256 = validationResult.ChecksumSha256 }, TestContext.Current.CancellationToken);
        ConnectorVersionResource imported = (await importedResponse.Content.ReadFromJsonAsync<ConnectorVersionResource>(cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.Equal(HttpStatusCode.Created, importedResponse.StatusCode);
        Assert.Equal(ConnectorVersionState.Draft, imported.State);

        using HttpResponseMessage validatedResponse = await client.PostAsJsonAsync($"/admin/v1/connectors/{connectorId}/versions/1.0.0:validate", new ConnectorVersionActionRequest(imported.RowVersion), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = (await validatedResponse.Content.ReadFromJsonAsync<ConnectorVersionResource>(cancellationToken: TestContext.Current.CancellationToken))!;
        using HttpResponseMessage publishedResponse = await client.PostAsJsonAsync($"/admin/v1/connectors/{connectorId}/versions/1.0.0:publish", new ConnectorVersionActionRequest(validated.RowVersion, 0), TestContext.Current.CancellationToken);
        ConnectorVersionResource published = (await publishedResponse.Content.ReadFromJsonAsync<ConnectorVersionResource>(cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.Equal(ConnectorVersionState.Published, published.State);

        Guid environmentId = Guid.NewGuid();
        using HttpResponseMessage bindingResponse = await client.PutAsJsonAsync($"/admin/v1/connectors/{connectorId}/bindings", new ConnectorBindingRequest(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://api-key", ["sample-vendor-client-certificate"] = "synthetic://certificate" }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, bindingResponse.StatusCode);
        using HttpResponseMessage testResponse = await client.PostAsJsonAsync($"/admin/v1/connectors/{connectorId}:test", new ConnectorTestRequest(environmentId, "submit"), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, testResponse.StatusCode);

        using HttpResponseMessage exportResponse = await client.GetAsync($"/admin/v1/connectors/{connectorId}/versions/1.0.0:export", TestContext.Current.CancellationToken);
        string exported = await exportResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(validationResult.ChecksumSha256, ConnectorCanonicalJson.Checksum(exported));
        Assert.DoesNotContain("synthetic://api-key", exported, StringComparison.Ordinal);
        Assert.DoesNotContain(GatewayApiFactory.AdminKey, string.Join('\n', factory.Logs), StringComparison.Ordinal);
    }
}

public sealed class GatewayM3TestingStartupTests
{
    [Fact]
    public async Task IT_M3_Gateway_starts_with_per_run_HMAC_only_in_explicit_M3Testing_environment()
    {
        const string tokenVariable = "M3_REGRESSION_SYNTHETIC_VAULT_TOKEN";
        Environment.SetEnvironmentVariable(tokenVariable, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), EnvironmentVariableTarget.Process);
        try
        {
            await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("M3Testing");
                builder.UseSetting("ConnectionStrings:GatewayDatabase", "Host=127.0.0.1;Port=1;Database=m3_regression;Username=unused;Password=unused;Timeout=1");
                builder.UseSetting("Gateway:SyntheticVaultUri", "https://vault.m3.test/");
                builder.UseSetting("Gateway:SyntheticVaultTokenEnvironmentVariable", tokenVariable);
                builder.UseSetting("Gateway:ActivationHmacKeyBase64", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            });
            using HttpClient client = factory.CreateClient();
            using HttpResponseMessage response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable(tokenVariable, null, EnvironmentVariableTarget.Process);
        }
    }
}

public sealed class GatewayApiFactory : WebApplicationFactory<Program>
{
    public const string AdminKey = "M4-DEVELOPMENT-ADMIN-KEY-TEST-ONLY";
    private readonly RecordingLoggerProvider loggerProvider = new();
    public IReadOnlyCollection<string> Logs => loggerProvider.Messages;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Environment.SetEnvironmentVariable("M4_GATEWAY_ADMIN_TEST_KEY", AdminKey, EnvironmentVariableTarget.Process);
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentApiKey");
        builder.UseSetting("Gateway:Admin:ApiKeyEnvironmentVariable", "M4_GATEWAY_ADMIN_TEST_KEY");
        builder.ConfigureServices(services => services.AddSingleton<ILoggerProvider>(loggerProvider));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Environment.SetEnvironmentVariable("M4_GATEWAY_ADMIN_TEST_KEY", null, EnvironmentVariableTarget.Process);
    }
}

internal sealed class RecordingLoggerProvider : ILoggerProvider
{
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> messages = new();
    internal IReadOnlyCollection<string> Messages => messages.ToArray();
    public ILogger CreateLogger(string categoryName) => new RecordingLogger(messages);
    public void Dispose() { }

    private sealed class RecordingLogger(System.Collections.Concurrent.ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
    }
}

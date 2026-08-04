using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

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
}

public sealed class GatewayApiFactory : WebApplicationFactory<Program>
{
    private readonly RecordingLoggerProvider loggerProvider = new();
    public IReadOnlyCollection<string> Logs => loggerProvider.Messages;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services => services.AddSingleton<ILoggerProvider>(loggerProvider));
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

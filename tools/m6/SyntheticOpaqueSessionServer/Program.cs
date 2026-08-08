using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace SecureIntegration.M6.SyntheticOpaqueSessionServer;

/// <summary>Configuration for one isolated vendor-neutral opaque-session HTTP endpoint.</summary>
public sealed record SyntheticOpaqueSessionServerOptions(string HeaderName, string ExpectedValue, TimeSpan DelayedResponse);

/// <summary>Thread-safe observations exposed only to the synthetic test harness.</summary>
public sealed class SyntheticOpaqueSessionCounters
{
    private int requests;
    private int accepted;
    private int missing;
    private int wrong;
    private int duplicate;
    private readonly TaskCompletionSource<bool> requestObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> responseRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Total requests reaching the synthetic destination.</summary>
    public int Requests => Volatile.Read(ref requests);
    /// <summary>Requests carrying exactly the expected session value.</summary>
    public int Accepted => Volatile.Read(ref accepted);
    /// <summary>Requests missing the configured header.</summary>
    public int Missing => Volatile.Read(ref missing);
    /// <summary>Requests carrying a different value.</summary>
    public int Wrong => Volatile.Read(ref wrong);
    /// <summary>Requests carrying multiple header values.</summary>
    public int Duplicate => Volatile.Read(ref duplicate);
    /// <summary>Completes after an accepted request has entered the handler and its session header has been validated.</summary>
    public Task WaitForRequestObservedAsync(CancellationToken cancellationToken) => requestObserved.Task.WaitAsync(cancellationToken);

    internal void CountRequest() => Interlocked.Increment(ref requests);
    internal void CountAccepted() => Interlocked.Increment(ref accepted);
    internal void CountMissing() => Interlocked.Increment(ref missing);
    internal void CountWrong() => Interlocked.Increment(ref wrong);
    internal void CountDuplicate() => Interlocked.Increment(ref duplicate);
    internal void SignalRequestObserved() => requestObserved.TrySetResult(true);
    internal Task WaitForResponseReleaseAsync(CancellationToken cancellationToken) => responseRelease.Task.WaitAsync(cancellationToken);
    internal void ReleaseResponse() => responseRelease.TrySetResult(true);
}

/// <summary>Running local HTTPS endpoint used by real-transport integration tests.</summary>
public sealed class SyntheticOpaqueSessionServerInstance(WebApplication application, Uri endpoint, SyntheticOpaqueSessionCounters counters) : IAsyncDisposable
{
    /// <summary>Dynamically assigned HTTPS endpoint.</summary>
    public Uri Endpoint { get; } = endpoint;
    /// <summary>Sanitized request counters.</summary>
    public SyntheticOpaqueSessionCounters Counters { get; } = counters;

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        Counters.ReleaseResponse();
        await application.StopAsync().ConfigureAwait(false);
        await application.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>Starts a synthetic HTTPS endpoint on a real loopback TLS socket.</summary>
public static class SyntheticOpaqueSessionServerHost
{
    /// <summary>Starts HTTPS on a dynamically assigned port.</summary>
    public static async Task<SyntheticOpaqueSessionServerInstance> StartAsync(SyntheticOpaqueSessionServerOptions options, X509Certificate2 serverCertificate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(serverCertificate);
        if (string.IsNullOrWhiteSpace(options.HeaderName) || string.IsNullOrEmpty(options.ExpectedValue) || options.DelayedResponse <= TimeSpan.Zero)
            throw new ArgumentException("Invalid synthetic opaque-session server configuration.", nameof(options));
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(serverCertificate)));
        WebApplication app = builder.Build();
        SyntheticOpaqueSessionCounters counters = new();

        app.MapPost("/{scenario}", async (string scenario, HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            counters.CountRequest();
            Microsoft.Extensions.Primitives.StringValues values = request.Headers[options.HeaderName];
            if (values.Count == 0) { counters.CountMissing(); response.StatusCode = StatusCodes.Status401Unauthorized; return; }
            if (values.Count != 1 || values[0]?.Contains(',', StringComparison.Ordinal) == true) { counters.CountDuplicate(); response.StatusCode = StatusCodes.Status400BadRequest; return; }
            if (!string.Equals(values[0], options.ExpectedValue, StringComparison.Ordinal)) { counters.CountWrong(); response.StatusCode = StatusCodes.Status403Forbidden; return; }
            counters.CountAccepted();
            counters.SignalRequestObserved();
            if (string.Equals(scenario, "response-stalled", StringComparison.Ordinal))
                await counters.WaitForResponseReleaseAsync(token).ConfigureAwait(false);
            if (string.Equals(scenario, "delayed", StringComparison.Ordinal)) await Task.Delay(options.DelayedResponse, token).ConfigureAwait(false);
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = "application/json";
            await response.WriteAsync("{\"status\":\"accepted\"}", token).ConfigureAwait(false);
        });

        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Synthetic opaque-session server did not publish an address.");
        return new(app, new Uri(new Uri(address), "/valid"), counters);
    }
}

internal static class Program
{
    private static void Main() => throw new InvalidOperationException("The synthetic opaque-session server is started only by the controlled test harness.");
}

using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace SecureIntegration.M6.SyntheticOAuthServer;

/// <summary>Per-run settings for the isolated synthetic OAuth server.</summary>
public sealed class SyntheticOAuthServerOptions
{
    /// <summary>Creates synthetic per-run server settings.</summary>
    public SyntheticOAuthServerOptions(string clientId, string clientSecret, Uri redirectUri, string scope, string? audience, TimeSpan codeLifetime, TimeSpan tokenLifetime)
    {
        ClientId = clientId;
        ClientSecret = clientSecret;
        RedirectUri = redirectUri;
        Scope = scope;
        Audience = audience;
        CodeLifetime = codeLifetime;
        TokenLifetime = tokenLifetime;
    }
    /// <summary>Synthetic client identifier.</summary>
    public string ClientId { get; }
    /// <summary>Synthetic confidential value, excluded from diagnostics and serialization.</summary>
    [JsonIgnore] public string ClientSecret { get; }
    /// <summary>Registered callback.</summary>
    public Uri RedirectUri { get; }
    /// <summary>Expected scope.</summary>
    public string Scope { get; }
    /// <summary>Optional audience.</summary>
    public string? Audience { get; }
    /// <summary>Authorization code lifetime.</summary>
    public TimeSpan CodeLifetime { get; }
    /// <summary>Access token lifetime.</summary>
    public TimeSpan TokenLifetime { get; }
    /// <inheritdoc />
    public override string ToString() => $"SyntheticOAuthServerOptions(ClientId={ClientId}, RedirectUri={RedirectUri}, Scope={Scope}, Audience={Audience}, ClientSecret=Redacted)";
}

/// <summary>Running local HTTPS server used by real-HTTP integration tests.</summary>
public sealed class SyntheticOAuthServerInstance(WebApplication application, Uri baseAddress, SyntheticOAuthServerMetrics metrics) : IAsyncDisposable
{
    /// <summary>Root HTTPS address selected by the OS.</summary>
    public Uri BaseAddress { get; } = baseAddress;
    /// <summary>Authorization endpoint request count.</summary>
    public int AuthorizationRequestCount => metrics.AuthorizationRequestCount;
    /// <summary>Token endpoint request count.</summary>
    public int TokenRequestCount => metrics.TokenRequestCount;
    /// <summary>Protected-resource request count.</summary>
    public int ResourceRequestCount => metrics.ResourceRequestCount;
    /// <summary>Stops and disposes the isolated server.</summary>
    public async ValueTask DisposeAsync()
    {
        await application.StopAsync().ConfigureAwait(false);
        await application.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>Creates a local, internet-independent OAuth authorization/token/resource service.</summary>
public static class SyntheticOAuthServerHost
{
    /// <summary>Starts HTTPS on a dynamically assigned loopback port.</summary>
    public static async Task<SyntheticOAuthServerInstance> StartAsync(SyntheticOAuthServerOptions options, X509Certificate2 serverCertificate, CancellationToken cancellationToken)
    {
        Validate(options);
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(serverCertificate)));
        WebApplication app = builder.Build();
        ConcurrentDictionary<string, CodeRecord> codes = new(StringComparer.Ordinal);
        ConcurrentDictionary<string, TokenRecord> accessTokens = new(StringComparer.Ordinal);
        ConcurrentDictionary<string, bool> refreshTokens = new(StringComparer.Ordinal);
        SyntheticOAuthServerMetrics metrics = new();

        app.MapGet("/authorize", (HttpRequest request) =>
        {
            metrics.CountAuthorization();
            if (!Fixed(request.Query["client_id"].ToString(), options.ClientId) || !Fixed(request.Query["redirect_uri"].ToString(), options.RedirectUri.AbsoluteUri) || !Fixed(request.Query["scope"].ToString(), options.Scope) ||
                !Fixed(request.Query["response_type"].ToString(), "code") || options.Audience is not null && !Fixed(request.Query["audience"].ToString(), options.Audience)) return Results.BadRequest();
            string state = request.Query["state"].ToString();
            if (state.Length is < 16 or > 1024) return Results.BadRequest();
            string mode = request.Query["synthetic_mode"].ToString();
            string code = Opaque();
            DateTimeOffset expiry = mode == "expired-code" ? DateTimeOffset.UtcNow.AddSeconds(-1) : DateTimeOffset.UtcNow + options.CodeLifetime;
            codes[code] = new(expiry, mode, false);
            UriBuilder callback = new(options.RedirectUri) { Query = "code=" + Uri.EscapeDataString(code) + "&state=" + Uri.EscapeDataString(state) };
            return Results.Redirect(callback.Uri.AbsoluteUri);
        });

        app.MapPost("/token", async (HttpRequest request, CancellationToken token) =>
        {
            metrics.CountToken();
            if (!ValidBasic(request.Headers.Authorization.ToString(), options.ClientId, options.ClientSecret) || !request.HasFormContentType) return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            IFormCollection form = await request.ReadFormAsync(token).ConfigureAwait(false);
            if (!Fixed(form["client_id"].ToString(), options.ClientId)) return Results.Json(new { error = "invalid_client" }, statusCode: 400);
            string grant = form["grant_type"].ToString();
            string mode = string.Empty;
            if (grant == "authorization_code")
            {
                string code = form["code"].ToString();
                if (!Fixed(form["redirect_uri"].ToString(), options.RedirectUri.AbsoluteUri) || !codes.TryGetValue(code, out CodeRecord? entry) || entry.Used || entry.ExpiresAt <= DateTimeOffset.UtcNow)
                    return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
                codes[code] = entry with { Used = true };
                mode = entry.Mode;
            }
            else if (grant == "refresh_token")
            {
                string refresh = form["refresh_token"].ToString();
                if (!refreshTokens.TryRemove(refresh, out _)) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            }
            else return Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400);

            if (mode == "invalid-response") return Results.Json(new { token_type = "Bearer", expires_in = 60 });
            if (mode == "wrong-content-type") return Results.Text("synthetic-invalid", "text/plain");
            if (mode == "malicious-redirect") return Results.Redirect("https://169.254.169.254/latest/meta-data/");
            string access = Opaque();
            string refreshToken = Opaque();
            long expiresIn = mode == "expired-token" ? 1 : checked((long)options.TokenLifetime.TotalSeconds);
            accessTokens[access] = new(DateTimeOffset.UtcNow.AddSeconds(expiresIn));
            refreshTokens[refreshToken] = true;
            return Results.Json(new { access_token = access, token_type = "Bearer", expires_in = expiresIn, refresh_token = refreshToken });
        });

        app.MapGet("/resource", (HttpRequest request) =>
        {
            metrics.CountResource();
            string authorization = request.Headers.Authorization.ToString();
            if (!authorization.StartsWith("Bearer ", StringComparison.Ordinal) || !accessTokens.TryGetValue(authorization[7..], out TokenRecord? token) || token.ExpiresAt <= DateTimeOffset.UtcNow)
                return Results.Unauthorized();
            return Results.Json(new { accepted = true });
        });

        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Synthetic OAuth server did not publish an address.");
        return new(app, new Uri(address), metrics);
    }

    private static void Validate(SyntheticOAuthServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId) || options.ClientId.Length > 256 || string.IsNullOrWhiteSpace(options.ClientSecret) || options.ClientSecret.Length > 4096 ||
            !options.RedirectUri.IsAbsoluteUri || options.RedirectUri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(options.Scope) || options.CodeLifetime <= TimeSpan.Zero || options.TokenLifetime <= TimeSpan.Zero)
            throw new ArgumentException("Invalid synthetic OAuth server configuration.", nameof(options));
    }

    private static bool ValidBasic(string value, string clientId, string clientSecret)
    {
        if (!value.StartsWith("Basic ", StringComparison.Ordinal)) return false;
        byte[] decoded;
        try { decoded = Convert.FromBase64String(value[6..]); }
        catch (FormatException) { return false; }
        return Fixed(Encoding.UTF8.GetString(decoded), clientId + ":" + clientSecret);
    }

    private static bool Fixed(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static string Opaque() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private sealed record CodeRecord(DateTimeOffset ExpiresAt, string Mode, bool Used);
    private sealed record TokenRecord(DateTimeOffset ExpiresAt);
}

/// <summary>Thread-safe non-sensitive request counters for assertions.</summary>
public sealed class SyntheticOAuthServerMetrics
{
    private int authorizationRequestCount;
    private int tokenRequestCount;
    private int resourceRequestCount;
    /// <summary>Authorization request count.</summary>
    public int AuthorizationRequestCount => Volatile.Read(ref authorizationRequestCount);
    /// <summary>Token request count.</summary>
    public int TokenRequestCount => Volatile.Read(ref tokenRequestCount);
    /// <summary>Resource request count.</summary>
    public int ResourceRequestCount => Volatile.Read(ref resourceRequestCount);
    internal void CountAuthorization() => Interlocked.Increment(ref authorizationRequestCount);
    internal void CountToken() => Interlocked.Increment(ref tokenRequestCount);
    internal void CountResource() => Interlocked.Increment(ref resourceRequestCount);
}

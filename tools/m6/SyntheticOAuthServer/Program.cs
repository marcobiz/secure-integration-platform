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
    public SyntheticOAuthServerOptions(string clientId, string clientSecret, Uri redirectUri, string scope, string? audience, TimeSpan codeLifetime, TimeSpan tokenLifetime,
        bool requirePkceS256 = false, string? resource = null, string? clientCredentialsMode = null)
    {
        ClientId = clientId;
        ClientSecret = clientSecret;
        RedirectUri = redirectUri;
        Scope = scope;
        Audience = audience;
        CodeLifetime = codeLifetime;
        TokenLifetime = tokenLifetime;
        RequirePkceS256 = requirePkceS256;
        Resource = resource;
        ClientCredentialsMode = clientCredentialsMode;
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
    /// <summary>Requires RFC 7636 S256 for authorization-code issue and exchange.</summary>
    public bool RequirePkceS256 { get; }
    /// <summary>Optional expected RFC 8707 resource parameter.</summary>
    public string? Resource { get; }
    /// <summary>Test-only response behavior for Client Credentials.</summary>
    [JsonIgnore] public string? ClientCredentialsMode { get; }
    /// <inheritdoc />
    public override string ToString() => $"SyntheticOAuthServerOptions(ClientId={ClientId}, RedirectUri={RedirectUri}, Scope={Scope}, Audience={Audience}, Resource={Resource}, RequirePkceS256={RequirePkceS256}, ClientSecret=Redacted)";
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
            string? codeChallenge = null;
            if (options.RequirePkceS256)
            {
                codeChallenge = request.Query["code_challenge"].ToString();
                if (!Fixed(request.Query["code_challenge_method"].ToString(), "S256") || !ValidChallenge(codeChallenge)) return Results.BadRequest();
            }
            else if (!string.IsNullOrEmpty(request.Query["code_challenge"].ToString()) || !string.IsNullOrEmpty(request.Query["code_challenge_method"].ToString())) return Results.BadRequest();
            string mode = request.Query["synthetic_mode"].ToString();
            string code = Opaque();
            DateTimeOffset expiry = mode == "expired-code" ? DateTimeOffset.UtcNow.AddSeconds(-1) : DateTimeOffset.UtcNow + options.CodeLifetime;
            codes[code] = new(expiry, mode, false, codeChallenge);
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
                string verifier = form["code_verifier"].ToString();
                if (options.RequirePkceS256 && (!ValidVerifier(verifier) || !Fixed(S256(verifier), entry.CodeChallenge!)) || !options.RequirePkceS256 && !string.IsNullOrEmpty(verifier))
                    return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
                mode = entry.Mode;
            }
            else if (grant == "refresh_token")
            {
                string refresh = form["refresh_token"].ToString();
                if (!refreshTokens.TryRemove(refresh, out _)) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            }
            else if (grant == "client_credentials")
            {
                if (!Fixed(form["scope"].ToString(), options.Scope) || options.Audience is not null && !Fixed(form["audience"].ToString(), options.Audience) ||
                    options.Resource is not null && !Fixed(form["resource"].ToString(), options.Resource))
                    return Results.Json(new { error = "invalid_scope" }, statusCode: 400);
                mode = options.ClientCredentialsMode ?? string.Empty;
            }
            else return Results.Json(new { error = "unsupported_grant_type" }, statusCode: 400);

            if (mode == "invalid-response") return Results.Json(new { token_type = "Bearer", expires_in = 60 });
            if (mode == "wrong-content-type") return Results.Text("synthetic-invalid", "text/plain");
            if (mode == "malicious-redirect") return Results.Redirect("https://169.254.169.254/latest/meta-data/");
            string access = Opaque();
            string refreshToken = Opaque();
            long expiresIn = mode == "expired-token" ? 1 : checked((long)options.TokenLifetime.TotalSeconds);
            accessTokens[access] = new(DateTimeOffset.UtcNow.AddSeconds(expiresIn));
            if (grant == "client_credentials") return Results.Json(new { access_token = access, token_type = "Bearer", expires_in = expiresIn });
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
            !options.RedirectUri.IsAbsoluteUri || options.RedirectUri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(options.Scope) || options.CodeLifetime <= TimeSpan.Zero || options.TokenLifetime <= TimeSpan.Zero ||
            options.Resource is { Length: > 256 } || options.ClientCredentialsMode is not (null or "invalid-response" or "wrong-content-type" or "expired-token" or "malicious-redirect"))
            throw new ArgumentException("Invalid synthetic OAuth server configuration.", nameof(options));
    }

    private static bool ValidBasic(string value, string clientId, string clientSecret)
    {
        if (!value.StartsWith("Basic ", StringComparison.Ordinal)) return false;
        byte[] decoded;
        try { decoded = Convert.FromBase64String(value[6..]); }
        catch (FormatException) { return false; }
        string credentials = Encoding.UTF8.GetString(decoded);
        int separator = credentials.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0) return false;
        try { return Fixed(FormDecode(credentials[..separator]), clientId) && Fixed(FormDecode(credentials[(separator + 1)..]), clientSecret); }
        catch (UriFormatException) { return false; }
    }

    private static string FormDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

    private static bool Fixed(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static string Opaque() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static bool ValidVerifier(string value) => value.Length is >= 43 and <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~');
    private static bool ValidChallenge(string value) => value.Length == 43 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    private static string S256(string verifier) => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private sealed record CodeRecord(DateTimeOffset ExpiresAt, string Mode, bool Used, string? CodeChallenge);
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

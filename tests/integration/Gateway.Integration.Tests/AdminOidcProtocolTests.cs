using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SecureIntegration.Gateway.Api;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class AdminOidcProtocolTests
{
    [Fact]
    public async Task ADMIN_RATE_LIMIT_OIDC_pre_and_post_auth_partitions_are_correct()
    {
        await using SyntheticOidcFactory factory = new(authPermitLimit: 2, apiPermitLimit: 3);
        using HttpClient client = factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        (string state, string nonce, _) = await BeginAsync(client);
        factory.Backchannel.Nonce = nonce;
        using HttpResponseMessage callback = await CallbackAsync(client, state);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);

        using HttpResponseMessage firstMe = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        firstMe.EnsureSuccessStatusCode();
        using HttpResponseMessage csrf = await client.GetAsync("/admin/auth/csrf", TestContext.Current.CancellationToken);
        csrf.EnsureSuccessStatusCode();

        using HttpResponseMessage exhaustedAuth = await client.GetAsync("/admin/auth/login", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhaustedAuth.StatusCode);

        using HttpResponseMessage secondMe = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        secondMe.EnsureSuccessStatusCode();
        using HttpResponseMessage exhaustedApi = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhaustedApi.StatusCode);
    }

    [Fact]
    public async Task M5_IT_AUTH_OIDC_code_PKCE_state_nonce_cookie_rotation_logout_and_replay()
    {
        await using SyntheticOidcFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });

        (string state, string nonce, string challenge) = await BeginAsync(client);
        factory.Backchannel.Nonce = nonce;
        using HttpResponseMessage callback = await CallbackAsync(client, state);
        Assert.True(callback.StatusCode == HttpStatusCode.Redirect, $"OIDC callback returned {(int)callback.StatusCode}: {factory.Backchannel.RemoteFailure}");
        Assert.Equal("/admin", callback.Headers.Location?.OriginalString);
        string adminCookie = Assert.Single(callback.Headers.GetValues("Set-Cookie"), value => value.StartsWith("__Host-SecureIntegration.Admin=", StringComparison.Ordinal));
        Assert.Contains("secure", adminCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", adminCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", adminCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", adminCookie, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(factory.Backchannel.CodeVerifier));
        Assert.Equal(challenge, Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(factory.Backchannel.CodeVerifier!))));

        using HttpResponseMessage me = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        string oldCookie = adminCookie.Split(';', 2)[0];
        string csrf = (await client.GetFromJsonAsync<JsonElement>("/admin/auth/csrf", TestContext.Current.CancellationToken)).GetProperty("token").GetString()!;
        using HttpRequestMessage logoutRequest = new(HttpMethod.Post, "/admin/auth/logout");
        logoutRequest.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage logout = await client.SendAsync(logoutRequest, TestContext.Current.CancellationToken);
        Assert.True(logout.StatusCode is HttpStatusCode.NoContent or HttpStatusCode.Redirect);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false });
        using HttpRequestMessage replayRequest = new(HttpMethod.Get, "/admin/auth/me");
        replayRequest.Headers.Add("Cookie", oldCookie);
        replayRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage replayResponse = await replay.SendAsync(replayRequest, TestContext.Current.CancellationToken);
        Assert.True(replayResponse.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Redirect);
    }

    [Fact]
    public async Task M5_IT_AUTH_OIDC_rejects_invalid_state_nonce_and_issuer()
    {
        await AssertCallbackRejectedAsync(static (factory, state, nonce) => (state + "tampered", nonce));
        await AssertCallbackRejectedAsync(static (factory, state, nonce) => { factory.Backchannel.Nonce = "wrong-nonce"; return (state, nonce); });
        await AssertCallbackRejectedAsync(static (factory, state, nonce) => { factory.Backchannel.Issuer = "https://wrong-issuer.example.test"; return (state, nonce); });
    }

    private static async Task AssertCallbackRejectedAsync(Func<SyntheticOidcFactory, string, string, (string State, string Nonce)> mutate)
    {
        await using SyntheticOidcFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
        (string state, string nonce, _) = await BeginAsync(client);
        factory.Backchannel.Nonce = nonce;
        (state, _) = mutate(factory, state, nonce);
        using HttpResponseMessage callback = await CallbackAsync(client, state);
        Assert.True((int)callback.StatusCode >= 400, $"OIDC callback unexpectedly returned {(int)callback.StatusCode}.");
        using HttpRequestMessage meRequest = new(HttpMethod.Get, "/admin/auth/me");
        meRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage me = await client.SendAsync(meRequest, TestContext.Current.CancellationToken);
        Assert.True(me.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Redirect);
    }

    private static async Task<(string State, string Nonce, string Challenge)> BeginAsync(HttpClient client)
    {
        using HttpResponseMessage response = await client.GetAsync("/admin/auth/login", TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Redirect, $"OIDC challenge returned {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        Uri location = response.Headers.Location ?? throw new InvalidOperationException("OIDC authorization redirect missing.");
        Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", query["response_type"].ToString());
        Assert.Equal("S256", query["code_challenge_method"].ToString());
        Assert.Equal("m5-admin", query["client_id"].ToString());
        Assert.Equal("form_post", query["response_mode"].ToString());
        return (query["state"].ToString(), query["nonce"].ToString(), query["code_challenge"].ToString());
    }

    private static async Task<HttpResponseMessage> CallbackAsync(HttpClient client, string state)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/signin-oidc") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "synthetic-code", ["state"] = state }) };
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }
}

public sealed class SyntheticOidcFactory : WebApplicationFactory<Program>
{
    private const string SecretVariable = "M5_SYNTHETIC_OIDC_CLIENT_SECRET";
    private readonly int? authPermitLimit;
    private readonly int? apiPermitLimit;
    public SyntheticOidcBackchannel Backchannel { get; } = new();

    public SyntheticOidcFactory(int? authPermitLimit = null, int? apiPermitLimit = null)
    {
        this.authPermitLimit = authPermitLimit;
        this.apiPermitLimit = apiPermitLimit;
        Environment.SetEnvironmentVariable(SecretVariable, "synthetic-client-secret", EnvironmentVariableTarget.Process);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "Oidc");
        builder.UseSetting("Gateway:Admin:Oidc:Authority", SyntheticOidcBackchannel.CorrectIssuer);
        builder.UseSetting("Gateway:Admin:Oidc:ClientId", "m5-admin");
        builder.UseSetting("Gateway:Admin:Oidc:ClientSecretEnvironmentVariable", SecretVariable);
        builder.UseSetting("Gateway:Admin:Oidc:CallbackPath", "/signin-oidc");
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>>(new SyntheticOidcPostConfigure(Backchannel));
            if (authPermitLimit is not null && apiPermitLimit is not null)
            {
                services.Configure<RateLimiterOptions>(options =>
                    options.GlobalLimiter = AdminRateLimiting.CreateGlobalLimiter(
                        authPermitLimit.Value,
                        apiPermitLimit.Value,
                        TimeSpan.FromMinutes(1),
                        "/signin-oidc"));
            }
        });
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Environment.SetEnvironmentVariable(SecretVariable, null, EnvironmentVariableTarget.Process);
        GC.SuppressFinalize(this);
    }
}

public sealed class SyntheticOidcPostConfigure(SyntheticOidcBackchannel backchannel) : IPostConfigureOptions<OpenIdConnectOptions>
{
    public void PostConfigure(string? name, OpenIdConnectOptions options)
    {
        if (!string.Equals(name, OpenIdConnectDefaults.AuthenticationScheme, StringComparison.Ordinal)) return;
        OpenIdConnectConfiguration configuration = new()
        {
            Issuer = SyntheticOidcBackchannel.CorrectIssuer,
            AuthorizationEndpoint = SyntheticOidcBackchannel.CorrectIssuer + "/authorize",
            TokenEndpoint = SyntheticOidcBackchannel.CorrectIssuer + "/token",
            EndSessionEndpoint = SyntheticOidcBackchannel.CorrectIssuer + "/logout"
        };
        configuration.SigningKeys.Add(backchannel.SigningKey);
        options.Configuration = configuration;
        options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
        options.BackchannelHttpHandler = backchannel;
        options.Backchannel = new HttpClient(backchannel) { Timeout = TimeSpan.FromSeconds(10) };
        options.RequireHttpsMetadata = true;
        options.Events.OnRemoteFailure = context =>
        {
            backchannel.RemoteFailure = context.Failure;
            context.HandleResponse();
            context.Response.StatusCode = 418;
            return Task.CompletedTask;
        };
    }
}

public sealed class SyntheticOidcBackchannel : HttpMessageHandler
{
    public const string CorrectIssuer = "https://synthetic-oidc.example.test";
    private readonly RSA rsa = RSA.Create(2048);
    public RsaSecurityKey SigningKey { get; }
    public string Issuer { get; set; } = CorrectIssuer;
    public string? Nonce { get; set; }
    public string? CodeVerifier { get; private set; }
    public Exception? RemoteFailure { get; set; }

    public SyntheticOidcBackchannel() => SigningKey = new RsaSecurityKey(rsa) { KeyId = "m5-synthetic" };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Dictionary<string, Microsoft.Extensions.Primitives.StringValues> form = QueryHelpers.ParseQuery("?" + body);
        CodeVerifier = form["code_verifier"].ToString();
        JsonWebTokenHandler handler = new();
        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = "m5-admin",
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "synthetic-subject", ["name"] = "Synthetic OIDC user", ["nonce"] = Nonce ?? string.Empty }
        });
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { access_token = "synthetic-access-token", token_type = "Bearer", expires_in = 300, id_token = token })
        };
    }
}

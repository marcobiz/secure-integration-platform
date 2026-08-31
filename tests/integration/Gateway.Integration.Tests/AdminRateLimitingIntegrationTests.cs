using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Api;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class AdminRateLimitingIntegrationTests
{
    private static readonly IPAddress SyntheticRemoteAddress = IPAddress.Parse("192.0.2.25");

    [Fact]
    public async Task ADMIN_RATE_LIMIT_auth_and_api_use_distinct_partitions_for_same_identity()
    {
        DefaultHttpContext auth = Context("/admin/auth/login", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());

        AdminRateLimitPartitionKey authKey = AdminRateLimiting.GetPartitionKey(auth);
        AdminRateLimitPartitionKey apiKey = AdminRateLimiting.GetPartitionKey(api);
        Assert.Equal(AdminRateLimitPolicyClass.Auth, authKey.PolicyClass);
        Assert.Equal(AdminRateLimitPrincipalKind.RemoteIp, authKey.PrincipalKind);
        Assert.Equal(AdminRateLimitPolicyClass.Api, apiKey.PolicyClass);
        Assert.Equal(AdminRateLimitPrincipalKind.AuthenticatedSubject, apiKey.PrincipalKind);
        Assert.NotEqual(authKey, apiKey);

        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 1, TimeSpan.FromMinutes(1));
        Assert.True(await AcquireAsync(limiter, auth));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.False(await AcquireAsync(limiter, auth));
        Assert.False(await AcquireAsync(limiter, api));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_auth_first_does_not_apply_auth_limit_to_admin_api()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 3, TimeSpan.FromMinutes(1));
        DefaultHttpContext auth = Context("/admin/auth/login", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());

        Assert.True(await AcquireAsync(limiter, auth));
        Assert.False(await AcquireAsync(limiter, auth));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.False(await AcquireAsync(limiter, api));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_api_first_does_not_apply_api_limit_to_auth()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 3, TimeSpan.FromMinutes(1));
        DefaultHttpContext auth = Context("/admin/auth/login", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());

        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, auth));
        Assert.False(await AcquireAsync(limiter, auth));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_auth_exhaustion_does_not_throttle_supported_provisioning()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 12, TimeSpan.FromMinutes(1));
        DefaultHttpContext auth = Context("/admin/auth/login", subject: SyntheticRemoteAddress.ToString());

        Assert.True(await AcquireAsync(limiter, auth));
        Assert.False(await AcquireAsync(limiter, auth));
        for (int request = 0; request < 12; request++)
        {
            DefaultHttpContext api = Context(
                $"/admin/api/v1/connectors/synthetic/versions/1.0.{request}",
                subject: SyntheticRemoteAddress.ToString());
            Assert.True(await AcquireAsync(limiter, api));
        }

        TestContext.Current.TestOutputHelper?.WriteLine(
            "TARGET_PRINCIPAL_429_COUNT=1; CROSS_POLICY_REJECTION_COUNT=0");
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_api_exhaustion_does_not_consume_auth_quota()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 2, TimeSpan.FromMinutes(1));
        DefaultHttpContext api = Context("/admin/api/v1/connectors", subject: "synthetic-principal-a");
        DefaultHttpContext auth = Context("/admin/auth/login", subject: "synthetic-principal-a");

        Assert.True(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, api));
        Assert.False(await AcquireAsync(limiter, api));
        Assert.True(await AcquireAsync(limiter, auth));
        TestContext.Current.TestOutputHelper?.WriteLine(
            "TARGET_PRINCIPAL_429_COUNT=1; CROSS_POLICY_REJECTION_COUNT=0");
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_one_authenticated_principal_does_not_throttle_another()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 2, TimeSpan.FromMinutes(1));
        DefaultHttpContext target = Context("/admin/api/v1/connectors", subject: "synthetic-principal-a");
        DefaultHttpContext other = Context("/admin/api/v1/connectors", subject: "synthetic-principal-b");

        Assert.True(await AcquireAsync(limiter, target));
        Assert.True(await AcquireAsync(limiter, target));
        Assert.False(await AcquireAsync(limiter, target));
        Assert.True(await AcquireAsync(limiter, other));
        Assert.True(await AcquireAsync(limiter, other));
        TestContext.Current.TestOutputHelper?.WriteLine(
            "TARGET_PRINCIPAL_429_COUNT=1; OTHER_PRINCIPAL_429_COUNT=0");
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_distinct_authenticated_subjects_have_no_shared_global_bucket()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 1, TimeSpan.FromMinutes(1));
        DefaultHttpContext firstSubject = Context("/admin/api/v1/installations", subject: "synthetic-principal-a");
        DefaultHttpContext secondSubject = Context("/admin/api/v1/installations", subject: "synthetic-principal-b");

        Assert.NotEqual(
            AdminRateLimiting.GetPartitionKey(firstSubject),
            AdminRateLimiting.GetPartitionKey(secondSubject));
        Assert.True(await AcquireAsync(limiter, firstSubject));
        Assert.False(await AcquireAsync(limiter, firstSubject));
        Assert.True(await AcquireAsync(limiter, secondSubject));
        TestContext.Current.TestOutputHelper?.WriteLine(
            "TARGET_PRINCIPAL_429_COUNT=1; OTHER_SUBJECT_429_COUNT=0");
    }

    [Fact]
    public void ADMIN_RATE_LIMIT_pre_auth_endpoints_use_AUTH_remote_ip()
    {
        string[] preAuthenticationPaths =
        [
            "/admin/auth/login",
            "/admin/auth/development/login",
            "/admin/auth/csrf",
            "/signin-oidc"
        ];

        foreach (string path in preAuthenticationPaths)
        {
            AdminRateLimitPartitionKey key = AdminRateLimiting.GetPartitionKey(
                Context(path),
                oidcCallbackPath: "/signin-oidc");
            Assert.Equal(AdminRateLimitPolicyClass.Auth, key.PolicyClass);
            Assert.Equal(AdminRateLimitPrincipalKind.RemoteIp, key.PrincipalKind);
            Assert.Equal(SyntheticRemoteAddress.ToString(), key.Identity);
        }
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_authenticated_session_endpoints_use_API_subject()
    {
        string[] authenticatedPaths =
        [
            "/admin/auth/csrf",
            "/admin/auth/me",
            "/admin/auth/logout",
            "/admin/api/v1/connectors"
        ];
        foreach (string path in authenticatedPaths)
        {
            AdminRateLimitPartitionKey key = AdminRateLimiting.GetPartitionKey(
                Context(path, subject: "synthetic-authenticated-subject"));
            Assert.Equal(AdminRateLimitPolicyClass.Api, key.PolicyClass);
            Assert.Equal(AdminRateLimitPrincipalKind.AuthenticatedSubject, key.PrincipalKind);
            Assert.Equal("synthetic-authenticated-subject", key.Identity);
        }

        await using ReducedRateLimitFactory factory = new(authPermitLimit: 4, apiPermitLimit: 1);
        using HttpClient editor = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true });
        using HttpClient approver = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true });
        await LoginWithoutPostAuthenticationProbeAsync(editor, "editor");
        await LoginWithoutPostAuthenticationProbeAsync(approver, "approver");

        using HttpResponseMessage editorMe = await editor.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        using HttpResponseMessage approverMe = await approver.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        editorMe.EnsureSuccessStatusCode();
        approverMe.EnsureSuccessStatusCode();
    }

    [Fact]
    public void ADMIN_RATE_LIMIT_unknown_auth_endpoint_fails_closed()
    {
        AdminRateLimitPartitionKey key = AdminRateLimiting.GetPartitionKey(
            Context("/admin/auth/future-endpoint", subject: "synthetic-authenticated-subject"));

        Assert.Equal(AdminRateLimitPolicyClass.Auth, key.PolicyClass);
        Assert.Equal(AdminRateLimitPrincipalKind.RemoteIp, key.PrincipalKind);
        Assert.Equal(SyntheticRemoteAddress.ToString(), key.Identity);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_DevelopmentApiKey_does_not_consume_browser_AUTH_quota()
    {
        await using DevelopmentApiKeyRateLimitFactory factory = new();
        using HttpClient apiClient = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        apiClient.DefaultRequestHeaders.Add("X-Admin-Key", DevelopmentApiKeyRateLimitFactory.ApiKey);
        apiClient.DefaultRequestHeaders.Add("X-Admin-Actor", "caller-selected-actor-a");

        using HttpResponseMessage firstApi = await apiClient.GetAsync("/admin/v1/connectors", TestContext.Current.CancellationToken);
        firstApi.EnsureSuccessStatusCode();
        apiClient.DefaultRequestHeaders.Remove("X-Admin-Actor");
        apiClient.DefaultRequestHeaders.Add("X-Admin-Actor", "caller-selected-actor-b");
        using HttpResponseMessage secondApi = await apiClient.GetAsync("/admin/v1/connectors", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, secondApi.StatusCode);

        using HttpClient invalidApiClient = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage invalidApi = await invalidApiClient.GetAsync("/admin/v1/connectors", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, invalidApi.StatusCode);
        using HttpResponseMessage invalidApiExhausted = await invalidApiClient.GetAsync("/admin/v1/connectors", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, invalidApiExhausted.StatusCode);

        using HttpClient browser = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage firstAuth = await browser.GetAsync("/admin/auth/csrf", TestContext.Current.CancellationToken);
        firstAuth.EnsureSuccessStatusCode();
        using HttpResponseMessage secondAuth = await browser.GetAsync("/admin/auth/csrf", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, secondAuth.StatusCode);
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_request_61_is_rejected_without_affecting_another_IP()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter();
        DefaultHttpContext target = Context("/admin/auth/login");
        for (int request = 1; request <= 60; request++)
            Assert.True(await AcquireAsync(limiter, target));
        Assert.False(await AcquireAsync(limiter, target));

        DefaultHttpContext other = Context("/admin/auth/login");
        other.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.25");
        Assert.True(await AcquireAsync(limiter, other));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_request_601_is_rejected_without_affecting_another_subject()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter();
        DefaultHttpContext target = Context("/admin/api/v1/connectors", subject: "synthetic-principal-a");
        for (int request = 1; request <= 600; request++)
            Assert.True(await AcquireAsync(limiter, target));
        Assert.False(await AcquireAsync(limiter, target));

        DefaultHttpContext other = Context("/admin/api/v1/connectors", subject: "synthetic-principal-b");
        Assert.True(await AcquireAsync(limiter, other));
    }

    [Fact]
    public async Task ADMIN_RATE_LIMIT_rejection_returns_bounded_retry_after_and_safe_problem()
    {
        const string callerCanary = "synthetic-caller-metadata-must-not-be-exposed";
        await using ReducedRateLimitFactory factory = new(authPermitLimit: 1, apiPermitLimit: 1);
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using (HttpRequestMessage firstRequest = new(HttpMethod.Get, "/admin/auth/csrf"))
        {
            firstRequest.Headers.Add("X-Forwarded-For", callerCanary);
            using HttpResponseMessage first = await client.SendAsync(firstRequest, TestContext.Current.CancellationToken);
            first.EnsureSuccessStatusCode();
        }
        using HttpRequestMessage rejectedRequest = new(HttpMethod.Get, "/admin/auth/csrf");
        rejectedRequest.Headers.Add("X-Forwarded-For", callerCanary);
        using HttpResponseMessage response = await client.SendAsync(rejectedRequest, TestContext.Current.CancellationToken);

        Assert.Equal(System.Net.HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.TryGetValues("Retry-After", out IEnumerable<string>? retryAfterValues));
        string retryAfter = Assert.Single(retryAfterValues);
        Assert.True(int.TryParse(retryAfter, out int retryAfterSeconds));
        Assert.InRange(retryAfterSeconds, 0, 3600);
        using JsonDocument problem = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(TestContext.Current.CancellationToken),
            cancellationToken: TestContext.Current.CancellationToken);
        JsonElement root = problem.RootElement;
        Assert.Equal(5, root.EnumerateObject().Count());
        Assert.Equal("BGW-RATE-LIMITED", root.GetProperty("code").GetString());
        Assert.Equal(429, root.GetProperty("status").GetInt32());
        Assert.True(root.GetProperty("retryable").GetBoolean());
        string serialized = root.GetRawText();
        Assert.DoesNotContain(callerCanary, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(SyntheticRemoteAddress.ToString(), serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("stack", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("quota", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.False(AdminRateLimiting.TryGetBoundedRetryAfterSeconds(TimeSpan.FromSeconds(-1), out _));
        Assert.False(AdminRateLimiting.TryGetBoundedRetryAfterSeconds(TimeSpan.FromSeconds(3601), out _));
        Assert.True(AdminRateLimiting.TryGetBoundedRetryAfterSeconds(TimeSpan.Zero, out int zero));
        Assert.Equal(0, zero);
        Assert.True(AdminRateLimiting.TryGetBoundedRetryAfterSeconds(TimeSpan.FromHours(1), out int maximum));
        Assert.Equal(3600, maximum);
    }

    [Fact]
    public void ADMIN_RATE_LIMIT_untrusted_forwarded_headers_cannot_select_partition()
    {
        DefaultHttpContext context = Context("/admin/auth/development/login");
        context.Request.Headers["X-Forwarded-For"] = "127.0.0.1";
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        Microsoft.AspNetCore.Builder.ForwardedHeadersOptions forwarding =
            AdminRateLimiting.CreateForwardedHeadersOptions(["198.51.100.10"]);

        AdminRateLimitPartitionKey key = AdminRateLimiting.GetPartitionKey(context);

        Assert.Single(forwarding.KnownProxies);
        Assert.Empty(forwarding.KnownIPNetworks);
        Assert.DoesNotContain(SyntheticRemoteAddress, forwarding.KnownProxies);
        Assert.DoesNotContain(IPAddress.Loopback, forwarding.KnownProxies);
        Assert.Equal(AdminRateLimitPolicyClass.Auth, key.PolicyClass);
        Assert.Equal(AdminRateLimitPrincipalKind.RemoteIp, key.PrincipalKind);
        Assert.Equal(SyntheticRemoteAddress.ToString(), key.Identity);
        Assert.NotEqual(context.Request.Headers["X-Forwarded-For"].ToString(), key.Identity);
    }

    [Fact]
    public void ADMIN_RATE_LIMIT_production_defaults_remain_60_600_one_minute_and_zero_queue()
    {
        FixedWindowRateLimiterOptions auth = AdminRateLimiting.ProductionOptions(AdminRateLimitPolicyClass.Auth);
        FixedWindowRateLimiterOptions api = AdminRateLimiting.ProductionOptions(AdminRateLimitPolicyClass.Api);

        Assert.Equal(60, auth.PermitLimit);
        Assert.Equal(600, api.PermitLimit);
        Assert.Equal(TimeSpan.FromMinutes(1), auth.Window);
        Assert.Equal(TimeSpan.FromMinutes(1), api.Window);
        Assert.Equal(0, auth.QueueLimit);
        Assert.Equal(0, api.QueueLimit);
        Assert.True(auth.AutoReplenishment);
        Assert.True(api.AutoReplenishment);
    }

    private static DefaultHttpContext Context(string path, string? subject = null)
    {
        DefaultHttpContext context = new();
        context.Request.Path = path;
        context.Connection.RemoteIpAddress = SyntheticRemoteAddress;
        if (subject is not null)
        {
            context.User = new ClaimsPrincipal(
                new ClaimsIdentity([new Claim("sub", subject)], authenticationType: "synthetic"));
        }
        return context;
    }

    private static async Task<bool> AcquireAsync(
        PartitionedRateLimiter<HttpContext> limiter,
        HttpContext context)
    {
        using RateLimitLease lease = await limiter.AcquireAsync(
            context,
            permitCount: 1,
            TestContext.Current.CancellationToken);
        return lease.IsAcquired;
    }

    private static async Task LoginWithoutPostAuthenticationProbeAsync(HttpClient client, string user)
    {
        using HttpResponseMessage csrfResponse = await client.GetAsync("/admin/auth/csrf", TestContext.Current.CancellationToken);
        csrfResponse.EnsureSuccessStatusCode();
        JsonElement csrf = await csrfResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        using HttpRequestMessage login = new(HttpMethod.Post, "/admin/auth/development/login")
        {
            Content = JsonContent.Create(new { userName = user })
        };
        login.Headers.Add("X-CSRF-TOKEN", csrf.GetProperty("token").GetString());
        using HttpResponseMessage response = await client.SendAsync(login, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private sealed class ReducedRateLimitFactory(int authPermitLimit, int apiPermitLimit) : AdminDevelopmentFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services => services.Configure<RateLimiterOptions>(options =>
                options.GlobalLimiter = AdminRateLimiting.CreateGlobalLimiter(
                    authPermitLimit,
                    apiPermitLimit,
                    TimeSpan.FromMinutes(1))));
        }
    }

    private sealed class DevelopmentApiKeyRateLimitFactory : AdminDevelopmentFactory
    {
        private const string ApiKeyVariable = "GATEWAY_RATE_LIMIT_DEVELOPMENT_API_KEY";
        internal const string ApiKey = "synthetic-development-api-key-rate-limit";

        internal DevelopmentApiKeyRateLimitFactory() =>
            Environment.SetEnvironmentVariable(ApiKeyVariable, ApiKey, EnvironmentVariableTarget.Process);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentApiKey");
            builder.UseSetting("Gateway:Admin:ApiKeyEnvironmentVariable", ApiKeyVariable);
            builder.ConfigureServices(services => services.Configure<RateLimiterOptions>(options =>
                options.GlobalLimiter = AdminRateLimiting.CreateGlobalLimiter(
                    authPermitLimit: 1,
                    apiPermitLimit: 1,
                    window: TimeSpan.FromMinutes(1))));
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            Environment.SetEnvironmentVariable(ApiKeyVariable, null, EnvironmentVariableTarget.Process);
            GC.SuppressFinalize(this);
        }
    }
}

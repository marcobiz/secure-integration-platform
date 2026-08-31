using System.Net;
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
        DefaultHttpContext auth = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/api/v1/connectors", subject: SyntheticRemoteAddress.ToString());

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
        DefaultHttpContext auth = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/api/v1/connectors", subject: SyntheticRemoteAddress.ToString());

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
        DefaultHttpContext auth = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());
        DefaultHttpContext api = Context("/admin/api/v1/connectors", subject: SyntheticRemoteAddress.ToString());

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
        DefaultHttpContext auth = Context("/admin/auth/me", subject: SyntheticRemoteAddress.ToString());

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
        DefaultHttpContext auth = Context("/admin/auth/me", subject: "synthetic-principal-a");

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
    public async Task ADMIN_RATE_LIMIT_tenant_or_installation_isolation_has_no_shared_global_bucket()
    {
        using PartitionedRateLimiter<HttpContext> limiter = AdminRateLimiting.CreateGlobalLimiter(1, 1, TimeSpan.FromMinutes(1));
        DefaultHttpContext firstInstallation = Context(
            "/admin/api/v1/installations/11111111-1111-1111-1111-111111111111",
            subject: "synthetic-tenant-a-admin");
        DefaultHttpContext secondInstallation = Context(
            "/admin/api/v1/installations/22222222-2222-2222-2222-222222222222",
            subject: "synthetic-tenant-b-admin");

        Assert.NotEqual(
            AdminRateLimiting.GetPartitionKey(firstInstallation),
            AdminRateLimiting.GetPartitionKey(secondInstallation));
        Assert.True(await AcquireAsync(limiter, firstInstallation));
        Assert.False(await AcquireAsync(limiter, firstInstallation));
        Assert.True(await AcquireAsync(limiter, secondInstallation));
        TestContext.Current.TestOutputHelper?.WriteLine(
            "TARGET_PRINCIPAL_429_COUNT=1; CROSS_TENANT_REJECTION_COUNT=0");
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
    public void ADMIN_RATE_LIMIT_untrusted_forwarded_headers_cannot_select_partition_identity()
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
    public void ADMIN_RATE_LIMIT_production_defaults_remain_20_240_one_minute_and_zero_queue()
    {
        FixedWindowRateLimiterOptions auth = AdminRateLimiting.ProductionOptions(AdminRateLimitPolicyClass.Auth);
        FixedWindowRateLimiterOptions api = AdminRateLimiting.ProductionOptions(AdminRateLimitPolicyClass.Api);

        Assert.Equal(20, auth.PermitLimit);
        Assert.Equal(240, api.PermitLimit);
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
}

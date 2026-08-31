using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;

namespace SecureIntegration.Gateway.Api;

internal enum AdminRateLimitPolicyClass
{
    Auth,
    Api
}

internal enum AdminRateLimitPrincipalKind
{
    RemoteIp,
    AuthenticatedSubject,
    Unavailable
}

internal readonly record struct AdminRateLimitPartitionKey(
    AdminRateLimitPolicyClass PolicyClass,
    AdminRateLimitPrincipalKind PrincipalKind,
    string Identity);

internal static class AdminRateLimiting
{
    internal const int AuthPermitLimit = 20;
    internal const int ApiPermitLimit = 240;
    internal const int QueueLimit = 0;
    internal const bool AutoReplenishment = true;
    internal const string SafeRejectionCode = "BGW-RATE-LIMITED";
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromHours(1);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter() =>
        CreateGlobalLimiter(AuthPermitLimit, ApiPermitLimit, Window);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(
        int authPermitLimit,
        int apiPermitLimit,
        TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(authPermitLimit);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(apiPermitLimit);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);

        return PartitionedRateLimiter.Create<HttpContext, AdminRateLimitPartitionKey>(context =>
        {
            AdminRateLimitPartitionKey key = GetPartitionKey(context);
            int permitLimit = key.PolicyClass == AdminRateLimitPolicyClass.Auth
                ? authPermitLimit
                : apiPermitLimit;
            return RateLimitPartition.GetFixedWindowLimiter(
                key,
                _ => CreateFixedWindowOptions(permitLimit, window));
        });
    }

    internal static AdminRateLimitPartitionKey GetPartitionKey(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (IsAuthRequest(context.Request.Path))
        {
            return RemoteIpKey(AdminRateLimitPolicyClass.Auth, context.Connection.RemoteIpAddress);
        }

        string? subject = context.User.FindFirst("sub")?.Value;
        if (!string.IsNullOrEmpty(subject))
        {
            return new(
                AdminRateLimitPolicyClass.Api,
                AdminRateLimitPrincipalKind.AuthenticatedSubject,
                subject);
        }

        return RemoteIpKey(AdminRateLimitPolicyClass.Api, context.Connection.RemoteIpAddress);
    }

    internal static FixedWindowRateLimiterOptions ProductionOptions(AdminRateLimitPolicyClass policyClass) =>
        CreateFixedWindowOptions(
            policyClass == AdminRateLimitPolicyClass.Auth ? AuthPermitLimit : ApiPermitLimit,
            Window);

    internal static ForwardedHeadersOptions CreateForwardedHeadersOptions(IEnumerable<string> trustedProxies)
    {
        ArgumentNullException.ThrowIfNull(trustedProxies);
        ForwardedHeadersOptions options = new()
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (string configuredProxy in trustedProxies)
        {
            if (!IPAddress.TryParse(configuredProxy, out IPAddress? proxy))
                throw new InvalidOperationException("Gateway Admin trusted proxy is invalid.");
            options.KnownProxies.Add(proxy);
        }
        return options;
    }

    internal static async ValueTask WriteSafeRejectionAsync(
        HttpContext context,
        RateLimitLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(lease);

        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.ContentType = "application/problem+json";
        if (lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter) &&
            TryGetBoundedRetryAfterSeconds(retryAfter, out int retryAfterSeconds))
        {
            context.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        }

        await context.Response.WriteAsJsonAsync(
            new
            {
                type = "about:blank",
                title = "Too many requests",
                status = StatusCodes.Status429TooManyRequests,
                code = SafeRejectionCode,
                retryable = true
            },
            options: null,
            contentType: "application/problem+json",
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    internal static bool TryGetBoundedRetryAfterSeconds(TimeSpan retryAfter, out int seconds)
    {
        seconds = 0;
        if (retryAfter < TimeSpan.Zero || retryAfter > MaximumRetryAfter || !double.IsFinite(retryAfter.TotalSeconds))
            return false;

        seconds = checked((int)Math.Ceiling(retryAfter.TotalSeconds));
        return seconds is >= 0 and <= 3600;
    }

    private static bool IsAuthRequest(PathString path) =>
        path.StartsWithSegments("/admin/auth", StringComparison.OrdinalIgnoreCase);

    private static AdminRateLimitPartitionKey RemoteIpKey(
        AdminRateLimitPolicyClass policyClass,
        IPAddress? remoteIpAddress)
    {
        if (remoteIpAddress is null)
            return new(policyClass, AdminRateLimitPrincipalKind.Unavailable, "unavailable");

        IPAddress normalized = remoteIpAddress.IsIPv4MappedToIPv6
            ? remoteIpAddress.MapToIPv4()
            : remoteIpAddress;
        return new(policyClass, AdminRateLimitPrincipalKind.RemoteIp, normalized.ToString());
    }

    private static FixedWindowRateLimiterOptions CreateFixedWindowOptions(int permitLimit, TimeSpan window) => new()
    {
        PermitLimit = permitLimit,
        Window = window,
        QueueLimit = QueueLimit,
        AutoReplenishment = AutoReplenishment
    };
}

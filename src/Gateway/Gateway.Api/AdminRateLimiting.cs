using System.Globalization;
using System.Net;
using System.Security.Claims;
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
    internal const int AuthPermitLimit = 60;
    internal const int ApiPermitLimit = 600;
    internal const int QueueLimit = 0;
    internal const bool AutoReplenishment = true;
    internal const string SafeRejectionCode = "BGW-RATE-LIMITED";
    internal const string DevelopmentApiKeySubject = "development-api-key";
    internal const string DevelopmentApiKeyAuthenticationType = "DevelopmentApiKey";
    internal const string DevelopmentApiKeyRejectedItem = "AdminRateLimit.DevelopmentApiKeyRejected";
    internal const string PreAuthenticationCallbackLeaseItem = "AdminRateLimit.PreAuthenticationCallbackLease";
    internal const string DefaultOidcCallbackPath = "/admin/auth/callback";
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromHours(1);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter() =>
        CreateGlobalLimiter(AuthPermitLimit, ApiPermitLimit, Window, DefaultOidcCallbackPath);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(string oidcCallbackPath) =>
        CreateGlobalLimiter(AuthPermitLimit, ApiPermitLimit, Window, oidcCallbackPath);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(
        int authPermitLimit,
        int apiPermitLimit,
        TimeSpan window,
        string oidcCallbackPath = DefaultOidcCallbackPath)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(authPermitLimit);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(apiPermitLimit);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        if (string.IsNullOrWhiteSpace(oidcCallbackPath) || oidcCallbackPath[0] != '/')
            throw new ArgumentException("OIDC callback path must be absolute.", nameof(oidcCallbackPath));

        return PartitionedRateLimiter.Create<HttpContext, AdminRateLimitPartitionKey>(context =>
        {
            AdminRateLimitPartitionKey key = GetPartitionKey(context, oidcCallbackPath);
            if (context.Items.ContainsKey(PreAuthenticationCallbackLeaseItem))
                return RateLimitPartition.GetNoLimiter(key);
            int permitLimit = key.PolicyClass == AdminRateLimitPolicyClass.Auth
                ? authPermitLimit
                : apiPermitLimit;
            return RateLimitPartition.GetFixedWindowLimiter(
                key,
                _ => CreateFixedWindowOptions(permitLimit, window));
        });
    }

    internal static AdminRateLimitPartitionKey GetPartitionKey(
        HttpContext context,
        string oidcCallbackPath = DefaultOidcCallbackPath)
    {
        ArgumentNullException.ThrowIfNull(context);

        PathString path = context.Request.Path;
        if (IsPreAuthenticationPath(path, oidcCallbackPath) ||
            (IsExactPath(path, "/admin/auth/csrf") && !TryGetAuthenticatedSubject(context, out _)) ||
            IsUnknownAuthPath(path))
        {
            return RemoteIpKey(AdminRateLimitPolicyClass.Auth, context.Connection.RemoteIpAddress);
        }

        if (TryGetAuthenticatedSubject(context, out string subject))
        {
            return new(
                AdminRateLimitPolicyClass.Api,
                AdminRateLimitPrincipalKind.AuthenticatedSubject,
                subject);
        }

        return RemoteIpKey(AdminRateLimitPolicyClass.Api, context.Connection.RemoteIpAddress);
    }

    internal static ClaimsPrincipal DevelopmentApiKeyPrincipal() =>
        new(new ClaimsIdentity(
            [new Claim("sub", DevelopmentApiKeySubject)],
            DevelopmentApiKeyAuthenticationType,
            "sub",
            ClaimTypes.Role));

    internal static bool IsOidcCallback(PathString path, string oidcCallbackPath) =>
        IsExactPath(path, oidcCallbackPath);

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

    private static bool IsPreAuthenticationPath(PathString path, string oidcCallbackPath) =>
        IsExactPath(path, "/admin/auth/login") ||
        IsExactPath(path, "/admin/auth/development/login") ||
        IsOidcCallback(path, oidcCallbackPath);

    private static bool IsUnknownAuthPath(PathString path) =>
        path.StartsWithSegments("/admin/auth", StringComparison.OrdinalIgnoreCase) &&
        !IsExactPath(path, "/admin/auth/csrf") &&
        !IsExactPath(path, "/admin/auth/me") &&
        !IsExactPath(path, "/admin/auth/logout") &&
        !IsExactPath(path, "/admin/auth/login") &&
        !IsExactPath(path, "/admin/auth/development/login");

    private static bool TryGetAuthenticatedSubject(HttpContext context, out string subject)
    {
        string? candidate = context.User.Identity?.IsAuthenticated == true
            ? context.User.FindFirst("sub")?.Value
            : null;
        subject = string.IsNullOrWhiteSpace(candidate) ? string.Empty : candidate;
        return subject.Length > 0;
    }

    private static bool IsExactPath(PathString path, string expected) =>
        string.Equals(path.Value, expected, StringComparison.OrdinalIgnoreCase);

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

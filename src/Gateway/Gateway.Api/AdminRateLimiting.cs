using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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

internal readonly record struct AdminRateLimitObservation(
    long Sequence,
    long LimiterInstanceId,
    long WindowGeneration,
    AdminRateLimitPolicyClass PolicyClass,
    AdminRateLimitPrincipalKind PrincipalKind,
    string PartitionFingerprint,
    bool Acquired);

internal interface IAdminRateLimitObserver
{
    void Observe(AdminRateLimitObservation observation);
}

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

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(IAdminRateLimitObserver observer) =>
        CreateGlobalLimiter(AuthPermitLimit, ApiPermitLimit, Window, DefaultOidcCallbackPath, observer);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(
        IAdminRateLimitObserver observer,
        TimeProvider observationTimeProvider) =>
        CreateGlobalLimiter(AuthPermitLimit, ApiPermitLimit, Window, DefaultOidcCallbackPath, observer, observationTimeProvider);

    internal static PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(
        int authPermitLimit,
        int apiPermitLimit,
        TimeSpan window,
        string oidcCallbackPath = DefaultOidcCallbackPath,
        IAdminRateLimitObserver? observer = null,
        TimeProvider? observationTimeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(authPermitLimit);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(apiPermitLimit);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        if (string.IsNullOrWhiteSpace(oidcCallbackPath) || oidcCallbackPath[0] != '/')
            throw new ArgumentException("OIDC callback path must be absolute.", nameof(oidcCallbackPath));
        if (observer is null && observationTimeProvider is not null)
            throw new ArgumentException("An observation time provider requires an observer.", nameof(observationTimeProvider));

        AdminRateLimitObservationState? observationState = observer is null
            ? null
            : new(observer, observationTimeProvider ?? TimeProvider.System);

        PartitionedRateLimiter<HttpContext> limiter = PartitionedRateLimiter.Create<HttpContext, AdminRateLimitPartitionKey>(context =>
        {
            AdminRateLimitPartitionKey key = GetPartitionKey(context, oidcCallbackPath);
            if (context.Items.ContainsKey(PreAuthenticationCallbackLeaseItem))
                return RateLimitPartition.GetNoLimiter(key);
            int permitLimit = key.PolicyClass == AdminRateLimitPolicyClass.Auth
                ? authPermitLimit
                : apiPermitLimit;
            return observationState is null
                ? RateLimitPartition.GetFixedWindowLimiter(
                    key,
                    _ => CreateFixedWindowOptions(permitLimit, window))
                : RateLimitPartition.Get(
                    key,
                    partitionKey => observationState.CreatePartitionLimiter(
                        partitionKey,
                        CreateFixedWindowOptions(permitLimit, window),
                        window));
        });
        return observationState is null ? limiter : new ObservationOwnedAdminRateLimiter(limiter, observationState);
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

    private sealed class AdminRateLimitObservationState : IDisposable
    {
        private static long nextInstanceId;
        private readonly long instanceId = Interlocked.Increment(ref nextInstanceId);
        private readonly IAdminRateLimitObserver observer;
        private readonly TimeProvider timeProvider;
        private readonly byte[] fingerprintKey = RandomNumberGenerator.GetBytes(32);
        private long sequence;
        private int disposed;

        internal AdminRateLimitObservationState(
            IAdminRateLimitObserver observer,
            TimeProvider timeProvider)
        {
            this.observer = observer;
            this.timeProvider = timeProvider;
        }

        internal ObservedPartitionRateLimiter CreatePartitionLimiter(
            AdminRateLimitPartitionKey partition,
            FixedWindowRateLimiterOptions options,
            TimeSpan window)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            long partitionCreatedTimestamp = timeProvider.GetTimestamp();
            string fingerprint = Fingerprint(partition);
            return new ObservedPartitionRateLimiter(
                new FixedWindowRateLimiter(options),
                this,
                partition.PolicyClass,
                partition.PrincipalKind,
                fingerprint,
                partitionCreatedTimestamp,
                window);
        }

        internal void Observe(
            AdminRateLimitPolicyClass policyClass,
            AdminRateLimitPrincipalKind principalKind,
            string partitionFingerprint,
            long partitionCreatedTimestamp,
            TimeSpan window,
            bool acquired)
        {
            long currentTimestamp = timeProvider.GetTimestamp();
            TimeSpan elapsed = timeProvider.GetElapsedTime(partitionCreatedTimestamp, currentTimestamp);
            long generation = elapsed.Ticks / window.Ticks;
            observer.Observe(new(
                Interlocked.Increment(ref sequence),
                instanceId,
                generation,
                policyClass,
                principalKind,
                partitionFingerprint,
                acquired));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            CryptographicOperations.ZeroMemory(fingerprintKey);
        }

        private string Fingerprint(AdminRateLimitPartitionKey partition)
        {
            ReadOnlySpan<byte> policy = partition.PolicyClass switch
            {
                AdminRateLimitPolicyClass.Auth => "AUTH"u8,
                AdminRateLimitPolicyClass.Api => "API"u8,
                _ => throw new InvalidOperationException("ADMIN_RATE_LIMIT_POLICY_CLASS_INVALID")
            };
            ReadOnlySpan<byte> principal = partition.PrincipalKind switch
            {
                AdminRateLimitPrincipalKind.RemoteIp => "REMOTE_IP"u8,
                AdminRateLimitPrincipalKind.AuthenticatedSubject => "AUTHENTICATED_SUBJECT"u8,
                AdminRateLimitPrincipalKind.Unavailable => "UNAVAILABLE"u8,
                _ => throw new InvalidOperationException("ADMIN_RATE_LIMIT_PRINCIPAL_KIND_INVALID")
            };
            int identityByteCount = Encoding.UTF8.GetByteCount(partition.Identity);
            byte[] canonical = GC.AllocateUninitializedArray<byte>(
                policy.Length + 1 + principal.Length + 1 + identityByteCount);
            try
            {
                int offset = 0;
                policy.CopyTo(canonical.AsSpan(offset));
                offset += policy.Length;
                canonical[offset++] = 0x1f;
                principal.CopyTo(canonical.AsSpan(offset));
                offset += principal.Length;
                canonical[offset++] = 0x1f;
                _ = Encoding.UTF8.GetBytes(partition.Identity, canonical.AsSpan(offset));
                return Convert.ToHexString(HMACSHA256.HashData(fingerprintKey, canonical));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
    }

    private sealed class ObservedPartitionRateLimiter(
        RateLimiter inner,
        AdminRateLimitObservationState observationState,
        AdminRateLimitPolicyClass policyClass,
        AdminRateLimitPrincipalKind principalKind,
        string partitionFingerprint,
        long partitionCreatedTimestamp,
        TimeSpan window) : RateLimiter
    {
        public override TimeSpan? IdleDuration => inner.IdleDuration;

        public override RateLimiterStatistics? GetStatistics() => inner.GetStatistics();

        protected override RateLimitLease AttemptAcquireCore(int permitCount)
        {
            RateLimitLease lease = inner.AttemptAcquire(permitCount);
            Observe(lease);
            return lease;
        }

        protected override async ValueTask<RateLimitLease> AcquireAsyncCore(int permitCount, CancellationToken cancellationToken)
        {
            RateLimitLease lease = await inner.AcquireAsync(permitCount, cancellationToken).ConfigureAwait(false);
            Observe(lease);
            return lease;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            await base.DisposeAsyncCore().ConfigureAwait(false);
        }

        private void Observe(RateLimitLease lease) => observationState.Observe(
            policyClass,
            principalKind,
            partitionFingerprint,
            partitionCreatedTimestamp,
            window,
            lease.IsAcquired);
    }

    private sealed class ObservationOwnedAdminRateLimiter(
        PartitionedRateLimiter<HttpContext> inner,
        AdminRateLimitObservationState observationState) : PartitionedRateLimiter<HttpContext>
    {

        public override RateLimiterStatistics? GetStatistics(HttpContext resource) => inner.GetStatistics(resource);

        protected override RateLimitLease AttemptAcquireCore(HttpContext resource, int permitCount)
            => inner.AttemptAcquire(resource, permitCount);

        protected override async ValueTask<RateLimitLease> AcquireAsyncCore(HttpContext resource, int permitCount, CancellationToken cancellationToken)
            => await inner.AcquireAsync(resource, permitCount, cancellationToken).ConfigureAwait(false);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    inner.Dispose();
                }
                finally
                {
                    observationState.Dispose();
                }
            }
            base.Dispose(disposing);
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            try
            {
                await inner.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                observationState.Dispose();
            }
            await base.DisposeAsyncCore().ConfigureAwait(false);
        }
    }
}

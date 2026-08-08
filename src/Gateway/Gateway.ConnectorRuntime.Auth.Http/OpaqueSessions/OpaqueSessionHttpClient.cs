using System.Net;
using System.Net.Http.Headers;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

/// <summary>
/// Performs a single destination-bound opaque-session projection and restricted dispatch.
/// It never returns an authenticated request or exposes the upstream session value.
/// </summary>
public sealed class OpaqueSessionHttpClient
{
    private readonly OpaqueSessionLeaseProvider sessions;
    private readonly IHostResolver resolver;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly IPrivateDestinationAllowance? privateDestinationAllowance;
    private readonly Func<CancellationToken, Task>? beforeFinalAuthorization;

    /// <summary>Creates the generic one-shot dispatcher over a controlled opaque-session lifecycle.</summary>
    public OpaqueSessionHttpClient(OpaqueSessionLeaseProvider sessions, IHostResolver resolver, IRestrictedTransport transport, IGatewayClock clock, IPrivateDestinationAllowance? privateDestinationAllowance = null)
        : this(sessions, resolver, transport, clock, privateDestinationAllowance, null)
    {
    }

    internal OpaqueSessionHttpClient(OpaqueSessionLeaseProvider sessions, IHostResolver resolver, IRestrictedTransport transport, IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance, Func<CancellationToken, Task>? beforeFinalAuthorization)
    {
        this.sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        this.resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.privateDestinationAllowance = privateDestinationAllowance;
        this.beforeFinalAuthorization = beforeFinalAuthorization;
    }

    /// <summary>Materializes a safe request, then acquires final authority and dispatches exactly once.</summary>
    public async Task<OpaqueSessionHttpResponse> SendAsync(
        OpaqueSessionResolvedExecutionContext resolvedContext,
        ReadOnlyMemory<byte> businessBody,
        OpaqueSessionReference sessionReference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        ArgumentNullException.ThrowIfNull(sessionReference);
        OpaqueSessionHttpAuthorityState expected = resolvedContext.State;
        EnsureDeadline(expected);
        if (businessBody.Length > expected.MaximumRequestBytes || (expected.Method == HttpMethod.Get && !businessBody.IsEmpty))
            throw OpaqueSessionHttpFailures.RequestInvalid();

        // All potentially expensive caller-controlled materialization happens before final authorization.
        byte[] payload = businessBody.ToArray();
        using HttpRequestMessage outbound = new(expected.Method, expected.Endpoint);
        outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", expected.CorrelationId.ToString("D"));
        if (expected.Method != HttpMethod.Get)
            outbound.Content = new ByteArrayContent(payload) { Headers = { ContentType = MediaTypeHeaderValue.Parse(expected.ContentType!) } };

        IPAddress[] addresses;
        try { addresses = await resolver.ResolveAsync(expected.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { throw OpaqueSessionHttpFailures.DestinationDenied(); }
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(expected.Endpoint.DnsSafeHost, address) != true))
            throw OpaqueSessionHttpFailures.DestinationDenied();

        if (beforeFinalAuthorization is not null)
            await beforeFinalAuthorization(cancellationToken).ConfigureAwait(false);

        OpaqueSessionHttpAuthorityState current = await RevalidateAsync(resolvedContext, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(expected.SecurityFingerprint, current.SecurityFingerprint, StringComparison.Ordinal))
            throw OpaqueSessionHttpFailures.Stale();
        EnsureDeadline(current);
        TimeSpan remaining = current.Deadline - clock.UtcNow;
        TimeSpan timeout = remaining < current.Timeout ? remaining : current.Timeout;
        if (timeout <= TimeSpan.Zero) throw OpaqueSessionHttpFailures.DeadlineExpired();

        // Security-final synchronous section: no await or expensive work before the transport invocation.
        OpaqueSessionDispatchLease lease = sessions.AcquireFinalLease(sessionReference, current.LifecycleBinding, clock.UtcNow);
        string projected = current.Placement.Format(lease.UpstreamValue);
        if (!outbound.Headers.TryAddWithoutValidation(current.Placement.HeaderName, projected) || outbound.Headers.GetValues(current.Placement.HeaderName).Count() != 1)
            throw OpaqueSessionHttpFailures.Configuration();
        lease.EnsureCurrent(clock.UtcNow);

        Task<ExternalResponse> dispatch;
        try
        {
            dispatch = transport.SendAsync(outbound, addresses, null, timeout, current.MaximumResponseBytes, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw OpaqueSessionHttpFailures.Transport();
        }

        try
        {
            ExternalResponse response = await dispatch.ConfigureAwait(false);
            OpaqueSessionHttpAuthorityState afterDispatch = await RevalidateAsync(resolvedContext, cancellationToken).ConfigureAwait(false);
            lease.EnsureCurrent(clock.UtcNow);
            if (!string.Equals(current.SecurityFingerprint, afterDispatch.SecurityFingerprint, StringComparison.Ordinal))
                throw OpaqueSessionHttpFailures.Stale();
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw OpaqueSessionHttpFailures.Timeout(); }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw OpaqueSessionHttpFailures.Transport();
        }
    }

    private static async Task<OpaqueSessionHttpAuthorityState> RevalidateAsync(OpaqueSessionResolvedExecutionContext context, CancellationToken cancellationToken)
    {
        try { return await context.Revalidate(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException) { throw; }
        catch (Exception) { throw OpaqueSessionHttpFailures.Rejected(); }
    }

    private void EnsureDeadline(OpaqueSessionHttpAuthorityState state)
    {
        if (state.Deadline <= clock.UtcNow) throw OpaqueSessionHttpFailures.DeadlineExpired();
    }
}
